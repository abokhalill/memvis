# Engine

The engine is the consumer process. It is a Rust binary (`memvis`) that
attaches to the tracer's shared memory rings, drains events, correlates them
with DWARF debug information, and renders a live view of the target program's
memory state.

This document covers each subsystem: DWARF parsing, ring orchestration,
address indexing, shadow register file, heap graph, world state management,
and rendering. All claims are derived from the current `engine/src/` source.

## Subsystems

```
                       +------------------+
                       |    DWARF parser  |  (startup, one-shot)
                       |    dwarf.rs      |
                       +--------+---------+
                                |
                         DwarfInfo (globals, functions, locals, types)
                                |
                                v
+------------------+   +------------------+   +------------------+
|  Ring            |-->|  Event processor |-->|  World state     |
|  orchestrator    |   |     main.rs      |   |    world.rs      |
|  ring.rs         |   |                  |   |  Arc<WorldInner> |
+------------------+   +---+---------+----+   +--------+---------+
                            |         |                 |
                     AddressIndex  ShadowRegs    CoW snapshot
                     index.rs     shadow_regs.rs        |
                            |         |                 v
                     HeapGraph    HeapOracle   +------------------+
                     heap_graph.rs             |  Renderer        |
                                               |  tui.rs (TUI)    |
                                               |  main.rs (text)  |
                                               +------------------+
```

## DWARF parser (`dwarf.rs`)

The DWARF parser runs once at startup. It reads the target ELF binary and
extracts three categories of information.

### Globals

A global variable is a `DW_TAG_variable` with a `DW_AT_location` attribute
that resolves to a fixed address (`DW_OP_addr`). The parser extracts name,
address, and type information via recursive `DW_AT_type` resolution (including
struct field decomposition, depth-limited to 2 levels).

### Functions

A function is a `DW_TAG_subprogram` or `DW_TAG_inlined_subroutine` with
`DW_AT_low_pc` and `DW_AT_high_pc`. The parser extracts name, PC range,
frame base convention (CFA or register), and local variables with location
tables.

### Type resolution

`resolve_type_at` follows `DW_AT_type` through typedefs, const/volatile
qualifiers, pointers, structs, unions, and arrays. Peels up to 8 levels of
indirection. Caps struct field extraction at depth 2.

```rust
pub struct TypeInfo {
    pub name: String,
    pub byte_size: u64,
    pub is_pointer: bool,
    pub fields: Vec<FieldInfo>,
}
```

### Location tables

DWARF location descriptions can be simple or PC-qualified. The parser supports
both via `LocationTable`:

```rust
pub struct LocationTable {
    pub entries: Vec<(Range, LocationPiece)>,
}
```

Supported `LocationPiece` variants:

| Variant | DWARF equivalent | Meaning |
|---|---|---|
| `Address(u64)` | `DW_OP_addr` | Fixed memory address |
| `FrameBaseOffset(i64)` | `DW_OP_fbreg` | Frame base + offset |
| `Register(u16)` | `DW_OP_reg*` | Value lives in a register |
| `RegisterOffset(u16, i64)` | `DW_OP_breg*` | Register + offset |
| `ImplicitValue(u64)` | `DW_OP_implicit_value` | Compile-time constant |
| `CFA` | `DW_OP_call_frame_cfa` | Canonical frame address |
| `Expr(DwarfExprOp)` | Complex expression | Stack machine or pattern match |

### Expression evaluator

`DwarfExprOp` has three fast-path patterns plus a general stack machine:

- **`DerefRegOffset`**: `DW_OP_breg + DW_OP_deref` (returns pre-deref addr).
- **`RegPlusReg`**: Two register+offset values added.
- **`StackMachine`**: Full evaluator supporting arithmetic, bitwise, stack
  manipulation (`Drop`, `Pick`, `Swap`, `Rot`), `DW_OP_piece`, and
  `DW_OP_stack_value`. Cannot dereference target memory (separate address
  space), so `DW_OP_deref` preserves the address on the stack.

DWARF-to-memvis register mapping is defined in `DWARF_TO_REGFILE[17]`,
translating DWARF register numbers (0=RAX, 1=RDX, 2=RCX, 3=RBX, ...) to
memvis indices (0=RAX, 1=RBX, 2=RCX, 3=RDX, ...).

## Ring orchestrator (`ring.rs`)

The orchestrator manages all shared memory connections to the tracer.

### Structures

- **`MappedShm`**: RAII wrapper around `shm_open` + `mmap`/`munmap`.
- **`ThreadRing`**: A single thread's ring buffer. Provides `pop`, `pop_n`,
  `peek`, `batch_pop`, and `fill` methods.
- **`RingOrchestrator`**: Manages the control ring and a vector of
  `ThreadRing`s. Provides `try_attach_ctl`, `poll_new_rings`,
  `batch_drain`, `merge_pop`, `total_fill`, and `update_backpressure`.

### Protocol version handshake

On attach, both `try_attach_ctl` and `ThreadRing::from_shm` validate:
1. `magic` matches the expected constant.
2. `proto_version == MEMVIS_PROTO_VERSION` (currently 3).

Mismatches are rejected with a diagnostic message to stderr.

### Batch drain

The primary drain method is `batch_drain(per_ring, buf)`:

1. Iterates all rings from the current round-robin index.
2. Per ring: loads `tail` (relaxed) and `head` (acquire) once, reads up
   to `per_ring` events via `read_volatile`, stores `tail + n` (release).
3. Appends `(ring_index, event)` pairs to the output buffer.

With `per_ring = 20,000` and 6 rings, a single call can return up to
120,000 events with 12 atomic operations total.

### Backpressure

After each drain: computes fill in eighths per ring. Sets `backpressure = 1`
(release) when fill ≥ 6/8, clears when fill < 3/8. The tracer reads this
with relaxed ordering and sheds `READ` events.

## Address index (`index.rs`)

Sorted interval map resolving addresses to named variables in O(log N).

### Two-tier design

1. **Static globals.** Inserted once after DWARF parsing and relocation.
   Never removed.
2. **Dynamic locals.** Inserted on CALL, removed on RETURN. Tagged with
   `frame_id` for batch removal.

### Lookup priority

On overlapping intervals, `lookup(addr)` prefers:
1. Locals over fields over globals.
2. Narrower intervals over wider intervals (within the same tier).

### Finalization

`finalize()` re-sorts the interval vector. Deferred to end of each batch
drain cycle (not per-event) to amortize sorting cost.

## Shadow Register File (`shadow_regs.rs`)

Per-thread register tracking with provenance and coherence.

### Confidence tiers

Each of the 18 tracked registers carries a `Confidence` level:

| Tier | Label | Source |
|---|---|---|
| `Observed` | `OBS` | Direct `REG_SNAPSHOT` from tracer |
| `AbiInferred` | `ABI` | ABI convention (e.g., return value in RAX) |
| `WriteBack` | `WB` | Value written back to known memory source |
| `Speculative` | `SPEC` | Heuristic inference |
| `Stale` | `STALE` | Invalidated by a memory write to the source |
| `Unknown` | `???` | No information |

The TUI renders a 10-segment confidence bar per register with color coding.

### Coherence checking

On every write event, `check_coherence(addr, value, size, seq)` scans all
registers. For each register with a known memory source (`src_addr`,
`src_size`), it checks for interval overlap:

```
overlap = addr < (src_addr + src_size) && (addr + write_size) > src_addr
```

If the write overlaps the register's source and the value differs, the
register is marked `Stale`. This detects cross-thread coherence violations
and same-thread overwrites of spilled register values.

### Event handlers

- **`on_snapshot(regs)`**: Sets all 18 registers to `Observed` confidence.
- **`on_call()`**: Marks caller-saved registers (RAX, RCX, RDX, RSI, RDI,
  R8-R11) as `Unknown`. Callee-saved registers retain their confidence.
- **`on_return()`**: Marks RAX as `AbiInferred` (return value). Callee-saved
  registers retain confidence. Others become `Unknown`.
- **`on_reload(reg, value, src_addr, src_size, seq, rip)`**: Sets register
  to `Observed` with known memory source for future coherence checking.

### Piece assembler

`PieceAssembler` reconstructs `DW_OP_piece`-fragmented variables. It parses
a sequence of `ExprStep`s into `PieceFragment`s, each with a byte offset,
size, and source (`Register`, `Memory`, or `Implicit`). The `assemble`
method reads fragment values from the SRF and produces an `AssembledValue`
with per-fragment confidence tracking.

## Heap graph (`heap_graph.rs`)

Autonomous heap object discovery from the write event stream.

### HeapOracle

Classifies addresses as heap, stack, or module:
- **Module**: Falls within any `(base, base+size)` range from loaded modules.
- **Stack**: Falls within any thread's `(min_rsp, max_rsp + 128KB)` range.
- **Heap**: Plausible userspace pointer (≥0x1000, <0x0000_8000_0000_0000)
  that is neither module nor stack.

### Object discovery via clustering

`process_write` maintains a sliding window of recent writes
(`CLUSTER_WINDOW = 64`). When ≥3 writes fall within `CLUSTER_RADIUS = 256`
bytes of each other and target heap addresses, a new `HeapObject` is created
with the minimum address as base and the span as inferred size.

### Pointer edge tracking

Fields where `size == 8` and the value is a plausible pointer are tagged as
pointer fields. `HeapEdge`s track source→target relationships with write
counts.

### Type inference

Periodically (`TYPE_INFERENCE_INTERVAL = 10,000` events), `run_type_inference`
matches observed field layouts against DWARF struct definitions. Each
candidate is scored by field-offset/size match ratio with a 10% bonus for
exact size match. Objects with score ≥0.5 get a type annotation.

### Garbage collection

`gc_stale(current_seq, max_age)` evicts objects not written within `max_age`
sequence numbers. Called every 65,536 events with `max_age = 500,000`.

## World state (`world.rs`)

The engine's in-memory model of the target program's observable state.

### WorldInner

```rust
pub struct WorldInner {
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: BTreeMap<NodeId, PointerEdge>,
    pub insn_counter: u64,
    pub reg_file: LiveRegisterFile,
    pub cache_heat: CacheHeatmap,
    pub cl_tracker: CacheLineTracker,
}
```

### Node IDs

```rust
pub enum NodeId {
    Global(u32),
    Field(u32, u16),
    Local(FrameId, u16),
}
```

### Copy-on-write snapshots

`WorldState` wraps `WorldInner` in an `Arc`. `snapshot()` is a ref-count
bump (1 atomic). `cow()` calls `Arc::make_mut` — no-op if refcount is 1,
clones if a snapshot is held by the renderer.

### Pointer edge tracking

When a tracked pointer variable is written:
1. `addr_index.lookup(pointer_value)` resolves the pointee.
2. If tracked: `PointerEdge` links source to target.
3. If untracked: edge marked `is_dangling = true`.
4. If NULL: edge removed.

### Cache-line contention tracking

`CacheLineTracker` monitors which threads write to each 64-byte cache line.
`contention_score(addr)` returns the number of distinct writer threads. The
TUI annotates cache lines with `FALSE_SHARE T=N` when N > 1.

`tick()` decays write counts by half and evicts dead entries. Called every
4,096 events alongside `cache_heat_tick()`.

### Shadow stacks

Per-thread shadow stacks mirror the target's call stack:

```rust
pub struct ShadowStack {
    pub frames: Vec<ShadowFrame>,
    pub mismatches: u64,
    pub max_depth: usize,
}
```

- **CALL**: Push frame with ID, callee PC, function name.
- **RETURN**: Pop frame. Remove locals from index. Queue nodes for deferred
  removal (32-frame delay for renderer visibility).
- **Mismatch**: Incremented when RETURN has empty stack (missed CALL,
  indirect calls, `longjmp`).

### Snapshot ring

Circular buffer of 512 `Arc<WorldInner>` snapshots for time-travel:

```rust
pub struct SnapshotRing {
    buf: Vec<SnapEntry>,
    cap: usize,
    write_pos: usize,
    len: usize,
}
```

Each entry: snapshot + instruction counter + render tick + event sequence.

## Event processing (`main.rs`)

Central dispatch for all event types:

| Event | Action |
|---|---|
| `WRITE` (0) | `shadow_regs.check_coherence`. `heap_oracle.update_stack` (if stack addr). `heap_graph.process_write` (if heap addr). `addr_index.lookup` → `world.update_value` + `world.update_edge`. `cl_tracker.record_write`. |
| `READ` (1) | Journal only (no state mutation). |
| `CALL` (2) | DWARF function lookup (relocated PC). Push shadow frame. Insert locals into index. |
| `RETURN` (3) | Pop shadow frame. Remove locals. Queue deferred node removal. |
| `REG_SNAPSHOT` (5) | Pop 6 continuation events. Unpack 18 registers. `shadow_regs.on_snapshot`. `world.reg_file` update. |
| `CACHE_MISS` (6) | `addr_index.lookup`. Record miss in `cache_heat`. |
| `MODULE_LOAD` (7) | Compute relocation delta. Re-populate globals with relocated addresses. |
| `TAIL_CALL` (8) | Like CALL but does not push a new shadow frame (replaces current). |
| `RELOAD` (12) | `shadow_regs.on_reload(reg, value, src_addr, size, seq, rip)`. |

Returns `true` if the event was "interesting" (tracked write or control
event). Untracked writes return `false` and are not journaled (~90% of
writes in typical workloads).

### Periodic maintenance

Every 4,096 events (`total & 0xFFF == 0`):
- `world.cache_heat_tick()` — decay cache miss counts.
- `world.cl_tracker_tick()` — decay contention tracking, evict dead entries.

Every 65,536 events (`total & 0xFFFF == 0`):
- `heap_graph.gc_stale(total, 500_000)` — evict old heap objects.

Heap type inference runs when `heap_graph.needs_type_inference()` returns
true (every 10,000 heap events with objects present).

### Sequence tracking

Each event carries a per-thread 16-bit sequence number. The engine tracks
the expected next sequence per thread and increments `seq_gaps` on
mismatches. Gaps indicate dropped events (ring overflow) and are displayed
in the TUI header.

## Rendering

### Interactive mode (TUI, `tui.rs`)

ratatui with crossterm backend. 20 Hz refresh. Six panels:

1. **Header bar.** Instruction counter, event count, node count, edge count,
   ring count, LAG metric, time-travel indicator, pause indicator, gap
   warnings.
2. **Memory map** (top-left, 55%). Variables grouped by cache line. Addresses,
   sizes, type names, values with recency coloring (red <100 events, yellow
   <1K, white <10K, gray older). Pointer values show pointee name. Struct
   fields indented under parent. `FALSE_SHARE T=N` on multi-writer cache
   lines.
3. **Events** (bottom-left, 45%). Filterable journal. Kind labels: W, R,
   CALL, RET, OVF, REG, CMIS, MLOAD, TCAL, RLOD. Thread ID. Address, size,
   value. Auto-scrolls to bottom unless user has scrolled.
4. **Shadow Registers** (top-right, 40%). 18 registers with hex values,
   10-segment confidence bar (color-coded by tier), stale warnings.
5. **Call Stacks** (mid-right, 30%). Per-thread shadow stacks. Top 4 frames
   shown (newest first). Idle threads show max depth.
6. **Heap Objects** (bottom-right, 30%). Object count, edge count. Top 8 by
   recency: base address, inferred size, type name, confidence %, field
   count, edge count.

### Event filters

Active when Events panel is focused:

| Key | Filter |
|---|---|
| `w` | Writes only (kind 0) |
| `r` | Hide reads (kind 1) |
| `0-9` | Filter by thread ID (toggle) |
| `x` | Clear all filters |

Filter state shown in panel title: `Events [W only, T3]`.

### Time travel

- `←`/`h`: Step backward through snapshot ring. Auto-pauses.
- `→`/`l`: Step forward. Returns to live when past latest snapshot.
- `End`: Jump to live (exit time-travel).

### Headless mode (`--once`)

Plain-text output to stdout. Prints status line every 100 ms. Exits after
`--min-events` threshold. Used for end-to-end testing and scripting.

### LAG metric

| LAG | Color | Meaning |
|---|---|---|
| 0–1,000 | Green | Consumer keeping up |
| 1,001–50,000 | Yellow | Falling behind |
| >50,000 | Red | Significant lag |

Displayed with K/M suffixes.

## Startup sequence

Full startup when the user runs `memvis <target>`:

1. Parse command-line arguments (`--once`, `--min-events`, `--consumer-only`).
2. Locate `drrun` (via `DYNAMORIO_HOME`, `MEMVIS_DRRUN`, or PATH).
3. Locate `libmemvis_tracer.so` (via `MEMVIS_TRACER` or relative to binary).
4. Clean up stale `/dev/shm/memvis_*` from previous runs.
5. Install signal handlers (SIGINT, SIGTERM) to forward to the tracer.
6. Spawn the tracer: `drrun -c libmemvis_tracer.so -- <target> [args]`.
7. Parse DWARF from the target ELF binary (globals, functions, locals, types).
8. Poll for `/memvis_ctl` (up to 30 seconds, validating magic + proto).
9. Discover the first thread ring and attach (validating magic + proto).
10. Spawn the consumer on a 64 MB stack thread (required for deep DWARF
    type resolution on complex programs).
11. Consumer enters the main event loop (TUI or headless).
12. On exit: send SIGTERM to tracer, reap child process, unmap all rings.
