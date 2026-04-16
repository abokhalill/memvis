# Engine

The engine is a Rust crate (`engine/`) that produces three binaries:

| Binary | Entry point | Purpose |
|---|---|---|
| `memvis` | `main.rs` | Live instrumentation (TUI/headless), event recording, event replay |
| `memvis-diff` | `diff.rs` | Offline ASLR-invariant differential topology comparison |
| `memvis-check` | `check.rs` | CI/CD structural assertion engine over JSONL topology files |

All three share the same library modules via `lib.rs`. This document covers
each subsystem. All claims are derived from the current `engine/src/` source.

## Subsystems

```
                       +------------------+
                       |    DWARF parser  |  (startup, one-shot)
                       |    dwarf.rs      |
                       |  + ELF symtab    |
                       +--------+---------+
                                |
                      DwarfInfo + type_registry
                                |
                                v
+------------------+   +------------------+   +------------------+
|  Ring            |-->|  Reconciler      |-->|  World state     |
|  orchestrator    |   |  reconciler.rs   |   |    world.rs      |
|  ring.rs         |   |  process_event   |   |  Arc<WorldInner> |
+------------------+   |  warm_scan       |   +--------+---------+
         |              +---+---------+----+            |
   EventPlayer              |         |          CoW snapshot
   record.rs         AddressIndex  ShadowRegs          |
         |           index.rs     shadow_regs.rs       v
         v                  |         |       +------------------+
   memvis-diff       HeapGraph    HeapOracle  |  Renderer        |
   diff.rs           heap_graph.rs            |  tui.rs (TUI)    |
         |                  |                 |  main.rs (text)  |
   memvis-check      ShadowTypeMap (STM)      +------------------+
   check.rs          HeapAllocTracker                  |
         |           Visual ASan               EventRecorder
   topology.jsonl    world.rs                  record.rs
   topology.rs                                        |
                                               TopologyStream
                                               topology.rs
```

## DWARF parser (`dwarf.rs`)

The DWARF parser runs once at startup. It reads the target ELF binary and
extracts four categories of information.

### Globals

A global variable is a `DW_TAG_variable` with a `DW_AT_location` attribute
that resolves to a fixed address (`DW_OP_addr`). The parser extracts name,
address, and type information via recursive `DW_AT_type` resolution (including
struct field decomposition, depth-limited to 2 levels).

**ELF symtab fallback**: Globals with `DW_AT_specification` but no
`DW_AT_location` (common in C++ and large C programs like Redis) have their
addresses resolved from the ELF symbol table via `try_extract_spec_global`.
This recovers globals that would otherwise be invisible to the STM and
warm-scan.

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

### Type registry

After parsing, `register_recursive` builds a `HashMap<String, TypeInfo>`
mapping struct/union names to their full `TypeInfo`. Only non-empty,
non-pointer types with `byte_size > 0` are registered. This registry is
used by the Shadow Type Map and RTR to resolve pointee types at runtime.

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
(release) when fill >= 6/8, clears when fill < 3/8. The tracer reads this
with relaxed ordering and sheds `READ` events.

## Address index (`index.rs`)

Two-tier sorted interval map resolving addresses to named variables in O(log N).

### Tier 1: Static globals

Inserted once after DWARF parsing and relocation into a sorted
`Vec<Interval>`. Binary search for O(log N) lookup. Never removed.

### Tier 2: Dynamic locals

Inserted on CALL, removed on RETURN. Stored in
`HashMap<FrameId, Vec<Interval>>` for O(1) frame removal. Scanned linearly
on lookup (typically <10 frames, <5 locals each).

### MRU cache

8-slot MRU cache shared across both tiers with LRU promotion. Each entry
is either `Static { lo, hi, idx }` or `Dynamic { lo, hi, frame_id, local_idx }`.

### Lookup priority

On overlapping intervals, `lookup(addr)` prefers:
1. Locals over fields over globals.
2. Narrower intervals over wider intervals (within the same tier).

### Finalization

`finalize()` re-sorts the static interval vector. Deferred to end of each
batch drain cycle (not per-event) to amortize sorting cost.

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
- **Heap**: Plausible userspace pointer (>=0x1000, <0x0000_8000_0000_0000)
  that is neither module nor stack.

### Object discovery via clustering

`process_write` maintains a sliding window of recent writes
(`CLUSTER_WINDOW = 64`). When >=3 writes fall within `CLUSTER_RADIUS = 256`
bytes of each other and target heap addresses, a new `HeapObject` is created
with the minimum address as base and the span as inferred size.

### Field value storage

Each `HeapObject` stores a `BTreeMap<u64, HeapFieldInfo>` mapping field
offsets to their last-known values, sizes, write counts, and pointer flags.
This is the data source for Retrospective Type Reconciliation — RTR reads
`last_value` from these fields to discover pointer chains without additional
tracer events.

### Pointer edge tracking

Fields where `size == 8` and the value is a plausible pointer are tagged as
pointer fields. `HeapEdge`s track source->target relationships with write
counts.

### Type inference

Periodically (`TYPE_INFERENCE_INTERVAL = 10,000` events), `run_type_inference`
matches observed field layouts against DWARF struct definitions. Each
candidate is scored by field-offset/size match ratio with a 10% bonus for
exact size match. Objects with score >=0.5 get a type annotation.

### Lifecycle integration

`on_free(addr, size)` removes all objects whose base address falls within
the freed range, and purges their entries from `addr_to_base`.

### Garbage collection

`gc_stale(current_seq, max_age)` evicts objects not written within `max_age`
sequence numbers. Called every 65,536 events with `max_age = 500,000`.

## Shadow Type Map (`world.rs`)

The STM is a `HashMap<u64, TypeProjection>` mapping heap addresses to
authoritative DWARF type projections. Each projection stores:

```rust
pub struct TypeProjection {
    pub base_addr: u64,
    pub type_info: TypeInfo,
    pub source_name: String,
    pub stamp_seq: u64,
}
```

### Stamp paths

1. **Direct stamp** (`stamp_type`): When a DWARF-typed pointer global or
   local writes a non-zero value to a heap address, the pointee's struct
   type is looked up in `type_registry` and stamped. Returns `true` if this
   is a new stamp (address was not previously in the map).

2. **Field propagation** (`propagate_field_write`): When a write hits an
   address covered by an existing STM projection, and the written field is
   a pointer whose pointee type exists in `type_registry`, the engine stamps
   the written value with the pointee type.

3. **Size-validation sentinel** (`HeapAllocTracker::check_size`): Before
   stamping, if the type's `byte_size` exceeds the known allocation size,
   a `SizeMismatch` is recorded but the stamp still proceeds (last-write-wins).

### Purge

`purge_range(addr, size)` removes all projections whose `base_addr` falls
within `[addr, addr + size)`. Called on every confirmed FREE event.

## Retrospective Type Reconciliation (`world.rs`)

`ShadowTypeMap::retrospective_scan` performs a bounded BFS from a
freshly-stamped address:

```
queue = [seed_addr]
stamped = 0
while queue not empty AND stamped < 64:
    base = queue.pop_front()
    proj = stm.get(base)           // must be stamped
    obj  = heap_graph.find(base)   // must have observed fields
    candidates = []
    for each pointer field in proj.type_info.fields:
        val = obj.fields[field.byte_offset].last_value
        if val != 0 AND val not in stm AND val in live_allocs:
            pointee_type = type_registry[field.type_info.name.strip_prefix('*')]
            candidates.push((field.name, val, pointee_type))
    candidates.sort_by(field_name)          // deterministic order
    for (name, val, type) in candidates:
        stm.stamp(val, type, name, seq)
        stamped += 1
        queue.push_back(val)
```

The fuel budget (64 nodes) prevents latency spikes on large graphs.
**Deterministic BFS**: candidates are sorted by field name before pushing to
the queue, ensuring identical discovery order across ASLR'd runs. The BFS
uses `find_object_base` on the HeapGraph to handle cases where the STM stamp
address differs from the HeapGraph's clustering base, adjusting field offsets
by the delta.

**Effect**: The instant a global pointer is assigned to the head of a linked
list, RTR discovers and types every reachable node in the chain — even if
the list was built before tracing began.

## Allocator lifecycle (`world.rs`)

`HeapAllocTracker` tracks live allocations in a `BTreeMap<u64, u64>` (addr
to size), enabling O(log N) range queries via `containing_alloc`.

### Event handling

- **ALLOC** (kind 9): `on_alloc(ptr, size)` inserts the allocation.
  Size is read from `ev.size` (32-bit field).
- **FREE** (kind 10): `on_free(ptr)` removes the allocation and returns
  the old size. If no matching ALLOC exists (orphan free), the counter
  `orphan_frees` is incremented but the STM is **not** purged.

### Orphan free policy

Orphan frees occur when the ALLOC event was dropped due to ring backpressure.
Purging the STM on an orphan free would cause "type blindness" — typed nodes
silently vanishing from the output. The conservative policy (count but don't
purge) preserves type information until the address is overwritten or freed
with a matching allocation.

### Headless output

The status line includes allocation metrics:
```
allocs {total_allocs}/{total_frees} live {live_count} [orphan_free={orphan_frees}]
```

## Visual ASan (`world.rs`)

On every heap write, `check_write_bounds(addr, write_size, stm)` checks
whether the write stays within a live allocation boundary.

### Hazard classification

```rust
pub enum HazardKind {
    OutOfBounds,  // write starts in alloc, extends past end
    HeapHole,     // write addr between allocations (UAF / wild write)
}
```

### Symbolic intent

For OOB hazards, the engine looks up the STM projection covering the write
address. If found, it reports the type name and specific field name, enabling
output like:

```
OOB  0x...40 +8B exceeds alloc [0x...20..+24] by 8B (intended for node_t.next)
```

### Heap-hole filtering

HeapHole hazards are only reported if the write address falls within the
span `[min_alloc_addr, max_alloc_addr + max_alloc_size)`. This prevents
false positives from globals and stack addresses that `HeapOracle` loosely
classifies as heap.

### Register context

Each `HeapHazard` carries two additional fields populated at creation time
in `reconciler::process_event`:

- **`pc`** (`u64`): faulting program counter from `ev.rip_lo` (module-relative).
- **`reg_snapshot`** (`Option<[u64; 18]>`): full register values from the
  per-thread `ShadowRegisterFile::values()` at hazard time.

The diff output extracts a compact `HazardRegContext` with `pc`, `rax`,
`rdi`, `rsi`, `rdx`, `rsp` for each hazard.

### Deduplication

Hazards are deduplicated by `write_addr` — if a previous hazard exists for
the same address, the new one is suppressed. Total hazard count is capped
at 64 to bound memory usage.

## World state (`world.rs`)

The engine's in-memory model of the target program's observable state.

### WorldState

```rust
pub struct WorldState {
    inner: Arc<WorldInner>,
    pub cl_tracker: CacheLineTracker,
    pub stm: ShadowTypeMap,
    pub heap_allocs: HeapAllocTracker,
    pub hazards: Vec<HeapHazard>,
}
```

### WorldInner

```rust
pub struct WorldInner {
    pub nodes: BTreeMap<NodeId, Node>,
    pub edges: BTreeMap<NodeId, PointerEdge>,
    pub insn_counter: u64,
    pub reg_file: LiveRegisterFile,
    pub cache_heat: CacheHeatmap,
}
```

Note: `cl_tracker`, `stm`, `heap_allocs`, and `hazards` are on `WorldState`
(mutable), not `WorldInner` (snapshotted). This is intentional — these
structures are only needed by the event processor, not the renderer.

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

## Event reconciler (`reconciler.rs`)

Extracted from `main.rs` into a library module for consumption by both the
live engine and `memvis-diff`. Contains three public functions:

- **`process_event`**: Central dispatch for all event types.
- **`populate_globals`**: Inserts DWARF globals into the address index.
- **`warm_scan`**: Engine-side BFS over `/proc/<pid>/mem`.

### Event dispatch table

| Event | Action |
|---|---|
| `WRITE` (0) | `cl_tracker.record_write`. `shadow_regs.check_coherence`. If heap: `heap_graph.process_write`, `stm.propagate_field_write` (+ RTR on new stamp), `heap_allocs.check_write_bounds` (Visual ASan, populates `pc` + `reg_snapshot` on hazard). `addr_index.lookup` → `world.update_value` + `world.update_edge`. If pointer to heap: `stm.stamp_type` + RTR scan. |
| `READ` (1) | Journal only (no state mutation). |
| `CALL` (2) | DWARF function lookup (relocated PC). Push shadow frame. Insert locals into index. |
| `RETURN` (3) | Pop shadow frame. Remove locals. Queue deferred node removal. |
| `REG_SNAPSHOT` (5) | Pop 6 continuation events from ring. Unpack 18 registers. `shadow_regs.apply_snapshot`. `world.update_regs`. |
| `CACHE_MISS` (6) | `addr_index.lookup`. Record miss in `cache_heat`. |
| `MODULE_LOAD` (7) | Compute relocation delta. Re-populate globals with relocated addresses. Register heap oracle module range. |
| `TAIL_CALL` (8) | Like CALL but does not push a new shadow frame (replaces current). |
| `ALLOC` (9) | `heap_allocs.on_alloc(ptr, size)`. Size read from `ev.size` (32-bit). |
| `FREE` (10) | `heap_allocs.on_free(ptr)`. If matched: `stm.purge_range` + `heap_graph.on_free`. If orphan: count only, no purge. |
| `RELOAD` (12) | `shadow_regs.on_reload(reg, value, src_addr, size, seq, rip)`. |

Returns `true` if the event was "interesting" (tracked write or control
event). Untracked writes return `false` and are not journaled (~90% of
writes in typical workloads).

### Warm-scan

Engine-side BFS that reads `/proc/<pid>/mem` to discover cold data structures.
Triggered after target quiescence (2M events + 10 consecutive idle rounds).

```
for each DWARF global with pointer fields:
    read pointer value from /proc/<pid>/mem
    if value is a live heap allocation:
        resolve pointee type from type_registry
        stm.stamp_type(value, pointee_type, field_name)
        enqueue for recursive scan (depth-limited)
```

Emits `COLD_STAMP` and `COLD_LINK` events to the topology stream.
Discovery statistics: globals scanned, reads, null pointers, missing
pointee types, stamps, max depth, read errors, non-heap pointers.

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
   ring count, LAG metric, allocation stats, time-travel indicator, pause
   indicator, gap warnings.
2. **Memory map** (top-left, 55%). Variables grouped by cache line. Addresses,
   sizes, type names, values with recency coloring (red <100 events, yellow
   <1K, white <10K, gray older). Pointer values show pointee name. Struct
   fields indented under parent. `FALSE_SHARE T=N` on multi-writer cache
   lines. STM-typed heap regions shown in HEAP TYPES section.
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

- `<-`/`h`: Step backward through snapshot ring. Auto-pauses.
- `->`/`l`: Step forward. Returns to live when past latest snapshot.
- `End`: Jump to live (exit time-travel).

### Headless mode (`--once`)

Plain-text output to stdout. Exits via idle-timeout: after events begin
flowing, if the ring stays empty for 500ms (50 consecutive 10ms polls),
the engine renders the final snapshot and exits.

Headless output sections:
1. **Status line**: insn count, events, nodes, edges, rings, LAG, alloc stats.
2. **Memory map**: variables grouped by cache line.
3. **HEAP TYPES**: STM projections with field decomposition.
4. **Size mismatches**: warnings from size-validation sentinel.
5. **Heap hazards**: OOB and heap-hole detections with symbolic intent.
6. **Pointer edges**: resolved and dangling pointer relationships.
7. **Event journal**: last 12 events.

### LAG metric

| LAG | Color | Meaning |
|---|---|---|
| 0-1,000 | Green | Consumer keeping up |
| 1,001-50,000 | Yellow | Falling behind |
| >50,000 | Red | Significant lag |

Displayed with K/M suffixes.

## Event recording (`record.rs`)

### File format

```
Bytes 0..8:    magic  = 0x4D454D5649535243 ("MEMVISRC")
Bytes 8..12:   proto_version (u32) = 3
Bytes 12..20:  event_count (u64, backpatched on close)
Bytes 20..24:  reserved (u32, zero)
Bytes 24..:    packed events, 32 bytes each
```

Each event on disk: `addr(8) + size(4) + tid(2) + seq(2) + value(8) + kind_flags(4) + rip_lo(4) = 32 bytes`.

### Compound REG_SNAPSHOT recording

`EventRecorder::record_reg_snapshot(header, regs)` writes 7 consecutive events:

- Event 0: header (kind = REG_SNAPSHOT)
- Events 1-6: continuation, each packing 3 register values:
  - `addr` = `regs[i*3]`
  - `size` = `regs[i*3+1]` (truncated to u32)
  - `value` = `regs[i*3+2]`

This mirrors the ring protocol layout. The replayer (`memvis-diff`) detects
the header, reads 6 continuations, reconstructs the 18-register array, and
calls `world.update_regs` + `srf.apply_snapshot`.

### EventPlayer

`EventPlayer::open(path)` validates magic and proto_version. `next_event()`
reads one event. `read_batch(buf, max)` reads up to `max` events into a
pre-allocated buffer, returning the count read.

## Topology streaming (`topology.rs`)

JSONL emitter for structural graph deltas. Activated by `--export-topology`.
Each line is a self-contained JSON object.

| Event type | Fields | Emitted when |
|---|---|---|
| `ALLOC` | seq, tid, addr, size | `on_alloc` |
| `FREE` | seq, tid, addr, size | `on_free` (confirmed) |
| `STAMP` | seq, addr, type_name, type_size, source, fields | STM stamp |
| `LINK` | seq, from, from_addr, to_addr, pointee_type, edge | Pointer edge |
| `COLD_STAMP` | addr, type_name, type_size, source, fields, depth | Warm-scan discovery |
| `COLD_LINK` | from, from_addr, to_addr, pointee_type, edge | Warm-scan pointer |
| `HAZARD` | seq, kind, write_addr, write_size, alloc_base, alloc_size, overflow, type_name, field_name | Visual ASan |
| `FALSE_SHARE` | seq, cl_addr, threads, names[] | Cache-line contention |
| `SUMMARY` | total_events, nodes, edges, stm_projections, live_allocs, hazards | End of run |

Consumed by `memvis-check` for structural assertions.

## Differential topology (`diff.rs`, `memvis-diff`)

Replays two `.bin` recordings through `reconciler::process_event` with
`RingOrchestrator::new_offline()`, checkpoints ASLR-invariant topology at
configurable intervals, and reports structural divergence.

### Usage

```sh
memvis-diff --baseline a.bin --subject b.bin --dwarf <elf> \
    [--interval N] [--output diff.jsonl]
```

### Canonical stamps

Each topology checkpoint captures a `BTreeSet<CanonicalStamp>`:

```rust
struct CanonicalStamp {
    source: String,      // symbolic: "server.db", not "0x7f..."
    type_name: String,   // DWARF type name
    type_size: u64,
    field_count: usize,
}
```

Sources come from `TypeProjection::source_name` in the STM. These are
already symbolic (e.g., `server.db`, `shared.ok`), not address-based.
ASLR has no effect on stamp identity.

### Common stamp mask

Stamps present in both final checkpoints are filtered from intermediate
diffs. This eliminates discovery-order noise (warm-scan timing, BFS
non-determinism) while preserving intentional structural divergence.

### Steady-state type histogram

Final checkpoints are compared using an order-invariant `BTreeMap<type_name, count>`.
This is immune to both ASLR and discovery order. Output shows `+N` deltas per type.

### Hazard register context

Each `CanonicalHazard` carries `pc` (from `ev.rip_lo`). The diff output
includes a `HazardRegContext` with `pc`, `rax`, `rdi`, `rsi`, `rdx`, `rsp`
from the `ShadowRegisterFile` at hazard time. JSONL output:

```json
{"hazard":"HOLE","write_size":8,"type":"?","field":"?","pc":"0x8c3cf","rax":"0x75d474c03b00",...}
```

### REG_SNAPSHOT replay

The replayer detects REG_SNAPSHOT headers in the event stream, reads 6
consecutive continuation events, reconstructs the 18-register array, and
calls `world.update_regs` + `srf.apply_snapshot`. This provides full CPU
context for hazard analysis during offline replay.

## Structural assertions (`check.rs`, `memvis-check`)

Reads a JSONL topology file and a `.assertions` file. Evaluates invariants
against the recorded structural events. Intended for CI/CD integration.

```sh
memvis-check topo.jsonl assertions.txt
```

Exit code 0 = all assertions pass. Non-zero = at least one failure.

## Startup sequence

Full startup when the user runs `memvis <target>`:

1. Parse CLI arguments (`--once`, `--consumer-only`, `--record`, `--replay`,
   `--export-topology`, `--min-events`).
2. If `--replay`: spawn replay thread, call `run_replay`. No tracer needed.
3. If `--consumer-only`: spawn consumer thread, attach to existing tracer.
4. Otherwise (launch mode):
   a. Locate `drrun` (via `DYNAMORIO_HOME`, `MEMVIS_DRRUN`, or PATH).
   b. Locate `libmemvis_tracer.so` (via `MEMVIS_TRACER` or relative to binary).
   c. Clean up stale `/dev/shm/memvis_*` from previous runs.
   d. Install signal handlers (SIGINT, SIGTERM) to forward to the tracer.
   e. Spawn the tracer: `drrun -c libmemvis_tracer.so -- <target> [args]`.
5. Parse DWARF from the target ELF binary (globals, functions, locals, types,
   type_registry). ELF symtab fallback for `DW_AT_specification` globals.
6. Poll for `/memvis_ctl` (up to 30 seconds, validating magic + proto).
7. Discover the first thread ring and attach (validating magic + proto).
8. Spawn the consumer on a 64 MB stack thread (deep DWARF resolution).
9. Consumer enters the main event loop (TUI or headless).
10. Warm-scan triggers after 2M events + 10 idle rounds (reads `/proc/<pid>/mem`).
11. If `--record`: `EventRecorder` writes events (compound REG_SNAPSHOT).
12. If `--export-topology`: `TopologyStream` writes JSONL.
13. On exit: finalize recorder/topology, send SIGTERM to tracer, reap child,
    unmap all rings.
