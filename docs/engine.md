# Engine

The engine is the consumer process. It is a Rust binary (`memvis`) that
attaches to the tracer's shared memory rings, drains events, correlates them
with DWARF debug information, and renders a live view of the target program's
memory state.

This document covers each subsystem of the engine: DWARF parsing, ring
orchestration, address indexing, world state management, and rendering.

## Subsystems

```
                       +------------------+
                       |    DWARF parser  |  (startup, one-shot)
                       |  engine/src/     |
                       |  dwarf.rs        |
                       +--------+---------+
                                |
                         DwarfInfo (globals, functions, locals, types)
                                |
                                v
+------------------+   +------------------+   +------------------+
|  Ring            |-->|  Event processor |-->|  World state     |
|  orchestrator    |   |  main.rs         |   |  world.rs        |
|  ring.rs         |   |  process_event() |   |  Arc<WorldInner> |
+------------------+   +--------+---------+   +--------+---------+
                                |                       |
                         AddressIndex            CoW snapshot
                         index.rs                       |
                                                        v
                                               +------------------+
                                               |  Renderer        |
                                               |  tui.rs (TUI)    |
                                               |  main.rs (text)  |
                                               +------------------+
```

## DWARF parser (`dwarf.rs`)

The DWARF parser runs once at startup. It reads the target ELF binary and
extracts three categories of information:

### Globals

A global variable is a `DW_TAG_variable` with a `DW_AT_location` attribute that
resolves to a fixed address (`DW_OP_addr`). The parser extracts:

- **Name** from `DW_AT_name`.
- **Address** from the location expression.
- **Type information** via recursive `DW_AT_type` resolution. This includes
  the type name, byte size, whether it is a pointer, and (for structs) a list
  of fields with their byte offsets and sizes.

Struct fields are decomposed up to 2 levels of nesting. This means a global
`struct rq` will have its direct fields extracted (e.g., `rq.nr_running`), and
those fields' own fields extracted one level deeper, but no further. This depth
limit prevents stack overflow on deeply nested types (e.g., Linux kernel
scheduler structs).

### Functions

A function is a `DW_TAG_subprogram` or `DW_TAG_inlined_subroutine` with
`DW_AT_low_pc` and `DW_AT_high_pc` attributes. The parser extracts:

- **Name** from `DW_AT_name` (or the abstract origin for inlined subroutines).
- **PC range** from `DW_AT_low_pc` and `DW_AT_high_pc`.
- **Frame base convention.** Whether the frame base is the CFA
  (`DW_OP_call_frame_cfa`) or a register value.
- **Local variables.** Extracted in a second pass over the compilation unit.
  Each local has a name, frame offset, size, type info, and a location table
  (for PC-qualified locations).

### Type resolution

The `resolve_type_at` function follows `DW_AT_type` references through
typedefs, const/volatile qualifiers, pointers, structs, unions, and arrays.
It peels up to 8 levels of typedef/qualifier indirection and caps struct field
extraction at depth 2.

Type resolution produces a `TypeInfo` struct:

```rust
pub struct TypeInfo {
    pub name: String,       // e.g. "int", "*task_t", "cfs_rq"
    pub byte_size: u64,     // sizeof the type
    pub is_pointer: bool,   // true for pointer types
    pub fields: Vec<FieldInfo>,  // struct/union fields (empty for non-aggregates)
}
```

### Location tables

DWARF location descriptions can be simple (a single expression valid for the
entire scope) or PC-qualified (different expressions for different PC ranges).
The parser supports both via `LocationTable`:

```rust
pub struct LocationTable {
    pub entries: Vec<(Range, LocationPiece)>,
}
```

The `lookup(pc)` method returns the `LocationPiece` whose range contains the
given program counter. Supported location pieces:

| Variant | DWARF equivalent | Meaning |
|---|---|---|
| `Address(u64)` | `DW_OP_addr` | Fixed memory address |
| `FrameBaseOffset(i64)` | `DW_OP_fbreg` | Frame base + offset |
| `Register(u16)` | `DW_OP_reg*` | Value lives in a register |
| `RegisterOffset(u16, i64)` | `DW_OP_breg*` | Register + offset |
| `ImplicitValue(u64)` | `DW_OP_implicit_value` | Compile-time constant |
| `CFA` | `DW_OP_call_frame_cfa` | Canonical frame address |
| `Expr(DwarfExprOp)` | Complex expression | Evaluated by stack machine |

The stack machine evaluator (`eval_stack_machine`) supports the full set of
DWARF expression operations: arithmetic, bitwise, stack manipulation, and
`DW_OP_piece`. It cannot dereference target memory (the engine runs in a
separate address space), so `DW_OP_deref` is a no-op that preserves the
address on the stack.

## Ring orchestrator (`ring.rs`)

The orchestrator manages all shared memory connections to the tracer.

### Structures

- **`MappedShm`**: RAII wrapper around `mmap`/`munmap` for a POSIX shared
  memory object.
- **`ThreadRing`**: A single thread's ring buffer. Wraps a `MappedShm` and
  provides `pop`, `pop_n`, `peek`, `batch_pop`, and `fill` methods.
- **`RingOrchestrator`**: Manages the control ring and a vector of
  `ThreadRing`s. Provides `poll_new_rings`, `batch_drain`, `merge_pop`,
  `total_fill`, and `update_backpressure`.

### Discovery

The orchestrator opens `/memvis_ctl` via `try_attach_ctl()`. On success, it
polls the control ring for new thread entries via `poll_new_rings()`, which
runs every 200 ms in the main loop.

### Batch drain

The primary drain method is `batch_drain(per_ring, buf)`:

1. Iterates all rings starting from the current round-robin index.
2. For each ring, calls `batch_pop(per_ring)` which:
   - Loads `tail` (relaxed) and `head` (acquire) once.
   - Reads up to `per_ring` events via `read_volatile`.
   - Stores `tail + n` (release) once.
3. Appends `(ring_index, event)` pairs to the output buffer.
4. Advances the round-robin index.

With the default `per_ring = 20,000` and up to 6 rings, a single
`batch_drain` call can return up to 120,000 events with only 12 atomic
operations total (2 per ring).

### Backpressure

After each drain cycle, the orchestrator calls `update_backpressure()`:

- For each ring, computes fill level in eighths: `(head - tail) << 3 / capacity`.
- If fill >= 6/8 and backpressure is not set: stores `backpressure = 1`
  (release).
- If fill < 3/8 and backpressure is set: stores `backpressure = 0` (release).

This is a consumer-to-producer signal. The tracer reads the flag with relaxed
ordering and sheds `READ` events when it is set.

## Address index (`index.rs`)

The address index is a sorted interval map that resolves memory addresses to
named variables in O(log N) time.

### Structure

```rust
pub struct AddressIndex {
    intervals: Vec<Interval>,   // sorted by lo address
    needs_sort: bool,
}

struct Interval {
    lo: u64,                    // start address (inclusive)
    hi: u64,                    // end address (exclusive)
    meta: VarMeta,              // name, type, node ID, frame ID
}
```

### Two-tier design

The index supports two tiers of entries:

1. **Static globals.** Inserted once after DWARF parsing and relocation.
   Include global variables and their struct fields. Never removed.
2. **Dynamic locals.** Inserted on `CALL` events and removed on `RETURN`
   events. Each local is tagged with a `frame_id` so that all locals from a
   single stack frame can be removed in one operation.

### Lookup

The `lookup(addr)` method performs a binary search (`partition_point`) to find
the rightmost interval where `lo <= addr`, then checks `addr < hi`. On
overlapping intervals (e.g., a local variable at the same address as a global
struct), the lookup prefers:

1. Locals over fields over globals.
2. Narrower intervals over wider intervals (within the same tier).

This ensures that stack-allocated locals shadow heap or global allocations when
their address ranges overlap.

### Finalization

After inserting new entries, `finalize()` must be called to re-sort the
interval vector. The engine defers finalization to the end of each batch drain
cycle (not per-event) to amortize the sorting cost.

## World state (`world.rs`)

The world state is the engine's in-memory model of the target program's
observable state.

### WorldInner

The core data structure:

```rust
pub struct WorldInner {
    pub nodes: BTreeMap<NodeId, Node>,          // tracked variables
    pub edges: BTreeMap<NodeId, PointerEdge>,   // pointer relationships
    pub insn_counter: u64,                      // logical clock
    pub reg_file: LiveRegisterFile,             // 18 x86-64 registers
    pub cache_heat: CacheHeatmap,               // per-node miss tracking
    pub cl_tracker: CacheLineTracker,           // per-cacheline contention
}
```

### Node IDs

Every tracked variable has a unique `NodeId`:

```rust
pub enum NodeId {
    Global(u32),              // index into DwarfInfo.globals
    Field(u32, u16),          // (global_idx, field_idx)
    Local(FrameId, u16),      // (stack frame, local index)
}
```

### Copy-on-write snapshots

`WorldState` wraps `WorldInner` in an `Arc`:

```rust
pub struct WorldState {
    inner: Arc<WorldInner>,
}
```

- **`snapshot()`** returns `Arc::clone(&self.inner)`. This is a reference count
  increment (one atomic instruction). No data is copied.
- **`cow()`** (called before any mutation) invokes `Arc::make_mut`. If the
  `Arc` has a reference count of 1, this is a no-op. If the count is > 1
  (a snapshot is held by the TUI renderer), it clones the inner data.

This design allows the rendering thread to hold an immutable snapshot while the
event processing thread continues mutating the world state.

### Pointer edge tracking

When a tracked pointer variable is written:

1. `process_event` reads the new pointer value from the event.
2. It calls `addr_index.lookup(pointer_value)` to resolve the pointee.
3. If the pointee maps to a tracked variable, a `PointerEdge` is created
   linking source to target.
4. If the pointee does not map to any tracked variable, the edge is marked
   as `is_dangling = true`.
5. If the pointer is set to NULL, the edge is removed.

### Cache-line contention tracking

The `CacheLineTracker` monitors which threads write to each 64-byte cache
line. A cache line is considered "false-shared" if more than one thread has
written to it. The TUI displays false-sharing annotations on affected cache
line headers.

Write counts decay by half on each `tick()` call (approximately every 4096
events), preventing stale contention data from persisting.

### Shadow stacks

The engine maintains a per-thread shadow stack that mirrors the target's call
stack:

```rust
pub struct ShadowStack {
    pub frames: Vec<ShadowFrame>,
    pub mismatches: u64,
    pub max_depth: usize,
}
```

On `CALL`: a new `ShadowFrame` is pushed with the frame ID, callee PC, and
function name.

On `RETURN`: the top frame is popped. Its locals are removed from the address
index and its nodes are queued for removal from the world state (deferred by
32 frames to allow the renderer to display the most recently returned frame).

If a `RETURN` occurs with an empty shadow stack, the mismatch counter is
incremented. This can happen when the tracer misses a CALL (e.g., indirect
calls) or when the target uses `longjmp`.

### Snapshot ring

The `SnapshotRing` is a circular buffer of `Arc<WorldInner>` snapshots, used
for time-travel in the TUI:

```rust
pub struct SnapshotRing {
    buf: Vec<SnapEntry>,   // capacity: 512
    cap: usize,
    write_pos: usize,
    len: usize,
}
```

Each entry stores the snapshot, the instruction counter, the render tick, and
the event sequence number. Binary search methods (`find_by_insn`,
`find_by_tick`, `find_by_seq`) allow O(log N) scrubbing to any point in the
buffered history.

## Event processing (`main.rs`)

The `process_event` function is the central dispatch for all event types:

| Event | Action |
|---|---|
| `WRITE` | Record cache-line write. Lookup address in index. If tracked: update node value, resolve pointer edges. |
| `CALL` | Look up callee PC in DWARF function map (after relocation). Push shadow frame. Insert locals into address index. |
| `RETURN` | Pop shadow frame. Remove locals from address index. Queue frame nodes for removal. |
| `REG_SNAPSHOT` | Pop 6 continuation events. Unpack 18 register values. Update world's register file. |
| `CACHE_MISS` | Lookup miss address. Record miss in cache heatmap. |
| `MODULE_LOAD` | Compute relocation delta. Re-populate globals with relocated addresses. |

The function returns `true` if the event was "interesting" (a tracked write or
any control event). The caller uses this to decide whether to add the event to
the journal. Untracked writes (addresses that do not map to any known variable)
return `false` and are not journaled, which eliminates approximately 90% of
journal overhead under heavy write workloads.

### Batch processing

The main loop uses `batch_drain` to pop up to 20,000 events per ring per cycle.
All events in the batch are processed sequentially. `addr_index.finalize()` is
called once at the end of the batch (not per-CALL event), amortizing the sort
cost.

### Sequence tracking

Each event carries a per-thread 16-bit sequence number. The engine tracks the
expected next sequence number per thread and increments a `seq_gaps` counter
on mismatches. Gaps indicate dropped events (ring overflow) and are displayed
in the TUI.

## Rendering

### Interactive mode (TUI)

The interactive renderer uses `ratatui` with a `crossterm` backend. It renders
at 20 Hz (50 ms refresh interval) and displays:

- **Header bar.** Instruction counter, event count, node count, edge count,
  active ring count, LAG (total events buffered across all rings).
- **Memory map.** All tracked variables grouped by cache line, with addresses,
  sizes, type names, and current values. Pointer values show the name of the
  pointee (or the raw address if the pointee is untracked). Cache lines with
  false sharing are annotated.
- **Pointer edges.** A list of all active pointer relationships.
- **Event journal.** The most recent 12 events with kind, thread ID, address,
  size, and value.
- **Register file.** Current values of all 18 registers, with highlighting for
  registers that changed since the last snapshot.

The TUI supports:
- **Pause/resume** (space bar).
- **Time-travel scrubbing** through the snapshot ring.
- **Quit** (q or Ctrl+C).

### Headless mode

In headless mode (`--once`), the engine writes the same information to stdout
as plain text. It prints a status line every 100 ms and exits after reaching
the `--min-events` threshold. This mode is used for end-to-end testing and
scripting.

### LAG metric

The LAG metric replaces the traditional "fill %" display. It shows the total
number of events currently buffered across all rings (head - tail, summed).
This directly represents how far behind the consumer is from the producer.

| LAG | Color | Meaning |
|---|---|---|
| 0 to 1,000 | Green | Consumer is keeping up |
| 1,001 to 50,000 | Yellow | Consumer is falling behind |
| > 50,000 | Red | Significant consumer lag |

Values are displayed with K (thousands) or M (millions) suffixes for
readability.

## Startup sequence

The full startup sequence when the user runs `memvis <target>`:

1. Engine parses command-line arguments.
2. Engine locates `drrun` (via `DYNAMORIO_HOME`, `MEMVIS_DRRUN`, or PATH).
3. Engine locates `libmemvis_tracer.so` (via `MEMVIS_TRACER` or relative to
   the engine binary).
4. Engine cleans up stale `/dev/shm/memvis_*` files from previous runs.
5. Engine installs signal handlers (SIGINT, SIGTERM) to forward to the tracer.
6. Engine spawns the tracer: `drrun -c libmemvis_tracer.so -- <target>`.
7. Engine parses DWARF from the target ELF binary.
8. Engine polls for `/memvis_ctl` (up to 30 seconds).
9. Engine discovers the first thread ring and attaches.
10. Engine spawns the consumer on a 64 MB stack thread (required for deep
    DWARF type resolution on complex programs).
11. Consumer enters the main event loop (TUI or headless).
12. On exit: engine sends SIGTERM to the tracer, reaps the child process,
    and cleans up shared memory.
