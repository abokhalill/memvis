# Architecture

Authoritative reference for the memvis system architecture. All claims are
derived from the current implementation in `tracer.c`, `memvis_bridge.h`, and
`engine/src/`. Protocol version: **3**.

## System overview

memvis consists of two cooperating OS processes connected by POSIX shared memory:

```
 +-------------------------------+      /dev/shm/         +-------------------------------+
 |           TRACER              | =====================> |            ENGINE             |
 |   (DynamoRIO client, C)       |  per-thread SPSC rings |   (Rust consumer + TUI)       |
 |                               |  control ring          |                               |
 |  tracer.c                     |                        |  engine/src/main.rs           |
 |  memvis_bridge.h              |                        |  engine/src/ring.rs           |
 |                               |                        |  engine/src/dwarf.rs          |
 |  inline pre/post write path   |                        |  engine/src/index.rs          |
 |  clean-call value capture     |                        |  engine/src/world.rs          |
 |  per-thread raw TLS scratch   |                        |  engine/src/shadow_regs.rs    |
 |  adaptive backpressure        |                        |  engine/src/heap_graph.rs     |
 |  tail-call detection          |                        |  engine/src/tui.rs            |
 |  selective reload detection   |                        |  engine/src/lib.rs            |
 |  allocator hooks (drwrap)     |                        |                               |
 +-------------------------------+                        +-------------------------------+
         runs inside                                               runs as the
      target's address space                                     memvis binary
       (via DynamoRIO)                                         (separate process)
```

The **tracer** is a shared library (`libmemvis_tracer.so`) loaded into the
target process by DynamoRIO. The **engine** is a standalone Rust binary
(`memvis`) that launches the tracer, attaches to the shared memory rings, and
consumes events.

## Components

### Tracer (`tracer.c`, `memvis_bridge.h`)

The tracer is a DynamoRIO client. DynamoRIO intercepts every basic block before
execution and gives the tracer a chance to insert instrumentation. The tracer
uses a **hybrid inline/clean-call** strategy:

- **Memory writes.** Two-phase inline instrumentation:
  - `emit_pre_write`: Reserves a ring slot inline via raw TLS scratch
    registers. Writes metadata (address, size, thread ID, sequence, kind,
    RIP offset) directly into the slot. No clean call.
  - `emit_post_write`: Captures the post-write value via a clean call to
    `safe_read_into_slot` (guarded by `DR_TRY_EXCEPT`). Bumps sequence and
    head counters inline. Conditionally flushes head to ring header every
    64 events (`MEMVIS_HEAD_FLUSH_MASK = 0x3F`).
  - **BB-exit flush**: Unconditionally flushes the cached head pointer to the
    ring header's atomic `head` field at the end of every basic block. This
    ensures the consumer sees events even from threads that produce fewer
    than 64 writes per BB.
- **Memory reads.** Buffered into a per-thread read buffer (capacity 16),
  flushed at the end of each basic block via a single clean call.
- **Direct calls.** Clean call to `at_call`: emits CALL event, snapshots 18
  registers via `dr_get_mcontext` (7-slot REG_SNAPSHOT).
- **Returns.** Clean call to `at_return`: emits RETURN event.
- **Tail calls.** Heuristic detection: direct JMP at end of BB, target >4KB
  away, within main module. Emits TAIL_CALL event (kind 8).
- **Reloads.** Selective detection: `MOV reg, [mem]` where destination is a
  callee-saved register (RBX, RBP, R12-R15). Emits RELOAD event (kind 12).
- **Allocator hooks.** `drwrap` intercepts `malloc`, `free`, `realloc`, and
  `calloc` in libc via `event_module_load`. Pre/post callbacks emit ALLOC
  (kind 9) and FREE (kind 10) events. `realloc` emits FREE for the old
  pointer in pre, ALLOC for the new pointer in post.

Each thread gets its own SPSC ring buffer allocated via `shm_open(3)`. Thread
metadata is published to a control ring (`/memvis_ctl`) so the engine can
discover new threads at runtime.

**Per-thread scratch pad** (`memvis_scratch_pad_t`, 128 bytes, 2 cache lines):

| Cache line | Offset | Field | Purpose |
|---|---|---|---|
| CL0 (hot) | 0 | `scratch[0]` | Saved EA for post-write reload |
| | 8 | `scratch[1]` | Event slot pointer (0 = pre-write skipped) |
| | 16 | `ring_data` | Pointer to ring data array |
| | 24 | `ring_mask` | `capacity - 1` (power-of-two mask) |
| | 28 | `_pad0` | Reserved |
| | 32-63 | `_cl0_reserved[4]` | Reserved |
| CL1 (stats) | 64 | `stat_inline_writes` | Inline write events emitted |
| | 72 | `stat_write_slow` | Slow-path writes |
| | 80 | `stat_reads` | Read events emitted |
| | 88 | `stat_reloads` | Reload events emitted |
| | 96 | `stat_calls` | Call events emitted |
| | 104 | `stat_returns` | Return events emitted |
| | 112 | `stat_tail_calls` | Tail-call events emitted |
| | 120 | `stat_dropped` | Events dropped (ring full) |

Stats are per-thread (zero contention). Thread exit drains pad stats into global
atomics via `atomic_fetch_add`.

Source files:

| File | Role |
|---|---|
| `tracer.c` | DynamoRIO client. Inline write path, clean calls, TLS, allocator hooks, stats. |
| `memvis_bridge.h` | Shared ABI. Ring protocol, event formats, control ring, scratch pad. |

### Engine (`engine/`)

The engine is the consumer process. It performs eleven tasks:

1. **DWARF parsing** (`dwarf.rs`). Parses the target ELF binary's
   `.debug_info` section using `gimli`. Extracts global variables, functions,
   local variables, and type information including struct field decomposition
   (depth-limited to 2 levels). Builds a `type_registry` mapping struct names
   to their full `TypeInfo` for use by the Shadow Type Map. Supports location
   tables with PC-qualified ranges, `DW_OP_piece` fragments, and a full
   stack-machine evaluator for complex expressions.

2. **Ring orchestration** (`ring.rs`). Attaches to the control ring with
   protocol version handshake (`MEMVIS_PROTO_VERSION = 3`). Discovers
   per-thread data rings and drains events using batch pops (up to 20,000
   events per ring per cycle, amortizing atomic overhead to 2 atomics per
   ring per batch).

3. **Address indexing** (`index.rs`). Two-tier sorted interval map that maps
   memory addresses to named variables in O(log N). Tier 1 (static): globals
   in a sorted `Vec<Interval>`, finalized once. Tier 2 (dynamic): stack
   locals in `HashMap<FrameId, Vec<Interval>>`, O(1) frame removal. 8-slot
   MRU cache shared across both tiers.

4. **Shadow Register File** (`shadow_regs.rs`). Per-thread register tracking
   with six confidence tiers: Observed, ABI-Inferred, WriteBack, Speculative,
   Stale, Unknown. Coherence checking on every write event via
   interval-overlap detection. Piece assembler for `DW_OP_piece`-fragmented
   variables.

5. **Heap graph** (`heap_graph.rs`). Autonomous heap object discovery via
   write-stream clustering (window=64, radius=256B, min 3 writes). Stores
   `last_value` per field offset for RTR consumption. Infers struct types by
   matching observed field layouts against DWARF type definitions. Tracks
   pointer edges. `on_free(addr, size)` purges objects within freed ranges.

6. **Shadow Type Map** (`world.rs`, `ShadowTypeMap`). Maps heap addresses to
   authoritative DWARF type projections. Populated by two paths:
   - **Direct stamp**: When a DWARF-typed pointer writes to a heap address,
     the pointee's struct type is stamped onto the target.
   - **Field propagation** (`propagate_field_write`): When a write hits an
     address covered by an existing stamp, pointer fields trigger recursive
     stamping of the written value.
   `purge_range(addr, size)` removes projections when memory is freed.

7. **Retrospective Type Reconciliation** (`world.rs`,
   `ShadowTypeMap::retrospective_scan`). On a fresh stamp, performs a bounded
   BFS (fuel=64 nodes) through the HeapGraph's last-known pointer field
   values. For each pointer field whose value is a live allocation and not
   yet stamped, the pointee type is resolved from `type_registry` and
   stamped. This discovers entire data structures (linked lists, trees)
   retroactively, even if they were built before tracing began.

8. **Allocator lifecycle** (`world.rs`, `HeapAllocTracker`). Tracks live
   allocations in a `BTreeMap<addr, size>` for O(log N) range queries.
   On FREE: purges STM projections and HeapGraph objects. **Orphan frees**
   (FREE without matching ALLOC, caused by ring event drops) are counted
   but do **not** purge — this prevents type blindness. Size-validation
   sentinel warns when a stamped type exceeds the known allocation size.

9. **Visual ASan** (`world.rs`, `HeapHazard`). On every heap write, checks
   whether the write stays within a live allocation boundary (O(log N) via
   `BTreeMap` range query). Two hazard classes:
   - **OutOfBounds**: Write starts inside an allocation but extends past its
     end. Reports overflow bytes, type name, and field name.
   - **HeapHole**: Write address falls between allocations within the known
     allocation span. Indicates use-after-free or wild write.
   Hazards are deduplicated by address, capped at 64 entries.

10. **World state** (`world.rs`). Maintains current values of all tracked
    variables, pointer edges, live register file, cache-line contention
    tracker, Shadow Type Map, HeapAllocTracker, and hazard log. Uses
    copy-on-write (`Arc::make_mut`) snapshotting for lock-free rendering.
    Circular snapshot ring (512 entries) for time-travel.

11. **Rendering** (`tui.rs`, `main.rs`). Interactive ratatui TUI at 20 Hz
    with six panels. Headless mode (`--once`) prints final snapshot when
    the ring goes idle for 500ms after event flow begins.

Source files:

| File | Role |
|---|---|
| `engine/src/main.rs` | Entry point, event loop, headless renderer, signal handling. |
| `engine/src/ring.rs` | SHM mapping, ring consumer, orchestrator, proto validation. |
| `engine/src/dwarf.rs` | DWARF parser: globals, functions, locals, types, type_registry. |
| `engine/src/index.rs` | Two-tier interval map. O(log N) address-to-variable lookup. |
| `engine/src/world.rs` | WorldState, STM, RTR, HeapAllocTracker, Visual ASan, CoW snapshots. |
| `engine/src/shadow_regs.rs` | Shadow Register File, confidence tiers, piece assembler. |
| `engine/src/heap_graph.rs` | Heap object discovery, field value storage, pointer edges, GC. |
| `engine/src/tui.rs` | ratatui TUI: panels, keybindings, event filters, time-travel. |
| `engine/src/lib.rs` | Crate root. Re-exports all modules. |

### Shared memory protocol (`memvis_bridge.h`)

The bridge header defines the binary interface between the tracer and engine:

- **Event formats.** Two event structs are defined:
  - `memvis_event_t` (v2): 32-byte with 64-bit `kind_flags`.
  - `memvis_event_v3_t` (v3): 32-byte with 32-bit `kind_flags` (kind:8 |
    flags:8 | seq_hi:16) and 32-bit `rip_lo` (app PC offset from module
    base). Used by the inline write path for extended sequence numbers.
- **Ring header.** 192-byte (3 cache lines) struct with `proto_version` field,
  head and tail cursors on separate cache lines.
- **Control ring.** Fixed-size structure (256 thread slots) with
  `proto_version` field. Dead-slot reclamation via CAS.
- **Build hash.** FNV-1a hash of `__DATE__ __TIME__` stored in the ctl header
  for detecting C/Rust header mismatches.

See [Ring Protocol](ring-protocol.md) for the full specification.

## Data flow

The path of a single memory write event from target program to screen:

```
 target program executes: *ptr = 42;
           |
           v
 [1] DynamoRIO intercepts the BB containing the store instruction
           |
           v
 [2] event_bb_insert calls emit_pre_write BEFORE the store:
     - reserves drreg scratch registers
     - computes EA via drutil_insert_get_mem_addr
     - saves EA to pad.scratch[0]
     - reserves ring slot inline (head & mask -> slot pointer)
     - writes metadata: addr, size, tid, seq_lo, kind_flags, rip_lo
     - saves slot pointer to pad.scratch[1]
           |
           v
 [3] target store executes: *ptr = 42;
           |
           v
 [4] emit_post_write runs AFTER the store:
     - reloads EA from pad.scratch[0] (base reg may be stale)
     - clean call to safe_read_into_slot (DR_TRY_EXCEPT guard)
     - bumps per-thread seq counter and cached head
     - conditionally flushes head to ring header (1/64 events)
           |
           v
 [5] at BB exit: unconditional head flush -> ring.head (release store)
           |
           v
 [6] engine ring.rs:batch_pop loads ring.head (acquire), reads up to
     20K events, stores ring.tail (release) -- 2 atomics per ring
           |
           v
 [7] main.rs event dispatch (EVENT_WRITE path):
     a. cl_tracker.record_write(addr, tid)
     b. shadow_regs.check_coherence(addr, value, size, seq)
     c. if heap addr:
        - heap_graph.process_write(addr, size, value, seq, oracle)
        - stm.propagate_field_write(addr, value, size, seq, type_registry)
        - if new stamp: stm.retrospective_scan(value, heap_graph, allocs, registry, seq)
        - heap_allocs.check_write_bounds(addr, size, stm) -> hazard log
     d. addr_index.lookup(addr) -> named variable (O(log N))
     e. world.update_value(node_id, value, insn)
     f. if pointer: world.update_edge + stm.stamp_type + retrospective_scan
           |
           v
 [8] world.snapshot() -> Arc<WorldInner> (ref-count bump, zero copy)
     TUI renders snapshot at 20 Hz
```

## Address space layout

The tracer runs inside the target's address space. The engine runs in a separate
process. They share data exclusively through POSIX shared memory:

```
/dev/shm/memvis_ctl       Control ring (thread discovery, ~14 KB)
/dev/shm/memvis_ring_0    Thread 0 data ring (1M entries, ~32 MB)
/dev/shm/memvis_ring_1    Thread 1 data ring
...
/dev/shm/memvis_ring_N    Thread N data ring (max N = 255)
```

Each data ring is `sizeof(memvis_ring_header_t) + capacity * 32` bytes. With the
default capacity of 2^20 (1,048,576 entries), each ring is approximately 32 MB.

## Shared memory lifecycle

| Phase | Actor | Action |
|---|---|---|
| Startup | Engine | Best-effort cleanup of stale `/dev/shm/memvis_*` from prior runs |
| Startup | Tracer | Creates `/memvis_ctl`, initializes header with magic + proto_version |
| Thread init | Tracer | Creates `/memvis_ring_N`, registers in ctl (CAS reclaim or allocate) |
| Attach | Engine | Opens `/memvis_ctl`, validates magic + proto_version, starts polling |
| Discovery | Engine | Opens `/memvis_ring_N` per ctl entry, validates magic + proto_version |
| Runtime | Both | Producer writes events, consumer drains them |
| Thread exit | Tracer | Marks thread DEAD (release store), unmaps/unlinks ring SHM |
| Shutdown | Tracer | Unmaps and unlinks `/memvis_ctl` |
| Shutdown | Engine | Unmaps all rings |

All shared memory objects are created with mode 0600 (owner read/write only).

## Relocation

PIE binaries are loaded at a random base address (ASLR). DWARF debug
information uses ELF virtual addresses. The engine computes the relocation
delta:

```
delta = runtime_module_base - elf_base_vaddr
```

The tracer emits a `MODULE_LOAD` event (kind 7) containing the runtime base
address. The engine receives this and re-populates all global variable
addresses by adding the delta. The tracer's `event_module_load` callback
detects libc (for allocator hook installation via `drwrap`) and captures
the first non-system module as the main executable.

## Concurrency model

The tracer and engine never share mutable state directly. All communication is
through SPSC ring buffers. Within the ring protocol:

- The **producer** (tracer thread) owns `head`. Relaxed load, release store
  after writing event data.
- The **consumer** (engine) owns `tail`. Relaxed load, release store after
  reading events.
- Cross-cursor reads use acquire ordering.

There is no mutex, spinlock, or CAS in the hot path. The only CAS operations
are:
- `memvis_ctl_register_thread`: CAS to reclaim DEAD slots (thread creation,
  once per thread lifetime).
- `g_module_base_phase`: CAS 1->2 to emit MODULE_LOAD (exactly once per
  process lifetime).

### Head caching

The tracer caches the ring head pointer in raw TLS (`MEMVIS_RAW_SLOT_HEAD`)
to avoid atomic stores on every event. The cached head is flushed to the
ring header's atomic `head` field:
- Every 64 events (`head & 0x3F == 0`): conditional inline flush.
- At every BB exit: unconditional flush (prevents stale data when a thread
  does fewer than 64 writes in a BB then blocks).

## Dependencies

| Component | Dependency | Version | Purpose |
|---|---|---|---|
| Tracer | DynamoRIO | 11.91+ | Dynamic binary instrumentation |
| Tracer | drmgr | (bundled) | Multi-callback management |
| Tracer | drutil | (bundled) | Memory operand analysis |
| Tracer | drreg | (bundled) | Register reservation |
| Tracer | drwrap | (bundled) | Function wrapping (allocator hooks) |
| Tracer | drsyms | (bundled) | Symbol lookup (allocator function resolution) |
| Engine | gimli | 0.31 | DWARF parsing |
| Engine | object | 0.36 | ELF parsing |
| Engine | ratatui | 0.29 | Terminal UI |
| Engine | crossterm | 0.28 | Terminal I/O |
| Engine | libc | 0.2 | POSIX shared memory (`shm_open`, `mmap`) |

## Build

### Docker

The multi-stage `Dockerfile` builds the tracer (CMake + DynamoRIO SDK) and
engine (Cargo) in an Ubuntu 22.04 builder stage, then produces a minimal
runtime image containing only:
- `drrun` + required DynamoRIO `.so` files
- `libmemvis_tracer.so`
- `memvis` engine binary

```sh
DOCKER_BUILDKIT=1 docker build -t memvis .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v /path/to/my_program:/app/my_program \
    memvis /app/my_program
```

`--cap-add=SYS_PTRACE` is required because DynamoRIO uses `ptrace` for
process attachment. The builder stage patches
`DrMemoryFrameworkConfig.cmake` for CMake 3.28+ compatibility.

### Manual

```sh
# tracer (requires DynamoRIO SDK)
cmake -B build -DDynamoRIO_DIR=/path/to/DynamoRIO/cmake
cmake --build build -j$(nproc)

# engine
cd engine && cargo build --release
```

## Invocation

```sh
# launch mode: starts tracer + engine together (interactive TUI)
memvis <target> [args...]

# headless mode: print final snapshot, exit when target finishes
memvis --once <target>

# consumer-only mode: engine only (tracer started separately via drrun)
memvis --consumer-only [--once] <target.elf>
```

Headless mode exits via idle-timeout: after events begin flowing, if the
ring stays empty for 500ms (50 consecutive 10ms polls), the engine renders
the final snapshot and exits.

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | Path to DynamoRIO installation directory |
| `MEMVIS_DRRUN` | Explicit path to `drrun` binary |
| `MEMVIS_TRACER` | Explicit path to `libmemvis_tracer.so` |
