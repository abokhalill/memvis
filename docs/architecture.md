# Architecture

Authoritative reference for the memvis system architecture. All claims are
derived from the current implementation in `tracer.c`, `memvis_bridge.h`, and
`engine/src/`. Protocol version: **3**.

## System overview

memvis consists of two cooperating OS processes connected by POSIX shared
memory, plus offline analysis tools that operate on recorded traces:

```
 ┌───────────────────────────┐  /dev/shm/     ┌───────────────────────────────────┐
 │         TRACER            │ =============> │             ENGINE                │
 │  (DynamoRIO client, C)    │  SPSC rings    │  (Rust, 3 binaries)               │
 │                           │  control ring  │                                   │
 │  tracer.c                 │                │  memvis       main.rs  (live)     │
 │  memvis_bridge.h          │                │  memvis-diff  diff.rs  (offline)  │
 │                           │                │  memvis-check check.rs (CI/CD)    │
 │  inline pre/post write    │                │                                   │
 │  clean-call value capture │                │  reconciler.rs  (event dispatch)  │
 │  per-thread raw TLS       │                │  record.rs      (recording I/O)   │
 │  adaptive backpressure    │                │  topology.rs    (JSONL streaming) │
 │  tail-call detection      │                │  dwarf.rs       (DWARF + ELF)     │
 │  selective reload detect  │                │  world.rs       (STM, RTR, ASan)  │
 │  allocator hooks (drwrap) │                │  ring.rs        (SHM consumer)    │
 └───────────────────────────┘                └───────────────────────────────────┘
       runs inside target's                         separate process(es)
       address space (DBI)
```

The **tracer** is a shared library (`libmemvis_tracer.so`) loaded into the
target by DynamoRIO. The **engine** is a Rust crate producing three binaries:

| Binary | Entry point | Purpose |
|---|---|---|
| `memvis` | `main.rs` | Live instrumentation (TUI/headless), recording, replay |
| `memvis-diff` | `diff.rs` | Offline ASLR-invariant differential topology comparison |
| `memvis-check` | `check.rs` | CI/CD structural assertion engine over JSONL topology |

## Components

### Tracer (`tracer.c`, `memvis_bridge.h`)

The tracer is a DynamoRIO client. It uses a **hybrid inline/clean-call**
strategy. See [Tracer](tracer.md) for the full specification.

Summary of instrumented event types:

| Event | Strategy | Description |
|---|---|---|
| Memory writes | Two-phase inline + clean call | Metadata inline, value via `safe_read_into_slot` |
| Memory reads | Buffered clean call | Per-BB flush of 16-entry buffer |
| Direct calls | Clean call | CALL event + 7-slot REG_SNAPSHOT (18 registers) |
| Returns | Clean call | RETURN event |
| Tail calls | Heuristic (JMP >4KB) | TAIL_CALL event |
| Reloads | Selective (callee-saved) | RELOAD event |
| Allocations | `drwrap` hooks | ALLOC/FREE events for malloc/free/realloc/calloc |

Each thread gets its own SPSC ring buffer via `shm_open(3)`. Thread metadata
is published to a control ring (`/memvis_ctl`). See [Ring Protocol](ring-protocol.md).

### Engine (`engine/`)

The engine is the consumer process. Its subsystems are organized into library
modules re-exported from `lib.rs`, with three binary entry points.

#### Core modules

| File | Module | Role |
|---|---|---|
| `reconciler.rs` | `reconciler` | Extracted event dispatch: `process_event`, `populate_globals`, `warm_scan` |
| `dwarf.rs` | `dwarf` | DWARF parser + ELF symtab fallback: globals, functions, locals, types, type_registry |
| `ring.rs` | `ring` | SHM mapping, ring consumer, orchestrator, `new_offline()` for replay |
| `index.rs` | `index` | Two-tier interval map. O(log N) address-to-variable lookup |
| `world.rs` | `world` | WorldState, STM, RTR, HeapAllocTracker, Visual ASan, CoW snapshots |
| `shadow_regs.rs` | `shadow_regs` | Shadow Register File, confidence tiers, piece assembler |
| `heap_graph.rs` | `heap_graph` | Heap object discovery, field value storage, pointer edges, type inference |
| `record.rs` | `record` | EventRecorder (write), EventPlayer (read), compound REG_SNAPSHOT I/O |
| `topology.rs` | `topology` | JSONL topology streamer: STAMP, LINK, HAZARD, COLD_*, SUMMARY |
| `tui.rs` | `tui` | ratatui TUI: 6 panels, keybindings, event filters, time-travel |
| `lib.rs` | — | Crate root. Re-exports all modules |

#### Binary entry points

| File | Binary | Role |
|---|---|---|
| `main.rs` | `memvis` | CLI shell: launch, consumer-only, record, replay, export-topology |
| `diff.rs` | `memvis-diff` | Replay two `.bin` traces, diff ASLR-invariant topology |
| `check.rs` | `memvis-check` | Evaluate `.assertions` against JSONL topology |

#### Engine subsystem summary

1. **DWARF parsing** (`dwarf.rs`). Parses `.debug_info` via `gimli`. Extracts
   globals, functions, locals, type information (depth-limited to 2 levels).
   Builds `type_registry` mapping struct names to `TypeInfo`. Supports
   location tables, `DW_OP_piece` fragments, and a stack-machine evaluator.
   **ELF symtab fallback**: globals with `DW_AT_specification` but no
   `DW_AT_location` have addresses resolved from the ELF symbol table.

2. **Event reconciler** (`reconciler.rs`). Extracted from `main.rs` for
   library consumption by `memvis-diff`. Contains `process_event` (central
   dispatch for all 12 event types), `populate_globals`, and `warm_scan`.

3. **Warm-scan** (`reconciler.rs`). Engine-side BFS over `/proc/<pid>/mem`.
   Reads global pointer fields from the target's memory after quiescence
   (2M events + 10 idle rounds). Discovers typed structures built before
   tracing. Emits COLD_STAMP and COLD_LINK events to the topology stream.

4. **Ring orchestration** (`ring.rs`). Attaches to control ring with protocol
   handshake. Discovers per-thread data rings. Batch pops up to 20,000
   events per ring per cycle (2 atomics per ring per batch).
   `new_offline()` creates a dummy orchestrator for replay without SHM.

5. **Shadow Type Map** (`world.rs`). Maps heap addresses to DWARF type
   projections. Three stamp paths: direct stamp, field propagation,
   retrospective scan. `purge_range` on FREE.

6. **Retrospective Type Reconciliation** (`world.rs`). Bounded BFS (fuel=64)
   from freshly-stamped addresses through HeapGraph pointer fields. Candidates
   sorted by field name for deterministic discovery order across runs.

7. **Visual ASan** (`world.rs`). OutOfBounds and HeapHole detection with
   symbolic intent. Each `HeapHazard` carries `pc` and `reg_snapshot`
   (18 registers from `ShadowRegisterFile::values()`).

8. **Event recording** (`record.rs`). `EventRecorder::record()` writes 32-byte
   events. `record_reg_snapshot()` writes header + 6 continuation events
   carrying 18 register values. `EventPlayer` reads them back. File format:
   24-byte header (magic + proto + count) followed by packed 32-byte events.

9. **Topology streaming** (`topology.rs`). JSONL emitter for structural graph
   deltas: ALLOC, FREE, STAMP, LINK, COLD_STAMP, COLD_LINK, HAZARD,
   FALSE_SHARE, SUMMARY. Consumed by `memvis-check`.

10. **Differential topology** (`diff.rs`). Replays two `.bin` recordings
    through `reconciler::process_event` with `RingOrchestrator::new_offline()`.
    Checkpoints at configurable intervals. Comparison features:
    - Canonical stamps: `(source, type_name, type_size, field_count)`.
    - Common stamp mask: filters discovery-order noise from intermediate diffs.
    - Steady-state type histogram: order-invariant final-checkpoint comparison.
    - Hazard register context: PC + RAX/RDI/RSI/RDX/RSP per hazard.

11. **World state** (`world.rs`). CoW snapshots via `Arc<WorldInner>`.
    Circular snapshot ring (512 entries) for time-travel. Cache-line
    contention tracker. Live register file.

12. **Rendering** (`tui.rs`, `main.rs`). Interactive ratatui TUI at 20 Hz
    with six panels. Headless mode exits on 500ms idle timeout.

### Shared memory protocol (`memvis_bridge.h`)

See [Ring Protocol](ring-protocol.md) for the full specification. Summary:

- **v3 event format**: 32 bytes. `kind_flags` (u32: kind:8|flags:8|seq_hi:16)
  + `rip_lo` (u32: app PC offset). Extended 32-bit sequence numbers.
- **Ring header**: 192 bytes (3 cache lines). Head and tail on separate lines.
- **Control ring**: 256 thread slots. Dead-slot reclamation via CAS.
- **Build hash**: FNV-1a of `__DATE__ __TIME__` for C/Rust mismatch detection.

## Data flow

### Live path (target write → screen)

```
 target executes: *ptr = 42;
         │
         ▼
 [1] DynamoRIO intercepts BB containing the store
         │
         ▼
 [2] emit_pre_write (inline, BEFORE store):
     reserves drreg scratch, computes EA, saves to pad.scratch[0],
     reserves ring slot, writes metadata (addr, size, tid, seq, kind, rip)
         │
         ▼
 [3] target store executes
         │
         ▼
 [4] emit_post_write (inline + clean call, AFTER store):
     reloads EA from pad.scratch[0], clean call safe_read_into_slot,
     bumps seq + cached head, conditional flush (1/64 events)
         │
         ▼
 [5] BB exit: unconditional head flush → ring.head (release store)
         │
         ▼
 [6] ring.rs:batch_pop: load head (acquire), read ≤20K events,
     store tail (release) — 2 atomics per ring per batch
         │
         ▼
 [7] reconciler::process_event (EVENT_WRITE path):
     a. cl_tracker.record_write(addr, tid)
     b. shadow_regs.check_coherence(addr, value, size, seq)
     c. if heap: heap_graph → stm.propagate → RTR → check_write_bounds
     d. addr_index.lookup → world.update_value + update_edge
     e. if pointer to heap: stm.stamp_type + retrospective_scan
         │
         ▼
 [8] recorder.record(ev) or recorder.record_reg_snapshot(ev, regs)
     [optional: writes to .bin file]
         │
         ▼
 [9] world.snapshot() → Arc<WorldInner> (ref-count bump)
     TUI renders at 20 Hz
```

### Recording path (live → `.bin` → replay)

```
 live run (memvis --record trace.bin)
         │
         ▼
 EventRecorder writes events to .bin (32 bytes each)
 REG_SNAPSHOT: header + 6 continuations = 7 events (18 registers)
         │
         ▼
 offline replay (memvis --replay trace.bin)
   or    offline diff (memvis-diff --baseline a.bin --subject b.bin)
         │
         ▼
 EventPlayer reads events → reconciler::process_event
 REG_SNAPSHOT reconstructed from 7 consecutive events
```

### Warm-scan path (cold discovery)

```
 target quiesces (2M events + 10 idle rounds)
         │
         ▼
 reconciler::warm_scan reads /proc/<pid>/mem
 BFS from DWARF globals → pointer fields → typed structs
         │
         ▼
 COLD_STAMP + COLD_LINK events → topology stream
 stm.stamp_type for each discovered allocation
```

## Address space layout

```
/dev/shm/memvis_ctl       Control ring (thread discovery, ~14 KB)
/dev/shm/memvis_ring_0    Thread 0 data ring (1M entries, ~32 MB)
/dev/shm/memvis_ring_1    Thread 1 data ring
...
/dev/shm/memvis_ring_N    Thread N data ring (max N = 255)
```

Each data ring is `sizeof(memvis_ring_header_t) + capacity * 32` bytes.
Default capacity: 2^20 (1,048,576 entries), ~32 MB per ring.

## Shared memory lifecycle

| Phase | Actor | Action |
|---|---|---|
| Startup | Engine | Best-effort cleanup of stale `/dev/shm/memvis_*` |
| Startup | Tracer | Creates `/memvis_ctl`, inits header (magic + proto_version) |
| Thread init | Tracer | Creates `/memvis_ring_N`, registers via CAS reclaim or alloc |
| Attach | Engine | Opens `/memvis_ctl`, validates magic + proto_version |
| Discovery | Engine | Opens `/memvis_ring_N`, validates magic + proto_version |
| Runtime | Both | Producer writes events, consumer drains them |
| Thread exit | Tracer | Marks DEAD (release store), unmaps/unlinks ring SHM |
| Shutdown | Tracer | Unmaps and unlinks `/memvis_ctl` |
| Shutdown | Engine | Unmaps all rings |

All shared memory objects: mode 0600 (owner read/write only).

## Relocation

PIE binaries load at a random base (ASLR). DWARF uses ELF virtual addresses.

```
delta = runtime_module_base - elf_base_vaddr
```

The tracer emits `MODULE_LOAD` (kind 7) with the runtime base. The engine
re-populates global addresses by adding the delta. The tracer's
`event_module_load` detects libc (for `drwrap` hooks) and captures the first
non-system module as the main executable.

## Concurrency model

No shared mutable state. All communication via SPSC ring buffers.

- **Producer** (tracer thread): owns `head`. Relaxed load, release store.
- **Consumer** (engine): owns `tail`. Relaxed load, release store.
- Cross-cursor reads: acquire ordering.

No mutex, spinlock, or CAS in the hot path. CAS only in:
- `memvis_ctl_register_thread` (once per thread lifetime).
- `g_module_base_phase` CAS 1→2 (once per process lifetime).

### Head caching

Cached in raw TLS (`MEMVIS_RAW_SLOT_HEAD`). Flushed to ring header:
- Every 64 events (`head & 0x3F == 0`): conditional inline flush.
- Every BB exit: unconditional flush.

## Dependencies

| Component | Dependency | Version | Purpose |
|---|---|---|---|
| Tracer | DynamoRIO | 11.91+ | Dynamic binary instrumentation |
| Tracer | drmgr | (bundled) | Multi-callback management |
| Tracer | drutil | (bundled) | Memory operand analysis |
| Tracer | drreg | (bundled) | Register reservation |
| Tracer | drwrap | (bundled) | Function wrapping (allocator hooks) |
| Tracer | drsyms | (bundled) | Symbol lookup (allocator resolution) |
| Engine | gimli | 0.31 | DWARF parsing |
| Engine | object | 0.36 | ELF parsing (including symtab fallback) |
| Engine | ratatui | 0.29 | Terminal UI |
| Engine | crossterm | 0.28 | Terminal I/O |
| Engine | libc | 0.2 | POSIX shared memory, `/proc/<pid>/mem` access |

## Build

### Docker

```sh
DOCKER_BUILDKIT=1 docker build -t memvis .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v /path/to/my_program:/app/my_program \
    memvis /app/my_program
```

`--cap-add=SYS_PTRACE` required for DynamoRIO process attachment.

### Manual

```sh
# tracer (requires DynamoRIO SDK)
cmake -B build -DDynamoRIO_DIR=/path/to/DynamoRIO/cmake
cmake --build build -j$(nproc)

# engine (produces memvis, memvis-diff, memvis-check)
cd engine && cargo build --release
```

## Invocation

```sh
# launch mode: tracer + engine together (interactive TUI)
memvis <target> [args...]

# headless: print final snapshot, exit on 500ms idle
memvis --once <target>

# record events for offline analysis
memvis --record trace.bin [--once] <target>

# replay recorded events (no tracer needed)
memvis --replay trace.bin [--once] <target.elf>

# stream topology deltas to JSONL
memvis --export-topology topo.jsonl [--once] <target>

# differential comparison of two recordings
memvis-diff --baseline a.bin --subject b.bin --dwarf <target.elf> \
    [--interval N] [--output diff.jsonl]

# structural assertions (CI/CD)
memvis-check <topology.jsonl> <assertions.txt>

# consumer-only: engine attaches to already-running tracer
memvis --consumer-only [--once] <target.elf>
```

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | Path to DynamoRIO installation directory |
| `MEMVIS_DRRUN` | Explicit path to `drrun` binary |
| `MEMVIS_TRACER` | Explicit path to `libmemvis_tracer.so` |
