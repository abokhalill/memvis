# memvis Architecture

memvis is a real-time memory visualization system for Linux x86-64 programs. It
instruments a target binary at runtime, captures every memory write, read,
function call, and return, then correlates those events with DWARF debug
information to build a live, named view of the program's memory state.

This document describes the system's architecture, its components, and how data
flows between them.

## System overview

memvis consists of two cooperating OS processes connected by POSIX shared memory:

```
 +---------------------------+        shared memory        +---------------------------+
 |         TRACER            |  ========================>  |          ENGINE            |
 |  (DynamoRIO client, C)   |   per-thread SPSC rings     |  (Rust consumer + TUI)    |
 |                           |   control ring              |                           |
 |  - instruments target     |                             |  - DWARF parser           |
 |  - emits 32-byte events   |                             |  - address index          |
 |  - per-thread TLS state   |                             |  - world state + CoW snap |
 |  - adaptive backpressure  |                             |  - ratatui terminal UI    |
 +---------------------------+                             +---------------------------+
        runs inside                                              runs as the
     target's address space                                    memvis binary
      (via DynamoRIO)                                        (separate process)
```

The tracer is a shared library (`libmemvis_tracer.so`) loaded into the target
process by DynamoRIO's dynamic binary instrumentation framework. The engine is a
standalone Rust binary (`memvis`) that launches the tracer, then attaches to the
shared memory rings and consumes events.

## Components

### Tracer (`tracer.c`)

The tracer is a DynamoRIO client. DynamoRIO intercepts every basic block before
execution and gives the tracer a chance to insert instrumentation. The tracer
inserts `clean_call` callbacks at:

- **Memory writes.** Captures the address, size, and post-write value.
- **Memory reads.** Buffered into a per-thread TLS read buffer (capacity 16),
  flushed at the end of each basic block.
- **Direct calls.** Captures the callee PC and the current stack pointer
  (used as frame base). Also snapshots all 18 x86-64 general-purpose registers.
- **Returns.** Captures the return address.

Each thread gets its own SPSC ring buffer allocated via `shm_open(3)`. Thread
metadata is published to a control ring (`/memvis_ctl`) so the engine can
discover new threads at runtime.

Source files:

| File | Role |
|---|---|
| `tracer.c` | DynamoRIO client. Instrumentation, TLS, event emission. |
| `memvis_bridge.h` | Shared header. Ring buffer protocol, event format, control ring. |

### Engine (`engine/`)

The engine is the consumer process. It performs five tasks:

1. **DWARF parsing.** Parses the target ELF binary's `.debug_info` section using
   `gimli` to extract global variables, functions, local variables, and type
   information including struct field decomposition.

2. **Ring orchestration.** Attaches to the control ring, discovers per-thread
   data rings, and drains events using batch pops (up to 20,000 events per ring
   per cycle, amortizing atomic overhead).

3. **Address indexing.** Maintains a sorted interval map that maps memory
   addresses to named variables. Supports two tiers: static globals (inserted
   once after DWARF parse) and dynamic locals (inserted/removed on CALL/RETURN).
   Locals shadow globals on address overlap.

4. **World state.** Maintains the current values of all tracked variables,
   pointer edges between them, a live register file, a cache-line contention
   tracker, and a cache miss heatmap. Uses copy-on-write (`Arc::make_mut`)
   snapshotting for lock-free rendering.

5. **Rendering.** Either an interactive ratatui TUI with time-travel scrubbing,
   or a headless text output mode for scripting and testing.

Source files:

| File | Role |
|---|---|
| `engine/src/main.rs` | Entry point, event processing loop, headless renderer. |
| `engine/src/ring.rs` | Ring buffer consumer, orchestrator, batch drain. |
| `engine/src/dwarf.rs` | DWARF parser. Globals, functions, locals, type resolution. |
| `engine/src/index.rs` | Sorted interval map. O(log N) address-to-variable lookup. |
| `engine/src/world.rs` | World state. Nodes, edges, registers, cache tracking, CoW snapshots. |
| `engine/src/tui.rs` | Ratatui terminal UI. Memory map, event journal, pointer graph. |
| `engine/src/lib.rs` | Crate root. Re-exports all modules. |

### Shared memory protocol (`memvis_bridge.h`)

The bridge header defines the binary interface between the tracer and engine:

- **Event format.** A 32-byte, 32-byte-aligned struct containing address, size,
  thread ID, sequence number, value, and kind/flags.
- **Ring header.** A 192-byte (3 cache lines) struct with head and tail cursors
  on separate cache lines to avoid false sharing.
- **Control ring.** A fixed-size structure with slots for up to 256 threads.
  Each slot contains a state field (empty/active/dead) and the POSIX shared
  memory name of that thread's data ring.

See [Ring Protocol](ring-protocol.md) for the full specification.

## Data flow

The following numbered steps describe the path of a single memory write event
from the target program to the screen:

```
 target program executes: *ptr = 42;
           |
           v
 [1] DynamoRIO intercepts the basic block containing the store instruction
           |
           v
 [2] tracer.c:event_bb_insert inserts a clean_call to at_mem_write()
     AFTER the store (so the post-write value is visible)
           |
           v
 [3] at_mem_write() reads the written value via safe_read_value(),
     packs a 32-byte event, pushes it to the thread's SPSC ring
     (single atomic store to ring->head with release ordering)
           |
           v
 [4] engine ring.rs:batch_pop loads ring->head with acquire ordering,
     copies up to 20K events in one shot, then stores ring->tail
     with release ordering (single atomic store for the whole batch)
           |
           v
 [5] main.rs:process_event matches EVENT_WRITE, calls addr_index.lookup()
     to resolve the address to a named variable (O(log N) binary search)
           |
           v
 [6] If the address maps to a tracked variable, world.update_value()
     records the new value. If the variable is a pointer, world.update_edge()
     resolves the pointee.
           |
           v
 [7] world.snapshot() returns an Arc<WorldInner> (zero-copy if no mutation
     since last snapshot). The TUI renders this snapshot at 20 Hz.
```

## Address space layout

The tracer runs inside the target's address space. The engine runs in a separate
process. They share data exclusively through POSIX shared memory objects visible
under `/dev/shm/`:

```
/dev/shm/memvis_ctl       Control ring (thread discovery)
/dev/shm/memvis_ring_0    Thread 0 data ring (1M entries, ~32 MB)
/dev/shm/memvis_ring_1    Thread 1 data ring
...
/dev/shm/memvis_ring_N    Thread N data ring
```

Each data ring is `sizeof(memvis_ring_header_t) + capacity * 32` bytes. With the
default capacity of 2^20 (1,048,576 entries), each ring is approximately 32 MB.

## Relocation

PIE (position-independent executable) binaries are loaded at a random base
address determined by ASLR. DWARF debug information uses ELF virtual addresses
(typically starting at 0x0 for PIE). To correlate runtime addresses with DWARF
addresses, the engine computes a relocation delta:

```
delta = runtime_module_base - elf_base_vaddr
```

The tracer emits a `MODULE_LOAD` event containing the runtime base address. The
engine receives this event and recomputes all global variable addresses by adding
the delta.

## Concurrency model

The tracer and engine never share mutable state directly. All communication is
through the SPSC ring buffers. Within the ring protocol:

- The **producer** (tracer thread) owns `head`. It loads `head` with relaxed
  ordering and stores with release ordering after writing the event data.
- The **consumer** (engine) owns `tail`. It loads `tail` with relaxed ordering
  and stores with release ordering after reading events.
- Cross-cursor reads use acquire ordering to ensure visibility of event data.

There is no mutex, spinlock, or CAS in the hot path. The only CAS in the system
is in the tracer's module load emission (`g_module_base_phase`), which executes
exactly once per process lifetime.

## Dependencies

| Component | Dependency | Version | Purpose |
|---|---|---|---|
| Tracer | DynamoRIO | 11.x | Dynamic binary instrumentation |
| Engine | gimli | 0.31 | DWARF parsing |
| Engine | object | 0.36 | ELF parsing |
| Engine | ratatui | 0.29 | Terminal UI |
| Engine | crossterm | 0.28 | Terminal I/O |
| Engine | libc | 0.2 | POSIX shared memory |

## Build

The tracer is built with CMake (requires DynamoRIO SDK):

```
mkdir build && cd build
cmake .. -DDynamoRIO_DIR=/path/to/DynamoRIO/cmake
make
```

The engine is built with Cargo:

```
cd engine && cargo build --release
```

## Invocation

```
# Launch mode: starts tracer + engine together
memvis <target> [args...]

# Headless mode: print to stdout, exit after min-events reached
memvis --once --min-events 50000 <target>

# Consumer-only mode: engine only (tracer started separately)
memvis --consumer-only [--once] [--min-events N] <target.elf>
```

Environment variables:

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | Path to DynamoRIO installation directory |
| `MEMVIS_DRRUN` | Explicit path to `drrun` binary |
| `MEMVIS_TRACER` | Explicit path to `libmemvis_tracer.so` |
