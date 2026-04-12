# memvis

Real-time memory visualization for Linux x86-64 programs. Instruments a target
binary at runtime, captures every memory write, read, function call, and return,
then correlates those events with DWARF debug information to produce a live,
named view of the program's memory state in the terminal.

No source modifications. No recompilation. Point it at a `-g` binary and watch.

## What it shows

```
MEMVIS | insn 50622 | events 50622 | nodes 17 | edges 3 | rings 3 | LAG 0

MEMORY MAP
  -- cacheline 0x55a3e000 --
  55a3e004     4B  g_counter            int             val=               12c
  55a3e008     4B  g_shared             int             val=               12c
  55a3e010     8B  g_ptr                *int            val=      55a3e004  -> g_counter
  -- cacheline 0x7ffd2780 --
  7ffd2798     4B  local_sum            int             val=                1e
  7ffd27a0     8B  local_ptr            *int            val=      7ffd2798  -> local_sum

POINTER EDGES
  g_ptr --> g_counter (0x55a3e004)
  local_ptr --> local_sum (0x7ffd2798)
```

- **Memory map.** Every DWARF-resolved global and local variable, sorted by
  address, with struct field decomposition, cache-line boundaries, and
  false-sharing annotations.
- **Pointer edges.** Live pointer-to-variable resolution. Updated on every
  write to a pointer variable.
- **Cache-line contention.** Tracks which threads write to each cache line.
  Flags lines written by multiple threads as false-shared.
- **Event journal.** The most recent events (writes, calls, returns, register
  snapshots, cache misses) with thread IDs and sequence numbers.
- **LAG metric.** Total events buffered across all per-thread rings. Shows
  how far behind the consumer is from the producer.

## Requirements

- Linux x86-64
- Rust 1.70+
- [DynamoRIO](https://dynamorio.org/) 11.x
- Target binary compiled with `-g` (DWARF debug info required)

## Build

```sh
# engine (Rust consumer + TUI)
cd engine
cargo build --release

# tracer (DynamoRIO client)
mkdir -p build && cd build
cmake .. -DDynamoRIO_DIR=/path/to/DynamoRIO/cmake
make
```

## Usage

```sh
# interactive TUI mode
DYNAMORIO_HOME=/path/to/DynamoRIO memvis ./my_program [args...]

# headless mode (print to stdout, exit after N events)
DYNAMORIO_HOME=/path/to/DynamoRIO memvis --once --min-events 50000 ./my_program
```

The `memvis` binary launches the target under DynamoRIO, attaches to the shared
memory rings, and starts consuming events. There is no need to run the tracer
and consumer separately.

For manual two-process operation:

```sh
# terminal 1: run target under tracer
drrun -c build/libmemvis_tracer.so -- ./my_program

# terminal 2: attach consumer
./engine/target/release/memvis --consumer-only ./my_program
```

### Environment variables

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | Path to the DynamoRIO installation directory |
| `MEMVIS_DRRUN` | Explicit path to the `drrun` binary |
| `MEMVIS_TRACER` | Explicit path to `libmemvis_tracer.so` |

## How it works

The system consists of two cooperating OS processes connected by POSIX shared
memory:

```
 +---------------------------+        /dev/shm/           +---------------------------+
 |         TRACER            |  ========================> |          ENGINE           |
 |  (DynamoRIO client, C)    |   per-thread SPSC rings    |  (Rust consumer + TUI)    |
 |                           |   control ring             |                           |
 |  instruments target       |                            |  DWARF parser             |
 |  emits 32-byte events     |                            |  address index            |
 |  per-thread TLS state     |                            |  world state + CoW snap   |
 |  adaptive backpressure    |                            |  ratatui terminal UI      |
 +---------------------------+                            +---------------------------+
        runs inside                                             runs as the
     target's address space                                   memvis binary
      (via DynamoRIO)                                       (separate process)
```

1. The **tracer** (`tracer.c`) is a DynamoRIO client loaded into the target
   process. It intercepts every basic block and inserts callbacks at memory
   writes, reads, calls, and returns. Each thread gets its own SPSC ring
   buffer over POSIX shared memory.

2. The **engine** (`engine/`) parses DWARF debug info from the target ELF,
   discovers per-thread rings via a control ring, batch-drains events (up to
   20K per ring per cycle), and correlates memory addresses with named
   variables. The result is rendered as an interactive TUI at 20 Hz or as
   headless text output.

No sockets. No serialization. No IPC framework. Raw shared memory with atomic
head/tail pointers on separate cache lines. The only synchronization in the
data path is a single release store (producer) and a single acquire load
(consumer) per batch.

## Documentation

Detailed technical documentation is in the [`docs/`](docs/) directory:

- [**Architecture**](docs/architecture.md) -- system overview, component map,
  data flow, relocation, concurrency model.
- [**Ring Protocol**](docs/ring-protocol.md) -- event format, ring header
  layout, SPSC memory ordering, batch operations, backpressure, control ring.
- [**Tracer**](docs/tracer.md) -- DynamoRIO client, instrumentation callbacks,
  TLS slots, read buffering, module load detection.
- [**Engine**](docs/engine.md) -- DWARF parser, ring orchestrator, address
  index, world state, CoW snapshots, TUI rendering.

## License

[MIT](LICENSE)
