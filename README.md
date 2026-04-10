# memvis

Live memory model visualization for C programs. Instruments a running binary via
DynamoRIO, reconstructs semantic state from DWARF, and renders it in the terminal.

No source modifications. No recompilation. Point it at a `-g -O0` binary and see
how your program lives in memory.

## What it shows

```
MEMVIS │ insn 6044 │ events 6044 │ nodes 5 │ edges 1 │ ring 0% (0/1048576)
────────────────────────────────────────────────────────────────────────────
MEMORY MAP
  ── cacheline 0x4040 ──
          4040    40B  g_state              GameState       val=               2
            4060     4B  count                int
            4064     4B  tick                 int
  ── cacheline 0x4080 ──
          4080    48B  g_player             Entity          val= ffffffffffffff3b  [297 misses]
            4090     4B  health               int
            40a8     8B  inventory            *void
          40f0     4B  g_score              int             val=              b9a
          40f8     8B  g_score_ptr          *int            val=             40f0  → g_score

POINTER EDGES
  g_score_ptr ──> g_score (0x40f0)

REGISTERS (insn 4455)
   rax=             b9a   rbx=            4040   rcx=             129
   rdi=            4080   rbp=    7fffffffde00   rsp=    7fffffffddf0

EVENTS (last 12)
      6040 W            4060     4                 2
      6041 RET             0     0                 0
      6042 REG          1167     0                 0
      6043 CMIS         4090     1              1139
```

- **Memory map**: every DWARF-resolved variable, sorted by address, with struct
  field expansion, cache line boundaries, and crossing alerts
- **Pointer edges**: resolved `→ target_name` inline and as a dedicated section
- **Registers**: 18 x86-64 GPRs, yellow when pointing into a live variable
- **Cache misses**: per-variable miss counts from the ring
- **Event journal**: raw SPSC tail showing writes, calls, returns, reg snapshots

## Architecture

```
┌─────────────────────┐         ┌──────────────────────┐
│   Target binary     │         │    memvis-dump       │
│   (instrumented)    │         │    (terminal UI)     │
│                     │  shm    │                      │
│   tracer.c          ├────────►│    main.rs           │
│   (DynamoRIO client)│  SPSC   │   DWARF + ring → tty │
│                     │  ring   │                      │ 
└─────────────────────┘         └──────────────────────┘
```

The tracer and consumer share a single SPSC lock-free ring buffer (`/dev/shm/memvis_ring`).
No sockets. No serialization. No IPC framework. Raw shared memory with atomic head/tail
pointers on separate cache lines.

## Requirements

- Linux x86-64
- Rust 1.70+
- Target binary compiled with `gcc -g -O0` (DWARF required)
- [DynamoRIO](https://dynamorio.org/) (for real instrumentation; not needed for the consumer)

## Build

```sh
# consumer (terminal visualizer)
cd engine
cargo build --release
```

The binary is `engine/target/release/memvis-dump` (~700KB, 3 dependencies).

```sh
# tracer (DynamoRIO client, optional — only needed for real instrumentation)
mkdir build && cd build
cmake .. -DDynamoRIO_DIR=/path/to/dynamorio/cmake
make
```

## Usage

### With DynamoRIO (real instrumentation)

```sh
# terminal 1: run target under DynamoRIO
drrun -c build/libmemvis_tracer.so -- ./my_program

# terminal 2: attach the visualizer
./engine/target/release/memvis-dump ./my_program
```

### Pipe-friendly snapshot

```sh
./engine/target/release/memvis-dump --once ./my_program
```

Prints a single snapshot and exits. Compose with `grep`, `less -R`, `watch`.

## Ring protocol

The shared memory layout is defined in [`memvis_bridge.h`](memvis_bridge.h) — a
single header, no dependencies beyond `<stdatomic.h>`. The ring is SPSC, lock-free,
and sized at 2M entries (64MB) by default. Events are 32 bytes each, aligned so two
fit per cache line with no split loads.

Event types: `WRITE`, `READ`, `CALL`, `RETURN`, `OVERFLOW`, `REG_SNAPSHOT`, `CACHE_MISS`.

Backpressure: when the ring fills past 7/8, the producer sheds `READ` events.
`WRITE`, `CALL`, and `RETURN` are never dropped — world state correctness is preserved.

## Project structure

```
memvis_bridge.h     ring buffer protocol (C header)
tracer.c            DynamoRIO client (producer)
CMakeLists.txt      tracer build
engine/
  src/
    main.rs         terminal visualizer (consumer)
    lib.rs          crate root
    dwarf.rs        DWARF parser (gimli)
    index.rs        address → variable interval map
    world.rs        state model + CoW snapshots
```

## License

[MIT](LICENSE) 
