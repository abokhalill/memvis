# memvis

Real-time memory observability for Linux x86-64. Instruments a target binary
via DynamoRIO, captures every memory write, function call, and return, then
correlates events with DWARF debug information to produce a live, named,
structure-aware view of the program's memory state — including heap type
recovery, out-of-bounds detection, and false-sharing identification.

No source modifications. No recompilation. Point it at a `-g` binary and watch.

## Capabilities

- **Named memory map.** Every tracked address is resolved to its DWARF
  variable name, type, struct field, and current value.
- **Shadow Type Map (STM).** Heap addresses are typed by observing pointer
  writes from DWARF-typed globals/locals. Recursive field propagation
  discovers nested structs.
- **Retrospective Type Reconciliation (RTR).** On a new type stamp, a bounded
  BFS (fuel=64) walks pointer fields using last-known values from the heap
  graph. Discovers entire linked lists the instant a global points at the head.
- **Allocator lifecycle tracking.** `malloc`, `free`, `realloc`, `calloc`
  hooked via `drwrap`. STM projections are purged on `free()` — no ghost types.
  Orphan frees (FREE without matching ALLOC) are logged but do not purge,
  preventing type blindness from dropped ring events.
- **Visual ASan.** Real-time out-of-bounds and heap-hole (use-after-free)
  detection with symbolic intent: reports the type, field name, allocation
  boundary, and overflow size.
- **False-sharing detection.** Cache-line contention tracker identifies lines
  written by multiple threads, annotated in the TUI and headless output.

## Example output

Headless output (`--once`) on a linked-list program after partial free (4 of 8
nodes freed, 4 surviving):

```
MEMVIS │ insn 33010 │ events 33010 │ nodes 2 │ edges 2 │ rings 1 │ LAG 0 │ allocs 9/4 live 5
────────────────────────────────────────────────────────────────────────────────────────────────────
MEMORY MAP
  ── cacheline 0x71cad77fe000 ──
  71cad77fe018     8B  g_head               *node           val=      71cad7800320  → 0x71cad7800320
  71cad77fe020     8B  g_tail               *node           val=      71cad7800380  → 0x71cad7800380

HEAP TYPES (Shadow Type Map: 4 projections)
  71cad7800320    24B  node                 (via g_head)
    71cad7800320     4B  value                int
    71cad7800324     4B  flags                int
    71cad7800328     8B  next                 *node
    71cad7800330     8B  prev                 *node
  71cad7800340    24B  node                 (via next)
    ...
  71cad7800360    24B  node                 (via next)
    ...
  71cad7800380    24B  node                 (via g_tail)
    ...
```

The freed nodes are absent from HEAP TYPES. The surviving chain was discovered
entirely by RTR; no writes occurred after `g_head` was re-pointed.

The interactive TUI (`ratatui`) renders the same data across six panels at
20 Hz: memory map with STM-typed heap regions, filterable event journal,
shadow registers with confidence bars, call stacks, heap objects, and a
status bar with LAG and allocation metrics.

## Requirements

- Linux x86-64
- Rust 1.74+ (edition 2021)
- [DynamoRIO](https://dynamorio.org/) 11.91+ (11.x series)
- CMake 3.7+
- Target binary compiled with `-g` (DWARF debug info)

## Build

### Docker

```sh
DOCKER_BUILDKIT=1 docker build -t memvis .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v /path/to/my_program:/app/my_program \
    memvis /app/my_program
```

`--cap-add=SYS_PTRACE` and `--security-opt seccomp=unconfined` are required
for DynamoRIO's process injection inside the container.

### Manual

```sh
# tracer (DynamoRIO client)
cmake -B build -DDynamoRIO_DIR=/path/to/DynamoRIO/cmake
cmake --build build -j$(nproc)

# engine (Rust consumer + TUI)
cargo build --release --manifest-path engine/Cargo.toml
```

## Usage

```sh
# interactive TUI
DYNAMORIO_HOME=/path/to/DynamoRIO memvis ./my_program [args...]

# headless: print final snapshot to stdout, exit when target finishes
DYNAMORIO_HOME=/path/to/DynamoRIO memvis --once ./my_program

# consumer-only: engine attaches to an already-running tracer
memvis --consumer-only [--once] ./my_program
```

The engine binary is at `engine/target/release/memvis`. It locates `drrun`
and `libmemvis_tracer.so` automatically.

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | DynamoRIO installation directory |
| `MEMVIS_DRRUN` | Explicit path to `drrun` |
| `MEMVIS_TRACER` | Explicit path to `libmemvis_tracer.so` |

### TUI keybindings

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Quit |
| `Tab` | Cycle focus: Memory → Events → Registers |
| `Space` | Pause / resume event consumption |
| `↑↓` / `jk` | Scroll focused panel |
| `PgUp` / `PgDn` | Page scroll |
| `Home` | Scroll to top |
| `←→` / `hl` | Time-travel scrub through snapshot history |
| `End` | Jump to live (exit time-travel) |
| `w` | Toggle writes-only filter (Events panel) |
| `r` | Toggle hide-reads filter (Events panel) |
| `0-9` | Filter by thread ID (Events panel) |
| `x` | Clear all event filters |

## Documentation

- [**Architecture**](docs/architecture.md) — system overview, data flow,
  concurrency model, shared memory lifecycle.
- [**Ring Protocol**](docs/ring-protocol.md) — v3 event format, SPSC memory
  ordering, backpressure, control ring, protocol handshake.
- [**Tracer**](docs/tracer.md) — DynamoRIO client internals, inline write
  path, value capture, allocator hooks, tail-call/reload detection.
- [**Engine**](docs/engine.md) — DWARF parser, ring orchestrator, Shadow Type
  Map, Retrospective Type Reconciliation, Visual ASan, heap graph, address
  index, world state, TUI rendering.

## License

[MIT](LICENSE)
