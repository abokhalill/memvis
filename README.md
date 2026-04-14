# memvis

Real-time memory visualization for Linux x86-64. Instruments a target binary
at runtime, captures every memory write, read, function call, and return, then
correlates events with DWARF debug information to produce a live, named view
of the program's memory state.

No source modifications. No recompilation. Point it at a `-g` binary and watch.

## What it shows

Headless output (`--once`) on a simple program with three globals and a 300-iteration
increment loop:

```
MEMVIS │ insn 25262 │ events 25262 │ nodes 6 │ edges 2 │ rings 1 │ LAG 0
────────────────────────────────────────────────────────────────────────────────────────────────────
MEMORY MAP
  ── cacheline 0x7e3f749fe000 ──
  7e3f749fe018     4B  g_counter            int             val=               12c
  7e3f749fe01c     4B  g_shared             int             val=               12c
  7e3f749fe020     8B  g_ptr                *int            val=      7e3f749fe018  → g_counter
  ── cacheline 0x7fff79ca1a00 ──
  7fff79ca1a04     4B  n                    int             val=                 0
  7fff79ca1a08     8B  p                    *int            val=      7e3f749fe018  → g_counter
  7fff79ca1a1c     4B  i                    int             val=               12c

POINTER EDGES
  g_ptr ──> g_counter (0x7e3f749fe018)
  p ──> g_counter (0x7e3f749fe018)

EVENTS (last 12)
     25254 CALL  T0   7e3f760ee200     0      7fff79ca19e0
     25255 REG   T0           1830     0                 0
     25260 REG   T0              1     0                 0
     25261 REG   T0   7e3f76204fc0     0               202
```

The interactive TUI (`ratatui`) renders the same data across six panels at
20 Hz: memory map, filterable event journal, shadow registers, call stacks,
heap objects, and a status bar with the LAG metric.

## Requirements

- Linux x86-64
- Rust 1.74+ (edition 2021; required by ratatui 0.29)
- [DynamoRIO](https://dynamorio.org/) 11.91+ (11.x series)
- CMake 3.7+
- Target binary compiled with `-g` (DWARF debug info)

## Build

### Docker (recommended)

```sh
DOCKER_BUILDKIT=1 docker build -t memvis .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v /path/to/my_program:/app/my_program \
    memvis /app/my_program
```

The multi-stage `Dockerfile` builds the tracer and engine in an Ubuntu 22.04
builder stage, then produces a runtime image containing only the compiled
binaries and the DynamoRIO shared libraries. Both `--cap-add=SYS_PTRACE` and
`--security-opt seccomp=unconfined` are required for DynamoRIO's process
injection and code cache management inside the container.

### Manual

```sh
# tracer (DynamoRIO client)
cmake -B build -DDynamoRIO_DIR=/path/to/DynamoRIO/cmake
cmake --build build -j$(nproc)

# engine (Rust consumer + TUI)
cargo build --release --manifest-path engine/Cargo.toml
```

The tracer and engine are independent — either can be built first.

## Usage

```sh
# launch mode: starts tracer + engine together (interactive TUI)
DYNAMORIO_HOME=/path/to/DynamoRIO memvis ./my_program [args...]

# headless mode: print final snapshot to stdout, exit when target finishes
DYNAMORIO_HOME=/path/to/DynamoRIO memvis --once ./my_program

# consumer-only mode: engine only, tracer started separately via drrun
memvis --consumer-only [--once] ./my_program
```

For manual builds, the binary is at `engine/target/release/memvis`.

The `memvis` binary locates `drrun` and `libmemvis_tracer.so` automatically.
Override with environment variables if needed:

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | Path to the DynamoRIO installation directory |
| `MEMVIS_DRRUN` | Explicit path to the `drrun` binary |
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

Detailed technical documentation is in [`docs/`](docs/):

- [**Architecture**](docs/architecture.md) — system overview, component map,
  data flow, concurrency model, shared memory lifecycle, build details.
- [**Ring Protocol**](docs/ring-protocol.md) — v2/v3 event formats, ring
  header layout, SPSC memory ordering, backpressure, control ring, protocol
  version handshake.
- [**Tracer**](docs/tracer.md) — DynamoRIO client internals, inline write
  path, raw TLS scratch pad, value capture, tail-call/reload detection.
- [**Engine**](docs/engine.md) — DWARF parser, ring orchestrator, shadow
  register file, heap graph, address index, world state, TUI rendering.

## License

[MIT](LICENSE)
