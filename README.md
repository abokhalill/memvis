# memvis

Runtime memory topology analyzer for Linux x86-64. Instruments a target binary
via DynamoRIO, captures every memory write, function call, and return, then
correlates events with DWARF debug information to produce a live, named,
structure-aware view of the program's heap layout, pointer topology, cacheline
contention, type stability, and allocation lifetimes; without recompilation or
source modification.

## What it answers

| Question | Subsystem |
|---|---|
| What type lives at this heap address? | Shadow Type Map (STM) |
| What data structures are reachable from this global? | Retrospective Type Reconciliation (RTR) |
| Which writes exceed allocation boundaries? | Visual ASan |
| Which cachelines have cross-thread contention? | CacheLineTracker |
| Which struct layouts cause false-sharing? | `memvis-lint` |
| Does predicted contention match observed reality? | `memvis-lint --heatmap` |
| How do two runs differ structurally? | `memvis-diff` |
| Do topology invariants hold across commits? | `memvis-check` |

## Binaries

The project produces four binaries from `engine/`:

| Binary | Purpose |
|---|---|
| `memvis` | Live instrumentation (TUI or headless), event recording, event replay |
| `memvis-lint` | Static cacheline false-sharing detector with divergence report |
| `memvis-diff` | Offline differential topology comparison of two recorded traces |
| `memvis-check` | CI/CD structural assertion engine over JSONL topology files |

## Capabilities

- **Named memory map.** Every tracked address resolves to its DWARF variable
  name, type, struct field, and current value.
- **Shadow Type Map (STM).** Heap addresses are typed by observing pointer
  writes from DWARF-typed globals/locals. Recursive field propagation discovers
  nested structs. Projections are purged on `free()`.
- **Retrospective Type Reconciliation (RTR).** On a new type stamp, a bounded
  BFS (fuel=64) walks pointer fields using last-known values from the heap
  graph. Discovers entire linked lists the instant a global points at the head.
  BFS is sorted by field name for deterministic discovery order across runs.
- **Warm-scan.** Engine-side BFS reads `/proc/<pid>/mem` to stamp cold global
  pointer fields after target quiescence. Discovers typed data structures that
  were built before tracing began (e.g., Redis `server` struct and all
  reachable objects). Triggered by sustained idle after 2M events.
- **ELF symtab fallback.** Globals with `DW_AT_specification` but no
  `DW_AT_location` (common in C++ and large C programs) have their addresses
  resolved from the ELF symbol table.
- **Allocator lifecycle tracking.** `malloc`, `free`, `realloc`, `calloc`
  hooked via `drwrap`. Orphan frees (FREE without matching ALLOC) are counted
  but do **not** purge the STM — prevents type blindness from dropped events.
- **Visual ASan.** Real-time out-of-bounds and heap-hole detection. Reports
  type, field name, allocation boundary, overflow size, faulting PC, and
  register snapshot at hazard time.
- **False-sharing detection.** Cache-line contention tracker identifies lines
  written by multiple threads, annotated with thread count.
- **Static cacheline lint.** `memvis-lint` reads DWARF from a compiled binary
  and maps struct fields to cacheline boundaries. Three-tier structural intent
  analysis: volatile/atomic from DWARF qualifiers (ground truth), alignment-
  intent violation from `DW_AT_alignment`, scalar-vs-pointer adjacency
  heuristic. Recursive sub-struct/union flattening with dotted field paths.
  Union overlap check for mixed-qualifier type-confused contention.
- **Divergence report.** `memvis-lint --heatmap` overlays static lint
  predictions with runtime heatmap observations (exported via
  `memvis --export-heatmap`). Classifies each cacheline as Confirmed
  (lint + hardware agree), Silent Killer (hardware-only), or False Alarm
  (lint-only). Closes the loop between static prediction and dynamic
  measurement.
- **Event recording and replay.** `--record` writes all events (including
  compound REG_SNAPSHOT with 18 register values) to a `.bin` file.
  `--replay` reconstructs the full world state offline.
- **Heatmap export.** `--export-heatmap` writes per-thread, per-field write
  counts as a TSV file for offline divergence analysis with `memvis-lint`.
- **Topology streaming.** `--export-topology` emits a JSONL stream of
  structural graph deltas: ALLOC, FREE, STAMP, LINK, COLD_STAMP, COLD_LINK,
  HAZARD, FALSE_SHARE, and SUMMARY events.
- **Differential topology comparison.** `memvis-diff` replays two recorded
  traces, checkpoints ASLR-invariant topology at configurable intervals, and
  reports structural divergence. Features:
  - **Canonical stamps**: `(source, type_name, type_size, field_count)` — symbolic,
    not address-based.
  - **Common stamp mask**: stamps present in both final checkpoints are filtered
    from intermediate diffs (eliminates discovery-order noise).
  - **Steady-state type histogram**: order-invariant `type_name → count` comparison
    of final checkpoints, immune to ASLR and BFS timing.
  - **Hazard register context**: each hazard carries PC, RAX, RDI, RSI, RDX, RSP.
  - **REG_SNAPSHOT replay**: compound events reconstructed offline with full
    ShadowRegisterFile population.
- **Structural assertions.** `memvis-check` evaluates invariants from a
  `.assertions` file against a JSONL topology log. Intended for CI/CD.

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

# engine (Rust consumer + TUI + offline tools)
cargo build --release --manifest-path engine/Cargo.toml
```

This produces `engine/target/release/{memvis,memvis-lint,memvis-diff,memvis-check}`.

## Usage

### Live instrumentation

```sh
# interactive TUI (6 panels, 20 Hz)
DYNAMORIO_HOME=/path/to/DynamoRIO memvis ./my_program [args...]

# headless: print final snapshot to stdout, exit on 500ms idle
DYNAMORIO_HOME=/path/to/DynamoRIO memvis --once ./my_program

# record events for offline analysis
DYNAMORIO_HOME=/path/to/DynamoRIO memvis --record trace.bin --once ./my_program

# stream topology deltas to JSONL
DYNAMORIO_HOME=/path/to/DynamoRIO memvis --export-topology topo.jsonl --once ./my_program
```

### Offline replay

```sh
# replay a recorded trace (headless output)
memvis --replay trace.bin --once ./my_program
```

### Differential comparison

```sh
# compare two traces with DWARF-grade type fidelity
memvis-diff --baseline a.bin --subject b.bin --dwarf ./my_program \
    --interval 500000 --output diff.jsonl
```

### Structural assertions (CI/CD)

```sh
# evaluate topology invariants
memvis-check topo.jsonl assertions.txt
```

### Static cacheline lint

```sh
# analyze a single struct for false-sharing
memvis-lint ./my_program --struct my_struct

# all structs with warnings
memvis-lint ./my_program --all

# field migration diff between two builds
memvis-lint ./old_binary ./new_binary --struct my_struct --diff

# divergence report: overlay lint predictions with runtime heatmap
memvis --once --export-heatmap heat.tsv ./my_program
memvis-lint ./my_program --struct my_struct --heatmap heat.tsv

# JSON output for CI/CD
memvis-lint ./my_program --struct my_struct --json
```

### Consumer-only mode

```sh
# engine attaches to an already-running tracer
memvis --consumer-only [--once] ./my_program
```

### Environment variables

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

## Architecture

```
 ┌───────────────────────────┐  /dev/shm/     ┌───────────────────────────┐
 │         TRACER            │ =============> │         ENGINE            │
 │  (DynamoRIO client, C)    │  SPSC rings    │  (Rust, 4 binaries)       │
 │                           │  control ring  │                           │
 │  tracer.c                 │                │  memvis      (live/TUI)   │
 │  memvis_bridge.h          │                │  memvis-lint (static)     │
 │                           │                │  memvis-diff (offline)    │
 │                           │                │  memvis-check (CI/CD)     │
 └───────────────────────────┘                └───────────────────────────┘
       runs inside                                  separate process
    target's address space
```

See [docs/](docs/) for full specification:

- [**Architecture**](docs/architecture.md) — system overview, data flow,
  concurrency model, shared memory lifecycle.
- [**Ring Protocol**](docs/ring-protocol.md) — v3 event format, SPSC memory
  ordering, backpressure, control ring, protocol handshake.
- [**Tracer**](docs/tracer.md) — DynamoRIO client internals, inline write
  path, value capture, allocator hooks, tail-call/reload detection.
- [**Engine**](docs/engine.md) — DWARF parser, reconciler, Shadow Type Map,
  RTR, warm-scan, Visual ASan, event recording, topology streaming,
  memvis-lint, memvis-diff, memvis-check, heap graph, world state, TUI
  rendering.

## License

[Apache License 2.0](LICENSE)
