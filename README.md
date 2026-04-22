# memvis

Runtime memory topology analyzer for Linux x86-64. Instruments a target binary
via DynamoRIO, captures every memory write, function call, and return, then
correlates events with DWARF debug information to produce a live, named,
structure-aware view of the program's heap layout, pointer topology, cacheline
contention, type stability, and allocation lifetimes — without recompilation or
source modification.

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

Headless output on a linked-list program after partial free. The freed nodes
are absent. The surviving 4-node chain was discovered entirely by retrospective
type reconciliation — no writes occurred after `g_head` was re-pointed.

## Quick start (native)

Prerequisites: Linux x86-64, Rust 1.74+, CMake 3.7+, a C compiler.

```sh
# 1. Install DynamoRIO (one-time, ~30s)
curl -fSL https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-11.91.20552/DynamoRIO-Linux-11.91.20552.tar.gz \
  | tar -xzC /opt
export DYNAMORIO_HOME=/opt/DynamoRIO-Linux-11.91.20552

# 2. Build memvis (~60s first time)
cmake -B build -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake
cmake --build build -j$(nproc)
cargo build --release --manifest-path engine/Cargo.toml

# 3. Compile a test target with debug info
gcc -g examples/heap_chain.c -o heap_chain

# 4. Run it
./engine/target/release/memvis ./heap_chain
```

You should see a named memory map with `g_head`, `g_tail`, heap type
projections, and a 4-node linked list discovered via retrospective type
reconciliation.

For the interactive TUI (live, 20 Hz refresh):

```sh
./engine/target/release/memvis ./heap_chain --live
```

## Quick start (Docker)

No local Rust or DynamoRIO install required. You must build the image first
(there is no published image yet).

```sh
# 1. Build the image (~3 min first time, cached after)
DOCKER_BUILDKIT=1 docker build -t memvis .

# 2. Compile a test target on the host (must be x86-64 Linux, -g)
gcc -g examples/heap_chain.c -o heap_chain

# 3. Run it
docker run --rm \
    --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v $(pwd)/heap_chain:/app/heap_chain \
    memvis /app/heap_chain
```

`--cap-add=SYS_PTRACE` and `--security-opt seccomp=unconfined` are required
for DynamoRIO's process injection. If you see a permission error, these flags
are missing.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `cannot find drrun` | DynamoRIO not installed or `DYNAMORIO_HOME` not set | `export DYNAMORIO_HOME=/path/to/DynamoRIO-Linux-*` |
| `cannot find libmemvis_tracer.so` | Tracer not built, or running from wrong directory | Build with `cmake --build build` and run from the repo root, or set `MEMVIS_TRACER=/path/to/libmemvis_tracer.so` |
| Empty output / no events | Target not compiled with `-g` | Recompile with `gcc -g` |
| Docker permission denied | Missing ptrace capability | Add `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined` |

## Binaries

| Binary | What it does | What it answers |
|---|---|---|
| `memvis` | Live TUI/headless instrumentation, recording, replay | What type lives at this heap address? What data structures are reachable from this global? Which writes exceed allocation boundaries? |
| `memvis-lint` | Static cacheline false-sharing detector with divergence report | Which struct layouts cause false-sharing? Does predicted contention match observed reality? |
| `memvis-diff` | Offline differential topology comparison of two recorded traces | How do two runs differ structurally? |
| `memvis-check` | CI/CD structural assertion engine over JSONL topology | Do topology invariants hold across commits? |

## Capabilities

- **Named memory map.** Every tracked address resolves to its DWARF variable
  name, type, struct field, and current value.
- **Shadow Type Map (STM).** Heap addresses are typed by observing pointer
  writes from typed globals/locals. Recursive field propagation discovers
  nested structs. Projections are purged on `free()`.
- **Retrospective Type Reconciliation (RTR).** On a new type stamp, a bounded
  BFS walks pointer fields to discover entire linked data structures.
- **CFI-hardened shadow stacks.** Callee-saved register preservation is
  verified against `.eh_frame` CFI data on every function return.
- **JIT DWARF resolution.** Deeply nested struct types that exceed the
  initial parse depth are resolved on demand when first encountered.
- **Warm-scan.** Discovers typed data structures built before tracing began
  by reading the target's memory after quiescence.
- **Backpressure.** Under load, low-priority read events are shed while
  writes and control events are preserved.
- **Visual ASan.** Real-time out-of-bounds and heap-hole detection with
  type-aware symbolic context and register snapshots.
- **False-sharing detection.** Identifies cachelines written by multiple
  threads at runtime; `memvis-lint` predicts them statically from DWARF.
- **Event recording and replay.** Full trace capture to `.bin` for offline
  analysis, differential comparison, and CI/CD assertion evaluation.

See [docs/engine.md](docs/engine.md) for implementation details on each
subsystem.

## Requirements

- Linux x86-64
- Rust 1.74+ (edition 2021)
- [DynamoRIO](https://dynamorio.org/) 11.91+ (11.x series)
- CMake 3.7+
- Target binary compiled with `-g` (DWARF debug info)

## Build

```sh
# tracer (DynamoRIO client)
cmake -B build -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake
cmake --build build -j$(nproc)

# engine (produces 4 binaries)
cargo build --release --manifest-path engine/Cargo.toml
```

This produces `engine/target/release/{memvis,memvis-lint,memvis-diff,memvis-check}`
and `build/libmemvis_tracer.so`. The engine auto-discovers the tracer when run
from the repo root; override with `MEMVIS_TRACER` if running from elsewhere.

See [USAGE.md](docs/USAGE.md) for the full flag reference, all binary invocations,
environment variables, and TUI keybindings.

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

- [**Architecture**](docs/architecture.md) — system overview, data flow,
  concurrency model, shared memory lifecycle.
- [**Ring Protocol**](docs/ring-protocol.md) — v3 event format, SPSC memory
  ordering, backpressure, control ring, protocol handshake.
- [**Tracer**](docs/tracer.md) — DynamoRIO client internals, inline write
  path, value capture, allocator hooks, tail-call/reload detection.
- [**Engine**](docs/engine.md) — DWARF parser, CFI table, JIT DWARF resolution,
  reconciler, Shadow Type Map, RTR, warm-scan, Visual ASan, Shadow Register
  File, event recording, topology streaming, heap graph, world state, TUI.

## License

[Apache License 2.0](LICENSE)
