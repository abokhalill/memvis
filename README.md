# memvis

Runtime memory topology analyzer for Linux x86-64. Instruments a target binary
via DynamoRIO, captures every memory write, read, function call, return,
basic block entry, and allocation event, then correlates with DWARF debug
information to produce a named, structure-aware view of heap layout, pointer
topology, cacheline contention, type stability, and allocation lifetimes —
without recompilation or source modification.

```
MEMVIS │ insn 74656 │ events 45245 │ nodes 2 │ edges 2 │ rings 1 │ LAG 0 │ allocs 9/4 live 5
────────────────────────────────────────────────────────────────────────────────────────────────────
MEMORY MAP
  ── cacheline 0x7b6201bfe000 ──
  7b6201bfe018     8B  g_head               *node           val=      7b6201c00320  → 0x7b6201c00320
  7b6201bfe020     8B  g_tail               *node           val=      7b6201c00380  → 0x7b6201c00380

HEAP TYPES (Shadow Type Map: 2 projections)
  7b6201c00320    24B  node                 (via g_head)
    7b6201c00320     4B  value                int
    7b6201c00328     8B  next                 *void
  7b6201c00380    24B  node                 (via g_tail)
    7b6201c00380     4B  value                int
    7b6201c00388     8B  next                 *void

BB COVERAGE: 42 unique blocks, 641 total hits
```

Default mode is headless: prints the final snapshot to stdout and exits on
500ms idle. The surviving nodes were discovered by retrospective type
reconciliation — no writes occurred after `g_head` was re-pointed.

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

# 4. Run (headless, default)
./engine/target/release/memvis ./heap_chain

# 5. Interactive TUI (20 Hz refresh)
./engine/target/release/memvis ./heap_chain --live
```

## Quick start (Docker)

```sh
DOCKER_BUILDKIT=1 docker build -t memvis .
gcc -g examples/heap_chain.c -o heap_chain
docker run --rm \
    --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v $(pwd)/heap_chain:/app/heap_chain \
    memvis /app/heap_chain
```

`--cap-add=SYS_PTRACE` and `--security-opt seccomp=unconfined` are required
for DynamoRIO's process injection.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `cannot find drrun` | `DYNAMORIO_HOME` not set | `export DYNAMORIO_HOME=/path/to/DynamoRIO-Linux-*` |
| `cannot find libmemvis_tracer.so` | Tracer not built or wrong cwd | `cmake --build build` from repo root, or `MEMVIS_TRACER=/path/to/libmemvis_tracer.so` |
| Empty output / no events | Target lacks DWARF info | Recompile with `gcc -g` |
| Docker permission denied | Missing ptrace capability | Add `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined` |

## Binaries

| Binary | Purpose |
|---|---|
| `memvis` | Headless/TUI instrumentation, recording, replay, attach. Subcommands: `record`, `replay`, `attach` (default: instrument and run headless). |
| `memvis-lint` | Static cacheline false-sharing detector with divergence report. |
| `memvis-diff` | Offline ASLR-invariant differential topology comparison of two recorded traces. `--dwarf` is optional. |
| `memvis-check` | CI/CD structural assertion engine over JSONL topology files. |

## Capabilities

- **Named memory map.** Every tracked address resolves to its DWARF variable
  name, type, struct field, and current value.
- **Shadow Type Map (STM).** Heap addresses typed by observing pointer writes
  from typed globals/locals. Recursive field propagation. Purged on `free()`.
- **Retrospective Type Reconciliation (RTR).** Bounded BFS from freshly-stamped
  addresses through HeapGraph pointer fields. Discovers entire linked data
  structures from a single pointer write.
- **Continuous warm-scan.** `WarmScanner` performs persistent incremental BFS
  over `/proc/<pid>/mem` from DWARF globals. Budget-bounded `seed()`/`step()`
  API. Discovers typed structures built before tracing began.
- **Container-of inference.** `build_container_of_map` detects intrusive
  container patterns (e.g., `list_head` embedded in `task_struct`). Warm-scan
  adjusts stamp addresses by subtracting field offsets to discover full
  enclosing objects from intrusive link pointers.
- **CFI-hardened shadow stacks.** Callee-saved register preservation verified
  against `.eh_frame` CFI data on every function return. Longjmp-aware:
  `pop_return_checked` detects non-local returns and unwinds intermediate
  frames, distinguishing `longjmp`/`setjmp` from true mismatches.
- **JIT DWARF resolution.** Deeply nested struct types resolved on demand via
  `patch_shallow_fields` and `resolve_deep`.
- **Backpressure.** Under load, `READ` and `BB_ENTRY` events are shed while
  writes, calls, returns, allocs, frees, and reloads are preserved.
- **BB coverage.** Per-basic-block hit counters. `--coverage` exports TSV.
  Headless output includes top-10 hottest blocks.
- **Visual ASan.** Real-time out-of-bounds and heap-hole detection with
  type-aware symbolic context and register snapshots.
- **False-sharing detection.** Runtime cacheline contention tracking with
  per-writer counts and observation-bias correction
  (`contention_score_weighted`); `memvis-lint` predicts statically from DWARF.
- **SnapshotDelta.** Temporal self-diff on SnapshotRing entries. Reports
  node/edge deltas, value mutations, added/removed nodes.
- **Event recording and replay.** Full trace capture to `.bin`. Replay
  supports `--no-bb` filter for topology-preserving event reduction.
- **Post-exit ring sweep.** On tracer exit or idle timeout, a final
  `poll_new_rings()` + drain captures events from short-lived pthreads that
  spawned and died between normal poll intervals.

See [docs/engine.md](docs/engine.md) for implementation details.

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

# engine (4 binaries)
cargo build --release --manifest-path engine/Cargo.toml
```

Produces `engine/target/release/{memvis,memvis-lint,memvis-diff,memvis-check}`
and `build/libmemvis_tracer.so`. The engine auto-discovers the tracer when run
from the repo root; override with `MEMVIS_TRACER` if running from elsewhere.

See [USAGE.md](docs/USAGE.md) for the full flag reference and TUI keybindings.

## Architecture

```
 ┌───────────────────────────┐  /dev/shm/     ┌───────────────────────────┐
 │         TRACER            │ =============> │         ENGINE            │
 │  (DynamoRIO client, C)    │  SPSC rings    │  (Rust, 4 binaries)       │
 │                           │  control ring  │                           │
 │  tracer.c                 │                │  memvis      (headless)   │
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
  reconciler, STM, RTR, WarmScanner, Visual ASan, Shadow Register File, event
  recording, topology streaming, heap graph, BB coverage, SnapshotDelta, TUI.

## License

[Apache License 2.0](LICENSE)
