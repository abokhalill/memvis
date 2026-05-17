# memvis

Runtime memory topology analyzer for Linux x86-64. Instruments any unmodified
binary via [DynamoRIO](https://dynamorio.org/), captures every memory write,
read, function call, return, allocation, and basic-block entry, then correlates
with DWARF debug information to produce a **named, structure-aware view** of
heap layout, pointer topology, cacheline contention, and type stability —
**without recompilation or source modification**.

Verified against **Redis 8.0** (487-field `redisServer`, 1.2M+ events) and **jq**.

## What You Get

```
MEMVIS │ insn 74656 │ events 45245 │ nodes 2 │ edges 2 │ rings 1 │ LAG 0 │ allocs 9/4 live 5
────────────────────────────────────────────────────────────────────────────────────────────────────
MEMORY MAP
  ── cacheline 0x7b6201bfe000 ──
  7b6201bfe018     8B      g_head               *node           val= 7b6201c00320  → 0x7b6201c00320
  7b6201bfe020     8B      g_tail               *node           val= 7b6201c00380  → 0x7b6201c00380
                   ▲          ▲                   ▲                      ▲
                   │          │                   │                      │
                 size    DWARF variable     DWARF type          heap address this
                         name from debug   resolved from       pointer targets ──┐
                         info              struct definition                     │
                                                                                 │
HEAP TYPES (Shadow Type Map: 2 projections)                                      │
  7b6201c00320    24B  node                 (via g_head)    ◄────────────────────┘
    7b6201c00320     4B  value                int            ← struct field, type, offset
    7b6201c00328     8B  next                 *void
  7b6201c00380    24B  node                 (via g_tail)    ← second node, typed via g_tail
    7b6201c00380     4B  value                int
    7b6201c00380     8B  next                 *void

BB COVERAGE: 42 unique blocks, 641 total hits
```

**Reading the output**: each line in MEMORY MAP is a tracked global variable
with its DWARF name, type, and current value. The `→` arrow means the value
is a pointer to a heap allocation. HEAP TYPES shows how memvis **typed that
heap memory** — it observed `g_head` being written with a pointer, looked up
`g_head`'s type (`*node`), and projected the `node` struct layout onto the
target address. This is the Shadow Type Map (STM) at work.

## Quick Start

**Requirements**: Linux x86-64, Rust 1.74+, CMake 3.7+, a C compiler,
[DynamoRIO](https://dynamorio.org/) 11.91+. Target binaries must include
DWARF debug info (`-g`).

```sh
# 1. Install DynamoRIO (one-time)
curl -fSL https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-11.91.20552/DynamoRIO-Linux-11.91.20552.tar.gz \
  | tar -xzC /opt
export DYNAMORIO_HOME=/opt/DynamoRIO-Linux-11.91.20552

# 2. Build tracer + engine
cmake -B build -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake
cmake --build build -j$(nproc)
cargo build --release --manifest-path engine/Cargo.toml

# 3. Run on any binary with debug info
gcc -g examples/heap_chain.c -o heap_chain
./engine/target/release/memvis ./heap_chain
```

### Docker

```sh
DOCKER_BUILDKIT=1 docker build -t memvis .
docker run --rm \
    --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v $(pwd)/heap_chain:/app/heap_chain \
    memvis /app/heap_chain
```

## The Four Tools

Build produces `engine/target/release/{memvis,memvis-lint,memvis-diff,memvis-check}`
and `build/libmemvis_tracer.so`. The engine auto-discovers the tracer from the
repo root; override with `MEMVIS_TRACER` if running from elsewhere.

### `memvis` — runtime instrumentation

Instruments a binary, captures events, and renders a type-aware memory
topology snapshot. Headless by default; `--live` enables a 20 Hz interactive
TUI with time-travel.

```sh
memvis ./my_program                        # headless snapshot
memvis ./my_program --live                 # interactive TUI
memvis ./my_program --topology topo.jsonl  # export structural graph
memvis record -o trace.bin ./my_program    # record for offline analysis
memvis replay trace.bin --dwarf ./my_program
```

Under the hood:

- **Shadow Type Map (STM)** types heap addresses by observing pointer writes
  from typed globals. Recursive field propagation (`propagate_field_write`)
  discovers entire struct layouts including indirect `**T` → element type
  registration for bucket arrays. Purged on `free()`.
- **Retrospective Type Reconciliation (RTR)** performs bounded BFS (fuel=64)
  from freshly-stamped addresses through pointer fields — discovers linked
  lists, trees, and graphs from a single pointer write.
- **Warm-scan** performs persistent incremental BFS over `/proc/<pid>/mem`
  from DWARF globals. Initial seed at 100K events; periodic re-seed every
  200K events (event-count based, works in both TUI and headless modes).
  Calls `ensure_type` on each global to fully materialize depth-truncated
  structs before traversal. Discovers intrusive containers via container-of
  inference. Budget: 2000 reads per step.
- **Library DWARF merge** resolves `DT_NEEDED` shared libraries and merges
  their type information at startup. Works from on-disk ELF files; immune to
  DynamoRIO's private loader.
- **Type Stability Monitor** validates every write to a stamped heap region
  against the projected field layout. Detects interstitial and spanning
  violations invisible to ASan.
- **Visual ASan** detects out-of-bounds and heap-hole accesses in real time.
  Each hazard carries the faulting PC and a full 18-register snapshot.
- **CFI-hardened shadow stacks** verify callee-saved register preservation
  against `.eh_frame` data on every return. Longjmp-aware.
- **Cross-process topology** tracks forks transparently. Shared-memory writes
  across processes are detected via `(dev, inode)` matching on `/proc/*/maps`.
- Lock-free SPSC rings (2 atomics per 20K-event batch), inline write capture
  (~19 meta-instructions), adaptive backpressure that sheds reads under load
  while preserving writes and control events.

### `memvis-lint` — static false-sharing detector

**No instrumentation needed.** Analyzes DWARF struct layouts to predict
cacheline false-sharing at compile time. Three-tier structural intent
analysis (volatile/atomic qualifiers → alignment intent → heuristic).
Overlay with runtime heatmaps for divergence reports.

```sh
memvis-lint ./my_program --struct my_struct
memvis-lint ./my_program --all                              # all structs
memvis-lint ./old_binary ./new_binary --struct S --diff      # field migration
memvis-lint ./my_program --struct S --heatmap heat.tsv       # divergence report
```

### `memvis-diff` — offline differential topology

Replays two recorded traces and compares their ASLR-invariant topology.
Canonical stamps, common-stamp masking, and steady-state type histograms
report structural regressions between builds or workloads.

```sh
memvis-diff --baseline a.bin --subject b.bin --dwarf ./my_program
```

### `memvis-check` — CI/CD assertion engine

Structural assertions over JSONL topology files. Exit code 0 = all pass.

```sh
memvis-check topo.jsonl assertions.txt
```

```
assert no_hazards                                    # zero heap hazards
assert alloc_before_stamp                            # every stamp has a preceding alloc
assert no_use_after_free                             # no stamps/links to freed memory
assert max_chain(type("node"), "next") < 100         # bounded list length
assert type_stable(global("head"), "node*")          # type consistency
```

See [USAGE.md](docs/USAGE.md) for the full flag reference, TUI keybindings,
and assertion DSL.

## Architecture

```
 ┌───────────────────────────┐  /dev/shm/     ┌───────────────────────────┐
 │         TRACER            │ =============> │         ENGINE            │
 │  (DynamoRIO client, C)    │  SPSC rings    │  (Rust, 4 binaries)       │
 │                           │  ctl per PID   │                           │
 │  tracer.c                 │                │  memvis      (headless)   │
 │  memvis_bridge.h          │                │  memvis-lint (static)     │
 │                           │                │  memvis-diff (offline)    │
 │  fork → child gets own    │                │  memvis-check (CI/CD)     │
 │  PID-scoped ctl + rings   │                │  ChildProcessTracker      │
 └───────────────────────────┘                └───────────────────────────┘
      runs inside target's                         separate process
      address space (+ forks)
```

[Architecture](docs/architecture.md) ·
[Ring Protocol](docs/ring-protocol.md) ·
[Tracer](docs/tracer.md) ·
[Engine](docs/engine.md)

<details>
<summary><strong>Troubleshooting</strong></summary>

| Symptom | Cause | Fix |
|---|---|---|
| `cannot find drrun` | `DYNAMORIO_HOME` not set | `export DYNAMORIO_HOME=/path/to/DynamoRIO-Linux-*` |
| `cannot find libmemvis_tracer.so` | Tracer not built or wrong cwd | `cmake --build build` from repo root, or `MEMVIS_TRACER=/path/to/libmemvis_tracer.so` |
| Empty output / no events | Target lacks DWARF info | Recompile with `gcc -g` |
| `ABI MISMATCH` | Tracer and engine built from different `memvis_bridge.h` | Rebuild both from the same source |
| Docker permission denied | Missing ptrace capability | Add `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined` |

</details>

## License

[Apache License 2.0](LICENSE)
