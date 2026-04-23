# Usage

Full flag reference and invocation examples for all memvis binaries.

## memvis

### Instrument and run

```sh
# headless (default): print snapshot to stdout, exit on idle
memvis ./my_program [args...]

# interactive TUI
memvis ./my_program --live [args...]

# record events for offline analysis
memvis record -o trace.bin ./my_program

# export topology, heatmap, and BB coverage
memvis ./my_program --topology topo.jsonl --heatmap heat.tsv --coverage cov.tsv

# skip BB_ENTRY events (reduces volume, no topology impact)
memvis ./my_program --no-bb
```

### Replay

```sh
memvis replay trace.bin --dwarf ./my_program
memvis replay trace.bin --no-bb
```

### Attach to running tracer

```sh
memvis attach --dwarf ./my_program
memvis attach --live
```

### Flags

| Flag | Description |
|---|---|
| `--live` | Interactive TUI instead of headless |
| `--topology <file>` | Export topology graph as JSONL |
| `--heatmap <file>` | Export field write heatmap as TSV |
| `--coverage <file>` | Export basic-block coverage map as TSV |
| `--no-bb` | Skip BB_ENTRY events (reduces volume) |
| `--min-events <N>` | Minimum events before snapshot (default: 1) |
| `--dwarf <elf>` | Explicit DWARF source |
| `-o, --output <file>` | Output file (for record) |

## memvis-diff

Offline differential topology comparison of two recorded traces.

```sh
memvis-diff --baseline a.bin --subject b.bin --dwarf ./my_program \
    --interval 500000 --output diff.jsonl
```

## memvis-check

CI/CD structural assertion engine over JSONL topology files.

```sh
memvis-check topo.jsonl assertions.txt
```

Exit code 0 = all assertions pass. Non-zero = at least one failure.

## memvis-lint

Static cacheline false-sharing detector.

```sh
# analyze a single struct
memvis-lint ./my_program --struct my_struct

# all structs with warnings
memvis-lint ./my_program --all

# list available struct types
memvis-lint ./my_program --list

# field migration diff between two builds
memvis-lint ./old_binary ./new_binary --struct my_struct --diff

# divergence report: overlay lint predictions with runtime heatmap
memvis-lint ./my_program --struct my_struct --heatmap heat.tsv

# annotation-based analysis
memvis-lint ./my_program --struct my_struct --annotations ann.txt --cacheline 64

# JSON output for CI/CD
memvis-lint ./my_program --struct my_struct --json
```

Exit code 1 if any warnings are emitted.

## Environment variables

| Variable | Purpose |
|---|---|
| `DYNAMORIO_HOME` | DynamoRIO installation directory |
| `MEMVIS_DRRUN` | Explicit path to `drrun` binary |
| `MEMVIS_TRACER` | Explicit path to `libmemvis_tracer.so` |

## TUI keybindings

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

## Docker

```sh
DOCKER_BUILDKIT=1 docker build -t memvis .
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v /path/to/my_program:/app/my_program \
    memvis /app/my_program
```

`--cap-add=SYS_PTRACE` and `--security-opt seccomp=unconfined` are required
for DynamoRIO's process injection inside the container.
