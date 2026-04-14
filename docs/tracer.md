# Tracer

The tracer is a DynamoRIO client written in C (`tracer.c`). It runs inside the
target process's address space and instruments every basic block to capture
memory writes, reads, function calls, returns, tail calls, and register
reloads. Events are pushed into per-thread SPSC ring buffers over POSIX
shared memory.

This document covers the tracer's instrumentation strategy, thread-local
storage layout, event emission, and performance characteristics. All claims
are derived from the current `tracer.c` and `memvis_bridge.h`.

## Initialization

The tracer entry point is `dr_client_main()`. It performs the following steps:

1. Initializes DynamoRIO extension libraries: `drmgr`, `drutil`, `drreg`.
2. Registers 6 drmgr TLS fields via `drmgr_register_tls_field`. The returned
   indices are stored in `g_tls_idx[]`.
3. Registers 8 raw TLS slots via `drmgr_tls_field_request_raw`.
4. Creates the control ring shared memory (`/memvis_ctl`).
5. Registers callbacks: module load, thread init/exit, process exit, BB
   analysis, and BB insertion.

### drmgr TLS fields

DynamoRIO assigns TLS field indices dynamically. The tracer stores them in
`g_tls_idx[]` and accesses them by symbolic slot index:

| Slot | Name | Purpose |
|---|---|---|
| 0 | `TLS_SLOT_GUARD` | Reentrancy guard (prevents recursive clean calls) |
| 1 | `TLS_SLOT_THREAD_ID` | Logical thread ID (u16, assigned sequentially) |
| 2 | `TLS_SLOT_SEQ` | Per-thread event sequence counter (u16, wraps) |
| 3 | `TLS_SLOT_RING` | Pointer to this thread's ring header |
| 4 | `TLS_SLOT_CTL_IDX` | Index in the control ring's thread array |
| 5 | `TLS_SLOT_RDBUF` | Pointer to the per-thread read buffer |

### Raw TLS slots

The raw TLS slots are used by inline JIT instrumentation (no clean call):

| Slot | Name | Purpose |
|---|---|---|
| 0 | `MEMVIS_RAW_SLOT_RING` | Ring header pointer (for inline head flush) |
| 1 | `MEMVIS_RAW_SLOT_HEAD` | Cached head counter (deferred release store) |
| 2 | `MEMVIS_RAW_SLOT_SEQ` | Cached sequence counter (inline increment) |
| 3 | `MEMVIS_RAW_SLOT_TID` | Thread ID (inline event metadata) |
| 4 | `MEMVIS_RAW_SLOT_BP` | Backpressure flag mirror (inline check) |
| 5 | `MEMVIS_RAW_SLOT_SCRATCH` | Pointer to `memvis_scratch_pad_t` |
| 6 | `MEMVIS_RAW_SLOT_RDBUF` | Read buffer pointer (inline overflow check) |
| 7 | `MEMVIS_RAW_SLOT_GUARD` | Inline reentrancy guard |

Raw TLS is accessed via segment base + offset (`dr_raw_tls_opnd`), which
compiles to a single `MOV` through `gs:` or `fs:` segment override — no
function call overhead.

## Instrumentation

DynamoRIO calls the tracer twice for each basic block:

1. **Analysis pass** (`event_bb_analysis`). Scans the BB for memory read
   instructions. Sets a boolean flag (`has_reads`) controlling whether a
   read buffer flush is inserted at the end of the BB. Also allocates
   `instru_data_t` for cross-instruction state.

2. **Insertion pass** (`event_bb_insert`). Called once per instruction.
   Inserts instrumentation based on instruction type. The pass also handles
   **deferred post-write** completion: if the previous instruction had a
   pending `emit_post_write`, it is emitted at the start of the current
   instruction's insertion callback.

### Writes (hybrid inline/clean-call)

The write path is the most performance-critical and uses a two-phase
inline/clean-call hybrid. This is the **only proven-stable approach** under
DynamoRIO's execution model. Six alternative inline value capture strategies
were tested and all failed (see Design Decisions below).

**Phase 1: `emit_pre_write` (fully inline, BEFORE the store)**

1. Reserve two scratch registers via `drreg` (`reg_addr`, `scratch`).
2. Compute effective address (EA) via `drutil_insert_get_mem_addr` into
   `reg_addr`.
3. Save EA to `pad.scratch[0]` via raw TLS (EA may become stale after
   the store — e.g., PUSH decrements RSP before writing).
4. Check ring null → skip if no ring allocated.
5. Check backpressure → skip if active.
6. Compute slot pointer: `ring_data + (head & mask) * 32`.
7. Write metadata into slot fields inline:
   - `addr` = EA
   - `size` = write size (JIT-time constant)
   - `thread_id` = from raw TLS
   - `seq_lo` = from raw TLS
   - `kind_flags` = `MEMVIS_EVENT_WRITE` | `(seq_hi << 16)`
   - `rip_lo` = app PC offset from module base (JIT-time constant)
8. Save slot pointer to `pad.scratch[1]` (0 if skipped).
9. Unreserve `scratch`. Keep `reg_addr` reserved across the app store.

**Phase 2: `emit_post_write` (inline + clean call, AFTER the store)**

1. Load `pad.scratch[1]`. If 0 → skip (pre-write was skipped).
2. Reload EA from `pad.scratch[0]` into `reg_addr` (base register may be
   stale after the app write).
3. Load slot pointer from `pad.scratch[1]`.
4. **Clean call** to `safe_read_into_slot(EA, size, slot_ptr)`:
   - Reads the post-write value via `DR_TRY_EXCEPT`-guarded `memcpy`.
   - Writes `value` into the slot.
   - On fault (unmapped page): leaves `value = 0`.
5. Increment `pad->stat_inline_writes` inline.
6. Increment per-thread `seq` counter (raw TLS).
7. Increment cached `head` counter (raw TLS).
8. Conditional head flush: if `head & 0x3F == 0`, flush to `ring->head`
   (release store).
9. Unreserve `reg_addr`.

**BB-exit head flush**: At the end of every basic block, a clean call to
`flush_head_cache` unconditionally stores the cached head to `ring->head`
with release ordering. This ensures the consumer sees events even from
threads that produce fewer than 64 writes per BB.

### Calls

For each direct `call` instruction:

```
flush_head_cache()    // ensure consumer sees prior writes
at_call(callee_pc, RSP)
```

The `at_call` function:
- Checks the reentrancy guard. Returns immediately if set.
- Sets the reentrancy guard.
- Calls `maybe_emit_module_load` (at most once per process, via CAS).
- Pushes a `CALL` event with callee PC and frame base (RSP).
- Increments `pad->stat_calls`.
- Increments `g_insn_counter` by 8 (relaxed).
- Snapshots all 18 registers via `dr_get_mcontext` and pushes a 7-slot
  `REG_SNAPSHOT` via `memvis_push_reg_snapshot`.
- Clears the reentrancy guard.

### Returns

For each `ret` instruction:

```
flush_head_cache()
at_return(instr_pc)
```

Pushes a `RETURN` event with the return address. Increments
`pad->stat_returns`.

### Tail calls

Detected heuristically at the end of each BB:

```
if instr_is_ubr(instr) && !instr_is_call(instr) && is_last_instr:
    target = branch_target_pc
    if target >= module_base && distance(target, here) > 4096:
        flush_head_cache()
        at_tail_call(target_pc, RSP)
```

The 4KB threshold filters out intra-function branches (if/else, loops) while
catching function-to-function tail calls emitted by `-O2`/`-O3`. Pushes a
`TAIL_CALL` event (kind 8) with callee PC and frame base.

### Reloads

Selective detection of callee-saved register reloads:

```
if instr is MOV reg, [mem]:
    if reg in {RBX, RBP, R12, R13, R14, R15}:
        at_reload(src_addr, size, dest_reg_idx)
```

Only callee-saved registers are instrumented — these are the registers that
DWARF promotes variables into at `-O3`. The reload event encodes the
destination register index in the `flags` byte of `kind_flags`, allowing the
Shadow Register File in the engine to update its confidence tracking.

### Reads

Memory reads use a buffered strategy to reduce clean_call overhead:

1. Before each read instruction, if the buffer might overflow, a
   `flush_read_buf_if_needed(needed)` call is inserted.
2. Each read source operand gets a clean_call to `at_mem_read_buf`, which
   appends the address and size to the per-thread read buffer (capacity 16).
   No ring push occurs here.
3. At the last application instruction of the BB, a `flush_read_buf` call is
   inserted. This iterates the buffer and pushes all buffered reads into the
   ring via `memvis_push_sampled` (which sheds reads under backpressure).

A BB with 10 read instructions produces 10 fast `at_mem_read_buf` calls (no
ring interaction) plus 1 `flush_read_buf` call (pushes up to 10 events).

## Thread lifecycle

### Thread init (`event_thread_init`)

1. Sets the reentrancy guard to NULL (inactive).
2. Assigns a sequential thread ID via `atomic_fetch_add` on
   `g_next_thread_id`.
3. Initializes the per-thread sequence counter to 0.
4. Allocates a per-thread ring via `shm_open` (name: `/memvis_ring_<id>`).
   Ring is initialized with `memvis_ring_init` (sets magic, capacity,
   proto_version).
5. Allocates a `memvis_scratch_pad_t` (128 bytes) via `dr_thread_alloc`.
   Populates `ring_data` and `ring_mask` from the ring header.
6. Allocates a per-thread read buffer (capacity 16) via `dr_thread_alloc`.
7. Initializes raw TLS slots: ring pointer, head=0, seq=0, tid, bp=0,
   scratch pad pointer.
8. Registers the thread in the control ring via
   `memvis_ctl_register_thread` (CAS reclaim or fresh allocation).

### Thread exit (`event_thread_exit`)

1. Flushes the cached head to the ring header (release store).
2. Drains per-thread pad stats into global atomics via
   `atomic_fetch_add_explicit`.
3. Marks the thread as `DEAD` in the control ring (`memvis_ctl_mark_dead`).
4. Unmaps and unlinks the per-thread ring shared memory.
5. Frees the scratch pad and read buffer via `dr_thread_free`.

## Module load detection

The tracer communicates the target binary's runtime base address to the engine
via a two-phase atomic protocol:

```
Phase 0 (initial):     g_module_base_phase = 0
Phase 1 (base set):    event_module_load stores g_module_base, then
                        stores g_module_base_phase = 1 (release)
Phase 2 (emitted):     first at_call reads phase with acquire,
                        CAS 1 → 2, emits MODULE_LOAD event
```

The `event_module_load` callback filters out system libraries (vdso, ld-linux,
libc, libpthread, libdynamorio) and captures the first non-system module as
the main executable. The CAS ensures exactly one thread emits the event.

## Reentrancy guard

Every clean_call function (except `at_mem_read_buf`) checks the per-thread
reentrancy guard in `TLS_SLOT_GUARD`. The guard prevents recursive
instrumentation: if a clean_call triggers a memory operation that would itself
be instrumented, the inner call sees the guard is set and returns immediately.

NULL = inactive. Non-NULL = clean_call in progress.

## Statistics

Stats use a two-tier architecture for zero-contention hot-path counting:

### Per-thread pad stats (hot path, zero atomics)

| Field | Meaning |
|---|---|
| `pad->stat_inline_writes` | Write events emitted via inline path |
| `pad->stat_reads` | Read events pushed to ring |
| `pad->stat_reloads` | Reload events emitted |
| `pad->stat_calls` | Call events pushed |
| `pad->stat_returns` | Return events pushed |
| `pad->stat_tail_calls` | Tail-call events emitted |
| `pad->stat_dropped` | Events dropped (ring full or backpressure) |

### Global atomics (drained at thread exit)

| Counter | Meaning |
|---|---|
| `g_stat_inline_writes` | Sum of all threads' inline write counts |
| `g_stat_reads` | Sum of all threads' read counts |
| `g_stat_reloads` | Sum of all threads' reload counts |
| `g_stat_calls` | Sum of all threads' call counts |
| `g_stat_returns` | Sum of all threads' return counts |
| `g_stat_dropped` | Sum of all threads' dropped counts |
| `g_stat_reg_snaps` | Register snapshots pushed (global, per-call) |
| `g_stat_rdbuf_flushes` | Read buffer flushes performed (global) |

All global counters use `atomic_fetch_add` with relaxed ordering. They are
printed at process exit via `dr_printf`.

## Design decisions

### Value capture: why clean call wins

Six inline value capture approaches were tested. All fail under DynamoRIO's
block builder:

| # | Approach | Failure mode |
|---|---|---|
| 1 | drreg-managed MOV | Corrupts lazy-restore state → exit SIGSEGV |
| 2 | Manual RAX spill to raw TLS | Implicit operand collision (CMPXCHG/XADD) |
| 3 | `dr_save_reg`/`dr_restore_reg` | wr_fast drops 14K→631, exit crash |
| 4 | PUSH [EA] / POP [slot] | DynamoRIO mangles meta PUSH/POP for shadow stack |
| 5 | MOVQ XMM0 relay | wr_fast drops 14K→631 (encoder ambiguity) |
| 6 | Manual R11 spill to private pad | wr_fast drops to 11 (block truncation) |

**Root cause**: Any meta-instruction that loads from an application-computed
effective address causes DynamoRIO's block builder to either truncate the
basic block or corrupt drreg's lazy-restore state machine. The register
choice, spill mechanism, and instruction encoding are irrelevant.

**Diagnostic signal**: The 23x write count drop (14K→631 or worse) is the
fingerprint of silent block truncation.

**Production answer**: Clean call (`safe_read_into_slot`) with
`DR_TRY_EXCEPT` is the only proven-stable value capture mechanism under DBI.
Pre-write metadata (addr, size, tid, seq, kind, rip) remains fully inline —
only the 8-byte value read goes through the clean call.

## Performance characteristics

- **Inline metadata**: 13 meta-instructions per write (pre-write path). No
  clean call, no context save/restore. Compiles to ~15 x86-64 instructions.
- **Value capture**: 1 clean call per write (~50-150 cycles context
  save/restore). `safe_read_into_slot` performs a single `memcpy` for writes
  ≤8 bytes; larger writes store `value = 0`.
- **Head caching**: Defers atomic store to every 64th event or BB exit,
  reducing release stores from 1-per-event to ~1-per-BB.
- **Read buffering**: Amortizes clean_call overhead from 1-per-read to
  1-per-BB-flush.
- **Backpressure**: Relaxed load of `backpressure` flag is essentially free
  (same cache line as ring metadata). Shedding reads under pressure avoids
  stalling the target.
- **Ring push** (`memvis_push_ex`): 1 relaxed load (head) + 1 acquire load
  (tail) + plain stores + 1 release store (head). On x86-64 under TSO, the
  release store is a plain `mov` (no `mfence` or `lock` prefix).
