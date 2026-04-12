# Tracer

The tracer is a DynamoRIO client written in C (`tracer.c`). It runs inside the
target process's address space and instruments every basic block to capture
memory operations, function calls, and returns. Events are pushed into
per-thread SPSC ring buffers over POSIX shared memory.

This document covers the tracer's instrumentation strategy, thread-local
storage layout, event emission, and performance characteristics.

## Initialization

The tracer entry point is `dr_client_main()`. It performs the following steps:

1. Initializes DynamoRIO extension libraries: `drmgr`, `drutil`, `drreg`.
2. Registers 6 TLS (thread-local storage) fields via `drmgr_register_tls_field`.
   The returned indices are stored in `g_tls_idx[]`.
3. Creates the control ring shared memory (`/memvis_ctl`).
4. Registers callbacks for module loads, thread init/exit, process exit, and
   basic block instrumentation.

DynamoRIO assigns TLS field indices dynamically. The tracer stores them in a
global array and accesses them by symbolic slot index:

| Slot | Name | Purpose |
|---|---|---|
| 0 | `TLS_SLOT_GUARD` | Reentrancy guard (prevents recursive instrumentation) |
| 1 | `TLS_SLOT_THREAD_ID` | Logical thread ID (u16, assigned sequentially) |
| 2 | `TLS_SLOT_SEQ` | Per-thread event sequence counter (u16, wraps) |
| 3 | `TLS_SLOT_RING` | Pointer to this thread's ring header |
| 4 | `TLS_SLOT_CTL_IDX` | Index in the control ring's thread array |
| 5 | `TLS_SLOT_RDBUF` | Pointer to the per-thread read buffer |

## Instrumentation

DynamoRIO calls the tracer twice for each basic block:

1. **Analysis pass** (`event_bb_analysis`). Scans the basic block for any
   memory read instructions. Sets a boolean flag (`user_data`) indicating
   whether the BB contains reads. This flag controls whether a read buffer
   flush is inserted at the end of the BB.

2. **Insertion pass** (`event_bb_insert`). Called once per instruction.
   Inserts instrumentation based on the instruction type:

### Calls

For each `call` instruction:

```
dr_insert_clean_call(at_call, callee_pc, RSP)
```

The `at_call` function:
- Checks the reentrancy guard. Returns immediately if already inside a
  clean_call.
- Sets the reentrancy guard.
- Emits a `MODULE_LOAD` event (at most once per process, via atomic CAS on
  `g_module_base_phase`).
- Pushes a `CALL` event with the callee PC and frame base (RSP).
- Increments the global instruction counter.
- Snapshots all 18 registers via `dr_get_mcontext` and pushes a 7-slot
  `REG_SNAPSHOT`.
- Clears the reentrancy guard.

### Returns

For each `ret` instruction:

```
dr_insert_clean_call(at_return, instr_pc)
```

Pushes a `RETURN` event with the return address.

### Writes

For each instruction that writes to memory:

1. Reserves two scratch registers via `drreg`.
2. Inserts `drutil_insert_get_mem_addr` to compute the effective address.
3. Inserts a clean_call to `at_mem_write` **after** the write instruction.
   This ordering ensures that `safe_read_value()` sees the post-write value.
4. Unreserves the scratch registers.

If the write is the last instruction in the basic block, the clean_call is
inserted before the write (fallback, since there is no "after" point).

The `at_mem_write` function:
- Checks the reentrancy guard.
- Reads the written value via `safe_read_value()` (a `DR_TRY_EXCEPT`-guarded
  `memcpy`).
- Pushes the event via `memvis_push_sampled()`. If backpressure is active and
  the event is a `READ`, it is silently dropped.
- Increments the appropriate stat counter (`g_stat_writes` or `g_stat_dropped`).

### Reads

Memory reads use a buffered strategy to reduce clean_call overhead:

1. Before each read instruction, if the buffer might overflow, a
   `flush_read_buf_if_needed` call is inserted.
2. Each read source operand gets a clean_call to `at_mem_read_buf`, which
   appends the address and size to the per-thread read buffer (capacity: 16
   entries). No ring push occurs here.
3. At the last application instruction of the BB, a `flush_read_buf` call is
   inserted. This function iterates the buffer and pushes all buffered reads
   into the ring in a single batch.

This design reduces the number of clean_calls for reads. A basic block with 10
read instructions that each read one operand produces 10 `at_mem_read_buf`
calls (fast: no ring interaction) plus 1 `flush_read_buf` call (pushes 10
events), instead of 10 individual ring pushes.

## Thread lifecycle

### Thread init (`event_thread_init`)

1. Sets the reentrancy guard to NULL (inactive).
2. Assigns a sequential thread ID via `atomic_fetch_add` on `g_next_thread_id`.
3. Initializes the per-thread sequence counter to 0.
4. Allocates a per-thread ring via `shm_open` (name: `/memvis_ring_<id>`).
5. Allocates a per-thread read buffer (256 bytes) via `dr_thread_alloc`.
6. Registers the thread in the control ring via `memvis_ctl_register_thread`.

### Thread exit (`event_thread_exit`)

1. Marks the thread as `DEAD` in the control ring.
2. Unmaps and unlinks the per-thread ring shared memory.
3. Frees the read buffer via `dr_thread_free`.

## Module load detection

The tracer needs to communicate the target binary's runtime base address to the
engine so the engine can compute the ASLR relocation delta. This is done through
a two-phase atomic protocol:

```
Phase 0 (initial):     g_module_base_phase = 0
Phase 1 (base set):    event_module_load stores g_module_base, then
                        stores g_module_base_phase = 1 (release)
Phase 2 (emitted):     first clean_call reads phase with acquire,
                        CAS 1 -> 2, emits MODULE_LOAD event
```

The `event_module_load` callback filters out system libraries (vdso, ld-linux,
libc, libpthread, libdynamorio) and captures the first non-system module as
the main executable.

The `maybe_emit_module_load` function is called from `at_call`. It checks the
phase, and if it is 1, performs a CAS to transition to phase 2 and emits the
`MODULE_LOAD` event. The CAS ensures that exactly one thread emits the event,
even if multiple threads call `at_call` concurrently.

## Reentrancy guard

Every clean_call function (except `at_mem_read_buf`) checks a per-thread
reentrancy guard stored in TLS slot 0. The guard prevents recursive
instrumentation: if a clean_call triggers a memory operation that would
itself be instrumented, the inner call sees the guard is set and returns
immediately.

The guard is stored as a pointer-width value: NULL means inactive, non-NULL
means a clean_call is in progress.

## Statistics

The tracer maintains global atomic counters for diagnostic purposes:

| Counter | Meaning |
|---|---|
| `g_stat_writes` | Write events successfully pushed |
| `g_stat_reads` | Read events successfully pushed |
| `g_stat_calls` | Call events pushed |
| `g_stat_returns` | Return events pushed |
| `g_stat_shed` | Read events shed due to backpressure |
| `g_stat_dropped` | Events dropped due to full ring |
| `g_stat_reg_snaps` | Register snapshots pushed |
| `g_stat_rdbuf_flushes` | Read buffer flushes performed |

All counters use `atomic_fetch_add` with relaxed ordering. They are printed
at process exit.

## Performance considerations

- **Clean_call overhead.** Each `dr_insert_clean_call` adds approximately
  50-150 cycles of context-save/restore overhead. The read buffering strategy
  reduces the number of clean_calls per basic block.
- **Ring push.** Each `memvis_push_ex` performs one relaxed load (head), one
  acquire load (tail), a memcpy into the ring slot, and one release store
  (head). On x86-64 under TSO, the release store is a plain `mov` (not an
  `mfence` or `lock` prefix).
- **Value capture.** `safe_read_value` performs a `memcpy` guarded by
  `DR_TRY_EXCEPT`. For writes of 8 bytes or fewer, this is a single load.
  Writes larger than 8 bytes are capped (value = 0).
- **Backpressure.** The relaxed load of `backpressure` is essentially free
  (same cache line as the ring header's metadata, loaded once per push).
  Shedding reads under pressure avoids stalling the target.
