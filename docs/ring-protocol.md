# Ring Protocol

This document specifies the shared memory ring buffer protocol used for
communication between the memvis tracer (producer) and engine (consumer).
The protocol is defined in `memvis_bridge.h`. Protocol version: **3**.

## Design goals

1. **Zero-copy.** Events are written directly into shared memory. No
   serialization, no syscalls in the hot path.
2. **Lock-free.** The SPSC (single-producer, single-consumer) design requires
   no mutexes or CAS operations in the data path.
3. **Cache-line conscious.** The head and tail cursors occupy separate 64-byte
   cache lines to eliminate false sharing between the producer and consumer
   cores.
4. **Bounded.** Each ring has a fixed power-of-two capacity. Full rings either
   drop events or spin, depending on a per-ring flag.
5. **Versioned.** Both ring headers and the control ring carry a
   `proto_version` field. The consumer validates this on attach and rejects
   mismatched versions.

## Event formats

Two event struct layouts are defined. Both are 32 bytes, 32-byte aligned.

### v2 format (`memvis_event_t`)

Used by `memvis_push_ex`, `memvis_push_reg_snapshot`, and the ring data
accessor functions:

```c
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;        // byte 0:  address (memory addr, callee PC, etc.)
    uint32_t size;        // byte 8:  size in bytes (for W/R events)
    uint16_t thread_id;   // byte 12: logical thread ID (0-based)
    uint16_t seq;         // byte 14: per-thread sequence number (wraps at 2^16)
    uint64_t value;       // byte 16: payload (written value, frame base, etc.)
    uint64_t kind_flags;  // byte 24: kind (low 8 bits) | flags (bits 8-15)
} memvis_event_t;
```

### v3 format (`memvis_event_v3_t`)

Used by the inline write path for extended sequence numbers and RIP tracking:

```c
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;        // byte 0:  effective address
    uint32_t size;        // byte 8:  write size in bytes
    uint16_t thread_id;   // byte 12: logical thread ID
    uint16_t seq_lo;      // byte 14: sequence number, low 16 bits
    uint64_t value;       // byte 16: post-write value (captured via clean call)
    uint32_t kind_flags;  // byte 24: kind:8 | flags:8 | seq_hi:16
    uint32_t rip_lo;      // byte 28: app PC offset from module base
} memvis_event_v3_t;
```

Both are `sizeof == 32` (compile-time asserted).

**Sequence number encoding** (v3): The full 32-bit sequence is reconstructed as:

```c
uint32_t seq = (uint32_t)seq_lo | ((uint32_t)(kind_flags >> 16) << 16);
```

At 50M events/sec (typical DBI throughput), 32-bit wrap occurs every ~86
seconds. Consumers MUST use modular arithmetic for ordering:
`(int32_t)(a - b) > 0`. The sequence is per-thread; cross-thread ordering uses
`(thread_id, seq)` pairs.

**ABI compatibility note**: On little-endian, the low 4 bytes of a v2
`kind_flags` (u64) at offset 24 occupy the same position as the v3
`kind_flags` (u32). The consumer currently reads events through the v2 layout
and extracts `kind` via `kind_flags & 0xFF`, which produces correct results
for both formats.

### Event kinds

| Kind | Value | `addr` | `size` | `value` | Notes |
|---|---|---|---|---|---|
| `WRITE` | 0 | Memory address | Byte count | Post-write value | `rip_lo` set (v3) |
| `READ` | 1 | Memory address | Byte count | 0 | Shed under backpressure |
| `CALL` | 2 | Callee PC | 0 | Frame base (RSP) | Triggers REG_SNAPSHOT |
| `RETURN` | 3 | Return address | 0 | 0 | |
| `OVERFLOW` | 4 | Instruction counter | 0 | 0 | Ring was full (diagnostic) |
| `REG_SNAPSHOT` | 5 | Instruction counter | 0 | 0 | 7 consecutive slots |
| `CACHE_MISS` | 6 | Miss address | Cache level | Sample IP | |
| `MODULE_LOAD` | 7 | Runtime base addr | 0 | 0 | Emitted exactly once |
| `TAIL_CALL` | 8 | Callee PC | 0 | Frame base (RSP) | JMP >4KB, main module |
| `ALLOC` | 9 | — | — | — | Reserved (not yet emitted) |
| `FREE` | 10 | — | — | — | Reserved (not yet emitted) |
| `BB_ENTRY` | 11 | — | — | — | Reserved (not yet emitted) |
| `RELOAD` | 12 | Source address | Load size | Register index | MOV to callee-saved |

### Register snapshots

A register snapshot occupies 7 consecutive event slots. The first slot is the
header (kind = `REG_SNAPSHOT`, `addr` = instruction counter). The next 6 slots
each carry 3 register values packed into `addr`, `size`, and `value`:

```
slot 0: header         { insn_counter, 0, tid, seq, 0, REG_SNAPSHOT }
slot 1: regs[0..2]     { regs[0],  (u32)regs[1],  tid, 0, regs[2],  REG_SNAPSHOT }
slot 2: regs[3..5]     { regs[3],  (u32)regs[4],  tid, 0, regs[5],  REG_SNAPSHOT }
slot 3: regs[6..8]     { regs[6],  (u32)regs[7],  tid, 0, regs[8],  REG_SNAPSHOT }
slot 4: regs[9..11]    { regs[9],  (u32)regs[10], tid, 0, regs[11], REG_SNAPSHOT }
slot 5: regs[12..14]   { regs[12], (u32)regs[13], tid, 0, regs[14], REG_SNAPSHOT }
slot 6: regs[15..17]   { regs[15], (u32)regs[16], tid, 0, regs[17], REG_SNAPSHOT }
```

Register indices follow the memvis layout (not DWARF numbering):

| Index | Register | Index | Register |
|---|---|---|---|
| 0 | RAX | 9 | R9 |
| 1 | RBX | 10 | R10 |
| 2 | RCX | 11 | R11 |
| 3 | RDX | 12 | R12 |
| 4 | RSI | 13 | R13 |
| 5 | RDI | 14 | R14 |
| 6 | RBP | 15 | R15 |
| 7 | RSP | 16 | RIP |
| 8 | R8 | 17 | RFLAGS |

The producer checks that 7 slots are available before writing a snapshot. If
there is insufficient space, the entire snapshot is dropped.

## Ring header

The ring header is a 192-byte (3 cache lines) struct:

```
Byte offset   Size   Field            Cache line
-----------   ----   -----            ----------
0             8      magic            CL 0
8             4      capacity
12            4      entry_size
16            8      flags
24            4      backpressure     (atomic)
28            4      proto_version
32            28     padding

64            8      head             CL 1 (atomic, producer-owned)
72            56     padding

128           8      tail             CL 2 (atomic, consumer-owned)
136           56     padding
```

Static assert: `sizeof(memvis_ring_header_t) == 192` (3 × `MEMVIS_CACHE_LINE`).

The event data array begins immediately after the header, at byte offset 192.

### Fields

- **`magic`** (u64): `0x4D454D56495342` (ASCII "MEMVISB"). Validated by both
  tracer (on init) and consumer (on attach).
- **`capacity`** (u32): Number of event slots. **Must be a power of two.**
  Enforced at runtime by `memvis_ring_init` — a non-power-of-two capacity
  causes the ring to be zero-initialized and left invalid. Default:
  `MEMVIS_THREAD_RING_CAPACITY = 1 << 20` (1,048,576). Compile-time asserted
  via `MEMVIS_IS_POW2`.
- **`entry_size`** (u32): `sizeof(memvis_event_t)` = 32.
- **`flags`** (u64): Bitfield. Bit 0 (`MEMVIS_FLAG_SPIN_ON_FULL`): if set, the
  producer spins when the ring is full instead of dropping the event.
- **`backpressure`** (atomic u32): Set to 1 by the consumer when ring fill
  exceeds 6/8 capacity. Cleared when fill drops below 3/8. The producer checks
  this flag and sheds `READ` events when backpressure is active.
- **`proto_version`** (u32): `MEMVIS_PROTO_VERSION` (currently 3). Written by
  `memvis_ring_init`. The consumer validates this on attach and rejects
  mismatched versions with a diagnostic message to stderr.
- **`head`** (atomic u64): Write cursor. Owned by the producer. Monotonically
  increasing (wraps at 2^64, masked to capacity for indexing).
- **`tail`** (atomic u64): Read cursor. Owned by the consumer. Monotonically
  increasing.

### Indexing

Both `head` and `tail` are unbounded 64-bit counters. The actual array index is
computed as:

```
index = counter & (capacity - 1)
```

This requires `capacity` to be a power of two. The number of events currently
in the ring is `head - tail` (unsigned subtraction handles wrap correctly).

### Head caching

The tracer caches the head pointer in raw TLS (`MEMVIS_RAW_SLOT_HEAD`) to
avoid an atomic store on every event. The cached head is flushed to the ring
header's atomic `head` field in two cases:

1. **Conditional flush**: Every 64 events (`head & MEMVIS_HEAD_FLUSH_MASK ==
   0`, where `MEMVIS_HEAD_FLUSH_MASK = 0x3F`).
2. **BB-exit flush**: Unconditionally at the end of every basic block. This
   ensures the consumer sees events even from threads that produce fewer than
   64 writes per BB before blocking.

The flush is a single release store to `ring->head`.

## Memory ordering

The ring uses a standard SPSC acquire-release protocol:

### Producer (tracer, single thread per ring)

```
1. Load head      (relaxed)       — only this thread writes head
2. Load tail      (acquire)       — synchronizes with consumer's tail store
3. Check: head - tail < capacity  — if full, drop or spin
4. Write event data to slot[head & mask]  (plain stores, no atomics)
5. Store head+1   (release)       — publishes the event data
```

The release store at step 5 guarantees that the event data written in step 4 is
visible to any thread that loads `head` with acquire ordering.

**Note**: The inline write path defers step 5 via head caching (see above). The
actual release store occurs at the flush point, not on every event.

### Consumer (engine, single thread)

```
1. Load tail      (relaxed)       — only this thread writes tail
2. Load head      (acquire)       — synchronizes with producer's head store
3. Check: tail == head            — if equal, ring is empty
4. Read event data from slot[tail & mask]  (volatile read)
5. Store tail+1   (release)       — frees the slot for reuse
```

### Batch operations

The engine's `batch_pop` reads up to N events in a single pass:

```
1. Load tail      (relaxed)
2. Load head      (acquire)
3. avail = head - tail
4. n = min(avail, max_batch)
5. For i in 0..n: read slot[(tail + i) & mask]  (volatile read)
6. Store tail + n (release)       — frees all n slots at once
```

This amortizes the atomic overhead from 2 atomics per event to 2 atomics per
batch. With `max_batch = 20,000` and 6 rings, a single drain cycle can return
up to 120,000 events with only 12 atomic operations total.

## Backpressure

The consumer monitors ring fill levels and communicates backpressure to the
producer through the `backpressure` field in the ring header:

```
Fill >= 6/8 capacity:  consumer stores backpressure = 1  (release)
Fill <  3/8 capacity:  consumer stores backpressure = 0  (release)
```

The producer checks `backpressure` with a relaxed load. When backpressure is
active, `memvis_push_sampled()` silently drops `READ` events (returns 1
instead of 0). `WRITE`, `CALL`, `RETURN`, `TAIL_CALL`, `RELOAD`, and other
control events are **never** dropped by backpressure.

This mechanism degrades gracefully under load: read events are low-priority
(they do not carry post-read values), so shedding them reduces ring pressure
without losing higher-value write and control events.

## Spin-on-full

If the ring's `flags` field has bit 0 set (`MEMVIS_FLAG_SPIN_ON_FULL`), the
producer spins instead of dropping events when the ring is full:

```c
while (head - tail >= capacity) {
    __builtin_ia32_pause();
    tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
}
```

The `pause` intrinsic reduces the rate of cache-line acquisitions on the
consumer's `tail` line. The default policy is `MEMVIS_FLAG_DROP_ON_FULL`
(flags = 0), which drops events rather than stalling the target program.

## Control ring

The control ring is a single shared memory object (`/memvis_ctl`) used for
thread discovery. It contains a fixed-size array of 256 thread entries:

```c
typedef struct {
    uint64_t magic;                              // 0x4D56435430303032 ("MVCTL002")
    uint32_t proto_version;                      // MEMVIS_PROTO_VERSION (3)
    _Atomic uint32_t thread_count;               // high-water mark of allocated slots
    uint32_t max_threads;                        // 256
    uint32_t _pad0;
    memvis_thread_entry_t threads[256];
} memvis_ctl_header_t;
```

Each thread entry is 56 bytes:

```c
typedef struct {
    _Atomic uint32_t state;       // EMPTY=0, ACTIVE=1, DEAD=2
    uint16_t thread_id;
    uint16_t _reserved;
    char shm_name[48];            // e.g. "/memvis_ring_0"
} memvis_thread_entry_t;
```

### Thread registration protocol

When a new thread starts in the target process, `memvis_ctl_register_thread`
executes a two-pass allocation:

**Pass 1: Dead-slot reclamation (CAS scan)**

```
for i in 0..max_threads:
    CAS(threads[i].state, DEAD → ACTIVE, acq_rel)
    if success: reuse slot i, return
```

This reclaims slots from exited threads without incrementing the high-water
mark. The CAS ensures exactly one thread wins each dead slot.

**Pass 2: Fresh allocation (fetch_add)**

```
idx = atomic_fetch_add(&thread_count, 1, acq_rel)
if idx >= max_threads: undo fetch_add, return -1
write thread_id and shm_name into threads[idx]
store threads[idx].state = ACTIVE (release)
```

The engine polls the control ring every drain cycle:

1. Load `thread_count` with acquire ordering.
2. For each slot (0..thread_count):
   - Load `state` with acquire ordering.
   - If `ACTIVE` and not already tracked: open the shared memory by name,
     validate magic + proto_version, add ring to orchestrator.
3. For all tracked rings: check for `DEAD` state transitions and mark
   inactive.

### Thread teardown

When a thread exits:

1. The tracer stores `state = DEAD` with release ordering
   (`memvis_ctl_mark_dead`).
2. The tracer unmaps and unlinks the shared memory ring.
3. The engine detects the `DEAD` state on its next poll and marks the ring
   as inactive. Inactive rings are still drained (the thread may have
   produced events before exiting).

### Protocol version handshake

Both the ring header and control ring header carry `proto_version`:

- `memvis_ring_init` sets `ring->proto_version = MEMVIS_PROTO_VERSION`.
- `memvis_ctl_init` sets `ctl->proto_version = MEMVIS_PROTO_VERSION`.
- The engine's `ThreadRing::from_shm` validates `proto_version` on ring
  attach and rejects mismatches.
- The engine's `try_attach_ctl` validates `proto_version` on ctl attach
  and rejects mismatches.

This prevents silent data corruption when the tracer and engine are built
against different versions of `memvis_bridge.h`.

## Shared memory lifecycle

| Phase | Actor | Action |
|---|---|---|
| Startup | Engine | Best-effort cleanup of stale `/dev/shm/memvis_*` |
| Startup | Tracer | Creates `/memvis_ctl`, inits header (magic + proto) |
| Thread init | Tracer | Creates `/memvis_ring_N`, registers via CAS/alloc |
| Attach | Engine | Opens `/memvis_ctl`, validates magic + proto_version |
| Discovery | Engine | Opens `/memvis_ring_N`, validates magic + proto_version |
| Runtime | Both | Producer writes events, consumer drains them |
| Thread exit | Tracer | Marks DEAD, unmaps/unlinks ring SHM |
| Shutdown | Tracer | Unmaps and unlinks `/memvis_ctl` |
| Shutdown | Engine | Unmaps all rings |

All shared memory objects are created with mode 0600 (owner read/write only).
