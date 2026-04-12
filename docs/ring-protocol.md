# Ring Protocol

This document specifies the shared memory ring buffer protocol used for
communication between the memvis tracer (producer) and engine (consumer). The
protocol is defined in `memvis_bridge.h`.

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

## Event format

Every event is a 32-byte struct aligned to a 32-byte boundary:

```c
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;        // byte 0:  address (memory addr, callee PC, etc.)
    uint32_t size;        // byte 8:  size in bytes (for W/R events)
    uint16_t thread_id;   // byte 12: logical thread ID (0-based, assigned by tracer)
    uint16_t seq;         // byte 14: per-thread sequence number (wraps at 65536)
    uint64_t value;       // byte 16: payload (written value, frame base, etc.)
    uint64_t kind_flags;  // byte 24: event kind (low 8 bits) | flags (bits 8-15)
} memvis_event_t;
```

Static assert: `sizeof(memvis_event_t) == 32`.

The 32-byte alignment guarantees that each event fits within a single cache line
or spans exactly two aligned 32-byte halves. No event straddles a 64-byte cache
line boundary, which ensures that reads and writes to a single event are atomic
at the cache-line level on x86-64.

### Event kinds

| Kind | Value | `addr` | `size` | `value` | Description |
|---|---|---|---|---|---|
| `WRITE` | 0 | Memory address | Byte count | Post-write value | Memory store |
| `READ` | 1 | Memory address | Byte count | 0 | Memory load |
| `CALL` | 2 | Callee PC | 0 | Frame base (RSP) | Direct function call |
| `RETURN` | 3 | Return address | 0 | 0 | Function return |
| `OVERFLOW` | 4 | Instruction counter | 0 | 0 | Ring was full (diagnostic) |
| `REG_SNAPSHOT` | 5 | Instruction counter | 0 | 0 | Register file snapshot (7 slots) |
| `CACHE_MISS` | 6 | Miss address | Cache level | Sample IP | Hardware cache miss |
| `MODULE_LOAD` | 7 | Runtime base address | 0 | 0 | Main module loaded |

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
28            28     padding

64            8      head             CL 1 (atomic, producer-owned)
72            56     padding

128           8      tail             CL 2 (atomic, consumer-owned)
136           56     padding
```

Static assert: `sizeof(memvis_ring_header_t) == 192`.

The event data array begins immediately after the header, at byte offset 192.

### Fields

- **`magic`** (u64): `0x4D454D56495342` (ASCII "MEMVISB"). Used to validate
  that the shared memory region contains a valid ring.
- **`capacity`** (u32): Number of event slots. Must be a power of two. Default:
  `1 << 20` (1,048,576).
- **`entry_size`** (u32): `sizeof(memvis_event_t)` = 32. Present for forward
  compatibility.
- **`flags`** (u64): Bitfield. Bit 0 (`MEMVIS_FLAG_SPIN_ON_FULL`): if set, the
  producer spins when the ring is full instead of dropping the event.
- **`backpressure`** (atomic u32): Set to 1 by the consumer when the ring fill
  exceeds 6/8 capacity. Cleared when fill drops below 3/8. The producer checks
  this flag and sheds `READ` events when backpressure is active.
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

This requires `capacity` to be a power of two. The number of events currently in
the ring is `head - tail` (unsigned subtraction handles wrap correctly).

## Memory ordering

The ring uses a standard SPSC acquire-release protocol:

### Producer (tracer, single thread per ring)

```
1. Load head      (relaxed)       -- only this thread writes head
2. Load tail      (acquire)       -- synchronizes with consumer's tail store
3. Check: head - tail < capacity  -- if full, drop or spin
4. Write event data to slot[head & mask]  (plain stores, no atomics)
5. Store head+1   (release)       -- publishes the event data
```

The release store at step 5 guarantees that the event data written in step 4 is
visible to any thread that loads `head` with acquire ordering.

### Consumer (engine, single thread)

```
1. Load tail      (relaxed)       -- only this thread writes tail
2. Load head      (acquire)       -- synchronizes with producer's head store
3. Check: tail == head            -- if equal, ring is empty
4. Read event data from slot[tail & mask]  (plain loads)
5. Store tail+1   (release)       -- frees the slot for reuse
```

The acquire load at step 2 ensures the consumer sees the event data that the
producer wrote before its release store of `head`.

### Batch operations

The engine's `batch_pop` reads up to N events in a single pass:

```
1. Load tail      (relaxed)
2. Load head      (acquire)
3. avail = head - tail
4. n = min(avail, max)
5. For i in 0..n: read slot[(tail + i) & mask]  (volatile read)
6. Store tail + n (release)        -- frees all n slots at once
```

This amortizes the atomic overhead from 2 atomics per event to 2 atomics per
batch.

## Backpressure

The consumer monitors ring fill levels and communicates backpressure to the
producer through the `backpressure` field in the ring header:

```
Fill >= 6/8 capacity:  consumer sets backpressure = 1  (release store)
Fill <  3/8 capacity:  consumer sets backpressure = 0  (release store)
```

The producer checks `backpressure` with a relaxed load. When backpressure is
active, the producer's `memvis_push_sampled()` function silently drops `READ`
events (returns 1 instead of 0). `WRITE`, `CALL`, `RETURN`, and other control
events are never dropped by backpressure.

This mechanism degrades gracefully under load: read events are low-priority
(they do not carry values), so shedding them reduces ring pressure without
losing the higher-value write and control events.

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
consumer's `tail` line, which would otherwise degrade consumer throughput.

The default policy is `MEMVIS_FLAG_DROP_ON_FULL` (flags = 0), which drops events
rather than stalling the target program.

## Control ring

The control ring is a single shared memory object (`/memvis_ctl`) used for
thread discovery. It contains a fixed-size array of 256 thread entries:

```c
typedef struct {
    uint64_t magic;                              // "MVCTL002"
    uint32_t proto_version;                      // 2
    _Atomic uint32_t thread_count;               // number of registered threads
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

When a new thread starts in the target process:

1. The tracer allocates a new shared memory ring (`shm_open`, `ftruncate`,
   `mmap`).
2. The tracer atomically increments `thread_count` with `fetch_add`
   (`acq_rel` ordering).
3. The tracer writes the thread ID and shared memory name into the slot.
4. The tracer stores `state = ACTIVE` with release ordering.

The engine polls the control ring every 200 ms:

1. Load `thread_count` with acquire ordering.
2. For each new slot (index >= previously known count):
   - Load `state` with acquire ordering.
   - If `ACTIVE`: open the shared memory by name, validate the magic number,
     and add the ring to the orchestrator.
3. For all known slots: check for `DEAD` state transitions and mark the
   corresponding ring as inactive.

### Thread teardown

When a thread exits:

1. The tracer stores `state = DEAD` with release ordering.
2. The tracer unmaps and unlinks the shared memory ring.
3. The engine detects the `DEAD` state on its next poll and marks the ring as
   inactive. Inactive rings are still drained (the thread may have produced
   events before exiting) but are not included in new thread counts.

## Shared memory lifecycle

| Phase | Actor | Action |
|---|---|---|
| Startup | Tracer | Creates `/memvis_ctl`, initializes header |
| Thread init | Tracer | Creates `/memvis_ring_N`, registers in ctl |
| Attach | Engine | Opens `/memvis_ctl`, reads magic, starts polling |
| Discovery | Engine | Opens `/memvis_ring_N` per ctl entry |
| Runtime | Both | Producer writes events, consumer drains them |
| Thread exit | Tracer | Marks thread DEAD, unmaps/unlinks ring shm |
| Shutdown | Engine | Unmaps all rings, unlinks `/memvis_ctl` |

All shared memory objects are created with mode 0600 (owner read/write only).
The engine performs best-effort cleanup of stale `/memvis_ring_*` objects on
startup and exit.
