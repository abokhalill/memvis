// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright (c) 2026 Yousef Mahmoud
 * <yosefkhalil610@gmail.com>
 *
 * SPSC ring over mmap'd shm. producer: DR client, consumer: rust engine.
 * head/tail on separate cache lines. 32 byte v3 events. */

#ifndef MEMVIS_BRIDGE_H
#define MEMVIS_BRIDGE_H

#include <stdint.h>
#include <stdatomic.h>
#include <string.h>

#define MEMVIS_CACHE_LINE    64
#define MEMVIS_MAGIC         0x4D454D56495342ULL  /* "MEMVISB\0" */
#define MEMVIS_PROTO_VERSION 3
#define MEMVIS_SHM_ENV       "MEMVIS_SHM_PATH"

/* hash me baby; detects C<->Rust header mismatch */
static inline uint32_t memvis_build_hash_compute(void) {
    const char stamp[] = __DATE__ " " __TIME__;
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; stamp[i]; i++) {
        h ^= (uint8_t)stamp[i];
        h *= 0x01000193u;
    }
    return h;
}

#define MEMVIS_EVENT_WRITE    0
#define MEMVIS_EVENT_READ     1
#define MEMVIS_EVENT_CALL     2
#define MEMVIS_EVENT_RETURN   3
#define MEMVIS_EVENT_OVERFLOW 4
#define MEMVIS_EVENT_REG_SNAPSHOT 5
#define MEMVIS_EVENT_CACHE_MISS   6
#define MEMVIS_EVENT_MODULE_LOAD  7
#define MEMVIS_EVENT_TAIL_CALL    8
#define MEMVIS_EVENT_ALLOC        9
#define MEMVIS_EVENT_FREE        10
#define MEMVIS_EVENT_BB_ENTRY    11
#define MEMVIS_EVENT_RELOAD      12

#define MEMVIS_REG_SNAPSHOT_SLOTS 7

#define MEMVIS_REG_RAX    0
#define MEMVIS_REG_RBX    1
#define MEMVIS_REG_RCX    2
#define MEMVIS_REG_RDX    3
#define MEMVIS_REG_RSI    4
#define MEMVIS_REG_RDI    5
#define MEMVIS_REG_RBP    6
#define MEMVIS_REG_RSP    7
#define MEMVIS_REG_R8     8
#define MEMVIS_REG_R9     9
#define MEMVIS_REG_R10   10
#define MEMVIS_REG_R11   11
#define MEMVIS_REG_R12   12
#define MEMVIS_REG_R13   13
#define MEMVIS_REG_R14   14
#define MEMVIS_REG_R15   15
#define MEMVIS_REG_RIP   16
#define MEMVIS_REG_RFLAGS 17
#define MEMVIS_REG_COUNT 18

#define MEMVIS_BP_HIGH_WATER  6  /* 6/8 capacity */
#define MEMVIS_BP_LOW_WATER   3

#define MEMVIS_BLOOM_U64S    512   /* 4KB = 32768 bits */
#define MEMVIS_BLOOM_BITS    (MEMVIS_BLOOM_U64S * 64)

#define MEMVIS_RAW_TLS_SLOTS     8
#define MEMVIS_RAW_SLOT_RING     0
#define MEMVIS_RAW_SLOT_HEAD     1
#define MEMVIS_RAW_SLOT_SEQ      2
#define MEMVIS_RAW_SLOT_TID      3
#define MEMVIS_RAW_SLOT_BP       4
#define MEMVIS_RAW_SLOT_SCRATCH  5
#define MEMVIS_RAW_SLOT_RDBUF    6
#define MEMVIS_RAW_SLOT_GUARD    7

#define MEMVIS_HEAD_FLUSH_MASK  0x3F

/* two cache lines per thread: hot path + ambient stats */
typedef struct __attribute__((aligned(MEMVIS_CACHE_LINE))) {
    /* cl0: hot */
    uint64_t scratch[2];
    uint64_t ring_data;
    uint32_t ring_mask;
    uint32_t _pad0;
    uint64_t _cl0_reserved[4];
    /* cl1: stats */
    uint64_t stat_inline_writes;
    uint64_t stat_reads;
    uint64_t stat_reloads;
    uint64_t stat_calls;
    uint64_t stat_returns;
    uint64_t stat_tail_calls;
    uint64_t stat_dropped;
    uint64_t ccc_audit_ctr;
} memvis_scratch_pad_t;

_Static_assert(sizeof(memvis_scratch_pad_t) == 2 * MEMVIS_CACHE_LINE, "");

/* v2 event (compat) */
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;
    uint32_t size;
    uint16_t thread_id;
    uint16_t seq;
    uint64_t value;
    uint64_t kind_flags;
} memvis_event_t;

_Static_assert(sizeof(memvis_event_t) == 32, "");

/* v3 event. 32 bit seq wraps ~86s at 50M ev/s; use modular arithmetic. */
typedef struct __attribute__((aligned(32))) {
    uint64_t addr;
    uint32_t size;
    uint16_t thread_id;
    uint16_t seq_lo;
    uint64_t value;
    uint32_t kind_flags;  /* kind:8 | flags:8 | seq_hi:16 */
    uint32_t rip_lo;      /* app PC offset from module base */
} memvis_event_v3_t;

_Static_assert(sizeof(memvis_event_v3_t) == 32, "");

static inline uint8_t memvis_v3_kind(const memvis_event_v3_t *e) {
    return (uint8_t)(e->kind_flags & 0xFF);
}
static inline uint32_t memvis_v3_seq(const memvis_event_v3_t *e) {
    return (uint32_t)e->seq_lo | ((uint32_t)(e->kind_flags >> 16) << 16);
}
static inline uint32_t memvis_v3_make_kf(uint8_t kind, uint8_t flags, uint16_t seq_hi) {
    return (uint32_t)kind | ((uint32_t)flags << 8) | ((uint32_t)seq_hi << 16);
}

static inline uint8_t memvis_event_kind(const memvis_event_t *e) {
    return (uint8_t)(e->kind_flags & 0xFF);
}
static inline uint8_t memvis_event_flags(const memvis_event_t *e) {
    return (uint8_t)((e->kind_flags >> 8) & 0xFF);
}
static inline uint64_t memvis_make_kind_flags(uint8_t kind, uint8_t flags) {
    return (uint64_t)kind | ((uint64_t)flags << 8);
}

#define MEMVIS_FLAG_DROP_ON_FULL  0x0
#define MEMVIS_FLAG_SPIN_ON_FULL  0x1

typedef struct {
    uint64_t magic;
    uint32_t capacity;
    uint32_t entry_size;
    uint64_t flags;
    _Atomic uint32_t backpressure;
    uint32_t proto_version;     
    uint8_t  _pad0[MEMVIS_CACHE_LINE - 28 - sizeof(_Atomic uint32_t)];
    _Alignas(MEMVIS_CACHE_LINE) _Atomic uint64_t head;
    uint8_t  _pad1[MEMVIS_CACHE_LINE - sizeof(_Atomic uint64_t)];
    _Alignas(MEMVIS_CACHE_LINE) _Atomic uint64_t tail;
    uint8_t  _pad2[MEMVIS_CACHE_LINE - sizeof(_Atomic uint64_t)];
} memvis_ring_header_t;

_Static_assert(sizeof(memvis_ring_header_t) == 3 * MEMVIS_CACHE_LINE, "");

static inline memvis_event_t *memvis_ring_data(memvis_ring_header_t *hdr) {
    return (memvis_event_t *)((uint8_t *)hdr + sizeof(memvis_ring_header_t));
}

static inline memvis_event_v3_t *memvis_ring_data_v3(memvis_ring_header_t *hdr) {
    return (memvis_event_v3_t *)((uint8_t *)hdr + sizeof(memvis_ring_header_t));
}

static inline size_t memvis_shm_size(uint32_t capacity) {
    return sizeof(memvis_ring_header_t) + (size_t)capacity * sizeof(memvis_event_v3_t);
}

static inline int memvis_push_ex_flags(memvis_ring_header_t *ring,
                                        uint64_t addr, uint32_t size,
                                        uint64_t value, uint8_t kind,
                                        uint8_t flags,
                                        uint16_t thread_id, uint32_t seq)
{
    const uint32_t mask = ring->capacity - 1;
    memvis_event_v3_t *data = memvis_ring_data_v3(ring);
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if (h - t >= ring->capacity) {
        if (!(ring->flags & MEMVIS_FLAG_SPIN_ON_FULL))
            return -1;
        while (h - t >= ring->capacity) {
            __builtin_ia32_pause();
            t = atomic_load_explicit(&ring->tail, memory_order_acquire);
        }
    }

    uint64_t idx = h & mask;
    data[idx].addr       = addr;
    data[idx].size       = size;
    data[idx].thread_id  = thread_id;
    data[idx].seq_lo     = (uint16_t)(seq & 0xFFFF);
    data[idx].value      = value;
    data[idx].kind_flags = memvis_v3_make_kf(kind, flags, (uint16_t)(seq >> 16));
    data[idx].rip_lo     = 0;

    atomic_store_explicit(&ring->head, h + 1, memory_order_release);
    return 0;
}

static inline int memvis_push_ex(memvis_ring_header_t *ring,
                                  uint64_t addr, uint32_t size,
                                  uint64_t value, uint8_t kind,
                                  uint16_t thread_id, uint32_t seq)
{
    return memvis_push_ex_flags(ring, addr, size, value, kind, 0, thread_id, seq);
}

static inline int memvis_push(memvis_ring_header_t *ring,
                               uint64_t addr, uint32_t size, uint64_t value,
                               uint16_t thread_id, uint32_t seq)
{
    return memvis_push_ex(ring, addr, size, value, MEMVIS_EVENT_WRITE, thread_id, seq);
}

static inline int memvis_push_reg_snapshot(memvis_ring_header_t *ring,
                                            uint64_t insn_counter,
                                            const uint64_t regs[MEMVIS_REG_COUNT],
                                            uint16_t thread_id, uint32_t seq)
{
    const uint32_t mask = ring->capacity - 1;
    memvis_event_v3_t *data = memvis_ring_data_v3(ring);

    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);
    if (h - t + MEMVIS_REG_SNAPSHOT_SLOTS > ring->capacity)
        return -1;

    uint16_t seq_lo = (uint16_t)(seq & 0xFFFF);
    uint16_t seq_hi = (uint16_t)(seq >> 16);
    uint32_t kf = memvis_v3_make_kf(MEMVIS_EVENT_REG_SNAPSHOT, 0, seq_hi);
    uint64_t idx = h & mask;
    data[idx] = (memvis_event_v3_t){ insn_counter, 0, thread_id, seq_lo, 0, kf, 0 };
    for (int s = 0; s < 6; s++) {
        idx = (h + 1 + s) & mask;
        data[idx] = (memvis_event_v3_t){ regs[s*3], (uint32_t)regs[s*3+1], thread_id, 0,
                                          regs[s*3+2], kf, 0 };
    }

    atomic_store_explicit(&ring->head, h + MEMVIS_REG_SNAPSHOT_SLOTS, memory_order_release);
    return 0;
}

static inline int memvis_push_cache_miss(memvis_ring_header_t *ring,
                                          uint64_t miss_addr,
                                          uint32_t cache_level,
                                          uint64_t sample_ip,
                                          uint16_t thread_id, uint32_t seq)
{
    return memvis_push_ex(ring, miss_addr, cache_level, sample_ip,
                          MEMVIS_EVENT_CACHE_MISS, thread_id, seq);
}

static inline int memvis_pop(memvis_ring_header_t *ring,
                              memvis_event_v3_t *out_event)
{
    const uint32_t mask = ring->capacity - 1;
    memvis_event_v3_t *data = memvis_ring_data_v3(ring);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
    if (t == h) return -1;
    *out_event = data[t & mask];
    atomic_store_explicit(&ring->tail, t + 1, memory_order_release);
    return 0;
}

#define MEMVIS_IS_POW2(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)

static inline void memvis_ring_init(memvis_ring_header_t *ring,
                                     uint32_t capacity, uint64_t flags)
{
    if (!MEMVIS_IS_POW2(capacity)) {
        memset(ring, 0, sizeof(memvis_ring_header_t));
        return;
    }
    memset(ring, 0, sizeof(memvis_ring_header_t));
    ring->magic         = MEMVIS_MAGIC;
    ring->capacity      = capacity;
    ring->entry_size    = sizeof(memvis_event_v3_t);
    ring->flags         = flags;
    ring->proto_version = MEMVIS_PROTO_VERSION;
    atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
    atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
}

static inline uint32_t memvis_ring_fill_eighths(memvis_ring_header_t *ring)
{
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    return (uint32_t)(((h - t) << 3) / ring->capacity);
}

/* shed reads and bb_entry under backpressure; lifecycle events always land */
static inline int memvis_push_sampled(memvis_ring_header_t *ring,
                                       uint64_t addr, uint32_t size,
                                       uint64_t value, uint8_t kind,
                                       uint16_t thread_id, uint32_t seq)
{
    if ((kind == MEMVIS_EVENT_READ || kind == MEMVIS_EVENT_BB_ENTRY) &&
        atomic_load_explicit(&ring->backpressure, memory_order_relaxed))
        return 1;
    return memvis_push_ex(ring, addr, size, value, kind, thread_id, seq);
}

static inline void memvis_push_overflow(memvis_ring_header_t *ring,
                                         uint64_t insn_counter,
                                         uint16_t thread_id, uint32_t seq)
{
    memvis_push_ex(ring, insn_counter, 0, 0, MEMVIS_EVENT_OVERFLOW, thread_id, seq);
}

/* ctl ring: thread discovery */

#define MEMVIS_CTL_SHM_NAME     "/memvis_ctl"
#define MEMVIS_CTL_MAGIC        0x4D56435430303032ULL  /* "MVCTL002" */
#define MEMVIS_MAX_THREADS      256
#define MEMVIS_RING_NAME_LEN    48

#define MEMVIS_THREAD_RING_CAPACITY  (1u << 20)
_Static_assert(MEMVIS_IS_POW2(MEMVIS_THREAD_RING_CAPACITY), "ring capacity must be power-of-two");

#define MEMVIS_THREAD_STATE_EMPTY        0
#define MEMVIS_THREAD_STATE_ACTIVE       1
#define MEMVIS_THREAD_STATE_DEAD         2
#define MEMVIS_THREAD_STATE_INITIALIZING 3

typedef struct {
    _Atomic uint32_t state;
    uint16_t thread_id;
    uint16_t _reserved;
    char     shm_name[MEMVIS_RING_NAME_LEN];
} memvis_thread_entry_t;

_Static_assert(sizeof(memvis_thread_entry_t) == 56, "thread entry sizing");

typedef struct {
    uint64_t magic;
    uint32_t proto_version;
    _Atomic uint32_t thread_count;
    uint32_t max_threads;
    uint32_t build_hash;
    uint32_t target_pid;
    uint32_t _pad0;
    uint64_t priority_bloom[MEMVIS_BLOOM_U64S];
    memvis_thread_entry_t threads[MEMVIS_MAX_THREADS];
} memvis_ctl_header_t;

static inline uint32_t memvis_bloom_h1(uint64_t addr) {
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; i < 8; i++) { h ^= (uint8_t)(addr >> (i * 8)); h *= 0x01000193u; }
    return h % MEMVIS_BLOOM_BITS;
}
static inline uint32_t memvis_bloom_h2(uint64_t addr) {
    uint32_t h = 0x01000193u;
    for (int i = 0; i < 8; i++) { h ^= (uint8_t)(addr >> (i * 8)); h *= 0x811c9dc5u; }
    return h % MEMVIS_BLOOM_BITS;
}
static inline void memvis_bloom_insert(uint64_t *bloom, uint64_t addr) {
    uint32_t b1 = memvis_bloom_h1(addr);
    uint32_t b2 = memvis_bloom_h2(addr);
    bloom[b1 / 64] |= (1ULL << (b1 % 64));
    bloom[b2 / 64] |= (1ULL << (b2 % 64));
}
static inline int memvis_bloom_query(const uint64_t *bloom, uint64_t addr) {
    uint32_t b1 = memvis_bloom_h1(addr);
    uint32_t b2 = memvis_bloom_h2(addr);
    return (bloom[b1 / 64] & (1ULL << (b1 % 64))) &&
           (bloom[b2 / 64] & (1ULL << (b2 % 64)));
}

static inline size_t memvis_ctl_shm_size(void) {
    return sizeof(memvis_ctl_header_t);
}

static inline void memvis_ctl_init(memvis_ctl_header_t *ctl) {
    memset(ctl, 0, sizeof(memvis_ctl_header_t));
    ctl->magic = MEMVIS_CTL_MAGIC;
    ctl->proto_version = MEMVIS_PROTO_VERSION;
    ctl->build_hash = memvis_build_hash_compute();
    ctl->max_threads = MEMVIS_MAX_THREADS;
    atomic_store_explicit(&ctl->thread_count, 0, memory_order_relaxed);
}

static inline int memvis_ctl_register_thread(memvis_ctl_header_t *ctl,
                                               uint16_t thread_id,
                                               const char *ring_shm_name)
{
    /* reclaim DEAD slot via CAS -> INITIALIZING -> populate -> ACTIVE */
    for (uint32_t i = 0; i < ctl->max_threads; i++) {
        uint32_t expected = MEMVIS_THREAD_STATE_DEAD;
        if (atomic_compare_exchange_strong_explicit(
                &ctl->threads[i].state, &expected,
                MEMVIS_THREAD_STATE_INITIALIZING,
                memory_order_acq_rel, memory_order_relaxed)) {
            ctl->threads[i].thread_id = thread_id;
            strncpy(ctl->threads[i].shm_name, ring_shm_name, MEMVIS_RING_NAME_LEN - 1);
            ctl->threads[i].shm_name[MEMVIS_RING_NAME_LEN - 1] = '\0';
            atomic_store_explicit(&ctl->threads[i].state,
                                  MEMVIS_THREAD_STATE_ACTIVE, memory_order_release);
            return (int)i;
        }
    }
    uint32_t idx = atomic_fetch_add_explicit(&ctl->thread_count, 1, memory_order_acq_rel);
    if (idx >= ctl->max_threads) {
        atomic_fetch_sub_explicit(&ctl->thread_count, 1, memory_order_relaxed);
        return -1;
    }
    memvis_thread_entry_t *entry = &ctl->threads[idx];
    entry->thread_id = thread_id;
    strncpy(entry->shm_name, ring_shm_name, MEMVIS_RING_NAME_LEN - 1);
    entry->shm_name[MEMVIS_RING_NAME_LEN - 1] = '\0';
    atomic_store_explicit(&entry->state, MEMVIS_THREAD_STATE_ACTIVE, memory_order_release);
    return (int)idx;
}

static inline void memvis_ctl_mark_dead(memvis_ctl_header_t *ctl, uint32_t idx) {
    if (idx < ctl->max_threads)
        atomic_store_explicit(&ctl->threads[idx].state, MEMVIS_THREAD_STATE_DEAD, memory_order_release);
}

#endif /* MEMVIS_BRIDGE_H */
