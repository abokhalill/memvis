// SPDX-License-Identifier: MIT

/*
 * Copyright (c) 2026 Yousef Mahmoud
 * <yosefkhalil610@gmail.com>
 *
 * SPSC lock free ring buffer over mmap'd shm.
 * producer: dynamorio client. consumer: rust engine.
 * head/tail on separate cache lines.
 */

#ifndef MEMVIS_BRIDGE_H
#define MEMVIS_BRIDGE_H

#include <stdint.h>
#include <stdatomic.h>
#include <string.h>

#define MEMVIS_CACHE_LINE    64
#define MEMVIS_MAGIC         0x4D454D56495342ULL  /* "MEMVISB\0" */
#define MEMVIS_SHM_NAME      "/memvis_ring"
#define MEMVIS_SHM_ENV       "MEMVIS_SHM_PATH"

#define MEMVIS_EVENT_WRITE    0
#define MEMVIS_EVENT_READ     1
#define MEMVIS_EVENT_CALL     2
#define MEMVIS_EVENT_RETURN   3
#define MEMVIS_EVENT_OVERFLOW 4
#define MEMVIS_EVENT_REG_SNAPSHOT 5
#define MEMVIS_EVENT_CACHE_MISS   6

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

// backpressure thresholds in 8ths of capacity
#define MEMVIS_BP_HIGH_WATER  7
#define MEMVIS_BP_LOW_WATER   4

typedef struct __attribute__((packed, aligned(32))) {
    uint64_t addr;
    uint64_t size;
    uint64_t value;
    uint64_t kind;
} memvis_event_t;

_Static_assert(sizeof(memvis_event_t) == 32, "event must be 32 bytes");

#define MEMVIS_FLAG_DROP_ON_FULL  0x0
#define MEMVIS_FLAG_SPIN_ON_FULL  0x1

#define MEMVIS_DEFAULT_CAPACITY   (1u << 21)

typedef struct {
    uint64_t magic;
    uint32_t capacity;
    uint32_t entry_size;
    uint64_t flags;
    _Atomic uint32_t backpressure;
    uint8_t  _pad0[MEMVIS_CACHE_LINE - 24 - sizeof(_Atomic uint32_t)];
    _Alignas(MEMVIS_CACHE_LINE) _Atomic uint64_t head;
    uint8_t  _pad1[MEMVIS_CACHE_LINE - sizeof(_Atomic uint64_t)];
    _Alignas(MEMVIS_CACHE_LINE) _Atomic uint64_t tail;
    uint8_t  _pad2[MEMVIS_CACHE_LINE - sizeof(_Atomic uint64_t)];
} memvis_ring_header_t;

_Static_assert(sizeof(memvis_ring_header_t) == 3 * MEMVIS_CACHE_LINE, "");

static inline memvis_event_t *memvis_ring_data(memvis_ring_header_t *hdr) {
    return (memvis_event_t *)((uint8_t *)hdr + sizeof(memvis_ring_header_t));
}

static inline size_t memvis_shm_size(uint32_t capacity) {
    return sizeof(memvis_ring_header_t) + (size_t)capacity * sizeof(memvis_event_t);
}

static inline int memvis_push_ex(memvis_ring_header_t *ring,
                                  uint64_t addr, uint64_t size,
                                  uint64_t value, uint64_t kind)
{
    const uint32_t mask = ring->capacity - 1;
    memvis_event_t *data = memvis_ring_data(ring);
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if (h - t >= ring->capacity) {
        if (!(ring->flags & MEMVIS_FLAG_SPIN_ON_FULL))
            return -1;
        while (h - t >= ring->capacity)
            t = atomic_load_explicit(&ring->tail, memory_order_acquire);
    }

    uint64_t idx = h & mask;
    data[idx].addr  = addr;
    data[idx].size  = size;
    data[idx].value = value;
    data[idx].kind  = kind;

    atomic_store_explicit(&ring->head, h + 1, memory_order_release);
    return 0;
}

static inline int memvis_push(memvis_ring_header_t *ring,
                               uint64_t addr, uint64_t size, uint64_t value)
{
    return memvis_push_ex(ring, addr, size, value, MEMVIS_EVENT_WRITE);
}

static inline int memvis_push_reg_snapshot(memvis_ring_header_t *ring,
                                            uint64_t insn_counter,
                                            const uint64_t regs[MEMVIS_REG_COUNT])
{
    const uint32_t mask = ring->capacity - 1;
    memvis_event_t *data = memvis_ring_data(ring);

    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);
    if (h - t + MEMVIS_REG_SNAPSHOT_SLOTS > ring->capacity)
        return -1;

    uint64_t idx = h & mask;
    data[idx] = (memvis_event_t){ insn_counter, 0, 0, MEMVIS_EVENT_REG_SNAPSHOT };
    for (int s = 0; s < 6; s++) {
        idx = (h + 1 + s) & mask;
        data[idx] = (memvis_event_t){ regs[s*3], regs[s*3+1], regs[s*3+2], MEMVIS_EVENT_REG_SNAPSHOT };
    }

    atomic_store_explicit(&ring->head, h + MEMVIS_REG_SNAPSHOT_SLOTS, memory_order_release);
    return 0;
}

static inline int memvis_push_cache_miss(memvis_ring_header_t *ring,
                                          uint64_t miss_addr,
                                          uint64_t cache_level,
                                          uint64_t sample_ip)
{
    return memvis_push_ex(ring, miss_addr, cache_level, sample_ip, MEMVIS_EVENT_CACHE_MISS);
}

static inline int memvis_pop(memvis_ring_header_t *ring,
                              memvis_event_t *out_event)
{
    const uint32_t mask = ring->capacity - 1;
    memvis_event_t *data = memvis_ring_data(ring);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
    if (t == h) return -1;
    *out_event = data[t & mask];
    atomic_store_explicit(&ring->tail, t + 1, memory_order_release);
    return 0;
}

static inline void memvis_ring_init(memvis_ring_header_t *ring,
                                     uint32_t capacity, uint64_t flags)
{
    memset(ring, 0, sizeof(memvis_ring_header_t));
    ring->magic      = MEMVIS_MAGIC;
    ring->capacity   = capacity;
    ring->entry_size = sizeof(memvis_event_t);
    ring->flags      = flags;
    atomic_store_explicit(&ring->head, 0, memory_order_relaxed);
    atomic_store_explicit(&ring->tail, 0, memory_order_relaxed);
}

static inline uint32_t memvis_ring_fill_eighths(memvis_ring_header_t *ring)
{
    uint64_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    return (uint32_t)(((h - t) << 3) / ring->capacity);
}

static inline int memvis_push_sampled(memvis_ring_header_t *ring,
                                       uint64_t addr, uint64_t size,
                                       uint64_t value, uint64_t kind)
{
    if (kind == MEMVIS_EVENT_READ &&
        atomic_load_explicit(&ring->backpressure, memory_order_relaxed))
        return 1;
    return memvis_push_ex(ring, addr, size, value, kind);
}

static inline void memvis_push_overflow(memvis_ring_header_t *ring,
                                         uint64_t insn_counter)
{
    memvis_push_ex(ring, insn_counter, 0, 0, MEMVIS_EVENT_OVERFLOW);
}

#endif /* MEMVIS_BRIDGE_H */
