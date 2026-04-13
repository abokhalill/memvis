// SPDX-License-Identifier: MIT
// ghost v3 tracer. inline write events, clean-call CALL/RET.

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "dr_ir_macros_x86.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "memvis_bridge.h"

static memvis_ctl_header_t *g_ctl     = NULL;
static int                  g_ctl_fd  = -1;

static _Atomic uint64_t g_insn_counter  = 0;

static _Atomic uint64_t g_stat_writes       = 0;
static _Atomic uint64_t g_stat_reads        = 0;
static _Atomic uint64_t g_stat_calls        = 0;
static _Atomic uint64_t g_stat_returns      = 0;
static _Atomic uint64_t g_stat_shed         = 0;
static _Atomic uint64_t g_stat_dropped      = 0;
static _Atomic uint64_t g_stat_reg_snaps    = 0;
static _Atomic uint64_t g_stat_rdbuf_flushes = 0;
static _Atomic uint64_t g_stat_inline_writes = 0;
static _Atomic uint64_t g_stat_spill_writes  = 0;
static _Atomic uint64_t g_stat_reloads       = 0;

static _Atomic uint16_t g_next_thread_id    = 0;

static uint64_t g_module_base = 0;
static _Atomic int g_module_base_phase = 0;

#define TLS_SLOT_GUARD     0
#define TLS_SLOT_THREAD_ID 1
#define TLS_SLOT_SEQ       2
#define TLS_SLOT_RING      3
#define TLS_SLOT_CTL_IDX   4
#define TLS_SLOT_RDBUF     5
#define TLS_SLOT_COUNT     6

#define RDBUF_CAP 16
typedef struct {
    uint32_t count;
    uint32_t _pad;
    struct { uint64_t addr; uint32_t size; uint32_t _p; } entries[RDBUF_CAP];
} read_buf_t;

static int g_tls_idx[TLS_SLOT_COUNT];

static reg_id_t g_raw_tls_seg;
static uint     g_raw_tls_off;
#define RAW_TLS(slot) (g_raw_tls_off + (slot) * sizeof(void *))

static void
map_ctl_ring(void)
{
    size_t sz = memvis_ctl_shm_size();
    g_ctl_fd = shm_open(MEMVIS_CTL_SHM_NAME, O_CREAT | O_RDWR, 0600);
    DR_ASSERT(g_ctl_fd >= 0);
    if (ftruncate(g_ctl_fd, (off_t)sz) != 0)
        DR_ASSERT(false);
    g_ctl = (memvis_ctl_header_t *)mmap(
        NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, g_ctl_fd, 0);
    DR_ASSERT(g_ctl != MAP_FAILED);
    if (g_ctl->magic != MEMVIS_CTL_MAGIC)
        memvis_ctl_init(g_ctl);
}

// predictable spill: deterministic RAX/RCX fallback when drreg fails.
typedef struct {
    reg_id_t r1;
    reg_id_t r2;
    bool r1_from_drreg;
    bool r2_from_drreg;
} scratch_pair_t;

static scratch_pair_t
acquire_scratch_pair(void *drcontext, instrlist_t *bb, instr_t *where)
{
    scratch_pair_t sp = { DR_REG_NULL, DR_REG_NULL, false, false };

    if (drreg_reserve_register(drcontext, bb, where, NULL, &sp.r1) == DRREG_SUCCESS) {
        sp.r1_from_drreg = true;
    } else {
        sp.r1 = DR_REG_RAX;
        sp.r1_from_drreg = false;
        // spill rax to raw TLS slot (repurposed as 64-bit spill)
        instrlist_meta_preinsert(bb, where,
            XINST_CREATE_store(drcontext,
                dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                    RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH)),
                opnd_create_reg(DR_REG_RAX)));
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_st(drcontext,
                opnd_create_base_disp(sp.r1, DR_REG_NULL, 0, 0, OPSZ_0),
                opnd_create_reg(sp.r1)));
    }

    if (drreg_reserve_register(drcontext, bb, where, NULL, &sp.r2) == DRREG_SUCCESS) {
        sp.r2_from_drreg = true;
    } else {
        sp.r2 = (sp.r1 == DR_REG_RAX) ? DR_REG_RCX : DR_REG_RAX;
        sp.r2_from_drreg = false;
        // spill r2 to GUARD slot (unused during inline emit)
        instrlist_meta_preinsert(bb, where,
            XINST_CREATE_store(drcontext,
                dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                    RAW_TLS(MEMVIS_RAW_SLOT_GUARD)),
                opnd_create_reg(sp.r2)));
    }

    return sp;
}

static void
release_scratch_pair(void *drcontext, instrlist_t *bb, instr_t *where,
                     scratch_pair_t *sp)
{
    if (sp->r2_from_drreg) {
        drreg_unreserve_register(drcontext, bb, where, sp->r2);
    } else {
        instrlist_meta_preinsert(bb, where,
            XINST_CREATE_load(drcontext,
                opnd_create_reg(sp->r2),
                dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                    RAW_TLS(MEMVIS_RAW_SLOT_GUARD))));
    }
    if (sp->r1_from_drreg) {
        drreg_unreserve_register(drcontext, bb, where, sp->r1);
    } else {
        instrlist_meta_preinsert(bb, where,
            XINST_CREATE_load(drcontext,
                opnd_create_reg(sp->r1),
                dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                    RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    }
}

static void
emit_inline_write_v3(void *drcontext, instrlist_t *bb, instr_t *where,
                     reg_id_t addr_reg, reg_id_t scratch,
                     uint32_t sz, app_pc app_pc_val)
{
    uint32_t rip_offset = (uint32_t)((uint64_t)(ptr_uint_t)app_pc_val
                                     - g_module_base);

    instr_t *skip_label = INSTR_CREATE_label(drcontext);

    // hot path: ring null check
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_RING))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(scratch), opnd_create_reg(scratch)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jz, opnd_create_instr(skip_label)));

    // backpressure check
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_BP))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(scratch), opnd_create_reg(scratch)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(skip_label)));

    // slot = ring_data + (head & mask) * 32
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));

    // save EA to pad, borrow addr_reg for head
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(scratch, offsetof(memvis_scratch_pad_t, scratch[0])),
            opnd_create_reg(addr_reg)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(addr_reg),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_HEAD))));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_and(drcontext,
            opnd_create_reg(addr_reg),
            OPND_CREATE_MEMPTR(scratch, offsetof(memvis_scratch_pad_t, ring_mask))));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(addr_reg),
            OPND_CREATE_INT8(5)));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_add(drcontext,
            opnd_create_reg(addr_reg),
            OPND_CREATE_MEMPTR(scratch, offsetof(memvis_scratch_pad_t, ring_data))));

    // store event fields. reload saved EA via pad ptr.
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_MEMPTR(addr_reg,
                -(int)(offsetof(memvis_scratch_pad_t, ring_data))
                )));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_MEMPTR(scratch, offsetof(memvis_scratch_pad_t, scratch[0]))));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(addr_reg,
                offsetof(memvis_event_v3_t, addr)),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(addr_reg, DR_REG_NULL, 0,
                offsetof(memvis_event_v3_t, size), OPSZ_4),
            OPND_CREATE_INT32((int)sz)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_TID))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(addr_reg, DR_REG_NULL, 0,
                offsetof(memvis_event_v3_t, thread_id), OPSZ_2),
            opnd_create_reg(reg_64_to_16(scratch))));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(addr_reg, DR_REG_NULL, 0,
                offsetof(memvis_event_v3_t, seq_lo), OPSZ_2),
            opnd_create_reg(reg_64_to_16(scratch))));

    // kind_flags = WRITE | (seq >> 16) << 16
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shr(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_or(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT32(MEMVIS_EVENT_WRITE)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(addr_reg, DR_REG_NULL, 0,
                offsetof(memvis_event_v3_t, kind_flags), OPSZ_4),
            opnd_create_reg(reg_64_to_32(scratch))));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(addr_reg, DR_REG_NULL, 0,
                offsetof(memvis_event_v3_t, rip_lo), OPSZ_4),
            OPND_CREATE_INT32((int)rip_offset)));

    // post-write value read
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_MEMPTR(scratch, offsetof(memvis_scratch_pad_t, scratch[0]))));
    if (sz <= 8) {
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_ld(drcontext,
                opnd_create_reg(scratch),
                opnd_create_base_disp(scratch, DR_REG_NULL, 0, 0,
                    opnd_size_from_bytes(sz > 4 ? 8 : sz))));
    } else {
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_xor(drcontext,
                opnd_create_reg(scratch), opnd_create_reg(scratch)));
    }
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(addr_reg,
                offsetof(memvis_event_v3_t, value)),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_add(drcontext,
            opnd_create_reg(scratch), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_store(drcontext,
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SEQ)),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_HEAD))));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_add(drcontext,
            opnd_create_reg(scratch), OPND_CREATE_INT32(1)));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_store(drcontext,
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_HEAD)),
            opnd_create_reg(scratch)));

    // cold trampoline: conditional head flush (1/64 events)
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT32(MEMVIS_HEAD_FLUSH_MASK)));

    instr_t *no_flush_label = INSTR_CREATE_label(drcontext);
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(no_flush_label)));

    // cold flush
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(addr_reg),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_RING))));
    // TSO: MOV is store-release
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(addr_reg,
                offsetof(memvis_ring_header_t, head)),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(addr_reg),
            OPND_CREATE_MEMPTR(addr_reg,
                offsetof(memvis_ring_header_t, tail))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_sub(drcontext,
            opnd_create_reg(scratch), opnd_create_reg(addr_reg)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_cmp(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT32(
                (int)((MEMVIS_THREAD_RING_CAPACITY * MEMVIS_BP_HIGH_WATER) >> 3))));

    instr_t *bp_off_label = INSTR_CREATE_label(drcontext);
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jb, opnd_create_instr(bp_off_label)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_store(drcontext,
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_BP)),
            OPND_CREATE_INT32(1)));

    instrlist_meta_preinsert(bb, where, bp_off_label);
    instrlist_meta_preinsert(bb, where, no_flush_label);
    instrlist_meta_preinsert(bb, where, skip_label);
}

static void
flush_head_cache(void *drcontext)
{
    memvis_ring_header_t *ring = (memvis_ring_header_t *)dr_raw_tls_get_value(
        drcontext, g_raw_tls_seg, RAW_TLS(MEMVIS_RAW_SLOT_RING));
    if (!ring) return;
    uint64_t cached_head = (uint64_t)(uintptr_t)dr_raw_tls_get_value(
        drcontext, g_raw_tls_seg, RAW_TLS(MEMVIS_RAW_SLOT_HEAD));
    atomic_store_explicit(&ring->head, cached_head, memory_order_release);
}

static memvis_ring_header_t *
alloc_thread_ring(const char *shm_name)
{
    uint32_t capacity = MEMVIS_THREAD_RING_CAPACITY;
    size_t sz = memvis_shm_size(capacity);
    int fd = shm_open(shm_name, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return NULL;
    if (ftruncate(fd, (off_t)sz) != 0) { close(fd); return NULL; }
    memvis_ring_header_t *ring = (memvis_ring_header_t *)mmap(
        NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (ring == MAP_FAILED) return NULL;
    memvis_ring_init(ring, capacity, MEMVIS_FLAG_DROP_ON_FULL);
    return ring;
}

static memvis_scratch_pad_t *
alloc_scratch_pad(void *drcontext, memvis_ring_header_t *ring)
{
    memvis_scratch_pad_t *pad = (memvis_scratch_pad_t *)dr_thread_alloc(
        drcontext, sizeof(memvis_scratch_pad_t));
    memset(pad, 0, sizeof(memvis_scratch_pad_t));
    if (ring) {
        pad->ring_data = (uint64_t)(uintptr_t)memvis_ring_data(ring);
        pad->ring_mask = ring->capacity - 1;
    }
    return pad;
}

static void
unmap_ctl_ring(void)
{
    if (g_ctl && g_ctl != (void *)MAP_FAILED) {
        munmap(g_ctl, memvis_ctl_shm_size());
        g_ctl = NULL;
    }
    if (g_ctl_fd >= 0) {
        close(g_ctl_fd);
        g_ctl_fd = -1;
    }
    shm_unlink(MEMVIS_CTL_SHM_NAME);
}

static inline uint16_t tls_thread_id(void *drcontext) {
    return (uint16_t)(uintptr_t)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_THREAD_ID]);
}

static inline uint16_t tls_next_seq(void *drcontext) {
    uint16_t s = (uint16_t)(uintptr_t)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_SEQ]);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_SEQ], (void *)(uintptr_t)(uint16_t)(s + 1));
    return s;
}

static inline memvis_ring_header_t *tls_ring(void *drcontext) {
    return (memvis_ring_header_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RING]);
}

static inline void maybe_emit_module_load(void *drcontext, memvis_ring_header_t *ring) {
    int phase = atomic_load_explicit(&g_module_base_phase, memory_order_acquire);
    if (phase != 1) return;
    if (!atomic_compare_exchange_strong_explicit(&g_module_base_phase, &phase, 2,
                                                  memory_order_acq_rel, memory_order_relaxed))
        return;
    uint16_t tid = tls_thread_id(drcontext);
    uint16_t seq = tls_next_seq(drcontext);
    memvis_push_ex(ring, g_module_base, 0, 0, MEMVIS_EVENT_MODULE_LOAD, tid, seq);
    dr_printf("memvis: emitted MODULE_LOAD base=0x%llx (tid=%u seq=%u)\n",
              (unsigned long long)g_module_base, (unsigned)tid, (unsigned)seq);
}

static inline uint64_t safe_read_value(uint64_t addr, uint32_t size) {
    uint64_t val = 0;
    if (size <= 8) {
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            memcpy(&val, (void *)(uintptr_t)addr, size);
        }, { /* fault: leave val=0 */ });
    }
    return val;
}

static void
at_mem_write(uint64_t addr, uint32_t size)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    memvis_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    uint16_t tid = tls_thread_id(drcontext);
    uint16_t seq = tls_next_seq(drcontext);
    uint64_t val = safe_read_value(addr, size);
    int rc = memvis_push_sampled(ring, addr, size, val,
                                  MEMVIS_EVENT_WRITE, tid, seq);
    if (rc == 0)
        atomic_fetch_add_explicit(&g_stat_writes, 1, memory_order_relaxed);
    else if (rc < 0)
        atomic_fetch_add_explicit(&g_stat_dropped, 1, memory_order_relaxed);

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static void
at_mem_read_buf(uint64_t addr, uint32_t size)
{
    void *drcontext = dr_get_current_drcontext();
    read_buf_t *buf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (!buf || buf->count >= RDBUF_CAP) return;
    uint32_t idx = buf->count++;
    buf->entries[idx].addr = addr;
    buf->entries[idx].size = size;
}

static void flush_read_buf(void);

static void
flush_read_buf_if_needed(int needed)
{
    void *drcontext = dr_get_current_drcontext();
    read_buf_t *buf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (!buf || (int)buf->count + needed <= RDBUF_CAP) return;
    flush_read_buf();
}

static void
flush_read_buf(void)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    read_buf_t *buf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (!buf || buf->count == 0) {
        drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
        return;
    }
    memvis_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) {
        buf->count = 0;
        drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
        return;
    }
    uint16_t tid = tls_thread_id(drcontext);
    uint32_t n = buf->count;
    for (uint32_t i = 0; i < n; i++) {
        uint16_t seq = tls_next_seq(drcontext);
        int rc = memvis_push_sampled(ring, buf->entries[i].addr,
                                      buf->entries[i].size, 0,
                                      MEMVIS_EVENT_READ, tid, seq);
        if (rc == 0)
            atomic_fetch_add_explicit(&g_stat_reads, 1, memory_order_relaxed);
        else if (rc == 1)
            atomic_fetch_add_explicit(&g_stat_shed, 1, memory_order_relaxed);
    }
    buf->count = 0;
    atomic_fetch_add_explicit(&g_stat_rdbuf_flushes, 1, memory_order_relaxed);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static void
at_call(uint64_t callee_pc, uint64_t frame_base)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    memvis_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    maybe_emit_module_load(drcontext, ring);
    uint16_t tid = tls_thread_id(drcontext);
    uint16_t seq = tls_next_seq(drcontext);
    memvis_push_ex(ring, callee_pc, 0, frame_base, MEMVIS_EVENT_CALL, tid, seq);
    atomic_fetch_add_explicit(&g_stat_calls, 1, memory_order_relaxed);
    uint64_t ic = atomic_fetch_add_explicit(&g_insn_counter, 8, memory_order_relaxed);

    dr_mcontext_t mc;
    mc.size = sizeof(mc);
    mc.flags = DR_MC_INTEGER | DR_MC_CONTROL;
    if (dr_get_mcontext(drcontext, &mc)) {
        uint64_t regs[MEMVIS_REG_COUNT];
        regs[MEMVIS_REG_RAX]    = (uint64_t)mc.rax;
        regs[MEMVIS_REG_RBX]    = (uint64_t)mc.rbx;
        regs[MEMVIS_REG_RCX]    = (uint64_t)mc.rcx;
        regs[MEMVIS_REG_RDX]    = (uint64_t)mc.rdx;
        regs[MEMVIS_REG_RSI]    = (uint64_t)mc.rsi;
        regs[MEMVIS_REG_RDI]    = (uint64_t)mc.rdi;
        regs[MEMVIS_REG_RBP]    = (uint64_t)mc.rbp;
        regs[MEMVIS_REG_RSP]    = (uint64_t)mc.rsp;
        regs[MEMVIS_REG_R8]     = (uint64_t)mc.r8;
        regs[MEMVIS_REG_R9]     = (uint64_t)mc.r9;
        regs[MEMVIS_REG_R10]    = (uint64_t)mc.r10;
        regs[MEMVIS_REG_R11]    = (uint64_t)mc.r11;
        regs[MEMVIS_REG_R12]    = (uint64_t)mc.r12;
        regs[MEMVIS_REG_R13]    = (uint64_t)mc.r13;
        regs[MEMVIS_REG_R14]    = (uint64_t)mc.r14;
        regs[MEMVIS_REG_R15]    = (uint64_t)mc.r15;
        regs[MEMVIS_REG_RIP]    = (uint64_t)mc.pc;
        regs[MEMVIS_REG_RFLAGS] = (uint64_t)mc.xflags;
        uint16_t rseq = tls_next_seq(drcontext);
        memvis_push_reg_snapshot(ring, ic + 8, regs, tid, rseq);
        atomic_fetch_add_explicit(&g_stat_reg_snaps, 1, memory_order_relaxed);
    }

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

// dwarf-mapped register reload: MOV reg, [mem] where reg is callee-saved.
// event encodes: addr=source mem addr, value=loaded value, size=load width.
// kind_flags[15:8] = dest register index (MEMVIS_REG_*).
static void
at_reload(uint64_t src_addr, uint32_t size, uint32_t dest_reg_idx)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    memvis_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    uint16_t tid = tls_thread_id(drcontext);
    uint16_t seq = tls_next_seq(drcontext);
    uint64_t val = safe_read_value(src_addr, size);
    // pack dest_reg_idx into flags byte of kind_flags
    uint8_t kind = MEMVIS_EVENT_RELOAD;
    uint8_t flags = (uint8_t)(dest_reg_idx & 0xFF);
    uint64_t kf = (uint64_t)kind | ((uint64_t)flags << 8);
    memvis_push_ex(ring, src_addr, size, val, kf, tid, seq);
    atomic_fetch_add_explicit(&g_stat_reloads, 1, memory_order_relaxed);

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

// map DR register to MEMVIS_REG_* index. returns -1 if not a tracked register.
static int
dr_reg_to_memvis_idx(reg_id_t reg)
{
    reg = reg_to_pointer_sized(reg);
    switch (reg) {
    case DR_REG_RAX: return MEMVIS_REG_RAX;
    case DR_REG_RBX: return MEMVIS_REG_RBX;
    case DR_REG_RCX: return MEMVIS_REG_RCX;
    case DR_REG_RDX: return MEMVIS_REG_RDX;
    case DR_REG_RSI: return MEMVIS_REG_RSI;
    case DR_REG_RDI: return MEMVIS_REG_RDI;
    case DR_REG_RBP: return MEMVIS_REG_RBP;
    case DR_REG_RSP: return MEMVIS_REG_RSP;
    case DR_REG_R8:  return MEMVIS_REG_R8;
    case DR_REG_R9:  return MEMVIS_REG_R9;
    case DR_REG_R10: return MEMVIS_REG_R10;
    case DR_REG_R11: return MEMVIS_REG_R11;
    case DR_REG_R12: return MEMVIS_REG_R12;
    case DR_REG_R13: return MEMVIS_REG_R13;
    case DR_REG_R14: return MEMVIS_REG_R14;
    case DR_REG_R15: return MEMVIS_REG_R15;
    default: return -1;
    }
}

// callee-saved regs are the ones DWARF promotes variables into at -O3.
// only instrument reloads into these to stay within 5% overhead budget.
static bool
is_dwarf_reload_candidate(reg_id_t reg)
{
    reg = reg_to_pointer_sized(reg);
    return reg == DR_REG_RBX || reg == DR_REG_RBP ||
           reg == DR_REG_R12 || reg == DR_REG_R13 ||
           reg == DR_REG_R14 || reg == DR_REG_R15;
}

static void
at_return(uint64_t retaddr)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    memvis_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    uint16_t tid = tls_thread_id(drcontext);
    uint16_t seq = tls_next_seq(drcontext);
    memvis_push_ex(ring, retaddr, 0, 0, MEMVIS_EVENT_RETURN, tid, seq);
    atomic_fetch_add_explicit(&g_stat_returns, 1, memory_order_relaxed);

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating, void **user_data)
{
    (void)drcontext; (void)tag;
    (void)for_trace; (void)translating;
    bool has_reads = false;
    for (instr_t *i = instrlist_first_app(bb); i != NULL; i = instr_get_next_app(i)) {
        if (instr_reads_memory(i)) { has_reads = true; break; }
    }
    *user_data = (void *)(uintptr_t)has_reads;
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                bool for_trace, bool translating, void *user_data)
{
    (void)tag; (void)for_trace; (void)translating;

    if (instr_is_call_direct(instr)) {
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)flush_head_cache, false, 0);
        app_pc target = instr_get_branch_target_pc(instr);
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)at_call, false, 2,
                             OPND_CREATE_INT64((uint64_t)(ptr_uint_t)target),
                             opnd_create_reg(DR_REG_XSP));
    }

    if (instr_is_return(instr)) {
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)flush_head_cache, false, 0);
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)at_return, false, 1,
                             OPND_CREATE_INT64((uint64_t)(ptr_uint_t)
                                 instr_get_app_pc(instr)));
    }

    // inline write path
    if (instr_writes_memory(instr)) {
        instr_t *next = instr_get_next_app(instr);
        for (int i = 0; i < instr_num_dsts(instr); i++) {
            opnd_t dst = instr_get_dst(instr, i);
            if (!opnd_is_memory_reference(dst))
                continue;

            uint32_t sz = opnd_size_in_bytes(opnd_get_size(dst));
            app_pc write_pc = instr_get_app_pc(instr);
            instr_t *emit_pt = next ? next : instr;

            scratch_pair_t sp = acquire_scratch_pair(drcontext, bb, instr);

            bool ok = drutil_insert_get_mem_addr(
                drcontext, bb, instr, dst, sp.r1, sp.r2);

            if (ok) {
                if (sp.r2_from_drreg)
                    drreg_unreserve_register(drcontext, bb, emit_pt, sp.r2);
                else {
                    instrlist_meta_preinsert(bb, emit_pt,
                        XINST_CREATE_load(drcontext,
                            opnd_create_reg(sp.r2),
                            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                                RAW_TLS(MEMVIS_RAW_SLOT_GUARD))));
                }

                reg_id_t ring_scratch;
                bool ring_scratch_drreg = false;
                if (drreg_reserve_register(drcontext, bb, emit_pt,
                                           NULL, &ring_scratch) == DRREG_SUCCESS) {
                    ring_scratch_drreg = true;
                } else {
                    ring_scratch = (sp.r1 == DR_REG_RCX) ? DR_REG_RDX : DR_REG_RCX;
                    instrlist_meta_preinsert(bb, emit_pt,
                        XINST_CREATE_store(drcontext,
                            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                                RAW_TLS(MEMVIS_RAW_SLOT_GUARD)),
                            opnd_create_reg(ring_scratch)));
                }

                emit_inline_write_v3(drcontext, bb, emit_pt,
                                     sp.r1, ring_scratch, sz, write_pc);

                if (ring_scratch_drreg)
                    drreg_unreserve_register(drcontext, bb, emit_pt, ring_scratch);
                else {
                    instrlist_meta_preinsert(bb, emit_pt,
                        XINST_CREATE_load(drcontext,
                            opnd_create_reg(ring_scratch),
                            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                                RAW_TLS(MEMVIS_RAW_SLOT_GUARD))));
                }

                if (sp.r1_from_drreg)
                    drreg_unreserve_register(drcontext, bb, emit_pt, sp.r1);
                else {
                    instrlist_meta_preinsert(bb, emit_pt,
                        XINST_CREATE_load(drcontext,
                            opnd_create_reg(sp.r1),
                            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
                }
            } else {
                release_scratch_pair(drcontext, bb, instr, &sp);
            }
        }
    }

    if (instr_reads_memory(instr)) {
        // selective reload detection: MOV reg, [mem] into DWARF-promoted regs.
        // only fires for callee-saved destinations. <5% overhead uplift.
        bool reload_handled = false;
        if (instr_num_dsts(instr) == 1 && opnd_is_reg(instr_get_dst(instr, 0))) {
            reg_id_t dst_reg = opnd_get_reg(instr_get_dst(instr, 0));
            if (is_dwarf_reload_candidate(dst_reg)) {
                for (int i = 0; i < instr_num_srcs(instr); i++) {
                    opnd_t src = instr_get_src(instr, i);
                    if (!opnd_is_memory_reference(src)) continue;
                    reg_id_t reg1, reg2;
                    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg1) != DRREG_SUCCESS)
                        break;
                    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg2) != DRREG_SUCCESS) {
                        drreg_unreserve_register(drcontext, bb, instr, reg1);
                        break;
                    }
                    bool ok = drutil_insert_get_mem_addr(drcontext, bb, instr, src, reg1, reg2);
                    uint32_t rd_sz = opnd_size_in_bytes(opnd_get_size(src));
                    int midx = dr_reg_to_memvis_idx(dst_reg);
                    if (ok && midx >= 0) {
                        // emit RELOAD after the load executes
                        instr_t *next = instr_get_next_app(instr);
                        instr_t *pt = next ? next : instr;
                        dr_insert_clean_call(drcontext, bb, pt,
                                             (void *)at_reload, false, 3,
                                             opnd_create_reg(reg1),
                                             OPND_CREATE_INT32((int)rd_sz),
                                             OPND_CREATE_INT32(midx));
                        reload_handled = true;
                    }
                    drreg_unreserve_register(drcontext, bb, instr, reg2);
                    drreg_unreserve_register(drcontext, bb, instr, reg1);
                    break; // one source per reload
                }
            }
        }

        // standard read buffering (skip if already handled as reload)
        if (!reload_handled) {
            int rd_ops = 0;
            for (int i = 0; i < instr_num_srcs(instr); i++) {
                if (opnd_is_memory_reference(instr_get_src(instr, i))) rd_ops++;
            }
            if (rd_ops > 0) {
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)flush_read_buf_if_needed, false, 1,
                                     OPND_CREATE_INT32(rd_ops));
            }
            for (int i = 0; i < instr_num_srcs(instr); i++) {
                opnd_t src = instr_get_src(instr, i);
                if (!opnd_is_memory_reference(src))
                    continue;
                reg_id_t reg1, reg2;
                if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg1) != DRREG_SUCCESS)
                    continue;
                if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg2) != DRREG_SUCCESS) {
                    drreg_unreserve_register(drcontext, bb, instr, reg1);
                    continue;
                }
                bool ok = drutil_insert_get_mem_addr(drcontext, bb, instr, src, reg1, reg2);
                uint32_t rd_sz = opnd_size_in_bytes(opnd_get_size(src));
                if (ok) {
                    dr_insert_clean_call(drcontext, bb, instr,
                                         (void *)at_mem_read_buf, false, 2,
                                         opnd_create_reg(reg1),
                                         OPND_CREATE_INT32((int)rd_sz));
                }
                drreg_unreserve_register(drcontext, bb, instr, reg2);
                drreg_unreserve_register(drcontext, bb, instr, reg1);
            }
        }
    }

    bool bb_has_reads = (bool)(uintptr_t)user_data;
    if (bb_has_reads && instr_get_next_app(instr) == NULL) {
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)flush_read_buf, false, 0);
    }

    return DR_EMIT_DEFAULT;
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    (void)drcontext; (void)loaded;
    if (atomic_load_explicit(&g_module_base_phase, memory_order_relaxed) == 0 &&
        info->full_path[0] != '\0') {
        const char *name = dr_module_preferred_name(info);
        if (name && strstr(name, "vdso") == NULL &&
            strstr(name, "ld-linux") == NULL &&
            strstr(name, "libc") == NULL &&
            strstr(name, "libpthread") == NULL &&
            strstr(name, "libmemvis") == NULL &&
            strstr(name, "libdynamorio") == NULL &&
            strstr(name, "libdr") == NULL) {
            g_module_base = (uint64_t)(uintptr_t)info->start;
            atomic_store_explicit(&g_module_base_phase, 1, memory_order_release);
            dr_printf("memvis: main module '%s' base=0x%llx\n",
                      name, (unsigned long long)g_module_base);
        }
    }
}

static void
event_thread_init(void *drcontext)
{
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
    uint16_t tid = atomic_fetch_add_explicit(&g_next_thread_id, 1, memory_order_relaxed);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_THREAD_ID], (void *)(uintptr_t)tid);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_SEQ], (void *)(uintptr_t)0);

    char name[MEMVIS_RING_NAME_LEN];
    dr_snprintf(name, sizeof(name), "/memvis_ring_%u", (unsigned)tid);
    memvis_ring_header_t *ring = alloc_thread_ring(name);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RING], (void *)ring);

    read_buf_t *rdbuf = (read_buf_t *)dr_thread_alloc(drcontext, sizeof(read_buf_t));
    memset(rdbuf, 0, sizeof(read_buf_t));
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF], (void *)rdbuf);

    memvis_scratch_pad_t *pad = alloc_scratch_pad(drcontext, ring);
    dr_raw_tls_set_value(drcontext, g_raw_tls_seg,
        RAW_TLS(MEMVIS_RAW_SLOT_RING), (void *)ring);
    dr_raw_tls_set_value(drcontext, g_raw_tls_seg,
        RAW_TLS(MEMVIS_RAW_SLOT_HEAD), (void *)(uintptr_t)0);
    dr_raw_tls_set_value(drcontext, g_raw_tls_seg,
        RAW_TLS(MEMVIS_RAW_SLOT_SEQ), (void *)(uintptr_t)0);
    dr_raw_tls_set_value(drcontext, g_raw_tls_seg,
        RAW_TLS(MEMVIS_RAW_SLOT_TID), (void *)(uintptr_t)tid);
    dr_raw_tls_set_value(drcontext, g_raw_tls_seg,
        RAW_TLS(MEMVIS_RAW_SLOT_BP), (void *)(uintptr_t)0);
    dr_raw_tls_set_value(drcontext, g_raw_tls_seg,
        RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH), (void *)pad);
    dr_raw_tls_set_value(drcontext, g_raw_tls_seg,
        RAW_TLS(MEMVIS_RAW_SLOT_RDBUF), (void *)rdbuf);
    dr_raw_tls_set_value(drcontext, g_raw_tls_seg,
        RAW_TLS(MEMVIS_RAW_SLOT_GUARD), NULL);

    int ctl_idx = -1;
    if (ring && g_ctl)
        ctl_idx = memvis_ctl_register_thread(g_ctl, tid, name);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_CTL_IDX], (void *)(uintptr_t)(ctl_idx + 1));

    dr_printf("memvis: thread %u ring @ %p pad @ %p (%s)\n",
              (unsigned)tid, (void *)ring, (void *)pad, name);
}

static void
event_thread_exit(void *drcontext)
{
    flush_head_cache(drcontext);

    int ctl_idx = (int)(uintptr_t)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_CTL_IDX]) - 1;
    if (ctl_idx >= 0 && g_ctl)
        memvis_ctl_mark_dead(g_ctl, (uint32_t)ctl_idx);

    uint16_t tid = tls_thread_id(drcontext);
    memvis_ring_header_t *ring = tls_ring(drcontext);
    if (ring) {
        size_t sz = memvis_shm_size(ring->capacity);
        munmap(ring, sz);
        char name[MEMVIS_RING_NAME_LEN];
        dr_snprintf(name, sizeof(name), "/memvis_ring_%u", (unsigned)tid);
        shm_unlink(name);
    }
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RING], NULL);

    memvis_scratch_pad_t *pad = (memvis_scratch_pad_t *)dr_raw_tls_get_value(
        drcontext, g_raw_tls_seg, RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH));
    if (pad)
        dr_thread_free(drcontext, pad, sizeof(memvis_scratch_pad_t));

    read_buf_t *rdbuf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (rdbuf) {
        dr_thread_free(drcontext, rdbuf, sizeof(read_buf_t));
        drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF], NULL);
    }
}

static void
event_exit(void)
{
    dr_printf("memvis: --- producer stats ---\n");
    dr_printf("memvis:   writes:  %llu\n", (unsigned long long)atomic_load(&g_stat_writes));
    dr_printf("memvis:   reads:   %llu\n", (unsigned long long)atomic_load(&g_stat_reads));
    dr_printf("memvis:   calls:   %llu\n", (unsigned long long)atomic_load(&g_stat_calls));
    dr_printf("memvis:   returns: %llu\n", (unsigned long long)atomic_load(&g_stat_returns));
    dr_printf("memvis:   shed:    %llu\n", (unsigned long long)atomic_load(&g_stat_shed));
    dr_printf("memvis:   dropped: %llu\n", (unsigned long long)atomic_load(&g_stat_dropped));
    dr_printf("memvis:   regsnap: %llu\n", (unsigned long long)atomic_load(&g_stat_reg_snaps));
    dr_printf("memvis:   rdflush: %llu\n", (unsigned long long)atomic_load(&g_stat_rdbuf_flushes));
    dr_printf("memvis:   inline:  %llu\n", (unsigned long long)atomic_load(&g_stat_inline_writes));
    dr_printf("memvis:   spill:   %llu\n", (unsigned long long)atomic_load(&g_stat_spill_writes));
    dr_printf("memvis:   reloads: %llu\n", (unsigned long long)atomic_load(&g_stat_reloads));
    dr_printf("memvis:   threads: %u\n", (unsigned)atomic_load(&g_next_thread_id));

    unmap_ctl_ring();
    drmgr_unregister_bb_insertion_event(event_bb_insert);
    for (int i = 0; i < TLS_SLOT_COUNT; i++)
        drmgr_unregister_tls_field(g_tls_idx[i]);
    dr_raw_tls_cfree(g_raw_tls_off, MEMVIS_RAW_TLS_SLOTS);
    drreg_exit();
    drutil_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    (void)id; (void)argc; (void)argv;

    dr_set_client_name("memvis tracer", "https://github.com/memvis");

    drmgr_init();
    drutil_init();
    drreg_options_t drreg_ops = { sizeof(drreg_ops), 4, false };
    drreg_init(&drreg_ops);

    if (!dr_raw_tls_calloc(&g_raw_tls_seg, &g_raw_tls_off,
                            MEMVIS_RAW_TLS_SLOTS, 0))
        DR_ASSERT_MSG(false, "dr_raw_tls_calloc failed");

    for (int i = 0; i < TLS_SLOT_COUNT; i++) {
        g_tls_idx[i] = drmgr_register_tls_field();
        DR_ASSERT(g_tls_idx[i] != -1);
    }

    map_ctl_ring();

    drmgr_register_module_load_event(event_module_load);
    drmgr_register_exit_event(event_exit);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

    drmgr_register_bb_instrumentation_event(event_bb_analysis,
                                            event_bb_insert, NULL);

    dr_printf("memvis: Ghost v3 tracer attached, macro-trampoline inline writes\n");
    dr_printf("memvis: raw TLS seg=%d off=0x%x, ctl @ %p\n",
              (int)g_raw_tls_seg, g_raw_tls_off, (void *)g_ctl);
}
