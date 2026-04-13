// SPDX-License-Identifier: MIT
// Ghost v3 tracer. inline write events, clean call CALL/RET.

#include <stddef.h>

#include "memvis_bridge.h"

// static offset manifest — compile-time struct layout, not runtime.
// hard-contract: _Static_assert catches bridge/pad drift at build time.

#define OFF_PAD_SCRATCH0       ((int)offsetof(memvis_scratch_pad_t, scratch[0]))
#define OFF_PAD_SCRATCH1       ((int)offsetof(memvis_scratch_pad_t, scratch[1]))
#define OFF_PAD_RING_MASK      ((int)offsetof(memvis_scratch_pad_t, ring_mask))
#define OFF_PAD_RING_DATA      ((int)offsetof(memvis_scratch_pad_t, ring_data))
#define OFF_PAD_STAT_INLINE    ((int)offsetof(memvis_scratch_pad_t, stat_inline_writes))
#define OFF_PAD_STAT_SLOW      ((int)offsetof(memvis_scratch_pad_t, stat_write_slow))
#define OFF_PAD_STAT_READS     ((int)offsetof(memvis_scratch_pad_t, stat_reads))
#define OFF_PAD_STAT_RELOADS   ((int)offsetof(memvis_scratch_pad_t, stat_reloads))
#define OFF_PAD_STAT_CALLS     ((int)offsetof(memvis_scratch_pad_t, stat_calls))
#define OFF_PAD_STAT_RETURNS   ((int)offsetof(memvis_scratch_pad_t, stat_returns))
#define OFF_PAD_STAT_TAILCALLS ((int)offsetof(memvis_scratch_pad_t, stat_tail_calls))
#define OFF_PAD_STAT_DROPPED   ((int)offsetof(memvis_scratch_pad_t, stat_dropped))

_Static_assert(offsetof(memvis_scratch_pad_t, scratch[0]) ==  0, "pad.scratch[0] drift");
_Static_assert(offsetof(memvis_scratch_pad_t, ring_data)  == 16, "pad.ring_data drift");
_Static_assert(offsetof(memvis_scratch_pad_t, ring_mask)  == 24, "pad.ring_mask drift");
_Static_assert(offsetof(memvis_scratch_pad_t, stat_inline_writes) == 64, "pad.stat_inline drift");
_Static_assert(sizeof(memvis_scratch_pad_t) == 128, "pad size drift");

#define OFF_EV3_ADDR       ((int)offsetof(memvis_event_v3_t, addr))
#define OFF_EV3_SIZE       ((int)offsetof(memvis_event_v3_t, size))
#define OFF_EV3_THREAD_ID  ((int)offsetof(memvis_event_v3_t, thread_id))
#define OFF_EV3_SEQ_LO     ((int)offsetof(memvis_event_v3_t, seq_lo))
#define OFF_EV3_VALUE      ((int)offsetof(memvis_event_v3_t, value))
#define OFF_EV3_KIND_FLAGS ((int)offsetof(memvis_event_v3_t, kind_flags))
#define OFF_EV3_RIP_LO     ((int)offsetof(memvis_event_v3_t, rip_lo))

_Static_assert(offsetof(memvis_event_v3_t, addr)       ==  0, "ev3.addr drift");
_Static_assert(offsetof(memvis_event_v3_t, size)       ==  8, "ev3.size drift");
_Static_assert(offsetof(memvis_event_v3_t, thread_id)  == 12, "ev3.thread_id drift");
_Static_assert(offsetof(memvis_event_v3_t, seq_lo)     == 14, "ev3.seq_lo drift");
_Static_assert(offsetof(memvis_event_v3_t, value)      == 16, "ev3.value drift");
_Static_assert(offsetof(memvis_event_v3_t, kind_flags) == 24, "ev3.kind_flags drift");
_Static_assert(offsetof(memvis_event_v3_t, rip_lo)     == 28, "ev3.rip_lo drift");
_Static_assert(sizeof(memvis_event_v3_t)               == 32, "ev3 size drift");

#define OFF_RING_HEAD      ((int)offsetof(memvis_ring_header_t, head))
#define OFF_RING_TAIL      ((int)offsetof(memvis_ring_header_t, tail))

_Static_assert(offsetof(memvis_ring_header_t, head) == 1 * MEMVIS_CACHE_LINE, "ring.head drift");
_Static_assert(offsetof(memvis_ring_header_t, tail) == 2 * MEMVIS_CACHE_LINE, "ring.tail drift");

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

// clean-call raw TLS access via segment base + offset pointer arithmetic.
// dr_raw_tls_get/set_value don't exist in this SDK; use segment base directly.
static inline void *raw_tls_get(void *drcontext, uint off) {
    void **base = (void **)dr_get_dr_segment_base(g_raw_tls_seg);
    return *(void **)((char *)base + off);
}
static inline void raw_tls_set(void *drcontext, uint off, void *val) {
    void **base = (void **)dr_get_dr_segment_base(g_raw_tls_seg);
    *(void **)((char *)base + off) = val;
}
static inline memvis_scratch_pad_t *tls_pad(void *drcontext) {
    return (memvis_scratch_pad_t *)raw_tls_get(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH));
}

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

// cross-instruction state for the memval_simple pattern.
// pre-write reserves reg_addr (EA) at instr N; post-write unreserves at instr N+1.
typedef struct {
    reg_id_t reg_addr;  // drreg-reserved, holds EA across app instr
    uint32_t write_sz;  // write size for post-write value capture
    bool     has_reads; // from analysis pass
} instru_data_t;

// pre write: check ring/bp, compute slot, store event fields, save slot ptr.
// reg_addr holds the EA (from drutil). scratch is a second drreg reg.
// on skip (ring null / backpressure), stores 0 to pad.scratch[1].
// on success, stores event slot ptr to pad.scratch[1].
// restores EA into reg_addr so the app write executes with correct address.
static void
emit_pre_write(void *drcontext, instrlist_t *bb, instr_t *where,
               reg_id_t reg_addr, reg_id_t scratch,
               uint32_t sz, app_pc app_pc_val)
{
    uint32_t rip_offset = (uint32_t)((uint64_t)(ptr_uint_t)app_pc_val
                                     - g_module_base);

    instr_t *skip_label = INSTR_CREATE_label(drcontext);

    // save aflags — our inline code clobbers EFLAGS
    drreg_reserve_aflags(drcontext, bb, where);

    // save EA to pad.scratch[0]
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0),
            opnd_create_reg(reg_addr)));

    // ring null check
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_RING))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(reg_addr), opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jz, opnd_create_instr(skip_label)));

    // backpressure check
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_BP))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(reg_addr), opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(skip_label)));

    // slot = ring_data + (head & mask) * 32. scratch still holds pad ptr.
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_HEAD))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_and(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_RING_MASK)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_INT8(5)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_add(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_RING_DATA)));

    // reg_addr = event slot ptr. recover EA from pad.scratch[0].
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));

    // ev.addr
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(reg_addr, OFF_EV3_ADDR),
            opnd_create_reg(scratch)));

    // ev.size
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_EV3_SIZE, OPSZ_4),
            OPND_CREATE_INT32((int)sz)));

    // pack [thread_id:16 | seq_lo:16] into one OPSZ_4 store
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SEQ))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_shl(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT8(16)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_or(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_TID))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_EV3_THREAD_ID, OPSZ_4),
            opnd_create_reg(reg_64_to_32(scratch))));

    // kind_flags = WRITE | (seq_hi << 16)
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SEQ))));
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
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_EV3_KIND_FLAGS, OPSZ_4),
            opnd_create_reg(reg_64_to_32(scratch))));

    // ev.rip_lo
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            opnd_create_base_disp(reg_addr, DR_REG_NULL, 0,
                OFF_EV3_RIP_LO, OPSZ_4),
            OPND_CREATE_INT32((int)rip_offset)));

    // save event slot ptr to pad.scratch[1] for post-write phase
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1),
            opnd_create_reg(reg_addr)));

    // restore EA into reg_addr for the app write
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));

    instr_t *done_label = INSTR_CREATE_label(drcontext);
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jmp(drcontext, opnd_create_instr(done_label)));

    // skip path: zero pad.scratch[1] to signal post-write to skip, restore EA
    instrlist_meta_preinsert(bb, where, skip_label);
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_xor(drcontext,
            opnd_create_reg(reg_addr), opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1),
            opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));

    instrlist_meta_preinsert(bb, where, done_label);

    // restore aflags
    drreg_unreserve_aflags(drcontext, bb, where);
}

// safe_read_value_into_slot: clean call fallback for page-straddling writes.
// reads sz bytes from addr with fault tolerance, stores into slot->value.
static void
safe_read_into_slot(uint64_t addr, uint32_t size, memvis_event_v3_t *slot)
{
    uint64_t val = 0;
    if (size <= 8) {
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            memcpy(&val, (void *)(uintptr_t)addr, size);
        }, { /* fault: val stays 0 */ });
    }
    slot->value = val;
}

// post-write: page-boundary probe → value capture → bump seq+head → flush.
// reg_addr = EA (drreg-held from pre-write). sz = JIT-time write size.
// pad.scratch[1] = event slot ptr (0 = pre-write skipped).
//
// key insight: slot_ptr lives in pad.scratch[1] throughout. we never move it
// to a register permanently — just reload from pad when needed. this means
// scratch is free for the page probe, and reg_addr stays as EA until the
// size-matched load clobbers it.
static void
emit_post_write(void *drcontext, instrlist_t *bb, instr_t *where,
                reg_id_t reg_addr, uint32_t sz)
{
    reg_id_t scratch;
    if (drreg_reserve_register(drcontext, bb, where, NULL, &scratch) != DRREG_SUCCESS) {
        DR_ASSERT(false);
        return;
    }

    instr_t *skip_label     = INSTR_CREATE_label(drcontext);
    instr_t *slow_label     = INSTR_CREATE_label(drcontext);
    instr_t *val_done       = INSTR_CREATE_label(drcontext);
    instr_t *no_flush_label = INSTR_CREATE_label(drcontext);

    drreg_reserve_aflags(drcontext, bb, where);

    // --- check if pre-write was skipped (pad.scratch[1] == 0) ---
    // load pad ptr, then check scratch[1]. don't clobber reg_addr (EA).
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_cmp(drcontext,
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1),
            OPND_CREATE_INT32(0)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jz, opnd_create_instr(skip_label)));

    // --- reload EA from pad.scratch[0] into reg_addr ---
    // reg_addr may be stale: app write can modify its base reg (e.g. PUSH/POP).
    // pre-write saved the computed EA to pad.scratch[0]. scratch still = pad ptr.
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(reg_addr),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH0)));

    // --- Page-Boundary Probe: scratch = (EA & 0xFFF) + sz ---
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_move(drcontext,
            opnd_create_reg(scratch), opnd_create_reg(reg_addr)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_and(drcontext,
            opnd_create_reg(scratch), OPND_CREATE_INT32(0xFFF)));
    if (sz > 0) {
        instrlist_meta_preinsert(bb, where,
            XINST_CREATE_add(drcontext,
                opnd_create_reg(scratch), OPND_CREATE_INT32((int)sz)));
    }
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_cmp(drcontext,
            opnd_create_reg(scratch), OPND_CREATE_INT32(0x1000)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_ja, opnd_create_instr(slow_label)));

    // --- All value reads go through safe clean call ---
    // The page-boundary probe above filters out the common case (no straddle)
    // but we route all reads through the fault-tolerant clean call for safety.
    // This avoids inline MOV corruption that causes exit-time segfaults.
    // The probe still gates: only non-straddling writes reach here; straddling
    // writes also use the same clean call path.
    // (fall through to slow_label for unified clean call path)

    instrlist_meta_preinsert(bb, where, slow_label);

    // reload slot_ptr from pad.scratch[1] for clean call arg
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(scratch),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_ld(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_MEMPTR(scratch, OFF_PAD_SCRATCH1)));

    dr_insert_clean_call(drcontext, bb, where,
        (void *)safe_read_into_slot, false, 3,
        opnd_create_reg(reg_addr),
        OPND_CREATE_INT32((int)sz),
        opnd_create_reg(scratch));

    // ambient telemetry: pad->stat_inline_writes++
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_add(drcontext,
            OPND_CREATE_MEMPTR(reg_addr, OFF_PAD_STAT_INLINE),
            OPND_CREATE_INT32(1)));

    instrlist_meta_preinsert(bb, where, val_done);

    // --- seq++ ---
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

    // --- head++ ---
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

    // --- conditional head flush (1/64 events) ---
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_test(drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT32(MEMVIS_HEAD_FLUSH_MASK)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_jcc(drcontext, OP_jnz, opnd_create_instr(no_flush_label)));

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
            opnd_create_reg(reg_addr),
            dr_raw_tls_opnd(drcontext, g_raw_tls_seg,
                RAW_TLS(MEMVIS_RAW_SLOT_RING))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_mov_st(drcontext,
            OPND_CREATE_MEMPTR(reg_addr, OFF_RING_HEAD),
            opnd_create_reg(scratch)));

    instrlist_meta_preinsert(bb, where, no_flush_label);
    instrlist_meta_preinsert(bb, where, skip_label);
    drreg_unreserve_aflags(drcontext, bb, where);

    if (drreg_unreserve_register(drcontext, bb, where, scratch) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

static void
flush_head_cache(void *drcontext)
{
    memvis_ring_header_t *ring = (memvis_ring_header_t *)raw_tls_get(
        drcontext, RAW_TLS(MEMVIS_RAW_SLOT_RING));
    if (!ring) return;
    uint64_t cached_head = (uint64_t)(uintptr_t)raw_tls_get(
        drcontext, RAW_TLS(MEMVIS_RAW_SLOT_HEAD));
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
    memvis_scratch_pad_t *pad = tls_pad(drcontext);
    uint32_t n = buf->count;
    for (uint32_t i = 0; i < n; i++) {
        uint16_t seq = tls_next_seq(drcontext);
        int rc = memvis_push_sampled(ring, buf->entries[i].addr,
                                      buf->entries[i].size, 0,
                                      MEMVIS_EVENT_READ, tid, seq);
        if (rc == 0 && pad)
            pad->stat_reads++;
        else if (rc == 1 && pad)
            pad->stat_dropped++;
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
    memvis_scratch_pad_t *pad = tls_pad(drcontext);
    if (pad) pad->stat_calls++;
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
    { memvis_scratch_pad_t *pad = tls_pad(drcontext); if (pad) pad->stat_reloads++; }

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
    { memvis_scratch_pad_t *pad = tls_pad(drcontext); if (pad) pad->stat_returns++; }

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

// tail call: direct JMP whose target is a known function entry in our module.
// emits MEMVIS_EVENT_TAIL_CALL so the Shadow Register File stays coherent.
static void
at_tail_call(uint64_t target_pc, uint64_t frame_base)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    memvis_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    uint16_t tid = tls_thread_id(drcontext);
    uint16_t seq = tls_next_seq(drcontext);
    memvis_push_ex(ring, target_pc, 0, frame_base, MEMVIS_EVENT_TAIL_CALL, tid, seq);
    { memvis_scratch_pad_t *pad = tls_pad(drcontext); if (pad) pad->stat_tail_calls++; }

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating, void **user_data)
{
    (void)tag; (void)for_trace; (void)translating;
    instru_data_t *data = (instru_data_t *)dr_thread_alloc(drcontext, sizeof(*data));
    data->reg_addr = DR_REG_NULL;
    data->write_sz = 0;
    data->has_reads = false;
    for (instr_t *i = instrlist_first_app(bb); i != NULL; i = instr_get_next_app(i)) {
        if (instr_reads_memory(i)) { data->has_reads = true; break; }
    }
    *user_data = (void *)data;
    return DR_EMIT_DEFAULT;
}

// handle deferred post-write from previous app instruction
static void
handle_pending_post_write(void *drcontext, instrlist_t *bb, instr_t *where,
                          instru_data_t *data)
{
    if (data->reg_addr == DR_REG_NULL)
        return;
    emit_post_write(drcontext, bb, where, data->reg_addr, data->write_sz);
    if (drreg_unreserve_register(drcontext, bb, where, data->reg_addr) != DRREG_SUCCESS)
        DR_ASSERT(false);
    data->reg_addr = DR_REG_NULL;
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                bool for_trace, bool translating, void *user_data)
{
    (void)tag; (void)for_trace; (void)translating;
    instru_data_t *data = (instru_data_t *)user_data;

    // complete any pending post-write from previous app instruction
    handle_pending_post_write(drcontext, bb, instr, data);

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

    // tail-call detection: direct JMP (not call, not ret) at end of BB
    // whose target is far enough to be a different function (>4KB away).
    // intra-function branches (if/else, loops) are typically <4KB.
    // -O3 tail calls jump to a different function entry, usually far away.
    if (instr_is_ubr(instr) && !instr_is_call(instr) &&
        drmgr_is_last_instr(drcontext, instr) && g_module_base != 0) {
        app_pc target = instr_get_branch_target_pc(instr);
        app_pc here   = instr_get_app_pc(instr);
        if (target != NULL && (ptr_uint_t)target >= g_module_base) {
            ptr_uint_t dist = (ptr_uint_t)target > (ptr_uint_t)here
                ? (ptr_uint_t)target - (ptr_uint_t)here
                : (ptr_uint_t)here - (ptr_uint_t)target;
            if (dist > 4096) {
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)flush_head_cache, false, 0);
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)at_tail_call, false, 2,
                                     OPND_CREATE_INT64((uint64_t)(ptr_uint_t)target),
                                     opnd_create_reg(DR_REG_XSP));
            }
        }
    }

    // inline write path: pre-write at current instr, post-write deferred to next
    if (instr_writes_memory(instr)) {
        bool seen_memref = false;
        for (int i = 0; i < instr_num_dsts(instr); i++) {
            opnd_t dst = instr_get_dst(instr, i);
            if (!opnd_is_memory_reference(dst))
                continue;
            if (seen_memref)
                break;
            seen_memref = true;

            uint32_t sz = opnd_size_in_bytes(opnd_get_size(dst));
            app_pc write_pc = instr_get_app_pc(instr);

            reg_id_t reg_addr, reg_scratch;
            if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_addr) !=
                    DRREG_SUCCESS)
                break;
            if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_scratch) !=
                    DRREG_SUCCESS) {
                drreg_unreserve_register(drcontext, bb, instr, reg_addr);
                break;
            }

            if (opnd_uses_reg(dst, reg_addr))
                drreg_get_app_value(drcontext, bb, instr, reg_addr, reg_addr);
            if (opnd_uses_reg(dst, reg_scratch))
                drreg_get_app_value(drcontext, bb, instr, reg_scratch, reg_scratch);

            bool ok = drutil_insert_get_mem_addr(
                drcontext, bb, instr, dst, reg_addr, reg_scratch);

            drreg_unreserve_register(drcontext, bb, instr, reg_scratch);

            if (ok) {
                reg_id_t pre_scratch;
                if (drreg_reserve_register(drcontext, bb, instr, NULL, &pre_scratch) !=
                        DRREG_SUCCESS) {
                    drreg_unreserve_register(drcontext, bb, instr, reg_addr);
                    break;
                }

                emit_pre_write(drcontext, bb, instr,
                               reg_addr, pre_scratch, sz, write_pc);

                drreg_unreserve_register(drcontext, bb, instr, pre_scratch);

                data->reg_addr = reg_addr;
                data->write_sz = sz;
            } else {
                drreg_unreserve_register(drcontext, bb, instr, reg_addr);
            }
        }
    }

    // free user_data at end of bb
    if (drmgr_is_last_instr(drcontext, instr)) {
        handle_pending_post_write(drcontext, bb, instr, data);
        dr_thread_free(drcontext, data, sizeof(instru_data_t));
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
                    // unreserve reg2 immediately — only needed for EA computation
                    drreg_unreserve_register(drcontext, bb, instr, reg2);
                    if (ok && midx >= 0) {
                        // emit RELOAD at current instr (same drreg window as reg1).
                        // at_reload reads the value via safe_read_value(EA, sz),
                        // so inserting before the app load is fine — the EA is
                        // valid and the memory content is about to be loaded.
                        dr_insert_clean_call(drcontext, bb, instr,
                                             (void *)at_reload, false, 3,
                                             opnd_create_reg(reg1),
                                             OPND_CREATE_INT32((int)rd_sz),
                                             OPND_CREATE_INT32(midx));
                        reload_handled = true;
                    }
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

    if (data->has_reads && instr_get_next_app(instr) == NULL) {
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
    raw_tls_set(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_RING), (void *)ring);
    raw_tls_set(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_HEAD), (void *)(uintptr_t)0);
    raw_tls_set(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_SEQ), (void *)(uintptr_t)0);
    raw_tls_set(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_TID), (void *)(uintptr_t)tid);
    raw_tls_set(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_BP), (void *)(uintptr_t)0);
    raw_tls_set(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH), (void *)pad);
    raw_tls_set(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_RDBUF), (void *)rdbuf);
    raw_tls_set(drcontext, RAW_TLS(MEMVIS_RAW_SLOT_GUARD), NULL);

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

    // drain per-thread ambient stats into globals before freeing pad
    memvis_scratch_pad_t *pad = (memvis_scratch_pad_t *)raw_tls_get(
        drcontext, RAW_TLS(MEMVIS_RAW_SLOT_SCRATCH));
    if (pad) {
        atomic_fetch_add_explicit(&g_stat_inline_writes, pad->stat_inline_writes, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_spill_writes,  pad->stat_write_slow,    memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_reads,         pad->stat_reads,          memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_reloads,       pad->stat_reloads,        memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_calls,         pad->stat_calls,          memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_returns,       pad->stat_returns,        memory_order_relaxed);
        atomic_fetch_add_explicit(&g_stat_dropped,       pad->stat_dropped,        memory_order_relaxed);
        dr_thread_free(drcontext, pad, sizeof(memvis_scratch_pad_t));
    }

    read_buf_t *rdbuf = (read_buf_t *)drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF]);
    if (rdbuf) {
        dr_thread_free(drcontext, rdbuf, sizeof(read_buf_t));
        drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_RDBUF], NULL);
    }
}

static void
event_exit(void)
{
    dr_printf("memvis: --- producer stats (ambient per-thread) ---\n");
    dr_printf("memvis:   wr_fast: %llu\n", (unsigned long long)atomic_load(&g_stat_inline_writes));
    dr_printf("memvis:   wr_slow: %llu\n", (unsigned long long)atomic_load(&g_stat_spill_writes));
    dr_printf("memvis:   reads:   %llu\n", (unsigned long long)atomic_load(&g_stat_reads));
    dr_printf("memvis:   calls:   %llu\n", (unsigned long long)atomic_load(&g_stat_calls));
    dr_printf("memvis:   returns: %llu\n", (unsigned long long)atomic_load(&g_stat_returns));
    dr_printf("memvis:   reloads: %llu\n", (unsigned long long)atomic_load(&g_stat_reloads));
    dr_printf("memvis:   dropped: %llu\n", (unsigned long long)atomic_load(&g_stat_dropped));
    dr_printf("memvis:   regsnap: %llu\n", (unsigned long long)atomic_load(&g_stat_reg_snaps));
    dr_printf("memvis:   rdflush: %llu\n", (unsigned long long)atomic_load(&g_stat_rdbuf_flushes));
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

    dr_set_client_name("memvis tracer", "https://github.com/abokhalill/memvis");

    drmgr_init();
    drutil_init();
    drreg_options_t drreg_ops = { sizeof(drreg_ops), 8, false };
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
