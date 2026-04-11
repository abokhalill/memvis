// SPDX-License-Identifier: MIT
// dynamorio client. per-thread spsc producer.

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"

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

static _Atomic uint16_t g_next_thread_id    = 0;

// main executable runtime base, captured at module load
static uint64_t g_module_base = 0;
static bool     g_module_base_set = false;
static _Atomic int g_module_load_emitted = 0;

#define TLS_SLOT_GUARD     0
#define TLS_SLOT_THREAD_ID 1
#define TLS_SLOT_SEQ       2
#define TLS_SLOT_RING      3
#define TLS_SLOT_CTL_IDX   4
#define TLS_SLOT_COUNT     5

// actual drmgr TLS field indices, filled at init
static int g_tls_idx[TLS_SLOT_COUNT];

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
    if (!g_module_base_set) return;
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&g_module_load_emitted, &expected, 1,
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
    if (rc == 0) {
        atomic_fetch_add_explicit(&g_stat_writes, 1, memory_order_relaxed);
    } else if (rc < 0) {
        atomic_fetch_add_explicit(&g_stat_dropped, 1, memory_order_relaxed);
        memvis_push_overflow(ring,
            atomic_load_explicit(&g_stat_writes, memory_order_relaxed),
            tid, seq);
    }

    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL);
}

static void
at_mem_read(uint64_t addr, uint32_t size)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD]);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], (void *)(uintptr_t)1);

    memvis_ring_header_t *ring = tls_ring(drcontext);
    if (!ring) { drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_GUARD], NULL); return; }
    uint16_t tid = tls_thread_id(drcontext);
    uint16_t seq = tls_next_seq(drcontext);
    int rc = memvis_push_sampled(ring, addr, size, 0,
                                  MEMVIS_EVENT_READ, tid, seq);
    if (rc == 0)
        atomic_fetch_add_explicit(&g_stat_reads, 1, memory_order_relaxed);
    else if (rc == 1)
        atomic_fetch_add_explicit(&g_stat_shed, 1, memory_order_relaxed);

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
    (void)drcontext; (void)tag; (void)bb;
    (void)for_trace; (void)translating; (void)user_data;
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                bool for_trace, bool translating, void *user_data)
{
    (void)tag; (void)for_trace; (void)translating; (void)user_data;

    if (instr_is_call_direct(instr)) {
        app_pc target = instr_get_branch_target_pc(instr);
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)at_call, false, 2,
                             OPND_CREATE_INT64((uint64_t)(ptr_uint_t)target),
                             opnd_create_reg(DR_REG_XSP));
    }

    if (instr_is_return(instr)) {
        dr_insert_clean_call(drcontext, bb, instr,
                             (void *)at_return, false, 1,
                             OPND_CREATE_INT64((uint64_t)(ptr_uint_t)
                                 instr_get_app_pc(instr)));
    }

    if (instr_writes_memory(instr)) {
        for (int i = 0; i < instr_num_dsts(instr); i++) {
            opnd_t dst = instr_get_dst(instr, i);
            if (!opnd_is_memory_reference(dst))
                continue;
            reg_id_t reg1, reg2;
            if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg1) != DRREG_SUCCESS)
                continue;
            if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg2) != DRREG_SUCCESS) {
                drreg_unreserve_register(drcontext, bb, instr, reg1);
                continue;
            }
            bool ok = drutil_insert_get_mem_addr(drcontext, bb, instr, dst, reg1, reg2);
            uint32_t sz = opnd_size_in_bytes(opnd_get_size(dst));
            if (ok) {
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)at_mem_write, false, 2,
                                     opnd_create_reg(reg1),
                                     OPND_CREATE_INT32((int)sz));
            }
            drreg_unreserve_register(drcontext, bb, instr, reg2);
            drreg_unreserve_register(drcontext, bb, instr, reg1);
        }
    }

    if (instr_reads_memory(instr)) {
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
            uint32_t sz = opnd_size_in_bytes(opnd_get_size(src));
            if (ok) {
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)at_mem_read, false, 2,
                                     opnd_create_reg(reg1),
                                     OPND_CREATE_INT32((int)sz));
            }
            drreg_unreserve_register(drcontext, bb, instr, reg2);
            drreg_unreserve_register(drcontext, bb, instr, reg1);
        }
    }

    return DR_EMIT_DEFAULT;
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    (void)drcontext; (void)loaded;
    // capture the main executable's runtime load base (first non-vdso module)
    if (!g_module_base_set && info->full_path[0] != '\0') {
        const char *name = dr_module_preferred_name(info);
        // skip system modules: vdso, ld-linux, libc, libpthread, DR itself
        if (name && strstr(name, "vdso") == NULL &&
            strstr(name, "ld-linux") == NULL &&
            strstr(name, "libc") == NULL &&
            strstr(name, "libpthread") == NULL &&
            strstr(name, "libmemvis") == NULL &&
            strstr(name, "libdynamorio") == NULL &&
            strstr(name, "libdr") == NULL) {
            g_module_base = (uint64_t)(uintptr_t)info->start;
            g_module_base_set = true;
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

    int ctl_idx = -1;
    if (ring && g_ctl)
        ctl_idx = memvis_ctl_register_thread(g_ctl, tid, name);
    drmgr_set_tls_field(drcontext, g_tls_idx[TLS_SLOT_CTL_IDX], (void *)(uintptr_t)(ctl_idx + 1));

    dr_printf("memvis: thread %u ring @ %p (%s)\n", (unsigned)tid, (void *)ring, name);
}

static void
event_thread_exit(void *drcontext)
{
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
    dr_printf("memvis:   threads: %u\n", (unsigned)atomic_load(&g_next_thread_id));

    unmap_ctl_ring();
    drmgr_unregister_bb_insertion_event(event_bb_insert);
    for (int i = 0; i < TLS_SLOT_COUNT; i++)
        drmgr_unregister_tls_field(g_tls_idx[i]);
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
    drreg_options_t drreg_ops = { sizeof(drreg_ops), 3, false };
    drreg_init(&drreg_ops);

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

    dr_printf("memvis: tracer attached (phase 4), per-thread rings, ctl @ %p\n",
              (void *)g_ctl);
    dr_printf("memvis: instrumentation: W+R+CALL+RET, adaptive sampling\n");
}
