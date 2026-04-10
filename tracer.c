// SPDX-License-Identifier: MIT
// tracer.c: dynamorio client. spsc producer.
// instruments W/R/CALL/RET and incorporates adaptive backpressure.

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

static memvis_ring_header_t *g_ring   = NULL;
static int                   g_shm_fd = -1;
static size_t                g_shm_sz = 0;

static volatile int g_overflow_emitted = 0;

static volatile uint64_t g_insn_counter  = 0;

static volatile uint64_t g_stat_writes       = 0;
static volatile uint64_t g_stat_reads        = 0;
static volatile uint64_t g_stat_calls        = 0;
static volatile uint64_t g_stat_returns      = 0;
static volatile uint64_t g_stat_shed         = 0;
static volatile uint64_t g_stat_dropped      = 0;
static volatile uint64_t g_stat_reg_snaps    = 0;

static void
map_shared_memory(void)
{
    uint32_t capacity = MEMVIS_DEFAULT_CAPACITY;
    g_shm_sz = memvis_shm_size(capacity);

    g_shm_fd = shm_open(MEMVIS_SHM_NAME, O_CREAT | O_RDWR, 0600);
    DR_ASSERT(g_shm_fd >= 0);

    if (ftruncate(g_shm_fd, (off_t)g_shm_sz) != 0)
        DR_ASSERT(false);

    g_ring = (memvis_ring_header_t *)mmap(
        NULL, g_shm_sz,
        PROT_READ | PROT_WRITE,
        MAP_SHARED, g_shm_fd, 0);
    DR_ASSERT(g_ring != MAP_FAILED);

    if (g_ring->magic != MEMVIS_MAGIC)
        memvis_ring_init(g_ring, capacity, MEMVIS_FLAG_DROP_ON_FULL);
}

static void
unmap_shared_memory(void)
{
    if (g_ring && g_ring != MAP_FAILED) {
        munmap(g_ring, g_shm_sz);
        g_ring = NULL;
    }
    if (g_shm_fd >= 0) {
        close(g_shm_fd);
        g_shm_fd = -1;
    }
    shm_unlink(MEMVIS_SHM_NAME);
}

static void
at_mem_write(uint64_t addr, uint64_t size)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, 0);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, 0, (void *)(uintptr_t)1);

    int rc = memvis_push_sampled(g_ring, addr, size, 0, MEMVIS_EVENT_WRITE);
    if (rc == 0) {
        g_stat_writes++;
        g_overflow_emitted = 0;
    } else if (rc < 0) {
        g_stat_dropped++;
        if (!g_overflow_emitted) {
            g_overflow_emitted = 1;
            memvis_push_overflow(g_ring, g_stat_writes + g_stat_reads);
        }
    }

    drmgr_set_tls_field(drcontext, 0, NULL);
}

static void
at_mem_read(uint64_t addr, uint64_t size)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, 0);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, 0, (void *)(uintptr_t)1);

    int rc = memvis_push_sampled(g_ring, addr, size, 0, MEMVIS_EVENT_READ);
    if (rc == 0)
        g_stat_reads++;
    else if (rc == 1)
        g_stat_shed++;

    drmgr_set_tls_field(drcontext, 0, NULL);
}

static void
at_call(uint64_t callee_pc, uint64_t frame_base)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, 0);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, 0, (void *)(uintptr_t)1);

    memvis_push_ex(g_ring, callee_pc, 0, frame_base, MEMVIS_EVENT_CALL);
    g_stat_calls++;
    g_insn_counter += 8;

    // reg snapshot on every call
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
        memvis_push_reg_snapshot(g_ring, g_insn_counter, regs);
        g_stat_reg_snaps++;
    }

    drmgr_set_tls_field(drcontext, 0, NULL);
}

static void
at_return(uint64_t retaddr)
{
    void *drcontext = dr_get_current_drcontext();
    void *guard = drmgr_get_tls_field(drcontext, 0);
    if (guard != NULL) return;
    drmgr_set_tls_field(drcontext, 0, (void *)(uintptr_t)1);

    memvis_push_ex(g_ring, retaddr, 0, 0, MEMVIS_EVENT_RETURN);
    g_stat_returns++;

    drmgr_set_tls_field(drcontext, 0, NULL);
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

            uint32_t sz = opnd_size_in_bytes(opnd_get_size(dst));
            dr_insert_clean_call(drcontext, bb, instr,
                                 (void *)at_mem_write, false, 2,
                                 OPND_CREATE_MEMPTR(opnd_get_base(dst),
                                                    opnd_get_disp(dst)),
                                 OPND_CREATE_INT32((int)sz));
        }
    }

    if (instr_reads_memory(instr)) {
        for (int i = 0; i < instr_num_srcs(instr); i++) {
            opnd_t src = instr_get_src(instr, i);
            if (!opnd_is_memory_reference(src))
                continue;

            uint32_t sz = opnd_size_in_bytes(opnd_get_size(src));
            dr_insert_clean_call(drcontext, bb, instr,
                                 (void *)at_mem_read, false, 2,
                                 OPND_CREATE_MEMPTR(opnd_get_base(src),
                                                    opnd_get_disp(src)),
                                 OPND_CREATE_INT32((int)sz));
        }
    }

    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    drmgr_set_tls_field(drcontext, 0, NULL);
}

static void
event_thread_exit(void *drcontext)
{
    (void)drcontext;
}

static void
event_exit(void)
{
    dr_printf("memvis: --- producer stats ---\n");
    dr_printf("memvis:   writes:  %llu\n", (unsigned long long)g_stat_writes);
    dr_printf("memvis:   reads:   %llu\n", (unsigned long long)g_stat_reads);
    dr_printf("memvis:   calls:   %llu\n", (unsigned long long)g_stat_calls);
    dr_printf("memvis:   returns: %llu\n", (unsigned long long)g_stat_returns);
    dr_printf("memvis:   shed:    %llu\n", (unsigned long long)g_stat_shed);
    dr_printf("memvis:   dropped: %llu\n", (unsigned long long)g_stat_dropped);
    dr_printf("memvis:   regsnap: %llu\n", (unsigned long long)g_stat_reg_snaps);

    unmap_shared_memory();
    drmgr_unregister_bb_insertion_event(event_bb_insert);
    drmgr_unregister_tls_field(0);
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

    int tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);

    map_shared_memory();

    dr_register_exit_event(event_exit);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

    drmgr_register_bb_instrumentation_event(event_bb_analysis,
                                            event_bb_insert, NULL);

    dr_printf("memvis: tracer attached (phase 3), ring @ %p, cap %u\n",
              (void *)g_ring, g_ring->capacity);
    dr_printf("memvis: instrumentation: W+R+CALL+RET, adaptive sampling\n");
}
