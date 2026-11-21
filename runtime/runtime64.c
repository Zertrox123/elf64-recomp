#include "runtime64.h"

#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define RT_DYN_THUNK_BASE  0x7078000000ULL
#define RT_RETURN_SENTINEL 0xDEADBEEFCAFEBABEULL
#define RT_STACK_CANARY    0x00A1B2C3D4E5F600ULL /* low byte 0 like glibc canary */

_Thread_local CPU64 *g_tls_cpu = NULL;
int    g_rt_argc = 0;
char **g_rt_argv = NULL;
char **g_rt_envp = NULL;

typedef enum {
    SLOT_EMPTY = 0,
    SLOT_LIFTED = 1,
    SLOT_SHIM = 2,
    SLOT_UNRESOLVED = 3,
} SlotKind;

typedef struct {
    uint64_t    addr;
    SlotKind    kind;
    RTLiftedFn  lifted;
    RTShimFn    shim;
    void       *userdata;
    const char *name;
} DispatchSlot;

typedef struct {
    const char *name;
    RTShimFn    fn;
    void       *userdata;
} ShimEntry;

static DispatchSlot   *g_disp_table = NULL;
static size_t          g_disp_mask = 0;

static ShimEntry      *g_shims = NULL;
static size_t          g_shim_count = 0;
static size_t          g_shim_cap = 0;

static pthread_mutex_t g_rt_mu = PTHREAD_MUTEX_INITIALIZER;
static uint64_t        g_next_dyn_thunk = RT_DYN_THUNK_BASE;

static inline uint64_t hash_addr(uint64_t x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static void disp_init(size_t min_entries) {
    size_t cap = 1024;
    while (cap < min_entries * 2) cap <<= 1;
    g_disp_table = (DispatchSlot *)calloc(cap, sizeof(DispatchSlot));
    if (!g_disp_table) {
        fprintf(stderr, "elf64-recomp: OOM allocating dispatch table (%zu)\n", cap);
        abort();
    }
    g_disp_mask = cap - 1;
}

static void disp_insert(uint64_t addr, SlotKind kind, RTLiftedFn lifted,
                        RTShimFn shim, void *userdata, const char *name) {
    size_t idx = (size_t)(hash_addr(addr) & g_disp_mask);
    for (size_t probe = 0; probe <= g_disp_mask; probe++) {
        DispatchSlot *s = &g_disp_table[(idx + probe) & g_disp_mask];
        if (s->kind == SLOT_EMPTY || s->addr == addr) {
            s->addr = addr;
            s->lifted = lifted;
            s->shim = shim;
            s->userdata = userdata;
            s->name = name;
            /* Release store so concurrent readers see fully initialized slot. */
            __atomic_store_n(&s->kind, kind, __ATOMIC_RELEASE);
            return;
        }
    }
    fprintf(stderr, "elf64-recomp: dispatch table full!\n");
    abort();
}

static inline const DispatchSlot *disp_lookup(uint64_t addr) {
    size_t idx = (size_t)(hash_addr(addr) & g_disp_mask);
    for (size_t probe = 0; probe <= g_disp_mask; probe++) {
        const DispatchSlot *s = &g_disp_table[(idx + probe) & g_disp_mask];
        SlotKind k = __atomic_load_n(&s->kind, __ATOMIC_ACQUIRE);
        if (k == SLOT_EMPTY) return NULL;
        if (s->addr == addr) return s;
    }
    return NULL;
}

void rt_register_shim(const char *name, RTShimFn fn, void *userdata) {
    pthread_mutex_lock(&g_rt_mu);
    for (size_t i = 0; i < g_shim_count; i++) {
        if (strcmp(g_shims[i].name, name) == 0) {
            g_shims[i].fn = fn;
            g_shims[i].userdata = userdata;
            pthread_mutex_unlock(&g_rt_mu);
            return;
        }
    }
    if (g_shim_count == g_shim_cap) {
        size_t ncap = g_shim_cap ? g_shim_cap * 2 : 256;
        ShimEntry *ns = (ShimEntry *)realloc(g_shims, ncap * sizeof(ShimEntry));
        if (!ns) abort();
        g_shims = ns;
        g_shim_cap = ncap;
    }
    g_shims[g_shim_count].name = name;
    g_shims[g_shim_count].fn = fn;
    g_shims[g_shim_count].userdata = userdata;
    g_shim_count++;
    pthread_mutex_unlock(&g_rt_mu);
}

RTShimFn rt_find_shim(const char *name, void **out_userdata) {
    /* Strip optional glibc version suffix (e.g., sym@GLIBC_2.2.5) on ELF only;
     * MSVC C++ mangled Win64 symbols legitimately contain '@'. */
    const char *at = g_rt_is_win64 ? NULL : strchr(name, '@');
    size_t nlen = at ? (size_t)(at - name) : strlen(name);
    for (size_t i = 0; i < g_shim_count; i++) {
        if (strlen(g_shims[i].name) == nlen && memcmp(g_shims[i].name, name, nlen) == 0) {
            if (out_userdata) *out_userdata = g_shims[i].userdata;
            return g_shims[i].fn;
        }
    }
    return NULL;
}

uint64_t rt_alloc_dynamic_thunk(const char *name, RTShimFn fn, void *userdata) {
    pthread_mutex_lock(&g_rt_mu);
    uint64_t addr = g_next_dyn_thunk;
    g_next_dyn_thunk += 8;
    disp_insert(addr, SLOT_SHIM, NULL, fn, userdata, name);
    pthread_mutex_unlock(&g_rt_mu);
    return addr;
}

uint64_t rt_lookup_export(const char *name) {
    for (size_t i = 0; i < g_rt_export_count; i++) {
        if (strcmp(g_rt_exports[i].name, name) == 0) {
            return g_rt_exports[i].addr;
        }
    }
    return 0;
}

uint64_t rt_lookup_export_in_module(uint64_t mod_base, const char *name) {
    if (!mod_base || !name) return 0;
    for (size_t i = 0; i < g_rt_export_count; i++) {
        if (g_rt_exports[i].mod_base == mod_base && strcmp(g_rt_exports[i].name, name) == 0) {
            return g_rt_exports[i].addr;
        }
    }
    return 0;
}

uint64_t rt_find_module_base(const char *name) {
    if (!name || !*name) {
        return g_rt_module_count > 0 ? g_rt_modules[0].map_addr : 0;
    }
    /* Match by basename so "bin\\win64\\launcher.dll" matches "launcher.dll". */
    const char *base = name;
    for (const char *p = name; *p; p++) {
        if (*p == '/' || *p == '\\') base = p + 1;
    }
    for (size_t i = 0; i < g_rt_module_count; i++) {
        if (strcasecmp(g_rt_modules[i].name, base) == 0) {
            return g_rt_modules[i].map_addr;
        }
        size_t nlen = strlen(base);
        if (strncasecmp(g_rt_modules[i].name, base, nlen) == 0 &&
            strcasecmp(g_rt_modules[i].name + nlen, ".dll") == 0) {
            return g_rt_modules[i].map_addr;
        }
    }
    return 0;
}

static void *map_exact_rw(uint64_t addr, size_t size, const char *label) {
    size_t aligned = (size + 0x3FFFULL) & ~0x3FFFULL;
    if (aligned == 0) aligned = 0x4000;
    void *p = mmap((void *)(uintptr_t)addr, aligned,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "elf64-recomp: mmap(%s @ 0x%llx, 0x%zx) failed: %s\n",
                label, (unsigned long long)addr, aligned, strerror(errno));
        abort();
    }
    if ((uint64_t)(uintptr_t)p != addr) {
        fprintf(stderr, "elf64-recomp: mmap(%s) wanted 0x%llx, got 0x%llx\n",
                label, (unsigned long long)addr, (unsigned long long)(uintptr_t)p);
        abort();
    }
    return p;
}

static void load_module_images(void) {
    for (size_t i = 0; i < g_rt_module_count; i++) {
        const RTModuleSpec *m = &g_rt_modules[i];
        void *mem = map_exact_rw(m->map_addr, (size_t)m->mem_size, m->name);
        int fd = open(m->image_path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "elf64-recomp: cannot open %s: %s\n",
                    m->image_path, strerror(errno));
            abort();
        }
        size_t remaining = (size_t)m->mem_size;
        uint8_t *dst = (uint8_t *)mem;
        while (remaining > 0) {
            ssize_t n = read(fd, dst, remaining);
            if (n <= 0) {
                fprintf(stderr, "elf64-recomp: short read on %s\n", m->image_path);
                abort();
            }
            dst += n;
            remaining -= (size_t)n;
        }
        close(fd);
    }

    for (size_t i = 0; i < g_rt_copy_reloc_count; i++) {
        const RTCopyReloc *cr = &g_rt_copy_relocs[i];
        if (cr->size > 0 && cr->src && cr->dst) {
            memcpy((void *)(uintptr_t)cr->dst, (const void *)(uintptr_t)cr->src, (size_t)cr->size);
        }
    }
}

static void init_data_imports(char **argv, char **envp) {
    if (g_rt_data_import_count == 0) return;
    map_exact_rw(g_rt_data_import_base, 0x4000, "data_imports");
    for (size_t i = 0; i < g_rt_data_import_count; i++) {
        const char *name = g_rt_data_imports[i].name;
        uint64_t addr = g_rt_data_imports[i].addr;
        uint64_t val = 0;
        if (strcmp(name, "stdin") == 0) val = (uint64_t)(uintptr_t)stdin;
        else if (strcmp(name, "stdout") == 0) val = (uint64_t)(uintptr_t)stdout;
        else if (strcmp(name, "stderr") == 0) val = (uint64_t)(uintptr_t)stderr;
        else if (strcmp(name, "environ") == 0 || strcmp(name, "__environ") == 0 ||
                 strcmp(name, "_environ") == 0) val = (uint64_t)(uintptr_t)envp;
        else if (strcmp(name, "__progname") == 0 || strcmp(name, "__progname_full") == 0)
            val = (uint64_t)(uintptr_t)(argv && argv[0] ? argv[0] : "guest");
        W64(addr, val);
    }
}

void rt_init_thread_cpu(CPU64 *c, size_t stack_size) {
    memset(c, 0, sizeof(*c));
    c->mxcsr = 0x1F80;

    if (stack_size == 0) stack_size = 8 * 1024 * 1024;
    void *stk = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stk == MAP_FAILED) abort();
    /* Leave 64 bytes of headroom and keep 16-byte alignment. */
    c->rsp = ((uint64_t)(uintptr_t)stk + stack_size - 64ULL) & ~15ULL;

    /* Allocate Variant II TLS block: [static_tls_bytes][TCB (>= 0x100 bytes)]. */
    size_t tls_sz = (size_t)((g_rt_total_tls_size + 63ULL) & ~63ULL);
    size_t tcb_sz = 0x200;
    uint8_t *tls_mem = (uint8_t *)calloc(1, tls_sz + tcb_sz);
    if (!tls_mem) abort();
    uint8_t *tcb = tls_mem + tls_sz;

    if (!g_rt_is_win64) {
        for (size_t i = 0; i < g_rt_module_count; i++) {
            const RTModuleSpec *m = &g_rt_modules[i];
            if (m->tls_memsz > 0 && m->tls_filesz > 0) {
                memcpy(tcb + m->tls_tpoff, (const void *)(uintptr_t)m->tls_vaddr, (size_t)m->tls_filesz);
            }
        }
    }

    uint64_t fs = (uint64_t)(uintptr_t)tcb;
    W64(fs + 0x00, fs);              /* %fs:0x00 self-pointer */
    W64(fs + 0x28, RT_STACK_CANARY); /* %fs:0x28 glibc stack guard */
    c->fs_base = fs;

    /* Allocate Windows x64 TEB + PEB + implicit TLS array on %gs_base when running PE64/Win64. */
    if (g_rt_is_win64) {
        uint8_t *teb = (uint8_t *)calloc(1, 0x2000);
        uint8_t *peb = (uint8_t *)calloc(1, 0x1000);
        uint8_t *pparams = (uint8_t *)calloc(1, 0x400);
        uint64_t *tls_arr = (uint64_t *)calloc(g_rt_module_count + 16, sizeof(uint64_t));
        if (!teb || !peb || !pparams || !tls_arr) abort();
        for (size_t i = 0; i < g_rt_module_count; i++) {
            const RTModuleSpec *m = &g_rt_modules[i];
            size_t bsz = (m->tls_memsz > 0) ? (size_t)m->tls_memsz : 64;
            uint8_t *blk = (uint8_t *)calloc(1, (bsz + 63) & ~63ULL);
            if (!blk) abort();
            if (m->tls_vaddr && m->tls_filesz > 0) {
                memcpy(blk, (const void *)(uintptr_t)m->tls_vaddr, (size_t)m->tls_filesz);
            }
            size_t slot = (size_t)m->tls_tpoff;
            if (slot < g_rt_module_count + 16) tls_arr[slot] = (uint64_t)(uintptr_t)blk;
        }
        uint64_t teb_va = (uint64_t)(uintptr_t)teb;
        uint64_t peb_va = (uint64_t)(uintptr_t)peb;
        uint64_t stk_lo = (uint64_t)(uintptr_t)stk;
        uint64_t stk_hi = stk_lo + stack_size;
        W64(teb_va + 0x08, stk_hi);                        /* NT_TIB.StackBase */
        W64(teb_va + 0x10, stk_lo);                        /* NT_TIB.StackLimit */
        W64(teb_va + 0x30, teb_va);                        /* TEB.Self (NtCurrentTeb) */
        W64(teb_va + 0x58, (uint64_t)(uintptr_t)tls_arr);  /* TEB.ThreadLocalStoragePointer */
        W64(teb_va + 0x60, peb_va);                        /* TEB.ProcessEnvironmentBlock */
        W64(peb_va + 0x10, g_rt_module_count > 0 ? g_rt_modules[0].map_addr : 0); /* PEB.ImageBaseAddress */
        W64(peb_va + 0x20, (uint64_t)(uintptr_t)pparams);  /* PEB.ProcessParameters */
        c->gs_base = teb_va;
    }
    g_tls_cpu = c;
}

void rt_destroy_thread_cpu(CPU64 *c) {
    /* shortcut: thread stack/TLS are not munmap'd until thread teardown helper tracks base ptrs; add base ptrs when spawning many short-lived threads. */
    (void)c;
}

__attribute__((weak)) void rt_register_win32_64(void) {}
__attribute__((weak)) void rt_register_win32_extra(void) {}
__attribute__((weak)) void rt_register_d3d11_64(void) {}

static int g_trace = 0;

static void rt_crash_handler(int sig, siginfo_t *info, void *uctx) {
    (void)uctx;
    fprintf(stderr, "\n=== elf64-recomp CRASH sig=%d fault_addr=%p ===\n",
            sig, info ? info->si_addr : NULL);
    CPU64 *c = g_tls_cpu;
    if (c) {
        fprintf(stderr, "  guest rip=0x%llx rsp=0x%llx rbp=0x%llx\n",
                (unsigned long long)c->rip, (unsigned long long)c->rsp, (unsigned long long)c->rbp);
        fprintf(stderr, "  rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx\n",
                (unsigned long long)c->rax, (unsigned long long)c->rbx,
                (unsigned long long)c->rcx, (unsigned long long)c->rdx);
        fprintf(stderr, "  rsi=0x%llx rdi=0x%llx r8=0x%llx r9=0x%llx\n",
                (unsigned long long)c->rsi, (unsigned long long)c->rdi,
                (unsigned long long)c->r8,  (unsigned long long)c->r9);
    }
    void *bt[24];
    int n = backtrace(bt, 24);
    backtrace_symbols_fd(bt, n, STDERR_FILENO);
    _exit(128 + sig);
}

void rt_init(int argc, char **argv, char **envp) {
    g_rt_argc = argc;
    g_rt_argv = argv;
    g_rt_envp = envp;
    g_trace = (getenv("ELF64_TRACE") != NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = rt_crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);

    if (g_rt_is_win64) {
        rt_register_win32_64();
        rt_register_win32_extra();
        rt_register_d3d11_64();
        rt_register_cairo_pango_64();
        rt_register_v8_jsc_64();
    } else {
        rt_register_libc64();
        rt_register_sdl2_64();
        rt_register_vulkan64();
    }

    load_module_images();
    init_data_imports(argv, envp);

    disp_init(g_rt_func_count + g_rt_import_count + 16384);
    for (size_t i = 0; i < g_rt_func_count; i++) {
        disp_insert(g_rt_funcs[i].addr, SLOT_LIFTED, g_rt_funcs[i].fn, NULL, NULL, NULL);
    }
    for (size_t i = 0; i < g_rt_import_count; i++) {
        void *ud = NULL;
        RTShimFn fn = NULL;
        if (g_rt_imports[i].dll) {
            char qual[256];
            snprintf(qual, sizeof(qual), "%s!%s", g_rt_imports[i].dll, g_rt_imports[i].name);
            fn = rt_find_shim(qual, &ud);
        }
        if (!fn) {
            fn = rt_find_shim(g_rt_imports[i].name, &ud);
        }
        if (fn) {
            disp_insert(g_rt_imports[i].addr, SLOT_SHIM, NULL, fn, ud, g_rt_imports[i].name);
        } else {
            disp_insert(g_rt_imports[i].addr, SLOT_UNRESOLVED, NULL, NULL, NULL, g_rt_imports[i].name);
        }
    }
}

void rt_call(CPU64 *c, uint64_t target) {
    if (c->halted) return;
    const DispatchSlot *s = disp_lookup(target);
    if (!s) {
        fprintf(stderr, "elf64-recomp: FATAL unmapped call target 0x%llx (rip=0x%llx rsp=0x%llx)\n",
                (unsigned long long)target, (unsigned long long)c->rip, (unsigned long long)c->rsp);
        abort();
    }
    if (s->kind == SLOT_LIFTED) {
        c->rip = target;
        s->lifted(c);
    } else if (s->kind == SLOT_SHIM) {
        if (g_trace) {
            fprintf(stderr, "[shim] %s(rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx)\n",
                    s->name ? s->name : "?",
                    (unsigned long long)c->rcx, (unsigned long long)c->rdx,
                    (unsigned long long)c->r8,  (unsigned long long)c->r9);
        }
        s->shim(c, s->userdata);
        if (!c->halted) {
            c->rip = pop64(c);
        }
    } else {
        fprintf(stderr, "elf64-recomp: FATAL missing host shim '%s' (addr=0x%llx)\n",
                s->name ? s->name : "?", (unsigned long long)target);
        abort();
    }
}

void rt_tailcall(CPU64 *c, uint64_t target) {
    rt_call(c, target);
}

uint64_t rt_invoke64(CPU64 *c, uint64_t target,
                     uint64_t a0, uint64_t a1, uint64_t a2,
                     uint64_t a3, uint64_t a4, uint64_t a5) {
    uint64_t saved_rdi = c->rdi, saved_rsi = c->rsi, saved_rdx = c->rdx;
    uint64_t saved_rcx = c->rcx, saved_r8  = c->r8,  saved_r9  = c->r9;
    uint64_t saved_r10 = c->r10, saved_r11 = c->r11, saved_rax = c->rax;
    uint64_t saved_rip = c->rip, saved_rsp = c->rsp;
    Xmm128   saved_xmm[8];
    memcpy(saved_xmm, c->xmm, sizeof(saved_xmm));

    /* Maintain System V AMD64 stack alignment: 16-byte aligned before call, rsp%16==8 at entry. */
    c->rsp = (c->rsp - 16ULL) & ~15ULL;
    push64(c, RT_RETURN_SENTINEL);
    c->rdi = a0; c->rsi = a1; c->rdx = a2;
    c->rcx = a3; c->r8  = a4; c->r9  = a5;

    rt_call(c, target);
    uint64_t ret = c->rax;

    c->rdi = saved_rdi; c->rsi = saved_rsi; c->rdx = saved_rdx;
    c->rcx = saved_rcx; c->r8  = saved_r8;  c->r9  = saved_r9;
    c->r10 = saved_r10; c->r11 = saved_r11; c->rax = saved_rax;
    c->rip = saved_rip; c->rsp = saved_rsp;
    memcpy(c->xmm, saved_xmm, sizeof(saved_xmm));
    return ret;
}

uint64_t rt_invoke_win64(CPU64 *c, uint64_t target,
                         uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5) {
    uint64_t saved_rcx = c->rcx, saved_rdx = c->rdx, saved_r8  = c->r8,  saved_r9  = c->r9;
    uint64_t saved_r10 = c->r10, saved_r11 = c->r11, saved_rax = c->rax;
    uint64_t saved_rip = c->rip, saved_rsp = c->rsp;
    Xmm128   saved_xmm[6];
    memcpy(saved_xmm, c->xmm, sizeof(saved_xmm));

    /* Win64 ABI: 16-byte aligned before call; 32B shadow space + 2 stack args = 48B. */
    c->rsp = (c->rsp - 64ULL) & ~15ULL;
    W64(c->rsp + 0x20, a4);
    W64(c->rsp + 0x28, a5);
    push64(c, RT_RETURN_SENTINEL); /* rsp % 16 == 8 at entry, shadow space at [rsp+8..rsp+39] */
    c->rcx = a0; c->rdx = a1; c->r8 = a2; c->r9 = a3;

    rt_call(c, target);
    uint64_t ret = c->rax;

    c->rcx = saved_rcx; c->rdx = saved_rdx; c->r8  = saved_r8;  c->r9  = saved_r9;
    c->r10 = saved_r10; c->r11 = saved_r11; c->rax = saved_rax;
    c->rip = saved_rip; c->rsp = saved_rsp;
    memcpy(c->xmm, saved_xmm, sizeof(saved_xmm));
    return ret;
}
