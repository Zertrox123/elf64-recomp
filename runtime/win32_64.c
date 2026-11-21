#include "runtime64.h"
#include "win64_abi.h"

#include <SDL.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static _Thread_local uint32_t g_last_error = 0;

/* ---- UTF-16 <-> UTF-8 helpers ---- */
static size_t utf16_to_utf8(const uint16_t *src, char *dst, size_t cap) {
    size_t out = 0;
    if (!src) { if (cap) dst[0] = '\0'; return 0; }
    while (*src && out + 4 < cap) {
        uint32_t cp = *src++;
        if (cp < 0x80) dst[out++] = (char)cp;
        else if (cp < 0x800) {
            dst[out++] = (char)(0xC0 | (cp >> 6));
            dst[out++] = (char)(0x80 | (cp & 0x3F));
        } else {
            dst[out++] = (char)(0xE0 | (cp >> 12));
            dst[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            dst[out++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    if (cap) dst[out] = '\0';
    return out;
}

static size_t utf8_to_utf16(const char *src, uint16_t *dst, size_t cap) {
    size_t out = 0;
    if (!src) { if (cap) dst[0] = 0; return 0; }
    while (*src && out + 1 < cap) {
        dst[out++] = (uint8_t)*src++;
    }
    if (cap) dst[out] = 0;
    return out;
}

/* ---- Win64 variadic printf engine (unified slot indexing) ---- */
static int win64_vsnprintf(char *out, size_t cap, const char *fmt, const CPU64 *c, int first_slot) {
    int slot = first_slot;
    size_t pos = 0;
    const char *p = fmt;
    while (*p) {
        if (*p != '%') {
            if (pos + 1 < cap) out[pos] = *p;
            pos++; p++;
            continue;
        }
        p++;
        if (*p == '%') {
            if (pos + 1 < cap) out[pos] = '%';
            pos++; p++;
            continue;
        }
        char spec[64];
        size_t sl = 0;
        spec[sl++] = '%';
        while (*p && strchr("-+ #0", *p) && sl < 50) spec[sl++] = *p++;
        while (*p >= '0' && *p <= '9' && sl < 50) spec[sl++] = *p++;
        if (*p == '.') {
            spec[sl++] = *p++;
            while (*p >= '0' && *p <= '9' && sl < 50) spec[sl++] = *p++;
        }
        int is_64 = 0;
        if (*p == 'I' && p[1] == '6' && p[2] == '4') {
            is_64 = 1; spec[sl++] = 'l'; spec[sl++] = 'l'; p += 3;
        } else if (*p == 'l') {
            spec[sl++] = *p++;
            if (*p == 'l') { is_64 = 1; spec[sl++] = *p++; }
        } else if (*p == 'z') {
            is_64 = 1; spec[sl++] = *p++;
        } else if (*p == 'h') {
            spec[sl++] = *p++; if (*p == 'h') spec[sl++] = *p++;
        }
        char conv = *p ? *p++ : '\0';
        if (!conv) break;
        spec[sl++] = conv;
        spec[sl] = '\0';

        char tmp[1024];
        int n = 0;
        if (conv == 'f' || conv == 'F' || conv == 'e' || conv == 'E' || conv == 'g' || conv == 'G') {
            double d = win64_arg_d(c, slot++);
            n = snprintf(tmp, sizeof(tmp), spec, d);
        } else if (conv == 's') {
            const char *s = (const char *)(uintptr_t)win64_arg_i(c, slot++);
            n = snprintf(tmp, sizeof(tmp), spec, s ? s : "(null)");
        } else if (conv == 'p') {
            void *ptr = (void *)(uintptr_t)win64_arg_i(c, slot++);
            n = snprintf(tmp, sizeof(tmp), spec, ptr);
        } else {
            uint64_t v = win64_arg_i(c, slot++);
            if (is_64) n = snprintf(tmp, sizeof(tmp), spec, (long long)v);
            else       n = snprintf(tmp, sizeof(tmp), spec, (int)v);
        }
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                if (pos + 1 < cap) out[pos] = tmp[i];
                pos++;
            }
        }
    }
    if (cap > 0) out[(pos < cap) ? pos : (cap - 1)] = '\0';
    return (int)pos;
}

/* ---- Win32 Handle table (threads, events, files, windows) ---- */
typedef enum {
    WH_NONE = 0,
    WH_THREAD = 1,
    WH_EVENT = 2,
    WH_FILE = 3,
} WinHandleKind;

typedef struct {
    WinHandleKind kind;
    pthread_t     tid;
    int           joined;
    int           finished;
    int           ev_signaled;
    int           ev_manual;
    int           fd;
} WinHandleObj;

static pthread_mutex_t g_wh_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_wh_cv = PTHREAD_COND_INITIALIZER;
static WinHandleObj   *g_wh_slots[1024];
static uint32_t        g_wh_next = 0x100;

static uint64_t wh_alloc(WinHandleObj *obj) {
    pthread_mutex_lock(&g_wh_mu);
    for (uint32_t i = 0; i < 1024; i++) {
        uint32_t idx = (g_wh_next + i) & 1023;
        if (!g_wh_slots[idx]) {
            g_wh_slots[idx] = obj;
            g_wh_next = idx + 1;
            pthread_mutex_unlock(&g_wh_mu);
            return (uint64_t)(idx + 0x100);
        }
    }
    pthread_mutex_unlock(&g_wh_mu);
    return 0;
}

static WinHandleObj *wh_get(uint64_t h) {
    if (h < 0x100 || h >= 0x100 + 1024) return NULL;
    return g_wh_slots[h - 0x100];
}

/* ---- CRITICAL_SECTION side-table (Windows 40B vs macOS 64B pthread_mutex_t) ---- */
typedef struct {
    uint64_t         guest_addr;
    pthread_mutex_t *mu;
} CsEntry;

static pthread_mutex_t g_cs_map_mu = PTHREAD_MUTEX_INITIALIZER;
static CsEntry        *g_cs_map = NULL;
static size_t          g_cs_n = 0, g_cs_cap = 0;

static pthread_mutex_t *lookup_cs(uint64_t addr) {
    pthread_mutex_lock(&g_cs_map_mu);
    for (size_t i = 0; i < g_cs_n; i++) {
        if (g_cs_map[i].guest_addr == addr) {
            pthread_mutex_t *m = g_cs_map[i].mu;
            pthread_mutex_unlock(&g_cs_map_mu);
            return m;
        }
    }
    if (g_cs_n == g_cs_cap) {
        g_cs_cap = g_cs_cap ? g_cs_cap * 2 : 64;
        g_cs_map = (CsEntry *)realloc(g_cs_map, g_cs_cap * sizeof(CsEntry));
    }
    pthread_mutex_t *m = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(m, &attr);
    pthread_mutexattr_destroy(&attr);
    g_cs_map[g_cs_n].guest_addr = addr;
    g_cs_map[g_cs_n].mu = m;
    g_cs_n++;
    pthread_mutex_unlock(&g_cs_map_mu);
    return m;
}

/* ---- TLS slots (TlsAlloc / TlsGetValue / TlsSetValue) ---- */
#define MAX_WIN_TLS 128
static pthread_key_t g_win_tls_keys[MAX_WIN_TLS];
static int           g_win_tls_used[MAX_WIN_TLS];
static pthread_mutex_t g_win_tls_mu = PTHREAD_MUTEX_INITIALIZER;

/* ---- Kernel32 shims ---- */
static void w_GetProcessHeap(CPU64 *c, void *ud) { (void)ud; c->rax = 0x10001ULL; }
static void w_HeapAlloc(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t flags = (uint32_t)c->rdx;
    size_t sz = (size_t)c->r8;
    void *p = (flags & 0x08) ? calloc(1, sz ? sz : 1) : malloc(sz ? sz : 1);
    c->rax = (uint64_t)(uintptr_t)p;
}
static void w_HeapReAlloc(CPU64 *c, void *ud) {
    (void)ud;
    void *p = realloc((void *)(uintptr_t)c->r8, (size_t)c->r9);
    c->rax = (uint64_t)(uintptr_t)p;
}
static void w_HeapFree(CPU64 *c, void *ud) {
    (void)ud;
    free((void *)(uintptr_t)c->r8);
    c->rax = 1;
}
typedef struct { uint64_t base; size_t size; } VmRegion;
static pthread_mutex_t g_vm_mu = PTHREAD_MUTEX_INITIALIZER;
static VmRegion *g_vm_regs = NULL;
static size_t    g_vm_n = 0, g_vm_cap = 0;

static void vm_track_add(uint64_t base, size_t size) {
    pthread_mutex_lock(&g_vm_mu);
    if (g_vm_n == g_vm_cap) {
        g_vm_cap = g_vm_cap ? g_vm_cap * 2 : 64;
        g_vm_regs = (VmRegion *)realloc(g_vm_regs, g_vm_cap * sizeof(VmRegion));
    }
    g_vm_regs[g_vm_n].base = base;
    g_vm_regs[g_vm_n].size = size;
    g_vm_n++;
    pthread_mutex_unlock(&g_vm_mu);
}

static int vm_contains(uint64_t addr) {
    pthread_mutex_lock(&g_vm_mu);
    for (size_t i = 0; i < g_vm_n; i++) {
        if (addr >= g_vm_regs[i].base && addr < g_vm_regs[i].base + g_vm_regs[i].size) {
            pthread_mutex_unlock(&g_vm_mu);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_vm_mu);
    return 0;
}

static size_t vm_track_remove(uint64_t base) {
    pthread_mutex_lock(&g_vm_mu);
    for (size_t i = 0; i < g_vm_n; i++) {
        if (g_vm_regs[i].base == base) {
            size_t sz = g_vm_regs[i].size;
            g_vm_regs[i] = g_vm_regs[--g_vm_n];
            pthread_mutex_unlock(&g_vm_mu);
            return sz;
        }
    }
    pthread_mutex_unlock(&g_vm_mu);
    return 0;
}

static void w_VirtualAlloc(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t req_addr = c->rcx;
    size_t   sz       = (size_t)c->rdx;
    uint32_t fl_type  = (uint32_t)c->r8;
    if (sz == 0) sz = 0x10000;
    sz = (sz + 0x3FFFULL) & ~0x3FFFULL;

    /* MEM_COMMIT (0x1000) without MEM_RESERVE (0x2000) inside an already-reserved region. */
    if ((fl_type & 0x1000) && !(fl_type & 0x2000) && req_addr && vm_contains(req_addr)) {
        c->rax = req_addr & ~0x3FFFULL;
        return;
    }

    /* Windows VirtualAlloc guarantees >=64 KiB alignment; align >=4 MiB requests to 4 MiB
     * (satisfies mimalloc 4 MiB / 8 MiB segment alignment on the first try). */
    size_t align = 0x10000;
    if (sz >= 0x400000) align = 0x400000;
    if (sz >= 0x800000) align = 0x800000;

    size_t total = sz + align;
    void *raw = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (raw == MAP_FAILED) { c->rax = 0; return; }
    uint64_t raw_u = (uint64_t)(uintptr_t)raw;
    uint64_t aligned = (raw_u + align - 1ULL) & ~(uint64_t)(align - 1ULL);
    if (aligned > raw_u) munmap((void *)(uintptr_t)raw_u, (size_t)(aligned - raw_u));
    uint64_t end_u = raw_u + total;
    if (end_u > aligned + sz) munmap((void *)(uintptr_t)(aligned + sz), (size_t)(end_u - (aligned + sz)));

    vm_track_add(aligned, sz);
    c->rax = aligned;
}
static void w_VirtualFree(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t addr = c->rcx;
    size_t sz = (size_t)c->rdx;
    uint32_t fl = (uint32_t)c->r8;
    if ((fl & 0x8000 /* MEM_RELEASE */) && addr) {
        size_t tracked = vm_track_remove(addr);
        if (tracked) munmap((void *)(uintptr_t)addr, tracked);
        else if (sz) munmap((void *)(uintptr_t)addr, sz);
    }
    c->rax = 1;
}
static void w_VirtualProtect(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r9) W32(c->r9, 0x04 /* PAGE_READWRITE */);
    c->rax = 1;
}

static void w_GetLastError(CPU64 *c, void *ud) { (void)ud; c->rax = g_last_error; }
static void w_SetLastError(CPU64 *c, void *ud) { (void)ud; g_last_error = (uint32_t)c->rcx; }

static int is_host_system_dll(const char *name) {
    if (!name) return 0;
    const char *base = name;
    for (const char *p = name; *p; p++) if (*p == '/' || *p == '\\') base = p + 1;
    static const char *const sys[] = {
        "kernel32", "kernelbase", "ntdll", "user32", "gdi32", "advapi32",
        "ole32", "oleaut32", "shell32", "shlwapi", "version", "winmm",
        "bcrypt", "ws2_32", "dbghelp", "winhttp", "wininet", "d3d11", "dxgi",
        "imm32", "dsound", "rpcrt4", "iphlpapi",
        "ucrtbase", "msvcrt", "vcruntime140", "steam_api64", NULL
    };
    if (strncasecmp(base, "api-ms-win-", 11) == 0) return 1;
    for (int i = 0; sys[i]; i++) {
        size_t n = strlen(sys[i]);
        if (strncasecmp(base, sys[i], n) == 0 && (base[n] == '\0' || strcasecmp(base + n, ".dll") == 0))
            return 1;
    }
    return 0;
}

static void w_GetModuleHandleA(CPU64 *c, void *ud) {
    (void)ud;
    const char *name = (const char *)(uintptr_t)c->rcx;
    uint64_t base = rt_find_module_base(name);
    if (!base && name && strstr(name, "client_legacyui")) base = rt_find_module_base("client.dll");
    if (!base && name && is_host_system_dll(name)) base = 0x7090000000ULL;
    if (!base && name && getenv("ELF64_TRACE")) {
        fprintf(stderr, "[win32] LoadLibrary/GetModuleHandle('%s') -> NULL (not loaded)\n", name);
    }
    c->rax = base;
}
static void w_GetModuleHandleW(CPU64 *c, void *ud) {
    (void)ud;
    char buf[260];
    utf16_to_utf8((const uint16_t *)(uintptr_t)c->rcx, buf, sizeof(buf));
    uint64_t base = rt_find_module_base(c->rcx ? buf : NULL);
    if (!base && c->rcx && is_host_system_dll(buf)) base = 0x7090000000ULL;
    if (!base && c->rcx && getenv("ELF64_TRACE")) {
        fprintf(stderr, "[win32] LoadLibraryW/GetModuleHandleW('%s') -> NULL (not loaded)\n", buf);
    }
    c->rax = base;
}
static void w_LoadLibraryA(CPU64 *c, void *ud) { w_GetModuleHandleA(c, ud); }
static void w_LoadLibraryW(CPU64 *c, void *ud) { w_GetModuleHandleW(c, ud); }
static void w_FreeLibrary(CPU64 *c, void *ud)  { (void)ud; c->rax = 1; }

static void w_GetProcAddress(CPU64 *c, void *ud) {
    (void)ud;
    const char *sym = (const char *)(uintptr_t)c->rdx;
    if (!sym || (uintptr_t)sym < 0x10000) { c->rax = 0; return; }
    if (c->rcx && c->rcx != 0x7090000000ULL) {
        uint64_t mod_exp = rt_lookup_export_in_module(c->rcx, sym);
        if (mod_exp) { c->rax = mod_exp; return; }
        /* Guest module does not export this symbol; do not cross-leak another DLL's export! */
        for (size_t i = 0; i < g_rt_module_count; i++) {
            if (g_rt_modules[i].map_addr == c->rcx) { c->rax = 0; return; }
        }
    }
    if (c->rcx == 0x7090000000ULL) {
        void *sud = NULL;
        RTShimFn fn = rt_find_shim(sym, &sud);
        c->rax = fn ? rt_alloc_dynamic_thunk(sym, fn, sud) : 0;
        return;
    }
    uint64_t exp = rt_lookup_export(sym);
    if (exp) { c->rax = exp; return; }
    void *sud = NULL;
    RTShimFn fn = rt_find_shim(sym, &sud);
    c->rax = fn ? rt_alloc_dynamic_thunk(sym, fn, sud) : 0;
}

static void format_win_module_path(uint64_t hmod, char *out, size_t cap) {
    const char *mname = (g_rt_module_count > 0) ? g_rt_modules[0].name : "guest.exe";
    for (size_t i = 0; i < g_rt_module_count; i++) {
        if (hmod && g_rt_modules[i].map_addr == hmod) {
            mname = g_rt_modules[i].name;
            break;
        }
    }
    const char *root = getenv("ELF64_WIN_ROOT");
    char raw[1024];
    if (root && *root) {
        snprintf(raw, sizeof(raw), "C:%s\\bin\\win64\\%s", root, mname);
    } else {
        char cwd[512];
        if (!getcwd(cwd, sizeof(cwd))) strcpy(cwd, "/tmp");
        snprintf(raw, sizeof(raw), "C:%s\\bin\\win64\\%s", cwd, mname);
    }
    size_t j = 0;
    for (size_t i = 0; raw[i] && j + 1 < cap; i++) {
        out[j++] = (raw[i] == '/') ? '\\' : raw[i];
    }
    out[j] = '\0';
}

static void w_GetModuleFileNameA(CPU64 *c, void *ud) {
    (void)ud;
    char *buf = (char *)(uintptr_t)c->rdx;
    uint32_t sz = (uint32_t)c->r8;
    char path[1024];
    format_win_module_path(c->rcx, path, sizeof(path));
    size_t n = strlen(path);
    if (n >= sz) n = sz ? sz - 1 : 0;
    if (buf && sz) { memcpy(buf, path, n); buf[n] = '\0'; }
    c->rax = n;
}
static void w_GetModuleFileNameW(CPU64 *c, void *ud) {
    (void)ud;
    char path[1024];
    format_win_module_path(c->rcx, path, sizeof(path));
    c->rax = utf8_to_utf16(path, (uint16_t *)(uintptr_t)c->rdx, (size_t)c->r8);
}

static void w_QueryPerformanceFrequency(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) W64(c->rcx, 1000000000ULL);
    c->rax = 1;
}
static void w_QueryPerformanceCounter(CPU64 *c, void *ud) {
    (void)ud;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (c->rcx) W64(c->rcx, (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec);
    c->rax = 1;
}
static void w_GetTickCount64(CPU64 *c, void *ud) {
    (void)ud;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    c->rax = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}
static void w_GetTickCount(CPU64 *c, void *ud) { w_GetTickCount64(c, ud); SET32(c->rax, c->rax); }
static void w_Sleep(CPU64 *c, void *ud) { (void)ud; usleep((useconds_t)c->rcx * 1000U); }
static void w_GetCurrentThreadId(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    c->rax = (uint32_t)tid;
}
static void w_GetCurrentProcessId(CPU64 *c, void *ud) { (void)ud; c->rax = (uint32_t)getpid(); }
static void w_GetSystemInfo(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) return;
    memset((void *)(uintptr_t)c->rcx, 0, 48);
    W16(c->rcx + 0, 9);           /* PROCESSOR_ARCHITECTURE_AMD64 */
    W32(c->rcx + 4, 4096);        /* dwPageSize */
    W32(c->rcx + 32, (uint32_t)sysconf(_SC_NPROCESSORS_ONLN)); /* dwNumberOfProcessors */
    W32(c->rcx + 40, 65536);      /* dwAllocationGranularity */
}

/* CriticalSection */
static void w_InitializeCriticalSection(CPU64 *c, void *ud) { (void)ud; lookup_cs(c->rcx); }
static void w_InitializeCriticalSectionAndSpinCount(CPU64 *c, void *ud) { (void)ud; lookup_cs(c->rcx); c->rax = 1; }
static void w_EnterCriticalSection(CPU64 *c, void *ud)    { (void)ud; pthread_mutex_lock(lookup_cs(c->rcx)); }
static void w_TryEnterCriticalSection(CPU64 *c, void *ud) { (void)ud; c->rax = (pthread_mutex_trylock(lookup_cs(c->rcx)) == 0) ? 1 : 0; }
static void w_LeaveCriticalSection(CPU64 *c, void *ud)    { (void)ud; pthread_mutex_unlock(lookup_cs(c->rcx)); }
static void w_DeleteCriticalSection(CPU64 *c, void *ud)   { (void)ud; (void)c; }

/* Threads & Events */
typedef struct { uint64_t fn; uint64_t param; WinHandleObj *ho; } WinThreadStart;

static void *win_thread_tramp(void *p) {
    WinThreadStart st = *(WinThreadStart *)p;
    free(p);
    CPU64 cpu;
    rt_init_thread_cpu(&cpu, 4 * 1024 * 1024);
    uint64_t r = rt_invoke_win64(&cpu, st.fn, st.param, 0, 0, 0, 0, 0);
    rt_destroy_thread_cpu(&cpu);
    pthread_mutex_lock(&g_wh_mu);
    st.ho->finished = 1;
    pthread_cond_broadcast(&g_wh_cv);
    pthread_mutex_unlock(&g_wh_mu);
    return (void *)(uintptr_t)r;
}

static void w_CreateThread(CPU64 *c, void *ud) {
    (void)ud;
    WinHandleObj *ho = (WinHandleObj *)calloc(1, sizeof(WinHandleObj));
    ho->kind = WH_THREAD;
    WinThreadStart *st = (WinThreadStart *)malloc(sizeof(WinThreadStart));
    st->fn = c->r8;
    st->param = c->r9;
    st->ho = ho;
    uint64_t handle = wh_alloc(ho);
    if (!handle || pthread_create(&ho->tid, NULL, win_thread_tramp, st) != 0) {
        free(st); free(ho); c->rax = 0; return;
    }
    uint64_t tid_out = win64_arg_i(c, 5);
    if (tid_out) W32(tid_out, (uint32_t)(uintptr_t)ho->tid);
    c->rax = handle;
}

static void w_CreateEventA(CPU64 *c, void *ud) {
    (void)ud;
    WinHandleObj *ho = (WinHandleObj *)calloc(1, sizeof(WinHandleObj));
    ho->kind = WH_EVENT;
    ho->ev_manual = (int)(c->rdx != 0);
    ho->ev_signaled = (int)(c->r8 != 0);
    c->rax = wh_alloc(ho);
}
static void w_SetEvent(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_wh_mu);
    WinHandleObj *ho = wh_get(c->rcx);
    if (!ho || ho->kind != WH_EVENT) { pthread_mutex_unlock(&g_wh_mu); c->rax = 0; return; }
    ho->ev_signaled = 1;
    pthread_cond_broadcast(&g_wh_cv);
    pthread_mutex_unlock(&g_wh_mu);
    c->rax = 1;
}
static void w_ResetEvent(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_wh_mu);
    WinHandleObj *ho = wh_get(c->rcx);
    if (!ho || ho->kind != WH_EVENT) { pthread_mutex_unlock(&g_wh_mu); c->rax = 0; return; }
    ho->ev_signaled = 0;
    pthread_mutex_unlock(&g_wh_mu);
    c->rax = 1;
}

static int wh_is_signaled_locked(uint64_t h) {
    if (h >= 0x30000ULL && h < 0x40000ULL) return 1; /* mutex/semaphore */
    WinHandleObj *ho = wh_get(h);
    if (!ho) return 1;
    if (ho->kind == WH_EVENT) return ho->ev_signaled;
    if (ho->kind == WH_THREAD) return ho->finished;
    return 1;
}

static void wh_consume_locked(uint64_t h) {
    WinHandleObj *ho = wh_get(h);
    if (!ho) return;
    if (ho->kind == WH_EVENT && !ho->ev_manual) ho->ev_signaled = 0;
}

static uint32_t wait_handles_impl(const uint64_t *handles, uint32_t count, int wait_all, uint32_t ms) {
    if (count == 0) return 0xFFFFFFFFU;
    struct timespec deadline;
    int has_timeout = (ms != 0xFFFFFFFFU && ms != 0);
    if (has_timeout) {
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += (time_t)(ms / 1000U);
        deadline.tv_nsec += (long)(ms % 1000U) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }
    }

    pthread_mutex_lock(&g_wh_mu);
    for (;;) {
        if (wait_all) {
            int all_ready = 1;
            for (uint32_t i = 0; i < count; i++) {
                if (!wh_is_signaled_locked(handles[i])) { all_ready = 0; break; }
            }
            if (all_ready) {
                for (uint32_t i = 0; i < count; i++) wh_consume_locked(handles[i]);
                pthread_mutex_unlock(&g_wh_mu);
                return 0;
            }
        } else {
            for (uint32_t i = 0; i < count; i++) {
                if (wh_is_signaled_locked(handles[i])) {
                    wh_consume_locked(handles[i]);
                    pthread_mutex_unlock(&g_wh_mu);
                    return i; /* WAIT_OBJECT_0 + i */
                }
            }
        }
        if (ms == 0) {
            pthread_mutex_unlock(&g_wh_mu);
            return 0x102; /* WAIT_TIMEOUT */
        }
        if (has_timeout) {
            int rc = pthread_cond_timedwait(&g_wh_cv, &g_wh_mu, &deadline);
            if (rc == ETIMEDOUT) {
                pthread_mutex_unlock(&g_wh_mu);
                return 0x102;
            }
        } else {
            pthread_cond_wait(&g_wh_cv, &g_wh_mu);
        }
    }
}

static void w_WaitForSingleObject(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t h = c->rcx;
    uint32_t ms = (uint32_t)c->rdx;
    uint32_t r = wait_handles_impl(&h, 1, 0, ms);
    if (r == 0) {
        pthread_t to_join = 0;
        int do_join = 0;
        pthread_mutex_lock(&g_wh_mu);
        WinHandleObj *ho = wh_get(h);
        if (ho && ho->kind == WH_THREAD && !ho->joined) {
            ho->joined = 1;
            to_join = ho->tid;
            do_join = 1;
        }
        pthread_mutex_unlock(&g_wh_mu);
        if (do_join) pthread_join(to_join, NULL);
    }
    c->rax = r;
}
static void w_WaitForMultipleObjects(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t count = (uint32_t)c->rcx;
    uint64_t arr_va = c->rdx;
    int wait_all = (int)(c->r8 != 0);
    uint32_t ms = (uint32_t)c->r9;
    if (count == 0 || count > 64 || !arr_va) { c->rax = 0xFFFFFFFFU; return; }
    uint64_t hs[64];
    for (uint32_t i = 0; i < count; i++) hs[i] = R64(arr_va + i * 8ULL);
    c->rax = wait_handles_impl(hs, count, wait_all, ms);
}
static void w_GetExitCodeThread(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rdx) { c->rax = 0; return; }
    pthread_mutex_lock(&g_wh_mu);
    WinHandleObj *ho = wh_get(c->rcx);
    uint32_t code = (ho && ho->kind == WH_THREAD && !ho->finished) ? 259U /* STILL_ACTIVE */ : 0U;
    pthread_mutex_unlock(&g_wh_mu);
    W32(c->rdx, code);
    c->rax = 1;
}
static void w_CloseHandle(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx >= 0x20000ULL && c->rcx < 0x30000ULL) {
        int fd = (int)(c->rcx - 0x20000ULL);
        if (fd > 2) close(fd);
        c->rax = 1;
        return;
    }
    pthread_mutex_lock(&g_wh_mu);
    WinHandleObj *ho = wh_get(c->rcx);
    if (!ho) { pthread_mutex_unlock(&g_wh_mu); c->rax = 1; return; }
    g_wh_slots[c->rcx - 0x100] = NULL;
    pthread_mutex_unlock(&g_wh_mu);
    if (ho->kind == WH_FILE && ho->fd >= 0) close(ho->fd);
    free(ho);
    c->rax = 1;
}

/* TLS */
static void w_TlsAlloc(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_win_tls_mu);
    for (int i = 0; i < MAX_WIN_TLS; i++) {
        if (!g_win_tls_used[i]) {
            g_win_tls_used[i] = 1;
            pthread_key_create(&g_win_tls_keys[i], NULL);
            pthread_mutex_unlock(&g_win_tls_mu);
            c->rax = (uint64_t)i;
            return;
        }
    }
    pthread_mutex_unlock(&g_win_tls_mu);
    c->rax = 0xFFFFFFFFU;
}
static void w_TlsGetValue(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx = (uint32_t)c->rcx;
    c->rax = (idx < MAX_WIN_TLS && g_win_tls_used[idx])
        ? (uint64_t)(uintptr_t)pthread_getspecific(g_win_tls_keys[idx]) : 0;
}
static void w_TlsSetValue(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx = (uint32_t)c->rcx;
    if (idx < MAX_WIN_TLS && g_win_tls_used[idx]) {
        pthread_setspecific(g_win_tls_keys[idx], (void *)(uintptr_t)c->rdx);
        c->rax = 1;
    } else c->rax = 0;
}
static void w_TlsFree(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx = (uint32_t)c->rcx;
    if (idx < MAX_WIN_TLS && g_win_tls_used[idx]) {
        pthread_key_delete(g_win_tls_keys[idx]);
        g_win_tls_used[idx] = 0;
        c->rax = 1;
    } else c->rax = 0;
}

/* Console / File I/O */
static void w_GetStdHandle(CPU64 *c, void *ud) {
    (void)ud;
    int32_t id = (int32_t)c->rcx;
    if (id == -10) c->rax = 1;      /* stdin */
    else if (id == -11) c->rax = 2; /* stdout */
    else if (id == -12) c->rax = 3; /* stderr */
    else c->rax = (uint64_t)-1;
}
static void w_WriteFile(CPU64 *c, void *ud) {
    (void)ud;
    int fd = -1;
    if (c->rcx == 2) fd = STDOUT_FILENO;
    else if (c->rcx == 3) fd = STDERR_FILENO;
    else { WinHandleObj *ho = wh_get(c->rcx); if (ho && ho->kind == WH_FILE) fd = ho->fd; }
    if (fd < 0) { c->rax = 0; return; }
    ssize_t n = write(fd, (const void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8);
    if (c->r9) W32(c->r9, n >= 0 ? (uint32_t)n : 0);
    c->rax = (n >= 0) ? 1 : 0;
}
static void w_OutputDebugStringA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) fprintf(stderr, "[ODS] %s", (const char *)(uintptr_t)c->rcx);
}
static void w_MultiByteToWideChar(CPU64 *c, void *ud) {
    (void)ud;
    const uint8_t *src = (const uint8_t *)(uintptr_t)c->r8;
    int slen = (int)(int32_t)c->r9;
    uint16_t *dst = (uint16_t *)(uintptr_t)win64_arg_i(c, 4);
    int dst_cap = (int)(int32_t)win64_arg_i(c, 5);
    if (!src) { c->rax = 0; return; }
    size_t nbytes = (slen < 0) ? (strlen((const char *)src) + 1) : (size_t)slen;
    if (dst_cap == 0 || !dst) { c->rax = nbytes; return; }
    size_t n = nbytes < (size_t)dst_cap ? nbytes : (size_t)dst_cap;
    for (size_t i = 0; i < n; i++) dst[i] = src[i];
    c->rax = n;
}
static void w_WideCharToMultiByte(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *src = (const uint16_t *)(uintptr_t)c->r8;
    int slen = (int)(int32_t)c->r9;
    char *dst = (char *)(uintptr_t)win64_arg_i(c, 4);
    int dst_cap = (int)(int32_t)win64_arg_i(c, 5);
    if (!src) { c->rax = 0; return; }
    size_t nchars = 0;
    if (slen < 0) {
        while (src[nchars]) nchars++;
        nchars++; /* include NUL */
    } else {
        nchars = (size_t)slen;
    }
    if (dst_cap == 0 || !dst) { c->rax = nchars; return; }
    size_t n = nchars < (size_t)dst_cap ? nchars : (size_t)dst_cap;
    for (size_t i = 0; i < n; i++) dst[i] = (src[i] < 128) ? (char)src[i] : '?';
    c->rax = n;
}
static void w_ExitProcess(CPU64 *c, void *ud) {
    (void)ud;
    c->exit_code = (int)c->rcx;
    c->halted = 1;
}

/* ---- UCRT / MSVCRT (Win64 ABI) ---- */
static void w_malloc(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)malloc((size_t)c->rcx); }
static void w_calloc(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)calloc((size_t)c->rcx, (size_t)c->rdx); }
static void w_realloc(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)realloc((void *)(uintptr_t)c->rcx, (size_t)c->rdx); }
static void w_free(CPU64 *c, void *ud)    { (void)ud; free((void *)(uintptr_t)c->rcx); }
static void w_memcpy(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)memcpy((void *)(uintptr_t)c->rcx, (const void *)(uintptr_t)c->rdx, (size_t)c->r8); }
static void w_memmove(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)memmove((void *)(uintptr_t)c->rcx, (const void *)(uintptr_t)c->rdx, (size_t)c->r8); }
static void w_memset(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)memset((void *)(uintptr_t)c->rcx, (int)c->rdx, (size_t)c->r8); }
static void w_memcmp(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(int64_t)memcmp((const void *)(uintptr_t)c->rcx, (const void *)(uintptr_t)c->rdx, (size_t)c->r8); }
static void w_strlen(CPU64 *c, void *ud)  { (void)ud; c->rax = strlen((const char *)(uintptr_t)c->rcx); }
static void w_strcmp(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(int64_t)strcmp((const char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx); }
static void w_strncmp(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)strncmp((const char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx, (size_t)c->r8); }
static void w_stricmp(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)strcasecmp((const char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx); }
static void w_puts(CPU64 *c, void *ud)    { (void)ud; c->rax = (uint64_t)(int64_t)puts((const char *)(uintptr_t)c->rcx); }
static void w_printf(CPU64 *c, void *ud) {
    (void)ud;
    char buf[4096];
    int n = win64_vsnprintf(buf, sizeof(buf), (const char *)(uintptr_t)c->rcx, c, 1);
    fwrite(buf, 1, (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1), stdout);
    c->rax = (uint64_t)(int64_t)n;
}
static void w_snprintf(CPU64 *c, void *ud) {
    (void)ud;
    int n = win64_vsnprintf((char *)(uintptr_t)c->rcx, (size_t)c->rdx, (const char *)(uintptr_t)c->r8, c, 3);
    c->rax = (uint64_t)(int64_t)n;
}

static _Thread_local uint64_t g_wqsort_cmp = 0;
static int win64_qsort_tramp(const void *a, const void *b) {
    return (int)(int32_t)rt_invoke_win64(g_tls_cpu, g_wqsort_cmp,
                                         (uint64_t)(uintptr_t)a, (uint64_t)(uintptr_t)b,
                                         0, 0, 0, 0);
}
static void w_qsort(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t prev = g_wqsort_cmp;
    g_wqsort_cmp = c->r9;
    qsort((void *)(uintptr_t)c->rcx, (size_t)c->rdx, (size_t)c->r8, win64_qsort_tramp);
    g_wqsort_cmp = prev;
}

/* ---- User32 -> SDL2 Windowing & Input ---- */
typedef struct {
    SDL_Window *sdl;
    int         w, h;
    uint64_t    wndproc;
} WinHwndObj;

static WinHwndObj *g_hwnds[64];
static uint64_t    g_last_class_wndproc = 0;
static uint8_t     g_vk_down[256];
static int         g_mouse_x = 640, g_mouse_y = 360;

SDL_Window *win32_hwnd_to_sdl(uint64_t hwnd) {
    if (hwnd < 0x1000 || hwnd >= 0x1000 + 64) return NULL;
    WinHwndObj *o = g_hwnds[hwnd - 0x1000];
    return o ? o->sdl : NULL;
}
uint64_t win32_get_wndproc(uint64_t hwnd) {
    if (hwnd < 0x1000 || hwnd >= 0x1000 + 64) return 0;
    return g_hwnds[hwnd - 0x1000] ? g_hwnds[hwnd - 0x1000]->wndproc : 0;
}
uint64_t win32_set_wndproc(uint64_t hwnd, uint64_t fn) {
    if (hwnd < 0x1000 || hwnd >= 0x1000 + 64 || !g_hwnds[hwnd - 0x1000]) return 0;
    uint64_t prev = g_hwnds[hwnd - 0x1000]->wndproc;
    g_hwnds[hwnd - 0x1000]->wndproc = fn;
    return prev;
}
int  win32_vk_is_down(int vk) { return (vk >= 0 && vk < 256) ? (int)g_vk_down[vk] : 0; }
void win32_get_mouse_xy(int *x, int *y) { if (x) *x = g_mouse_x; if (y) *y = g_mouse_y; }

static int sdl_key_to_vk(SDL_Keycode sym) {
    if (sym >= 'a' && sym <= 'z') return (int)(sym - 'a' + 'A');
    if (sym >= '0' && sym <= '9') return (int)sym;
    if (sym >= SDLK_F1 && sym <= SDLK_F12) return 0x70 + (int)(sym - SDLK_F1);
    switch (sym) {
        case SDLK_BACKSPACE: return 0x08;
        case SDLK_TAB:       return 0x09;
        case SDLK_RETURN:    return 0x0D;
        case SDLK_LSHIFT: case SDLK_RSHIFT: return 0x10;
        case SDLK_LCTRL:  case SDLK_RCTRL:  return 0x11;
        case SDLK_LALT:   case SDLK_RALT:   return 0x12;
        case SDLK_ESCAPE:    return 0x1B;
        case SDLK_SPACE:     return 0x20;
        case SDLK_LEFT:      return 0x25;
        case SDLK_UP:        return 0x26;
        case SDLK_RIGHT:     return 0x27;
        case SDLK_DOWN:      return 0x28;
        case SDLK_DELETE:    return 0x2E;
        case SDLK_BACKQUOTE: return 0xC0;
        default:             return 0;
    }
}

static void w_RegisterClassExA(CPU64 *c, void *ud) {
    (void)ud;
    /* WNDCLASSEX: cbSize(0), style(4), lpfnWndProc(8) */
    if (c->rcx) {
        uint64_t wp = R64(c->rcx + 8);
        if (wp) g_last_class_wndproc = wp;
    }
    c->rax = 0xC001;
}
static void create_window_common(CPU64 *c, const char *title) {
    uint32_t style = (uint32_t)c->r9;
    int w = (int)win64_arg_i(c, 6);
    int h = (int)win64_arg_i(c, 7);
    if (w <= 0 || w > 8192) w = 1280;
    if (h <= 0 || h > 8192) h = 720;
    if (!SDL_WasInit(SDL_INIT_VIDEO)) SDL_Init(SDL_INIT_VIDEO);
    uint32_t flags = SDL_WINDOW_METAL | ((style & 0x10000000U) ? 0 : SDL_WINDOW_HIDDEN);
    SDL_Window *win = SDL_CreateWindow((title && *title) ? title : "elf64-recomp",
                                       SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                       w, h, flags);
    if (!win) { c->rax = 0; return; }
    WinHwndObj *o = (WinHwndObj *)calloc(1, sizeof(WinHwndObj));
    o->sdl = win; o->w = w; o->h = h; o->wndproc = g_last_class_wndproc;
    for (int i = 0; i < 64; i++) {
        if (!g_hwnds[i]) { g_hwnds[i] = o; c->rax = (uint64_t)(0x1000 + i); return; }
    }
    SDL_DestroyWindow(win); free(o); c->rax = 0;
}
static void w_CreateWindowExA(CPU64 *c, void *ud) {
    (void)ud;
    create_window_common(c, (const char *)(uintptr_t)c->r8);
}
static void w_CreateWindowExW(CPU64 *c, void *ud) {
    (void)ud;
    char title[256] = {0};
    if (c->r8) utf16_to_utf8((const uint16_t *)(uintptr_t)c->r8, title, sizeof(title));
    create_window_common(c, title);
}
static void w_ShowWindow(CPU64 *c, void *ud) {
    (void)ud;
    SDL_Window *w = win32_hwnd_to_sdl(c->rcx);
    if (w) { if (c->rdx) SDL_ShowWindow(w); else SDL_HideWindow(w); }
    c->rax = 1;
}
static void w_DestroyWindow(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx >= 0x1000 && c->rcx < 0x1000 + 64 && g_hwnds[c->rcx - 0x1000]) {
        WinHwndObj *o = g_hwnds[c->rcx - 0x1000];
        if (o->sdl) SDL_DestroyWindow(o->sdl);
        free(o);
        g_hwnds[c->rcx - 0x1000] = NULL;
    }
    c->rax = 1;
}
static void w_GetClientRect(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rdx) { c->rax = 0; return; }
    int w = 800, h = 600;
    SDL_Window *win = win32_hwnd_to_sdl(c->rcx);
    if (win) SDL_GetWindowSize(win, &w, &h);
    W32(c->rdx + 0, 0); W32(c->rdx + 4, 0);
    W32(c->rdx + 8, (uint32_t)w); W32(c->rdx + 12, (uint32_t)h);
    c->rax = 1;
}
static void w_PeekMessageA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t msg_va = c->rcx;
    SDL_Event ev;
    while (SDL_PollEvent(&ev)) {
        uint32_t wm = 0;
        uint64_t wp = 0, lp = 0;
        if (ev.type == SDL_QUIT) {
            wm = 0x0012; /* WM_QUIT */
        } else if (ev.type == SDL_MOUSEMOTION) {
            g_mouse_x = ev.motion.x; g_mouse_y = ev.motion.y;
            wm = 0x0200; /* WM_MOUSEMOVE */
            lp = ((uint64_t)(uint16_t)ev.motion.y << 16) | (uint16_t)ev.motion.x;
        } else if (ev.type == SDL_MOUSEBUTTONDOWN || ev.type == SDL_MOUSEBUTTONUP) {
            int dn = (ev.type == SDL_MOUSEBUTTONDOWN);
            g_mouse_x = ev.button.x; g_mouse_y = ev.button.y;
            lp = ((uint64_t)(uint16_t)ev.button.y << 16) | (uint16_t)ev.button.x;
            if (ev.button.button == SDL_BUTTON_LEFT)       { wm = dn ? 0x0201 : 0x0202; g_vk_down[0x01] = (uint8_t)dn; }
            else if (ev.button.button == SDL_BUTTON_RIGHT) { wm = dn ? 0x0204 : 0x0205; g_vk_down[0x02] = (uint8_t)dn; }
            else if (ev.button.button == SDL_BUTTON_MIDDLE){ wm = dn ? 0x0207 : 0x0208; g_vk_down[0x04] = (uint8_t)dn; }
        } else if (ev.type == SDL_MOUSEWHEEL) {
            wm = 0x020A; /* WM_MOUSEWHEEL */
            wp = (uint64_t)(uint16_t)(int16_t)(ev.wheel.y * 120) << 16;
            lp = ((uint64_t)(uint16_t)g_mouse_y << 16) | (uint16_t)g_mouse_x;
        } else if (ev.type == SDL_KEYDOWN || ev.type == SDL_KEYUP) {
            int dn = (ev.type == SDL_KEYDOWN);
            int vk = sdl_key_to_vk(ev.key.keysym.sym);
            if (vk) {
                g_vk_down[vk] = (uint8_t)dn;
                wm = dn ? 0x0100 : 0x0101; /* WM_KEYDOWN / WM_KEYUP */
                wp = (uint64_t)vk;
                lp = 1ULL | ((uint64_t)(ev.key.keysym.scancode & 0xFF) << 16);
            }
        } else if (ev.type == SDL_TEXTINPUT && ev.text.text[0]) {
            wm = 0x0102; /* WM_CHAR */
            wp = (uint8_t)ev.text.text[0];
        }
        if (wm && msg_va) {
            memset((void *)(uintptr_t)msg_va, 0, 48);
            W64(msg_va + 0, 0x1000ULL);
            W32(msg_va + 8, wm);
            W64(msg_va + 16, wp);
            W64(msg_va + 24, lp);
            W32(msg_va + 36, (uint32_t)g_mouse_x);
            W32(msg_va + 40, (uint32_t)g_mouse_y);
            c->rax = 1;
            return;
        }
    }
    c->rax = 0;
}
static void w_TranslateMessage(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void w_DispatchMessageA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t msg_va = c->rcx;
    if (!msg_va) { c->rax = 0; return; }
    uint64_t hwnd = R64(msg_va + 0);
    uint32_t wm   = R32(msg_va + 8);
    uint64_t wp   = R64(msg_va + 16);
    uint64_t lp   = R64(msg_va + 24);
    uint64_t fn   = win32_get_wndproc(hwnd);
    if (fn && wm && wm != 0x0012) {
        c->rax = rt_invoke_win64(c, fn, hwnd, (uint64_t)wm, wp, lp, 0, 0);
        return;
    }
    c->rax = 0;
}
static void w_DefWindowProcA(CPU64 *c, void *ud)   { (void)ud; c->rax = 0; }

void rt_register_win32_64(void) {
    #define REG(name, fn) rt_register_shim(name, fn, NULL)
    /* Kernel32 */
    REG("GetProcessHeap", w_GetProcessHeap); REG("HeapAlloc", w_HeapAlloc);
    REG("HeapReAlloc", w_HeapReAlloc); REG("HeapFree", w_HeapFree);
    REG("VirtualAlloc", w_VirtualAlloc); REG("VirtualFree", w_VirtualFree); REG("VirtualProtect", w_VirtualProtect);
    REG("GetLastError", w_GetLastError); REG("SetLastError", w_SetLastError);
    REG("GetModuleHandleA", w_GetModuleHandleA); REG("GetModuleHandleW", w_GetModuleHandleW);
    REG("LoadLibraryA", w_LoadLibraryA); REG("LoadLibraryW", w_LoadLibraryW);
    REG("LoadLibraryExA", w_LoadLibraryA); REG("LoadLibraryExW", w_LoadLibraryW);
    REG("FreeLibrary", w_FreeLibrary); REG("GetProcAddress", w_GetProcAddress);
    REG("GetModuleFileNameA", w_GetModuleFileNameA); REG("GetModuleFileNameW", w_GetModuleFileNameW);
    REG("QueryPerformanceFrequency", w_QueryPerformanceFrequency);
    REG("QueryPerformanceCounter", w_QueryPerformanceCounter);
    REG("GetTickCount", w_GetTickCount); REG("GetTickCount64", w_GetTickCount64);
    REG("Sleep", w_Sleep); REG("GetCurrentThreadId", w_GetCurrentThreadId);
    REG("GetCurrentProcessId", w_GetCurrentProcessId); REG("GetSystemInfo", w_GetSystemInfo);
    REG("GetNativeSystemInfo", w_GetSystemInfo);
    REG("InitializeCriticalSection", w_InitializeCriticalSection);
    REG("InitializeCriticalSectionAndSpinCount", w_InitializeCriticalSectionAndSpinCount);
    REG("EnterCriticalSection", w_EnterCriticalSection);
    REG("TryEnterCriticalSection", w_TryEnterCriticalSection);
    REG("LeaveCriticalSection", w_LeaveCriticalSection);
    REG("DeleteCriticalSection", w_DeleteCriticalSection);
    REG("CreateThread", w_CreateThread); REG("CreateEventA", w_CreateEventA); REG("CreateEventW", w_CreateEventA);
    REG("SetEvent", w_SetEvent); REG("ResetEvent", w_ResetEvent);
    REG("WaitForSingleObject", w_WaitForSingleObject);
    REG("WaitForSingleObjectEx", w_WaitForSingleObject);
    REG("WaitForMultipleObjects", w_WaitForMultipleObjects);
    REG("GetExitCodeThread", w_GetExitCodeThread);
    REG("CloseHandle", w_CloseHandle);
    REG("TlsAlloc", w_TlsAlloc); REG("TlsGetValue", w_TlsGetValue);
    REG("TlsSetValue", w_TlsSetValue); REG("TlsFree", w_TlsFree);
    REG("GetStdHandle", w_GetStdHandle); REG("WriteFile", w_WriteFile);
    REG("OutputDebugStringA", w_OutputDebugStringA);
    REG("MultiByteToWideChar", w_MultiByteToWideChar); REG("WideCharToMultiByte", w_WideCharToMultiByte);
    REG("ExitProcess", w_ExitProcess);

    /* UCRT / MSVCRT */
    REG("malloc", w_malloc); REG("calloc", w_calloc); REG("realloc", w_realloc); REG("free", w_free);
    REG("memcpy", w_memcpy); REG("memmove", w_memmove); REG("memset", w_memset); REG("memcmp", w_memcmp);
    REG("strlen", w_strlen); REG("strcmp", w_strcmp); REG("strncmp", w_strncmp); REG("_stricmp", w_stricmp);
    REG("puts", w_puts); REG("printf", w_printf); REG("snprintf", w_snprintf); REG("_snprintf", w_snprintf);
    REG("qsort", w_qsort); REG("exit", w_ExitProcess); REG("_exit", w_ExitProcess);

    /* User32 */
    REG("RegisterClassExA", w_RegisterClassExA); REG("RegisterClassExW", w_RegisterClassExA);
    REG("CreateWindowExA", w_CreateWindowExA); REG("CreateWindowExW", w_CreateWindowExW);
    REG("ShowWindow", w_ShowWindow); REG("DestroyWindow", w_DestroyWindow);
    REG("GetClientRect", w_GetClientRect); REG("PeekMessageA", w_PeekMessageA); REG("PeekMessageW", w_PeekMessageA);
    REG("TranslateMessage", w_TranslateMessage); REG("DispatchMessageA", w_DispatchMessageA);
    REG("DispatchMessageW", w_DispatchMessageA); REG("DefWindowProcA", w_DefWindowProcA);
    REG("DefWindowProcW", w_DefWindowProcA);
    #undef REG
}
