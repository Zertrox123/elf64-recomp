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
    WH_SEMAPHORE = 4,
} WinHandleKind;

typedef struct {
    WinHandleKind kind;
    pthread_t     tid;
    int           joined;
    int           finished;
    int           ev_signaled;
    int           ev_manual;
    int           fd;
    int32_t       sem_count;
    int32_t       sem_max;
} WinHandleObj;

static pthread_mutex_t g_wh_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_wh_cv = PTHREAD_COND_INITIALIZER;
static WinHandleObj   *g_wh_slots[8192];
static uint32_t        g_wh_next = 0;

static uint64_t wh_alloc(WinHandleObj *obj) {
    pthread_mutex_lock(&g_wh_mu);
    for (uint32_t i = 0; i < 8192; i++) {
        uint32_t idx = (g_wh_next + i) & 8191;
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
    if (h < 0x100 || h >= 0x100 + 8192) return NULL;
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
        "bcrypt", "ws2_32", "wsock32", "dbghelp", "winhttp", "wininet", "d3d11", "dxgi",
        "imm32", "dsound", "rpcrt4", "iphlpapi", "vulkan-1", "sdl2",
        "libfreetype-6", "libfontconfig-1", "libfbxsdk",
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
    if (!base && name && strstr(name, "d3d9")) base = rt_find_module_base("dxvk_d3d9.dll");
    if (name && strstr(name, "shaderapidx9") && rt_find_module_base("shaderapivk.dll"))
        base = rt_find_module_base("shaderapivk.dll");
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
    if (!base && c->rcx && strstr(buf, "d3d9")) base = rt_find_module_base("dxvk_d3d9.dll");
    if (c->rcx && strstr(buf, "shaderapidx9") && rt_find_module_base("shaderapivk.dll"))
        base = rt_find_module_base("shaderapivk.dll");
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
    char cwd[512];
    if (!root || !*root) {
        if (!getcwd(cwd, sizeof(cwd))) strcpy(cwd, "/tmp");
        root = cwd;
    }
    char probe[1024], raw[1024];
    snprintf(probe, sizeof(probe), "%s/%s", root, mname);
    if (access(probe, F_OK) == 0) {
        snprintf(raw, sizeof(raw), "C:%s\\%s", root, mname);
    } else {
        snprintf(probe, sizeof(probe), "%s/bin/x64/%s", root, mname);
        if (access(probe, F_OK) == 0) {
            snprintf(raw, sizeof(raw), "C:%s\\bin\\x64\\%s", root, mname);
        } else {
            snprintf(probe, sizeof(probe), "%s/tf/bin/x64/%s", root, mname);
            if (access(probe, F_OK) == 0) {
                snprintf(raw, sizeof(raw), "C:%s\\tf\\bin\\x64\\%s", root, mname);
            } else {
                snprintf(raw, sizeof(raw), "C:%s\\bin\\win64\\%s", root, mname);
            }
        }
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
extern void win32_poll_audio_callbacks(CPU64 *c);
static void w_Sleep(CPU64 *c, void *ud) {
    (void)ud;
    win32_poll_audio_callbacks(c);
    usleep((useconds_t)c->rcx * 1000U);
    win32_poll_audio_callbacks(c);
}
__thread uint32_t g_win32_tid_override = 0;
uint32_t win32_current_tid(void) {
    if (g_win32_tid_override) return g_win32_tid_override;
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    return (uint32_t)tid;
}
static void w_GetCurrentThreadId(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = win32_current_tid();
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
typedef struct { uint64_t fn; uint64_t param; uint64_t tid_out; WinHandleObj *ho; } WinThreadStart;

static void *win_thread_tramp(void *p) {
    WinThreadStart st = *(WinThreadStart *)p;
    free(p);
    if (st.tid_out) {
        uint64_t tid = 0;
        pthread_threadid_np(NULL, &tid);
        W32(st.tid_out, (uint32_t)tid);
    }
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
    uint64_t tid_out = win64_arg_i(c, 5);
    WinThreadStart *st = (WinThreadStart *)malloc(sizeof(WinThreadStart));
    st->fn = c->r8;
    st->param = c->r9;
    st->tid_out = tid_out;
    st->ho = ho;
    uint64_t handle = wh_alloc(ho);
    if (!handle || pthread_create(&ho->tid, NULL, win_thread_tramp, st) != 0) {
        free(st); free(ho); c->rax = 0; return;
    }
    if (tid_out) {
        uint64_t tid = 0;
        pthread_threadid_np(ho->tid, &tid);
        W32(tid_out, (uint32_t)tid);
    }
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
static void w_CreateSemaphoreA(CPU64 *c, void *ud) {
    (void)ud;
    WinHandleObj *ho = (WinHandleObj *)calloc(1, sizeof(WinHandleObj));
    ho->kind = WH_SEMAPHORE;
    ho->sem_count = (int32_t)c->rdx;
    ho->sem_max = ((int32_t)c->r8 > 0) ? (int32_t)c->r8 : 0x7fffffff;
    c->rax = wh_alloc(ho);
}
static void w_ReleaseSemaphore(CPU64 *c, void *ud) {
    (void)ud;
    int32_t rel = (int32_t)c->rdx;
    pthread_mutex_lock(&g_wh_mu);
    WinHandleObj *ho = wh_get(c->rcx);
    if (!ho || ho->kind != WH_SEMAPHORE || rel <= 0 || (int64_t)ho->sem_count + rel > ho->sem_max) {
        pthread_mutex_unlock(&g_wh_mu);
        c->rax = 0;
        return;
    }
    if (c->r8) W32(c->r8, (uint32_t)ho->sem_count);
    ho->sem_count += rel;
    pthread_cond_broadcast(&g_wh_cv);
    pthread_mutex_unlock(&g_wh_mu);
    c->rax = 1;
}

static int wh_is_signaled_locked(uint64_t h) {
    if (h >= 0x30000ULL && h < 0x40000ULL) return 1; /* mutex */
    WinHandleObj *ho = wh_get(h);
    if (!ho) return 1;
    if (ho->kind == WH_EVENT) return ho->ev_signaled;
    if (ho->kind == WH_SEMAPHORE) return ho->sem_count > 0;
    if (ho->kind == WH_THREAD) return ho->finished;
    return 1;
}

static void wh_consume_locked(uint64_t h) {
    WinHandleObj *ho = wh_get(h);
    if (!ho) return;
    if (ho->kind == WH_EVENT && !ho->ev_manual) ho->ev_signaled = 0;
    else if (ho->kind == WH_SEMAPHORE && ho->sem_count > 0) ho->sem_count--;
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
    else if (c->rcx >= 0x20000ULL && c->rcx < 0x30000ULL) fd = (int)(c->rcx - 0x20000ULL);
    else { WinHandleObj *ho = wh_get(c->rcx); if (ho && ho->kind == WH_FILE) fd = ho->fd; }
    if (fd < 0) { c->rax = 0; return; }
    uint64_t ov = win64_arg_i(c, 4);
    ssize_t n;
    if (ov) {
        uint64_t off = (uint64_t)R32(ov + 16) | ((uint64_t)R32(ov + 20) << 32);
        n = pwrite(fd, (const void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8, (off_t)off);
        if (n >= 0) { W64(ov + 0, 0); W64(ov + 8, (uint64_t)n); }
    } else {
        n = write(fd, (const void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8);
    }
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
extern void win32_poll_audio_callbacks(CPU64 *c);

typedef struct {
    SDL_Window *sdl;
    int         w, h;
    int         borderless;
    int         borderless_fs;
    uint32_t    style;
    uint64_t    wndproc;
} WinHwndObj;

typedef struct {
    char     name[64];
    uint64_t wndproc;
} WinClassObj;

typedef struct {
    uint64_t hwnd;
    uint32_t wm;
    uint64_t wp;
    uint64_t lp;
    int      mx, my;
} WinQueuedMsg;

static WinHwndObj  *g_hwnds[64];
static WinClassObj  g_wndclasses[32];
static int          g_wndclass_count = 0;
static uint64_t     g_last_class_wndproc = 0;
static uint64_t     g_primary_hwnd = 0x1000ULL;
static uint8_t      g_vk_down[256];
static int          g_mouse_x = 640, g_mouse_y = 360;
static WinQueuedMsg g_msg_q[64];
static int          g_msg_head = 0, g_msg_tail = 0;
static int          g_sendmsg_depth = 0;
static uint8_t      g_raw_ring[64][48];
static uint32_t     g_raw_seq = 0;
static int          g_cursor_count = 0;
static int          g_bb_w = 0, g_bb_h = 0;
static int          g_last_wm_size_w = 0, g_last_wm_size_h = 0;

void win32_desktop_size(int *w, int *h) {
    int dw = 1512, dh = 982;
    if (!getenv("ELF64_HEADLESS")) {
        SDL_SetHint(SDL_HINT_VIDEO_MAC_FULLSCREEN_SPACES, "0");
        if (!SDL_WasInit(SDL_INIT_VIDEO)) SDL_Init(SDL_INIT_VIDEO);
        SDL_DisplayMode dm;
        if (SDL_GetDesktopDisplayMode(0, &dm) == 0 && dm.w >= 640 && dm.h >= 480) {
            dw = dm.w; dh = dm.h;
        }
    } else {
        dw = 1920; dh = 1080;
    }
    if (w) *w = dw;
    if (h) *h = dh;
}

static WinHwndObj *win32_find_hwnd_for_sdl(SDL_Window *win) {
    for (int i = 0; i < 64; i++) {
        if (g_hwnds[i] && g_hwnds[i]->sdl == win) return g_hwnds[i];
    }
    return NULL;
}

void win32_fit_window_size(SDL_Window *win, int req_w, int req_h) {
    if (!win || req_w < 64 || req_h < 64 || req_w > 8192 || req_h > 8192) return;
    WinHwndObj *o = win32_find_hwnd_for_sdl(win);
    uint32_t wf = SDL_GetWindowFlags(win);
    int is_fs = (wf & (SDL_WINDOW_FULLSCREEN | SDL_WINDOW_FULLSCREEN_DESKTOP)) != 0;
    int borderless = o ? o->borderless : ((wf & SDL_WINDOW_BORDERLESS) != 0);
    int dw = 1920, dh = 1080;
    win32_desktop_size(&dw, &dh);
    if (!getenv("ELF64_HEADLESS") && borderless && req_w >= dw && req_h >= dh) {
        if (!is_fs) SDL_SetWindowFullscreen(win, SDL_WINDOW_FULLSCREEN_DESKTOP);
        if (o) o->borderless_fs = 1;
        return;
    }
    if (o && o->borderless_fs) {
        if (!getenv("ELF64_HEADLESS")) SDL_SetWindowFullscreen(win, 0);
        o->borderless_fs = 0;
        is_fs = 0;
    }
    if (is_fs) return;
    if (!getenv("ELF64_HEADLESS")) {
        SDL_SetWindowBordered(win, borderless ? SDL_FALSE : SDL_TRUE);
    }
    int fw = req_w, fh = req_h;
    if (!getenv("ELF64_HEADLESS")) {
        SDL_Rect ub;
        if (SDL_GetDisplayUsableBounds(0, &ub) == 0 && ub.w >= 320 && ub.h >= 240) {
            int max_w = ub.w;
            int max_h = (ub.h > 40) ? (ub.h - 36) : ub.h;
            if (fw > max_w || fh > max_h) {
                double sx = (double)max_w / (double)fw;
                double sy = (double)max_h / (double)fh;
                double sc = sx < sy ? sx : sy;
                fw = (int)(fw * sc);
                fh = (int)(fh * sc);
            }
        }
    }
    if (fw < 320) fw = 320;
    if (fh < 200) fh = 200;
    SDL_SetWindowSize(win, fw, fh);
    if (!getenv("ELF64_HEADLESS")) {
        SDL_SetWindowPosition(win, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED);
    }
}

uint32_t win32_get_hwnd_style(uint64_t hwnd) {
    if (hwnd >= 0x1000 && hwnd < 0x1000 + 64 && g_hwnds[hwnd - 0x1000])
        return g_hwnds[hwnd - 0x1000]->style;
    return 0;
}

uint32_t win32_set_hwnd_style(uint64_t hwnd, uint32_t style) {
    if (hwnd < 0x1000 || hwnd >= 0x1000 + 64 || !g_hwnds[hwnd - 0x1000]) return 0;
    WinHwndObj *o = g_hwnds[hwnd - 0x1000];
    uint32_t prev = o->style;
    o->style = style;
    o->borderless = (style & 0x00C00000U) == 0;
    if (o->sdl && !getenv("ELF64_HEADLESS")) {
        win32_fit_window_size(o->sdl, o->w, o->h);
        if (style & 0x10000000U /* WS_VISIBLE */) {
            SDL_ShowWindow(o->sdl);
            SDL_RaiseWindow(o->sdl);
        }
    }
    return prev;
}

void win32_clear_borderless_fs(uint64_t hwnd) {
    if (hwnd >= 0x1000 && hwnd < 0x1000 + 64 && g_hwnds[hwnd - 0x1000])
        g_hwnds[hwnd - 0x1000]->borderless_fs = 0;
}

uint64_t win32_primary_hwnd(void);
static void msg_push(uint64_t hwnd, uint32_t wm, uint64_t wp, uint64_t lp);

void win32_post_size(uint64_t hwnd, int w, int h) {
    if (w < 64 || h < 64) return;
    if (w == g_last_wm_size_w && h == g_last_wm_size_h) return;
    g_last_wm_size_w = w; g_last_wm_size_h = h;
    uint64_t lp = ((uint64_t)(uint16_t)h << 16) | (uint16_t)w;
    msg_push(hwnd ? hwnd : win32_primary_hwnd(), 0x0005 /* WM_SIZE */, 0, lp);
}

void win32_set_hwnd_size(uint64_t hwnd, int w, int h) {
    if (hwnd < 0x1000 || hwnd >= 0x1000 + 64 || !g_hwnds[hwnd - 0x1000]) return;
    if (w > 0 && h > 0) { g_hwnds[hwnd - 0x1000]->w = w; g_hwnds[hwnd - 0x1000]->h = h; }
}
void win32_get_hwnd_size(uint64_t hwnd, int *w, int *h) {
    if (hwnd >= 0x1000 && hwnd < 0x1000 + 64 && g_hwnds[hwnd - 0x1000]) {
        if (w) *w = g_hwnds[hwnd - 0x1000]->w;
        if (h) *h = g_hwnds[hwnd - 0x1000]->h;
        return;
    }
    if (w) *w = g_bb_w > 0 ? g_bb_w : 1280;
    if (h) *h = g_bb_h > 0 ? g_bb_h : 720;
}
void win32_set_backbuffer_size(int w, int h) {
    if (w > 0 && h > 0) { g_bb_w = w; g_bb_h = h; }
}
void win32_get_backbuffer_size(int *w, int *h) {
    if (w) *w = g_bb_w;
    if (h) *h = g_bb_h;
}
static void scale_sdl_mouse(Uint32 win_id, int sx, int sy, int *ox, int *oy) {
    if (g_bb_w > 0 && g_bb_h > 0) {
        SDL_Window *w = SDL_GetWindowFromID(win_id);
        if (w) {
            int ww = 0, wh = 0;
            SDL_GetWindowSize(w, &ww, &wh);
            if (ww > 0 && wh > 0 && (ww != g_bb_w || wh != g_bb_h)) {
                *ox = (int)((int64_t)sx * g_bb_w / ww);
                *oy = (int)((int64_t)sy * g_bb_h / wh);
                return;
            }
        }
    }
    *ox = sx; *oy = sy;
}

void win32_set_mouse_xy(int x, int y) { g_mouse_x = x; g_mouse_y = y; }

int win32_show_cursor(int show) {
    g_cursor_count = show ? 0 : -1;
    if (!getenv("ELF64_HEADLESS")) {
        SDL_bool want = g_cursor_count < 0 ? SDL_TRUE : SDL_FALSE;
        if (SDL_GetRelativeMouseMode() != want) SDL_SetRelativeMouseMode(want);
    }
    return g_cursor_count;
}

uint32_t win32_get_raw_input_data(uint64_t hraw, uint32_t cmd, uint64_t pdata, uint64_t pcb_va) {
    uint32_t need = (cmd == 0x10000005U /* RID_HEADER */) ? 24U : 48U;
    if (!pcb_va) return (uint32_t)-1;
    if (!pdata) { W32(pcb_va, need); return 0; }
    uint32_t cap = R32(pcb_va);
    if (cap < need) { W32(pcb_va, need); return (uint32_t)-1; }
    uint32_t idx = (uint32_t)(hraw - 0x7A0000ULL);
    if (hraw < 0x7A0000ULL || idx >= 64U) return (uint32_t)-1;
    memcpy((void *)(uintptr_t)pdata, g_raw_ring[idx], need);
    W32(pcb_va, need);
    return need;
}

static uint64_t push_raw_mouse(int dx, int dy, uint16_t btn_flags, uint16_t btn_data) {
    uint32_t idx = (g_raw_seq++) & 63U;
    uint8_t *p = g_raw_ring[idx];
    memset(p, 0, 48);
    uint32_t dwType = 0, dwSize = 48;
    uint64_t hDev = 0x10001ULL;
    memcpy(p + 0,  &dwType, 4);
    memcpy(p + 4,  &dwSize, 4);
    memcpy(p + 8,  &hDev, 8);
    memcpy(p + 28, &btn_flags, 2);
    memcpy(p + 30, &btn_data, 2);
    int32_t lx = dx, ly = dy;
    memcpy(p + 36, &lx, 4);
    memcpy(p + 40, &ly, 4);
    return 0x7A0000ULL + idx;
}

static int io_log_enabled(void) {
    static int cached = -1;
    if (cached < 0) cached = (getenv("ELF64_IO_LOG") != NULL) ? 1 : 0;
    return cached;
}

uint64_t win32_primary_hwnd(void) {
    if (g_primary_hwnd >= 0x1000 && g_primary_hwnd < 0x1000 + 64 && g_hwnds[g_primary_hwnd - 0x1000])
        return g_primary_hwnd;
    for (int i = 63; i >= 0; i--) {
        if (g_hwnds[i]) return (uint64_t)(0x1000 + i);
    }
    return 0x1000ULL;
}
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
    if (io_log_enabled())
        fprintf(stderr, "[io] SetWndProc hwnd=0x%llx prev=0x%llx new=0x%llx\n",
                (unsigned long long)hwnd, (unsigned long long)prev, (unsigned long long)fn);
    return prev;
}
int  win32_vk_is_down(int vk) { return (vk >= 0 && vk < 256) ? (int)g_vk_down[vk] : 0; }
void win32_get_mouse_xy(int *x, int *y) { if (x) *x = g_mouse_x; if (y) *y = g_mouse_y; }

/* Bidirectional VK <-> Windows PS/2 Set-1 scancode table for InputSystem. */
static const struct { SDL_Scancode sdl; uint8_t vk; uint8_t vsc; } g_keymap[] = {
    {SDL_SCANCODE_ESCAPE, 0x1B, 0x01}, {SDL_SCANCODE_1, '1', 0x02}, {SDL_SCANCODE_2, '2', 0x03},
    {SDL_SCANCODE_3, '3', 0x04}, {SDL_SCANCODE_4, '4', 0x05}, {SDL_SCANCODE_5, '5', 0x06},
    {SDL_SCANCODE_6, '6', 0x07}, {SDL_SCANCODE_7, '7', 0x08}, {SDL_SCANCODE_8, '8', 0x09},
    {SDL_SCANCODE_9, '9', 0x0A}, {SDL_SCANCODE_0, '0', 0x0B}, {SDL_SCANCODE_MINUS, 0xBD, 0x0C},
    {SDL_SCANCODE_EQUALS, 0xBB, 0x0D}, {SDL_SCANCODE_BACKSPACE, 0x08, 0x0E},
    {SDL_SCANCODE_TAB, 0x09, 0x0F}, {SDL_SCANCODE_Q, 'Q', 0x10}, {SDL_SCANCODE_W, 'W', 0x11},
    {SDL_SCANCODE_E, 'E', 0x12}, {SDL_SCANCODE_R, 'R', 0x13}, {SDL_SCANCODE_T, 'T', 0x14},
    {SDL_SCANCODE_Y, 'Y', 0x15}, {SDL_SCANCODE_U, 'U', 0x16}, {SDL_SCANCODE_I, 'I', 0x17},
    {SDL_SCANCODE_O, 'O', 0x18}, {SDL_SCANCODE_P, 'P', 0x19}, {SDL_SCANCODE_LEFTBRACKET, 0xDB, 0x1A},
    {SDL_SCANCODE_RIGHTBRACKET, 0xDD, 0x1B}, {SDL_SCANCODE_RETURN, 0x0D, 0x1C},
    {SDL_SCANCODE_LCTRL, 0x11, 0x1D}, {SDL_SCANCODE_A, 'A', 0x1E}, {SDL_SCANCODE_S, 'S', 0x1F},
    {SDL_SCANCODE_D, 'D', 0x20}, {SDL_SCANCODE_F, 'F', 0x21}, {SDL_SCANCODE_G, 'G', 0x22},
    {SDL_SCANCODE_H, 'H', 0x23}, {SDL_SCANCODE_J, 'J', 0x24}, {SDL_SCANCODE_K, 'K', 0x25},
    {SDL_SCANCODE_L, 'L', 0x26}, {SDL_SCANCODE_SEMICOLON, 0xBA, 0x27},
    {SDL_SCANCODE_APOSTROPHE, 0xDE, 0x28}, {SDL_SCANCODE_GRAVE, 0xC0, 0x29},
    {SDL_SCANCODE_LSHIFT, 0x10, 0x2A}, {SDL_SCANCODE_BACKSLASH, 0xDC, 0x2B},
    {SDL_SCANCODE_Z, 'Z', 0x2C}, {SDL_SCANCODE_X, 'X', 0x2D}, {SDL_SCANCODE_C, 'C', 0x2E},
    {SDL_SCANCODE_V, 'V', 0x2F}, {SDL_SCANCODE_B, 'B', 0x30}, {SDL_SCANCODE_N, 'N', 0x31},
    {SDL_SCANCODE_M, 'M', 0x32}, {SDL_SCANCODE_COMMA, 0xBC, 0x33}, {SDL_SCANCODE_PERIOD, 0xBE, 0x34},
    {SDL_SCANCODE_SLASH, 0xBF, 0x35}, {SDL_SCANCODE_RSHIFT, 0x10, 0x36},
    {SDL_SCANCODE_LALT, 0x12, 0x38}, {SDL_SCANCODE_SPACE, 0x20, 0x39},
    {SDL_SCANCODE_CAPSLOCK, 0x14, 0x3A},
    {SDL_SCANCODE_F1, 0x70, 0x3B}, {SDL_SCANCODE_F2, 0x71, 0x3C}, {SDL_SCANCODE_F3, 0x72, 0x3D},
    {SDL_SCANCODE_F4, 0x73, 0x3E}, {SDL_SCANCODE_F5, 0x74, 0x3F}, {SDL_SCANCODE_F6, 0x75, 0x40},
    {SDL_SCANCODE_F7, 0x76, 0x41}, {SDL_SCANCODE_F8, 0x77, 0x42}, {SDL_SCANCODE_F9, 0x78, 0x43},
    {SDL_SCANCODE_F10, 0x79, 0x44}, {SDL_SCANCODE_F11, 0x7A, 0x57}, {SDL_SCANCODE_F12, 0x7B, 0x58},
    {SDL_SCANCODE_UP, 0x26, 0x48}, {SDL_SCANCODE_LEFT, 0x25, 0x4B},
    {SDL_SCANCODE_RIGHT, 0x27, 0x4D}, {SDL_SCANCODE_DOWN, 0x28, 0x50},
    {SDL_SCANCODE_DELETE, 0x2E, 0x53}, {SDL_SCANCODE_RCTRL, 0x11, 0x1D}, {SDL_SCANCODE_RALT, 0x12, 0x38},
};

uint32_t win32_map_virtual_key(uint32_t code, uint32_t map_type) {
    size_t n = sizeof(g_keymap) / sizeof(g_keymap[0]);
    if (map_type == 0 || map_type == 4) { /* MAPVK_VK_TO_VSC(_EX) */
        for (size_t i = 0; i < n; i++) if (g_keymap[i].vk == code) return g_keymap[i].vsc;
    } else if (map_type == 1 || map_type == 3) { /* MAPVK_VSC_TO_VK(_EX) */
        for (size_t i = 0; i < n; i++) if (g_keymap[i].vsc == (code & 0xFF)) return g_keymap[i].vk;
    } else if (map_type == 2) { /* MAPVK_VK_TO_CHAR */
        if ((code >= 'A' && code <= 'Z') || (code >= '0' && code <= '9') || code == ' ') return code;
    }
    return 0;
}

static void sdl_key_to_vk_vsc(SDL_Keysym ks, int *out_vk, int *out_vsc) {
    size_t n = sizeof(g_keymap) / sizeof(g_keymap[0]);
    for (size_t i = 0; i < n; i++) {
        if (g_keymap[i].sdl == ks.scancode) { *out_vk = g_keymap[i].vk; *out_vsc = g_keymap[i].vsc; return; }
    }
    if (ks.sym >= 'a' && ks.sym <= 'z') { *out_vk = (int)(ks.sym - 'a' + 'A'); *out_vsc = (int)win32_map_virtual_key((uint32_t)*out_vk, 0); return; }
    if (ks.sym >= '0' && ks.sym <= '9') { *out_vk = (int)ks.sym; *out_vsc = (int)win32_map_virtual_key((uint32_t)*out_vk, 0); return; }
    *out_vk = 0; *out_vsc = 0;
}

static void msg_push(uint64_t hwnd, uint32_t wm, uint64_t wp, uint64_t lp) {
    int next = (g_msg_tail + 1) & 63;
    if (next == g_msg_head) g_msg_head = (g_msg_head + 1) & 63;
    g_msg_q[g_msg_tail] = (WinQueuedMsg){ hwnd, wm, wp, lp, g_mouse_x, g_mouse_y };
    g_msg_tail = next;
}

static uint64_t hwnd_for_sdl_id(Uint32 win_id) {
    for (int i = 0; i < 64; i++) {
        if (g_hwnds[i] && g_hwnds[i]->sdl && SDL_GetWindowID(g_hwnds[i]->sdl) == win_id)
            return (uint64_t)(0x1000 + i);
    }
    return win32_primary_hwnd();
}

static void register_class_common(CPU64 *c, int wide) {
    /* Both WNDCLASS and WNDCLASSEX have lpfnWndProc at +8 and lpszClassName at +64 on Win64. */
    if (c->rcx) {
        uint64_t wp = R64(c->rcx + 8);
        uint64_t cn_va = R64(c->rcx + 64);
        char cname[64] = {0};
        if (cn_va > 0xFFFFULL) {
            if (wide) utf16_to_utf8((const uint16_t *)(uintptr_t)cn_va, cname, sizeof(cname));
            else      snprintf(cname, sizeof(cname), "%s", (const char *)(uintptr_t)cn_va);
        }
        if (wp) {
            g_last_class_wndproc = wp;
            if (cname[0]) {
                int slot = -1;
                for (int i = 0; i < g_wndclass_count; i++) {
                    if (strcasecmp(g_wndclasses[i].name, cname) == 0) { slot = i; break; }
                }
                if (slot < 0 && g_wndclass_count < 32) slot = g_wndclass_count++;
                if (slot >= 0) {
                    snprintf(g_wndclasses[slot].name, sizeof(g_wndclasses[slot].name), "%s", cname);
                    g_wndclasses[slot].wndproc = wp;
                }
            }
            if (io_log_enabled())
                fprintf(stderr, "[io] RegisterClass(%s) wp=0x%llx\n", cname, (unsigned long long)wp);
        }
    }
    c->rax = 0xC001;
}
static void w_RegisterClassA(CPU64 *c, void *ud) { (void)ud; register_class_common(c, 0); }
static void w_RegisterClassW(CPU64 *c, void *ud) { (void)ud; register_class_common(c, 1); }

static uint64_t lookup_class_wndproc(const char *cname) {
    if (cname && cname[0]) {
        for (int i = 0; i < g_wndclass_count; i++) {
            if (strcasecmp(g_wndclasses[i].name, cname) == 0) return g_wndclasses[i].wndproc;
        }
    }
    return g_last_class_wndproc;
}

static void create_window_common(CPU64 *c, const char *cls_name, const char *title) {
    uint32_t style = (uint32_t)c->r9;
    int raw_w = (int)win64_arg_i(c, 6);
    int raw_h = (int)win64_arg_i(c, 7);
    uint64_t parent = win64_arg_i(c, 8);
    int is_helper = (g_primary_hwnd != 0) &&
                    ((raw_w <= 1 && raw_h <= 1) || (style & 0x48000000U /* WS_CHILD | WS_DISABLED */) ||
                     parent != 0 || (cls_name && strcasecmp(cls_name, "shaderdx8") == 0));
    int w = (raw_w > 0 && raw_w <= 8192) ? raw_w : (is_helper ? 1 : 1280);
    int h = (raw_h > 0 && raw_h <= 8192) ? raw_h : (is_helper ? 1 : 720);
    SDL_Window *win = NULL;
    int borderless = (style & 0x00C00000U) == 0;
    if (!is_helper) {
        SDL_SetHint(SDL_HINT_VIDEO_MAC_FULLSCREEN_SPACES, "0");
        if (!SDL_WasInit(SDL_INIT_VIDEO)) SDL_Init(SDL_INIT_VIDEO);
        uint32_t flags = SDL_WINDOW_METAL | ((style & 0x10000000U) ? 0 : SDL_WINDOW_HIDDEN)
                       | (borderless ? SDL_WINDOW_BORDERLESS : 0);
        win = SDL_CreateWindow((title && *title) ? title : "elf64-recomp",
                               SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                               w, h, flags);
        if (!win) { c->rax = 0; return; }
    }
    WinHwndObj *o = (WinHwndObj *)calloc(1, sizeof(WinHwndObj));
    o->sdl = win; o->w = w; o->h = h; o->borderless = borderless; o->style = style; o->wndproc = lookup_class_wndproc(cls_name);
    for (int i = 0; i < 64; i++) {
        if (!g_hwnds[i]) {
            g_hwnds[i] = o;
            uint64_t hwnd = (uint64_t)(0x1000 + i);
            if (!is_helper && w >= 320 && h >= 200) g_primary_hwnd = hwnd;
            if (io_log_enabled())
                fprintf(stderr, "[io] CreateWindow hwnd=0x%llx cls='%s' title='%s' %dx%d helper=%d wp=0x%llx\n",
                        (unsigned long long)hwnd, cls_name ? cls_name : "", title ? title : "",
                        w, h, is_helper, (unsigned long long)o->wndproc);
            c->rax = hwnd;
            return;
        }
    }
    if (win) SDL_DestroyWindow(win);
    free(o); c->rax = 0;
}
static void w_CreateWindowExA(CPU64 *c, void *ud) {
    (void)ud;
    const char *cls = (c->rdx > 0xFFFFULL) ? (const char *)(uintptr_t)c->rdx : "";
    create_window_common(c, cls, c->r8 ? (const char *)(uintptr_t)c->r8 : "");
}
static void w_CreateWindowExW(CPU64 *c, void *ud) {
    (void)ud;
    char cls[64] = {0}, title[256] = {0};
    if (c->rdx > 0xFFFFULL) utf16_to_utf8((const uint16_t *)(uintptr_t)c->rdx, cls, sizeof(cls));
    if (c->r8) utf16_to_utf8((const uint16_t *)(uintptr_t)c->r8, title, sizeof(title));
    create_window_common(c, cls, title);
}
static void w_ShowWindow(CPU64 *c, void *ud) {
    (void)ud;
    SDL_Window *w = win32_hwnd_to_sdl(c->rcx);
    if (w) {
        if (c->rdx && !getenv("ELF64_HEADLESS")) {
            SDL_ShowWindow(w);
            SDL_RaiseWindow(w);
            g_primary_hwnd = c->rcx;
            msg_push(c->rcx, 0x001C /* WM_ACTIVATEAPP */, 1, 0);
            msg_push(c->rcx, 0x0006 /* WM_ACTIVATE */, 1, 0);
            msg_push(c->rcx, 0x0007 /* WM_SETFOCUS */, 0, 0);
        } else if (!c->rdx) {
            SDL_HideWindow(w);
        }
    }
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
    int w = 1280, h = 720;
    win32_get_hwnd_size(c->rcx, &w, &h);
    W32(c->rdx + 0, 0); W32(c->rdx + 4, 0);
    W32(c->rdx + 8, (uint32_t)w); W32(c->rdx + 12, (uint32_t)h);
    c->rax = 1;
}

static uint64_t mouse_mk_flags(void) {
    uint64_t f = 0;
    if (g_vk_down[0x01]) f |= 0x0001; /* MK_LBUTTON */
    if (g_vk_down[0x02]) f |= 0x0002; /* MK_RBUTTON */
    if (g_vk_down[0x10]) f |= 0x0004; /* MK_SHIFT */
    if (g_vk_down[0x11]) f |= 0x0008; /* MK_CONTROL */
    if (g_vk_down[0x04]) f |= 0x0010; /* MK_MBUTTON */
    return f;
}

static void pump_sdl_to_msgq(void) {
    SDL_Event ev;
    while (SDL_PollEvent(&ev)) {
        if (ev.type == SDL_QUIT) {
            SDL_SetRelativeMouseMode(SDL_FALSE);
            msg_push(win32_primary_hwnd(), 0x0012 /* WM_QUIT */, 0, 0);
        } else if (ev.type == SDL_MOUSEMOTION) {
            uint64_t h = hwnd_for_sdl_id(ev.motion.windowID);
            if (SDL_GetRelativeMouseMode()) {
                g_mouse_x += ev.motion.xrel;
                g_mouse_y += ev.motion.yrel;
            } else {
                scale_sdl_mouse(ev.motion.windowID, ev.motion.x, ev.motion.y, &g_mouse_x, &g_mouse_y);
            }
            if (ev.motion.xrel || ev.motion.yrel) {
                uint64_t hraw = push_raw_mouse(ev.motion.xrel, ev.motion.yrel, 0, 0);
                msg_push(h, 0x00FF /* WM_INPUT */, 0, hraw);
            }
            uint64_t lp = ((uint64_t)(uint16_t)g_mouse_y << 16) | (uint16_t)g_mouse_x;
            msg_push(h, 0x0200 /* WM_MOUSEMOVE */, mouse_mk_flags(), lp);
        } else if (ev.type == SDL_MOUSEBUTTONDOWN || ev.type == SDL_MOUSEBUTTONUP) {
            uint64_t h = hwnd_for_sdl_id(ev.button.windowID);
            int dn = (ev.type == SDL_MOUSEBUTTONDOWN);
            if (!SDL_GetRelativeMouseMode())
                scale_sdl_mouse(ev.button.windowID, ev.button.x, ev.button.y, &g_mouse_x, &g_mouse_y);
            uint64_t lp = ((uint64_t)(uint16_t)g_mouse_y << 16) | (uint16_t)g_mouse_x;
            uint32_t wm = 0;
            if (ev.button.button == SDL_BUTTON_LEFT)       { wm = dn ? 0x0201 : 0x0202; g_vk_down[0x01] = (uint8_t)dn; }
            else if (ev.button.button == SDL_BUTTON_RIGHT) { wm = dn ? 0x0204 : 0x0205; g_vk_down[0x02] = (uint8_t)dn; }
            else if (ev.button.button == SDL_BUTTON_MIDDLE){ wm = dn ? 0x0207 : 0x0208; g_vk_down[0x04] = (uint8_t)dn; }
            if (wm) {
                if (io_log_enabled())
                    fprintf(stderr, "[io] mouse btn=%d dn=%d xy=(%d,%d) hwnd=0x%llx\n",
                            ev.button.button, dn, g_mouse_x, g_mouse_y, (unsigned long long)h);
                msg_push(h, wm, mouse_mk_flags(), lp);
            }
        } else if (ev.type == SDL_MOUSEWHEEL) {
            uint64_t h = hwnd_for_sdl_id(ev.wheel.windowID);
            uint64_t wp = ((uint64_t)(uint16_t)(int16_t)(ev.wheel.y * 120) << 16) | mouse_mk_flags();
            uint64_t lp = ((uint64_t)(uint16_t)g_mouse_y << 16) | (uint16_t)g_mouse_x;
            msg_push(h, 0x020A /* WM_MOUSEWHEEL */, wp, lp);
        } else if (ev.type == SDL_KEYDOWN || ev.type == SDL_KEYUP) {
            uint64_t h = hwnd_for_sdl_id(ev.key.windowID);
            int dn = (ev.type == SDL_KEYDOWN);
            int vk = 0, vsc = 0;
            sdl_key_to_vk_vsc(ev.key.keysym, &vk, &vsc);
            if (vk) {
                g_vk_down[vk] = (uint8_t)dn;
                uint32_t wm = dn ? 0x0100 : 0x0101;
                uint64_t lp = 1ULL | ((uint64_t)(vsc & 0xFF) << 16) | (dn ? 0ULL : (3ULL << 30));
                if (io_log_enabled())
                    fprintf(stderr, "[io] key vk=0x%02x vsc=0x%02x dn=%d hwnd=0x%llx\n",
                            vk, vsc, dn, (unsigned long long)h);
                msg_push(h, wm, (uint64_t)vk, lp);
            }
        } else if (ev.type == SDL_TEXTINPUT && ev.text.text[0]) {
            uint64_t h = hwnd_for_sdl_id(ev.text.windowID);
            msg_push(h, 0x0102 /* WM_CHAR */, (uint8_t)ev.text.text[0], 1ULL);
        } else if (ev.type == SDL_WINDOWEVENT) {
            uint64_t h = hwnd_for_sdl_id(ev.window.windowID);
            if (ev.window.event == SDL_WINDOWEVENT_FOCUS_GAINED) {
                msg_push(h, 0x001C /* WM_ACTIVATEAPP */, 1, 0);
                msg_push(h, 0x0006 /* WM_ACTIVATE */, 1, 0);
                msg_push(h, 0x0007 /* WM_SETFOCUS */, 0, 0);
            } else if (ev.window.event == SDL_WINDOWEVENT_FOCUS_LOST) {
                SDL_SetRelativeMouseMode(SDL_FALSE);
                msg_push(h, 0x001C /* WM_ACTIVATEAPP */, 0, 0);
                msg_push(h, 0x0008 /* WM_KILLFOCUS */, 0, 0);
            }
        }
    }
}

static void w_PeekMessageA(CPU64 *c, void *ud) {
    (void)ud;
    win32_poll_audio_callbacks(c);
    pump_sdl_to_msgq();
    uint64_t msg_va = c->rcx;
    uint32_t remove = (uint32_t)win64_arg_i(c, 4);
    if (g_msg_head != g_msg_tail && msg_va) {
        WinQueuedMsg m = g_msg_q[g_msg_head];
        if (remove & 1U) g_msg_head = (g_msg_head + 1) & 63;
        memset((void *)(uintptr_t)msg_va, 0, 48);
        W64(msg_va + 0, m.hwnd);
        W32(msg_va + 8, m.wm);
        W64(msg_va + 16, m.wp);
        W64(msg_va + 24, m.lp);
        W32(msg_va + 36, (uint32_t)m.mx);
        W32(msg_va + 40, (uint32_t)m.my);
        c->rax = 1;
        return;
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
        if (io_log_enabled() && wm != 0x0200 && wm != 0x00FF)
            fprintf(stderr, "[io] Dispatch hwnd=0x%llx wm=0x%x fn=0x%llx\n",
                    (unsigned long long)hwnd, wm, (unsigned long long)fn);
        c->rax = rt_invoke_win64(c, fn, hwnd, (uint64_t)wm, wp, lp, 0, 0);
        return;
    }
    c->rax = 0;
}
static void w_CallWindowProc(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t fn = c->rcx;
    if (fn > 0x10000ULL && g_sendmsg_depth < 16) {
        g_sendmsg_depth++;
        c->rax = rt_invoke_win64(c, fn, c->rdx, c->r8, c->r9, win64_arg_i(c, 4), 0, 0);
        g_sendmsg_depth--;
        return;
    }
    c->rax = 0;
}
static void w_SendMessage(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t fn = win32_get_wndproc(c->rcx);
    if (fn > 0x10000ULL && g_sendmsg_depth < 16) {
        g_sendmsg_depth++;
        c->rax = rt_invoke_win64(c, fn, c->rcx, c->rdx, c->r8, c->r9, 0, 0);
        g_sendmsg_depth--;
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
    REG("CreateThread", w_CreateThread); REG("_beginthreadex", w_CreateThread);
    REG("CreateEventA", w_CreateEventA); REG("CreateEventW", w_CreateEventA);
    REG("SetEvent", w_SetEvent); REG("ResetEvent", w_ResetEvent);
    REG("CreateSemaphoreA", w_CreateSemaphoreA); REG("CreateSemaphoreW", w_CreateSemaphoreA);
    REG("ReleaseSemaphore", w_ReleaseSemaphore);
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
    REG("RegisterClassA", w_RegisterClassA); REG("RegisterClassW", w_RegisterClassW);
    REG("RegisterClassExA", w_RegisterClassA); REG("RegisterClassExW", w_RegisterClassW);
    REG("CreateWindowExA", w_CreateWindowExA); REG("CreateWindowExW", w_CreateWindowExW);
    REG("ShowWindow", w_ShowWindow); REG("DestroyWindow", w_DestroyWindow);
    REG("GetClientRect", w_GetClientRect); REG("PeekMessageA", w_PeekMessageA); REG("PeekMessageW", w_PeekMessageA);
    REG("TranslateMessage", w_TranslateMessage); REG("DispatchMessageA", w_DispatchMessageA);
    REG("DispatchMessageW", w_DispatchMessageA); REG("DefWindowProcA", w_DefWindowProcA);
    REG("DefWindowProcW", w_DefWindowProcA);
    REG("CallWindowProcA", w_CallWindowProc); REG("CallWindowProcW", w_CallWindowProc);
    REG("SendMessageA", w_SendMessage); REG("SendMessageW", w_SendMessage);
    #undef REG
}
