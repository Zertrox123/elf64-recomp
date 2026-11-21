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
    pthread_mutex_t ev_mu;
    pthread_cond_t  ev_cv;
    int           ev_signaled;
    int           ev_manual;
    int           fd;
} WinHandleObj;

static pthread_mutex_t g_wh_mu = PTHREAD_MUTEX_INITIALIZER;
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
static void w_VirtualAlloc(CPU64 *c, void *ud) {
    (void)ud;
    size_t sz = (size_t)c->rdx;
    if (sz == 0) sz = 0x4000;
    void *p = mmap((void *)(uintptr_t)c->rcx, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    c->rax = (p == MAP_FAILED) ? 0ULL : (uint64_t)(uintptr_t)p;
}
static void w_VirtualFree(CPU64 *c, void *ud) {
    (void)ud;
    size_t sz = (size_t)c->rdx;
    if (c->rcx && sz) munmap((void *)(uintptr_t)c->rcx, sz);
    c->rax = 1;
}
static void w_VirtualProtect(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r9) W32(c->r9, 0x04 /* PAGE_READWRITE */);
    c->rax = 1;
}

static void w_GetLastError(CPU64 *c, void *ud) { (void)ud; c->rax = g_last_error; }
static void w_SetLastError(CPU64 *c, void *ud) { (void)ud; g_last_error = (uint32_t)c->rcx; }

static void w_GetModuleHandleA(CPU64 *c, void *ud) {
    (void)ud;
    const char *name = (const char *)(uintptr_t)c->rcx;
    uint64_t base = rt_find_module_base(name);
    if (!base && name) base = 0x7090000000ULL; /* synthetic host DLL handle */
    c->rax = base;
}
static void w_GetModuleHandleW(CPU64 *c, void *ud) {
    (void)ud;
    char buf[260];
    utf16_to_utf8((const uint16_t *)(uintptr_t)c->rcx, buf, sizeof(buf));
    uint64_t base = rt_find_module_base(c->rcx ? buf : NULL);
    if (!base && c->rcx) base = 0x7090000000ULL;
    c->rax = base;
}
static void w_LoadLibraryA(CPU64 *c, void *ud) { w_GetModuleHandleA(c, ud); }
static void w_LoadLibraryW(CPU64 *c, void *ud) { w_GetModuleHandleW(c, ud); }
static void w_FreeLibrary(CPU64 *c, void *ud)  { (void)ud; c->rax = 1; }

static void w_GetProcAddress(CPU64 *c, void *ud) {
    (void)ud;
    const char *sym = (const char *)(uintptr_t)c->rdx;
    if (!sym || (uintptr_t)sym < 0x10000) { c->rax = 0; return; }
    uint64_t exp = rt_lookup_export(sym);
    if (exp) { c->rax = exp; return; }
    void *sud = NULL;
    RTShimFn fn = rt_find_shim(sym, &sud);
    c->rax = fn ? rt_alloc_dynamic_thunk(sym, fn, sud) : 0;
}

static void w_GetModuleFileNameA(CPU64 *c, void *ud) {
    (void)ud;
    char *buf = (char *)(uintptr_t)c->rdx;
    uint32_t sz = (uint32_t)c->r8;
    const char *path = (g_rt_module_count > 0) ? g_rt_modules[0].name : "guest.exe";
    size_t n = strlen(path);
    if (n >= sz) n = sz ? sz - 1 : 0;
    if (buf && sz) { memcpy(buf, path, n); buf[n] = '\0'; }
    c->rax = n;
}
static void w_GetModuleFileNameW(CPU64 *c, void *ud) {
    (void)ud;
    const char *path = (g_rt_module_count > 0) ? g_rt_modules[0].name : "guest.exe";
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
typedef struct { uint64_t fn; uint64_t param; } WinThreadStart;

static void *win_thread_tramp(void *p) {
    WinThreadStart st = *(WinThreadStart *)p;
    free(p);
    CPU64 cpu;
    rt_init_thread_cpu(&cpu, 4 * 1024 * 1024);
    uint64_t r = rt_invoke_win64(&cpu, st.fn, st.param, 0, 0, 0, 0, 0);
    rt_destroy_thread_cpu(&cpu);
    return (void *)(uintptr_t)r;
}

static void w_CreateThread(CPU64 *c, void *ud) {
    (void)ud;
    WinThreadStart *st = (WinThreadStart *)malloc(sizeof(WinThreadStart));
    st->fn = c->r8;
    st->param = c->r9;
    WinHandleObj *ho = (WinHandleObj *)calloc(1, sizeof(WinHandleObj));
    ho->kind = WH_THREAD;
    if (pthread_create(&ho->tid, NULL, win_thread_tramp, st) != 0) {
        free(st); free(ho); c->rax = 0; return;
    }
    uint64_t tid_out = win64_arg_i(c, 5);
    if (tid_out) W32(tid_out, (uint32_t)(uintptr_t)ho->tid);
    c->rax = wh_alloc(ho);
}

static void w_CreateEventA(CPU64 *c, void *ud) {
    (void)ud;
    WinHandleObj *ho = (WinHandleObj *)calloc(1, sizeof(WinHandleObj));
    ho->kind = WH_EVENT;
    ho->ev_manual = (int)(c->rdx != 0);
    ho->ev_signaled = (int)(c->r8 != 0);
    pthread_mutex_init(&ho->ev_mu, NULL);
    pthread_cond_init(&ho->ev_cv, NULL);
    c->rax = wh_alloc(ho);
}
static void w_SetEvent(CPU64 *c, void *ud) {
    (void)ud;
    WinHandleObj *ho = wh_get(c->rcx);
    if (!ho || ho->kind != WH_EVENT) { c->rax = 0; return; }
    pthread_mutex_lock(&ho->ev_mu);
    ho->ev_signaled = 1;
    if (ho->ev_manual) pthread_cond_broadcast(&ho->ev_cv);
    else pthread_cond_signal(&ho->ev_cv);
    pthread_mutex_unlock(&ho->ev_mu);
    c->rax = 1;
}
static void w_ResetEvent(CPU64 *c, void *ud) {
    (void)ud;
    WinHandleObj *ho = wh_get(c->rcx);
    if (!ho || ho->kind != WH_EVENT) { c->rax = 0; return; }
    pthread_mutex_lock(&ho->ev_mu);
    ho->ev_signaled = 0;
    pthread_mutex_unlock(&ho->ev_mu);
    c->rax = 1;
}
static void w_WaitForSingleObject(CPU64 *c, void *ud) {
    (void)ud;
    WinHandleObj *ho = wh_get(c->rcx);
    if (!ho) { c->rax = 0xFFFFFFFFU; return; }
    if (ho->kind == WH_THREAD) {
        if (!ho->joined) { pthread_join(ho->tid, NULL); ho->joined = 1; }
        c->rax = 0; /* WAIT_OBJECT_0 */
        return;
    }
    if (ho->kind == WH_EVENT) {
        uint32_t ms = (uint32_t)c->rdx;
        pthread_mutex_lock(&ho->ev_mu);
        if (!ho->ev_signaled && ms == 0) {
            pthread_mutex_unlock(&ho->ev_mu);
            c->rax = 0x102; /* WAIT_TIMEOUT */
            return;
        }
        while (!ho->ev_signaled) pthread_cond_wait(&ho->ev_cv, &ho->ev_mu);
        if (!ho->ev_manual) ho->ev_signaled = 0;
        pthread_mutex_unlock(&ho->ev_mu);
        c->rax = 0;
        return;
    }
    c->rax = 0;
}
static void w_CloseHandle(CPU64 *c, void *ud) {
    (void)ud;
    WinHandleObj *ho = wh_get(c->rcx);
    if (!ho) { c->rax = 1; return; }
    if (ho->kind == WH_FILE && ho->fd >= 0) close(ho->fd);
    pthread_mutex_lock(&g_wh_mu);
    g_wh_slots[c->rcx - 0x100] = NULL;
    pthread_mutex_unlock(&g_wh_mu);
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
    const char *src = (const char *)(uintptr_t)c->r8;
    uint16_t *dst = (uint16_t *)(uintptr_t)win64_arg_i(c, 4);
    int dst_cap = (int)win64_arg_i(c, 5);
    size_t len = strlen(src) + 1;
    if (dst_cap == 0 || !dst) { c->rax = len; return; }
    c->rax = utf8_to_utf16(src, dst, (size_t)dst_cap) + 1;
}
static void w_WideCharToMultiByte(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *src = (const uint16_t *)(uintptr_t)c->r8;
    char *dst = (char *)(uintptr_t)win64_arg_i(c, 4);
    int dst_cap = (int)win64_arg_i(c, 5);
    char tmp[1024];
    size_t n = utf16_to_utf8(src, tmp, sizeof(tmp)) + 1;
    if (dst_cap == 0 || !dst) { c->rax = n; return; }
    size_t cp = n < (size_t)dst_cap ? n : (size_t)dst_cap;
    memcpy(dst, tmp, cp);
    c->rax = cp;
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

/* ---- User32 -> SDL2 Windowing ---- */
typedef struct {
    SDL_Window *sdl;
    int         w, h;
} WinHwndObj;

static WinHwndObj *g_hwnds[64];

SDL_Window *win32_hwnd_to_sdl(uint64_t hwnd) {
    if (hwnd < 0x1000 || hwnd >= 0x1000 + 64) return NULL;
    WinHwndObj *o = g_hwnds[hwnd - 0x1000];
    return o ? o->sdl : NULL;
}

static void w_RegisterClassExA(CPU64 *c, void *ud) { (void)ud; c->rax = 0xC001; }
static void w_CreateWindowExA(CPU64 *c, void *ud) {
    (void)ud;
    const char *title = (const char *)(uintptr_t)c->r8;
    int w = (int)win64_arg_i(c, 6);
    int h = (int)win64_arg_i(c, 7);
    if (w <= 0 || w > 8192) w = 800;
    if (h <= 0 || h > 8192) h = 600;
    if (!SDL_WasInit(SDL_INIT_VIDEO)) SDL_Init(SDL_INIT_VIDEO);
    SDL_Window *win = SDL_CreateWindow(title ? title : "elf64-recomp",
                                       SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                                       w, h, SDL_WINDOW_METAL | SDL_WINDOW_HIDDEN);
    if (!win) { c->rax = 0; return; }
    WinHwndObj *o = (WinHwndObj *)calloc(1, sizeof(WinHwndObj));
    o->sdl = win; o->w = w; o->h = h;
    for (int i = 0; i < 64; i++) {
        if (!g_hwnds[i]) { g_hwnds[i] = o; c->rax = (uint64_t)(0x1000 + i); return; }
    }
    SDL_DestroyWindow(win); free(o); c->rax = 0;
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
    SDL_Event ev;
    if (SDL_PollEvent(&ev) && c->rcx) {
        memset((void *)(uintptr_t)c->rcx, 0, 48);
        if (ev.type == SDL_QUIT) W32(c->rcx + 8, 0x0012 /* WM_QUIT */);
        c->rax = 1;
        return;
    }
    c->rax = 0;
}
static void w_TranslateMessage(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void w_DispatchMessageA(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
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
    REG("InitializeCriticalSection", w_InitializeCriticalSection);
    REG("InitializeCriticalSectionAndSpinCount", w_InitializeCriticalSectionAndSpinCount);
    REG("EnterCriticalSection", w_EnterCriticalSection);
    REG("TryEnterCriticalSection", w_TryEnterCriticalSection);
    REG("LeaveCriticalSection", w_LeaveCriticalSection);
    REG("DeleteCriticalSection", w_DeleteCriticalSection);
    REG("CreateThread", w_CreateThread); REG("CreateEventA", w_CreateEventA); REG("CreateEventW", w_CreateEventA);
    REG("SetEvent", w_SetEvent); REG("ResetEvent", w_ResetEvent);
    REG("WaitForSingleObject", w_WaitForSingleObject); REG("CloseHandle", w_CloseHandle);
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
    REG("CreateWindowExA", w_CreateWindowExA); REG("CreateWindowExW", w_CreateWindowExA);
    REG("ShowWindow", w_ShowWindow); REG("DestroyWindow", w_DestroyWindow);
    REG("GetClientRect", w_GetClientRect); REG("PeekMessageA", w_PeekMessageA); REG("PeekMessageW", w_PeekMessageA);
    REG("TranslateMessage", w_TranslateMessage); REG("DispatchMessageA", w_DispatchMessageA);
    REG("DispatchMessageW", w_DispatchMessageA); REG("DefWindowProcA", w_DefWindowProcA);
    REG("DefWindowProcW", w_DefWindowProcA);
    #undef REG
}
