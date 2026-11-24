#include "runtime64.h"
#include "win64_abi.h"
#include <SDL.h>

#include <CoreGraphics/CoreGraphics.h>
#include <CoreText/CoreText.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <locale.h>
#include <mach/mach.h>
#include <malloc/malloc.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <wctype.h>

/* ---- Local UTF-16 helpers + Windows->POSIX path normalization ---- */
static size_t w16_to_u8(const uint16_t *src, char *dst, size_t cap) {
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

static size_t u8_to_w16(const char *src, uint16_t *dst, size_t cap) {
    size_t out = 0;
    if (!src) { if (cap) dst[0] = 0; return 0; }
    while (*src && out + 1 < cap) dst[out++] = (uint8_t)*src++;
    if (cap) dst[out] = 0;
    return out;
}

static size_t posix_to_win_path(const char *px, char *out, size_t cap) {
    if (!px || cap < 4) { if (cap) out[0] = '\0'; return 0; }
    size_t j = 0;
    if (px[0] == '/') { out[j++] = 'C'; out[j++] = ':'; }
    for (size_t i = 0; px[i] && j + 1 < cap; i++) {
        out[j++] = (px[i] == '/') ? '\\' : px[i];
    }
    out[j] = '\0';
    return j;
}

static void win_path_to_posix(const char *in, char *out, size_t cap) {
    if (!in || cap == 0) { if (cap) out[0] = '\0'; return; }
    /* Strip optional \\?\ prefix or X: drive prefix */
    if (strncmp(in, "\\\\?\\", 4) == 0) in += 4;
    if (isalpha((unsigned char)in[0]) && in[1] == ':') in += 2;
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < cap; i++) {
        out[j++] = (in[i] == '\\') ? '/' : in[i];
    }
    out[j] = '\0';
}

/* ---- Time & FILETIME (100ns ticks since 1601-01-01) ---- */
static uint64_t unix_to_filetime(time_t sec, long nsec) {
    return ((uint64_t)sec + 11644473600ULL) * 10000000ULL + (uint64_t)(nsec / 100);
}

static void w_GetSystemTimeAsFileTime(CPU64 *c, void *ud) {
    (void)ud;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t ft = unix_to_filetime(tv.tv_sec, tv.tv_usec * 1000L);
    if (c->rcx) W64(c->rcx, ft);
}

static void write_systemtime(uint64_t dst, const struct tm *tm, uint16_t ms) {
    if (!dst || !tm) return;
    W16(dst + 0,  (uint16_t)(tm->tm_year + 1900));
    W16(dst + 2,  (uint16_t)(tm->tm_mon + 1));
    W16(dst + 4,  (uint16_t)tm->tm_wday);
    W16(dst + 6,  (uint16_t)tm->tm_mday);
    W16(dst + 8,  (uint16_t)tm->tm_hour);
    W16(dst + 10, (uint16_t)tm->tm_min);
    W16(dst + 12, (uint16_t)tm->tm_sec);
    W16(dst + 14, ms);
}

static void w_GetSystemTime(CPU64 *c, void *ud) {
    (void)ud;
    struct timeval tv; gettimeofday(&tv, NULL);
    struct tm tm; gmtime_r(&tv.tv_sec, &tm);
    write_systemtime(c->rcx, &tm, (uint16_t)(tv.tv_usec / 1000));
}
static void w_GetLocalTime(CPU64 *c, void *ud) {
    (void)ud;
    struct timeval tv; gettimeofday(&tv, NULL);
    struct tm tm; localtime_r(&tv.tv_sec, &tm);
    write_systemtime(c->rcx, &tm, (uint16_t)(tv.tv_usec / 1000));
}
static void w_FileTimeToSystemTime(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t ft = c->rcx ? R64(c->rcx) : 0;
    time_t sec = (ft >= 116444736000000000ULL) ? (time_t)((ft - 116444736000000000ULL) / 10000000ULL) : 0;
    struct tm tm; gmtime_r(&sec, &tm);
    write_systemtime(c->rdx, &tm, (uint16_t)((ft / 10000ULL) % 1000ULL));
    c->rax = 1;
}
static void w_SystemTimeToFileTime(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W64(c->rdx, 116444736000000000ULL);
    c->rax = 1;
}
static void w_SystemTimeToTzSpecificLocalTime(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx && c->r8) memcpy((void *)(uintptr_t)c->r8, (const void *)(uintptr_t)c->rdx, 16);
    c->rax = 1;
}
static void w_GetTimeZoneInformation(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) memset((void *)(uintptr_t)c->rcx, 0, 172);
    c->rax = 0; /* TIME_ZONE_ID_UNKNOWN */
}

/* ---- FLS (Fiber Local Storage) ---- */
#define MAX_WIN_FLS 128
static pthread_key_t   g_fls_keys[MAX_WIN_FLS];
static int             g_fls_used[MAX_WIN_FLS];
static pthread_mutex_t g_fls_mu = PTHREAD_MUTEX_INITIALIZER;

static void w_FlsAlloc(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_fls_mu);
    for (int i = 0; i < MAX_WIN_FLS; i++) {
        if (!g_fls_used[i]) {
            g_fls_used[i] = 1;
            pthread_key_create(&g_fls_keys[i], NULL);
            pthread_mutex_unlock(&g_fls_mu);
            c->rax = (uint64_t)i;
            return;
        }
    }
    pthread_mutex_unlock(&g_fls_mu);
    c->rax = 0xFFFFFFFFU;
}
static void w_FlsGetValue(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx = (uint32_t)c->rcx;
    c->rax = (idx < MAX_WIN_FLS && g_fls_used[idx])
        ? (uint64_t)(uintptr_t)pthread_getspecific(g_fls_keys[idx]) : 0;
}
static void w_FlsSetValue(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx = (uint32_t)c->rcx;
    if (idx < MAX_WIN_FLS && g_fls_used[idx]) {
        pthread_setspecific(g_fls_keys[idx], (void *)(uintptr_t)c->rdx);
        c->rax = 1;
    } else c->rax = 0;
}
static void w_FlsFree(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx = (uint32_t)c->rcx;
    if (idx < MAX_WIN_FLS && g_fls_used[idx]) {
        pthread_key_delete(g_fls_keys[idx]);
        g_fls_used[idx] = 0;
        c->rax = 1;
    } else c->rax = 0;
}

/* ---- SRWLock, ConditionVariable, InitOnce, SList ---- */
typedef struct { uint64_t addr; pthread_mutex_t *mu; } SrwEnt;
typedef struct { uint64_t addr; pthread_cond_t  *cv; } CvEnt;
static pthread_mutex_t g_srw_map_mu = PTHREAD_MUTEX_INITIALIZER;
static SrwEnt *g_srw_map = NULL; static size_t g_srw_n = 0, g_srw_cap = 0;
static CvEnt  *g_cv_map  = NULL; static size_t g_cv_n  = 0, g_cv_cap  = 0;

static pthread_mutex_t *get_srw(uint64_t addr) {
    pthread_mutex_lock(&g_srw_map_mu);
    for (size_t i = 0; i < g_srw_n; i++) {
        if (g_srw_map[i].addr == addr) {
            pthread_mutex_t *m = g_srw_map[i].mu;
            pthread_mutex_unlock(&g_srw_map_mu);
            return m;
        }
    }
    if (g_srw_n == g_srw_cap) {
        g_srw_cap = g_srw_cap ? g_srw_cap * 2 : 64;
        g_srw_map = (SrwEnt *)realloc(g_srw_map, g_srw_cap * sizeof(SrwEnt));
    }
    pthread_mutex_t *m = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    pthread_mutex_init(m, NULL);
    g_srw_map[g_srw_n].addr = addr; g_srw_map[g_srw_n].mu = m; g_srw_n++;
    pthread_mutex_unlock(&g_srw_map_mu);
    return m;
}
static pthread_cond_t *get_cv(uint64_t addr) {
    pthread_mutex_lock(&g_srw_map_mu);
    for (size_t i = 0; i < g_cv_n; i++) {
        if (g_cv_map[i].addr == addr) {
            pthread_cond_t *cv = g_cv_map[i].cv;
            pthread_mutex_unlock(&g_srw_map_mu);
            return cv;
        }
    }
    if (g_cv_n == g_cv_cap) {
        g_cv_cap = g_cv_cap ? g_cv_cap * 2 : 64;
        g_cv_map = (CvEnt *)realloc(g_cv_map, g_cv_cap * sizeof(CvEnt));
    }
    pthread_cond_t *cv = (pthread_cond_t *)calloc(1, sizeof(pthread_cond_t));
    pthread_cond_init(cv, NULL);
    g_cv_map[g_cv_n].addr = addr; g_cv_map[g_cv_n].cv = cv; g_cv_n++;
    pthread_mutex_unlock(&g_srw_map_mu);
    return cv;
}

static void w_AcquireSRWLockExclusive(CPU64 *c, void *ud)    { (void)ud; pthread_mutex_lock(get_srw(c->rcx)); }
static void w_TryAcquireSRWLockExclusive(CPU64 *c, void *ud) { (void)ud; c->rax = (pthread_mutex_trylock(get_srw(c->rcx)) == 0) ? 1 : 0; }
static void w_ReleaseSRWLockExclusive(CPU64 *c, void *ud)    { (void)ud; pthread_mutex_unlock(get_srw(c->rcx)); }
static void w_InitializeConditionVariable(CPU64 *c, void *ud){ (void)ud; get_cv(c->rcx); }
static void w_WakeConditionVariable(CPU64 *c, void *ud)      { (void)ud; pthread_cond_signal(get_cv(c->rcx)); }
static void w_WakeAllConditionVariable(CPU64 *c, void *ud)   { (void)ud; pthread_cond_broadcast(get_cv(c->rcx)); }
static void w_SleepConditionVariableSRW(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t ms = (uint32_t)c->r8;
    if (ms == 0xFFFFFFFFU) {
        c->rax = (pthread_cond_wait(get_cv(c->rcx), get_srw(c->rdx)) == 0) ? 1 : 0;
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (time_t)(ms / 1000U);
        ts.tv_nsec += (long)(ms % 1000U) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        c->rax = (pthread_cond_timedwait(get_cv(c->rcx), get_srw(c->rdx), &ts) == 0) ? 1 : 0;
    }
}
static void w_SleepConditionVariableCS(CPU64 *c, void *ud)   { w_SleepConditionVariableSRW(c, ud); }
static void w_InitializeSListHead(CPU64 *c, void *ud)        { (void)ud; if (c->rcx) memset((void *)(uintptr_t)c->rcx, 0, 16); }
static void w_InterlockedFlushSList(CPU64 *c, void *ud)      { (void)ud; c->rax = 0; }

static void w_InitOnceBeginInitialize(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t *once = (uint64_t *)(uintptr_t)c->rcx;
    uint32_t flags = (uint32_t)c->rdx;
    uint64_t pending_va = c->r8;
    uint64_t ctx_va = c->r9;
    uint64_t cur = __atomic_load_n(once, __ATOMIC_ACQUIRE);
    if (cur & 2ULL) { /* already completed */
        if (pending_va) W32(pending_va, 0);
        if (ctx_va) W64(ctx_va, cur & ~3ULL);
        c->rax = 1;
        return;
    }
    if (flags & 1) { /* INIT_ONCE_CHECK_ONLY */
        if (pending_va) W32(pending_va, 0);
        c->rax = 0;
        return;
    }
    if (pending_va) W32(pending_va, 1);
    c->rax = 1;
}
static void w_InitOnceComplete(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t *once = (uint64_t *)(uintptr_t)c->rcx;
    uint64_t ctx = c->r8;
    __atomic_store_n(once, (ctx & ~3ULL) | 2ULL, __ATOMIC_RELEASE);
    c->rax = 1;
}
static void w_InitOnceExecuteOnce(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t *once = (uint64_t *)(uintptr_t)c->rcx;
    if (!(__atomic_load_n(once, __ATOMIC_ACQUIRE) & 2ULL)) {
        rt_invoke_win64(c, c->rdx, c->rcx, c->r8, c->r9, 0, 0, 0);
        __atomic_store_n(once, 2ULL, __ATOMIC_RELEASE);
    }
    c->rax = 1;
}

/* ---- Process / Environment / CommandLine / StartupInfo ---- */
static char     *g_cmdline_a = NULL;
static uint16_t *g_cmdline_w = NULL;

static void build_cmdlines(void) {
    if (g_cmdline_a) return;
    size_t cap = 4096;
    g_cmdline_a = (char *)calloc(1, cap);
    size_t pos = 0;
    for (int i = 0; i < g_rt_argc; i++) {
        if (i > 0 && pos + 1 < cap) g_cmdline_a[pos++] = ' ';
        const char *a = g_rt_argv[i];
        int need_q = (strchr(a, ' ') != NULL);
        if (need_q && pos + 1 < cap) g_cmdline_a[pos++] = '"';
        for (size_t k = 0; a[k] && pos + 2 < cap; k++) g_cmdline_a[pos++] = a[k];
        if (need_q && pos + 1 < cap) g_cmdline_a[pos++] = '"';
    }
    g_cmdline_a[pos] = '\0';
    g_cmdline_w = (uint16_t *)calloc(pos + 2, 2);
    u8_to_w16(g_cmdline_a, g_cmdline_w, pos + 2);
}

static void w_GetCommandLineA(CPU64 *c, void *ud) { (void)ud; build_cmdlines(); c->rax = (uint64_t)(uintptr_t)g_cmdline_a; }
static void w_GetCommandLineW(CPU64 *c, void *ud) { (void)ud; build_cmdlines(); c->rax = (uint64_t)(uintptr_t)g_cmdline_w; }

static void w_GetEnvironmentStringsW(CPU64 *c, void *ud) {
    (void)ud;
    size_t total = 4;
    for (char **e = g_rt_envp; e && *e; e++) total += strlen(*e) + 1;
    uint16_t *buf = (uint16_t *)calloc(total + 2, 2);
    size_t pos = 0;
    for (char **e = g_rt_envp; e && *e; e++) {
        pos += u8_to_w16(*e, buf + pos, total - pos) + 1;
    }
    buf[pos] = 0;
    c->rax = (uint64_t)(uintptr_t)buf;
}
static void w_FreeEnvironmentStringsW(CPU64 *c, void *ud) { (void)ud; free((void *)(uintptr_t)c->rcx); c->rax = 1; }
static void w_GetEnvironmentVariableA(CPU64 *c, void *ud) {
    (void)ud;
    const char *v = c->rcx ? getenv((const char *)(uintptr_t)c->rcx) : NULL;
    if (!v) { c->rax = 0; return; }
    size_t n = strlen(v);
    if (c->rdx && c->r8 > n) { memcpy((void *)(uintptr_t)c->rdx, v, n + 1); c->rax = n; }
    else c->rax = n + 1;
}
static void w_SetEnvironmentVariableA(CPU64 *c, void *ud) {
    (void)ud;
    const char *k = (const char *)(uintptr_t)c->rcx;
    const char *v = (const char *)(uintptr_t)c->rdx;
    if (k) { if (v) setenv(k, v, 1); else unsetenv(k); }
    c->rax = 1;
}
static void w_SetEnvironmentVariableW(CPU64 *c, void *ud) {
    (void)ud;
    char k[256], v[1024];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, k, sizeof(k));
    if (c->rdx) { w16_to_u8((const uint16_t *)(uintptr_t)c->rdx, v, sizeof(v)); setenv(k, v, 1); }
    else unsetenv(k);
    c->rax = 1;
}

static void w_GetStartupInfoW(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) { memset((void *)(uintptr_t)c->rcx, 0, 104); W32(c->rcx, 104); }
}
static void w_GetCurrentProcess(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)-1LL; }
static void w_GetCurrentThread(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)-2LL; }
static void w_GetCurrentProcessorNumber(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void w_GetThreadId(CPU64 *c, void *ud) { (void)ud; c->rax = c->rcx ? (uint32_t)c->rcx : 1U; }
static void w_EncodePointer(CPU64 *c, void *ud)     { (void)ud; c->rax = c->rcx; }
static void w_DecodePointer(CPU64 *c, void *ud)     { (void)ud; c->rax = c->rcx; }
static void w_IsDebuggerPresent(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void w_IsProcessorFeaturePresent(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t f = (uint32_t)c->rcx;
    /* SSE(6), SSE2(10), SSE3(13), CMPXCHG16B(14), RDTSC(8), FASTFAIL(23) */
    c->rax = (f == 6 || f == 8 || f == 10 || f == 13 || f == 23) ? 1 : 0;
}
static void w_GetACP(CPU64 *c, void *ud) { (void)ud; c->rax = 65001; /* UTF-8 */ }
static void w_GetOEMCP(CPU64 *c, void *ud) { (void)ud; c->rax = 65001; }
static void w_IsValidCodePage(CPU64 *c, void *ud) { (void)ud; c->rax = 1; }
static void w_GetCPInfo(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) { memset((void *)(uintptr_t)c->rdx, 0, 20); W32(c->rdx, 1); W8(c->rdx + 4, '?'); }
    c->rax = 1;
}
static void w_GetFileType(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx <= 3) c->rax = 2; /* FILE_TYPE_CHAR */
    else c->rax = 1; /* FILE_TYPE_DISK */
}
static void w_GetModuleHandleExW(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t flags = (uint32_t)c->rcx;
    uint64_t out_va = c->r8;
    uint64_t base = 0;
    if (flags & 4) { /* GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS */
        uint64_t addr = c->rdx;
        for (size_t i = 0; i < g_rt_module_count; i++) {
            if (addr >= g_rt_modules[i].map_addr && addr < g_rt_modules[i].map_addr + g_rt_modules[i].mem_size) {
                base = g_rt_modules[i].map_addr;
                break;
            }
        }
    } else if (c->rdx) {
        char buf[260];
        w16_to_u8((const uint16_t *)(uintptr_t)c->rdx, buf, sizeof(buf));
        base = rt_find_module_base(buf);
    } else {
        base = rt_find_module_base(NULL);
    }
    if (out_va) W64(out_va, base);
    c->rax = (base != 0) ? 1 : 0;
}
static void w_HeapSize(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = c->r8 ? (uint64_t)malloc_size((const void *)(uintptr_t)c->r8) : 0;
}
static void w_msize(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = c->rcx ? (uint64_t)malloc_size((const void *)(uintptr_t)c->rcx) : 0;
}
static void w_LocalFree(CPU64 *c, void *ud){ (void)ud; free((void *)(uintptr_t)c->rcx); c->rax = 0; }
static void w_GetLargePageMinimum(CPU64 *c, void *ud) { (void)ud; c->rax = 2 * 1024 * 1024; }
static void w_GetVersion(CPU64 *c, void *ud) { (void)ud; c->rax = 0x4A61000AULL; /* Win10 */ }
static void w_GetVersionExA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) {
        W32(c->rcx + 4, 10); W32(c->rcx + 8, 0); W32(c->rcx + 12, 19045); W32(c->rcx + 16, 2);
    }
    c->rax = 1;
}
static void w_GlobalMemoryStatusEx(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) { c->rax = 0; return; }
    uint64_t memsize = 16ULL * 1024 * 1024 * 1024;
    size_t sz = sizeof(memsize);
    sysctlbyname("hw.memsize", &memsize, &sz, NULL, 0);
    W32(c->rcx + 0, 64); W32(c->rcx + 4, 30);
    W64(c->rcx + 8, memsize); W64(c->rcx + 16, memsize / 2);
    W64(c->rcx + 24, memsize); W64(c->rcx + 32, memsize / 2);
    W64(c->rcx + 40, 1ULL << 46); W64(c->rcx + 48, 1ULL << 45);
    W64(c->rcx + 56, 0);
    c->rax = 1;
}
static void w_GetProcessAffinityMask(CPU64 *c, void *ud) {
    (void)ud;
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t mask = (ncpu >= 64) ? ~0ULL : ((1ULL << ncpu) - 1ULL);
    if (c->rdx) W64(c->rdx, mask);
    if (c->r8)  W64(c->r8, mask);
    c->rax = 1;
}
static void w_GetNumaHighestNodeNumber(CPU64 *c, void *ud) { (void)ud; if (c->rcx) W32(c->rcx, 0); c->rax = 1; }
static void w_GetNumaProcessorNode(CPU64 *c, void *ud)     { (void)ud; if (c->rdx) W8(c->rdx, 0); c->rax = 1; }
static void w_GetNumaNodeProcessorMask(CPU64 *c, void *ud) { (void)ud; if (c->rdx) W64(c->rdx, 0xFFULL); c->rax = 1; }
static void w_SwitchToThread(CPU64 *c, void *ud) { (void)ud; sched_yield(); c->rax = 1; }
static void w_SleepEx(CPU64 *c, void *ud) { (void)ud; usleep((useconds_t)c->rcx * 1000U); c->rax = 0; }
static void w_SetUnhandledExceptionFilter(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void w_UnhandledExceptionFilter(CPU64 *c, void *ud)    { (void)ud; c->rax = 0; }
static void w_RtlCaptureStackBackTrace(CPU64 *c, void *ud)    { (void)ud; c->rax = 0; }
static void w_RtlLookupFunctionEntry(CPU64 *c, void *ud)      { (void)ud; c->rax = 0; }
static void w_RtlCaptureContext(CPU64 *c, void *ud)           { (void)ud; if (c->rcx) memset((void *)(uintptr_t)c->rcx, 0, 1232); }
static void w_RtlPcToFileHeader(CPU64 *c, void *ud)           { (void)ud; if (c->rdx) W64(c->rdx, 0); c->rax = 0; }
static void w_TerminateProcess(CPU64 *c, void *ud) {
    (void)ud;
    if (getenv("ELF64_TRACE")) {
        fprintf(stderr, "[win32] TerminateProcess(code=%d) caller=0x%llx\n",
                (int)c->rdx, (unsigned long long)R64(c->rsp));
        void *bt[16];
        int n = backtrace(bt, 16);
        backtrace_symbols_fd(bt, n, 2);
    }
    c->exit_code = (int)c->rdx; c->halted = 1; c->rax = 1;
}
static void w_ExitThread(CPU64 *c, void *ud)                  { (void)ud; c->halted = 1; }

/* ---- Filesystem (CreateFileA/W, ReadFile, GetFileAttributesA/W, Dir, Paths) ---- */
static void w_GetCurrentDirectoryA(CPU64 *c, void *ud) {
    (void)ud;
    char cwd[1024], win[1024];
    if (!getcwd(cwd, sizeof(cwd))) { c->rax = 0; return; }
    size_t n = posix_to_win_path(cwd, win, sizeof(win));
    if (c->rdx && c->rcx > n) { memcpy((void *)(uintptr_t)c->rdx, win, n + 1); c->rax = n; }
    else c->rax = n + 1;
}
static void w_GetCurrentDirectoryW(CPU64 *c, void *ud) {
    (void)ud;
    char cwd[1024], win[1024];
    if (!getcwd(cwd, sizeof(cwd))) { c->rax = 0; return; }
    size_t n = posix_to_win_path(cwd, win, sizeof(win));
    if (c->rdx && c->rcx > n) c->rax = u8_to_w16(win, (uint16_t *)(uintptr_t)c->rdx, (size_t)c->rcx);
    else c->rax = n + 1;
}
static void w_SetCurrentDirectoryW(CPU64 *c, void *ud) {
    (void)ud;
    char u8[1024], px[1024];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    win_path_to_posix(u8, px, sizeof(px));
    c->rax = (chdir(px) == 0) ? 1 : 0;
}
static void w_GetFullPathNameW(CPU64 *c, void *ud) {
    (void)ud;
    char u8[1024], px[1024], resolved[1024], win[1024];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    win_path_to_posix(u8, px, sizeof(px));
    const char *res = realpath(px, resolved) ? resolved : px;
    size_t n = posix_to_win_path(res, win, sizeof(win));
    if (c->r8 && c->rdx > n) {
        u8_to_w16(win, (uint16_t *)(uintptr_t)c->r8, (size_t)c->rdx);
        if (c->r9) {
            uint16_t *wbuf = (uint16_t *)(uintptr_t)c->r8;
            uint16_t *last = wbuf;
            for (uint16_t *p = wbuf; *p; p++) if (*p == '/' || *p == '\\') last = p + 1;
            W64(c->r9, (uint64_t)(uintptr_t)last);
        }
        c->rax = n;
    } else c->rax = n + 1;
}
static uint32_t posix_stat_attrs(const char *path) {
    char px[1024];
    win_path_to_posix(path, px, sizeof(px));
    struct stat st;
    if (stat(px, &st) != 0) return 0xFFFFFFFFU;
    return S_ISDIR(st.st_mode) ? 0x10U : 0x80U;
}
static void w_GetFileAttributesA(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = c->rcx ? posix_stat_attrs((const char *)(uintptr_t)c->rcx) : 0xFFFFFFFFU;
}
static void w_GetFileAttributesW(CPU64 *c, void *ud) {
    (void)ud;
    char u8[1024];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    c->rax = posix_stat_attrs(u8);
}
static void w_GetFileAttributesExA(CPU64 *c, void *ud) {
    (void)ud;
    char px[1024];
    win_path_to_posix((const char *)(uintptr_t)c->rcx, px, sizeof(px));
    struct stat st;
    if (stat(px, &st) != 0) { c->rax = 0; return; }
    if (c->r8) {
        memset((void *)(uintptr_t)c->r8, 0, 36);
        W32(c->r8 + 0, S_ISDIR(st.st_mode) ? 0x10U : 0x80U);
        W32(c->r8 + 28, (uint32_t)((uint64_t)st.st_size >> 32));
        W32(c->r8 + 32, (uint32_t)st.st_size);
    }
    c->rax = 1;
}
static void w_GetFileAttributesExW(CPU64 *c, void *ud) {
    (void)ud;
    char u8[1024], px[1024];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    win_path_to_posix(u8, px, sizeof(px));
    struct stat st;
    if (stat(px, &st) != 0) { c->rax = 0; return; }
    if (c->r8) {
        memset((void *)(uintptr_t)c->r8, 0, 36);
        W32(c->r8 + 0, S_ISDIR(st.st_mode) ? 0x10U : 0x80U);
        W32(c->r8 + 28, (uint32_t)((uint64_t)st.st_size >> 32));
        W32(c->r8 + 32, (uint32_t)st.st_size);
    }
    c->rax = 1;
}
static void w_CreateDirectoryA(CPU64 *c, void *ud) {
    (void)ud;
    char px[1024]; win_path_to_posix((const char *)(uintptr_t)c->rcx, px, sizeof(px));
    c->rax = (mkdir(px, 0755) == 0 || errno == EEXIST) ? 1 : 0;
}
static void w_CreateDirectoryW(CPU64 *c, void *ud) {
    (void)ud;
    char u8[1024], px[1024]; w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    win_path_to_posix(u8, px, sizeof(px));
    c->rax = (mkdir(px, 0755) == 0 || errno == EEXIST) ? 1 : 0;
}
static void w_GetTempPathA(CPU64 *c, void *ud) {
    (void)ud;
    const char *t = "/tmp/";
    if (c->rdx && c->rcx > 5) memcpy((void *)(uintptr_t)c->rdx, t, 6);
    c->rax = 5;
}
static void w_GetTempPathW(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx && c->rcx > 5) u8_to_w16("/tmp/", (uint16_t *)(uintptr_t)c->rdx, (size_t)c->rcx);
    c->rax = 5;
}

/* Simple fd-backed CreateFileA/W handles (offset by 0x20000 to avoid colliding with WH_*) */
static uint64_t open_win_file(const char *path, uint32_t access, uint32_t disp) {
    char px[1024];
    win_path_to_posix(path, px, sizeof(px));
    int flags = O_RDONLY;
    if ((access & 0x40000000U) && (access & 0x80000000U)) flags = O_RDWR;
    else if (access & 0x40000000U) flags = O_WRONLY;
    if (disp == 2 /* CREATE_ALWAYS */) flags |= O_CREAT | O_TRUNC;
    else if (disp == 1 /* CREATE_NEW */) flags |= O_CREAT | O_EXCL;
    else if (disp == 4 /* OPEN_ALWAYS */) flags |= O_CREAT;
    else if (disp == 5 /* TRUNCATE_EXISTING */) flags |= O_TRUNC;
    int fd = open(px, flags, 0644);
    if (getenv("ELF64_TRACE")) {
        fprintf(stderr, "[fs] open('%s', flags=0x%x) -> fd=%d\n", px, flags, fd);
    }
    if (fd < 0) return (uint64_t)-1LL;
    return 0x20000ULL + (uint64_t)fd;
}
static void w_CreateFileA(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = open_win_file((const char *)(uintptr_t)c->rcx, (uint32_t)c->rdx, (uint32_t)win64_arg_i(c, 4));
}
static void w_CreateFileW(CPU64 *c, void *ud) {
    (void)ud;
    char u8[1024]; w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    c->rax = open_win_file(u8, (uint32_t)c->rdx, (uint32_t)win64_arg_i(c, 4));
}
static void w_ReadFile(CPU64 *c, void *ud) {
    (void)ud;
    int fd = (c->rcx == 1) ? STDIN_FILENO : ((c->rcx >= 0x20000ULL && c->rcx < 0x30000ULL) ? (int)(c->rcx - 0x20000ULL) : -1);
    if (fd < 0) { c->rax = 0; return; }
    uint64_t ov = win64_arg_i(c, 4);
    ssize_t n;
    if (ov) {
        uint64_t off = (uint64_t)R32(ov + 16) | ((uint64_t)R32(ov + 20) << 32);
        n = pread(fd, (void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8, (off_t)off);
        if (n >= 0) { W64(ov + 0, 0); W64(ov + 8, (uint64_t)n); }
    } else {
        n = read(fd, (void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8);
    }
    if (getenv("ELF64_TRACE")) {
        fprintf(stderr, "[fs] read(fd=%d, len=%u, ov=0x%llx) -> %zd\n",
                fd, (uint32_t)c->r8, (unsigned long long)ov, n);
    }
    if (c->r9) W32(c->r9, n >= 0 ? (uint32_t)n : 0);
    c->rax = (n >= 0) ? 1 : 0;
}
static void w_GetOverlappedResult(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx && c->r8) W32(c->r8, (uint32_t)R64(c->rdx + 8));
    c->rax = 1;
}
static void w_GetFileSizeEx(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx < 0x20000ULL || c->rcx >= 0x30000ULL) { c->rax = 0; return; }
    struct stat st;
    if (fstat((int)(c->rcx - 0x20000ULL), &st) != 0) { c->rax = 0; return; }
    if (c->rdx) W64(c->rdx, (uint64_t)st.st_size);
    c->rax = 1;
}
static void w_SetFilePointerEx(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx < 0x20000ULL || c->rcx >= 0x30000ULL) { c->rax = 0; return; }
    int whence = (c->r9 == 1) ? SEEK_CUR : ((c->r9 == 2) ? SEEK_END : SEEK_SET);
    off_t r = lseek((int)(c->rcx - 0x20000ULL), (off_t)c->rdx, whence);
    if (r < 0) { c->rax = 0; return; }
    if (c->r8) W64(c->r8, (uint64_t)r);
    c->rax = 1;
}
static void w_FlushFileBuffers(CPU64 *c, void *ud) { (void)ud; c->rax = 1; }
static void w_WriteConsoleW(CPU64 *c, void *ud) {
    (void)ud;
    char buf[2048];
    uint32_t cnt = (uint32_t)c->r8;
    const uint16_t *w = (const uint16_t *)(uintptr_t)c->rdx;
    size_t n = 0;
    for (uint32_t i = 0; i < cnt && n + 1 < sizeof(buf); i++) buf[n++] = (w[i] < 128) ? (char)w[i] : '?';
    fwrite(buf, 1, n, (c->rcx == 3) ? stderr : stdout);
    if (c->r9) W32(c->r9, cnt);
    c->rax = 1;
}
static void w_OutputDebugStringW(CPU64 *c, void *ud) {
    (void)ud;
    char buf[1024];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, buf, sizeof(buf));
    fprintf(stderr, "[ODS] %s", buf);
}
/* ---- Real POSIX FindFirstFileA/W + FindNextFileA/W + FindClose ---- */
typedef struct {
    DIR  *dir;
    char  dir_path[1024];
    char  pattern[256];
} WinFindObj;

static WinFindObj *g_finds[64];

static int match_wildcard(const char *pat, const char *str) {
    while (*pat) {
        if (*pat == '*') {
            while (*pat == '*') pat++;
            if (!*pat) return 1;
            for (; *str; str++) if (match_wildcard(pat, str)) return 1;
            return 0;
        }
        if (*pat == '?' || tolower((unsigned char)*pat) == tolower((unsigned char)*str)) {
            if (!*str) return 0;
            pat++; str++;
        } else return 0;
    }
    return *str == '\0';
}

static int fill_find_next(WinFindObj *fo, uint64_t data_va, int is_wide) {
    struct dirent *de;
    while ((de = readdir(fo->dir)) != NULL) {
        if (!match_wildcard(fo->pattern, de->d_name)) continue;
        char full[1280];
        snprintf(full, sizeof(full), "%s/%s", fo->dir_path, de->d_name);
        struct stat st;
        memset(&st, 0, sizeof(st));
        stat(full, &st);
        uint32_t attrs = S_ISDIR(st.st_mode) ? 0x10U : 0x80U;
        uint64_t mft = unix_to_filetime(st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec);
        if (is_wide) {
            memset((void *)(uintptr_t)data_va, 0, 592);
            W32(data_va + 0, attrs);
            W64(data_va + 20, mft);
            W32(data_va + 28, (uint32_t)((uint64_t)st.st_size >> 32));
            W32(data_va + 32, (uint32_t)st.st_size);
            u8_to_w16(de->d_name, (uint16_t *)(uintptr_t)(data_va + 44), 260);
        } else {
            memset((void *)(uintptr_t)data_va, 0, 320);
            W32(data_va + 0, attrs);
            W64(data_va + 20, mft);
            W32(data_va + 28, (uint32_t)((uint64_t)st.st_size >> 32));
            W32(data_va + 32, (uint32_t)st.st_size);
            snprintf((char *)(uintptr_t)(data_va + 44), 260, "%s", de->d_name);
        }
        return 1;
    }
    return 0;
}

static uint64_t start_find(const char *win_spec, uint64_t data_va, int is_wide) {
    char px[1024];
    win_path_to_posix(win_spec, px, sizeof(px));
    char *slash = strrchr(px, '/');
    char dirp[1024], pat[256];
    if (slash) {
        size_t dl = (size_t)(slash - px);
        if (dl == 0) strcpy(dirp, "/");
        else { memcpy(dirp, px, dl); dirp[dl] = '\0'; }
        snprintf(pat, sizeof(pat), "%s", slash + 1);
    } else {
        strcpy(dirp, ".");
        snprintf(pat, sizeof(pat), "%s", px);
    }
    DIR *d = opendir(dirp);
    if (!d) return (uint64_t)-1LL;
    WinFindObj *fo = (WinFindObj *)calloc(1, sizeof(WinFindObj));
    fo->dir = d;
    snprintf(fo->dir_path, sizeof(fo->dir_path), "%s", dirp);
    snprintf(fo->pattern, sizeof(fo->pattern), "%s", pat);
    if (!fill_find_next(fo, data_va, is_wide)) {
        closedir(d); free(fo);
        return (uint64_t)-1LL;
    }
    for (int i = 0; i < 64; i++) {
        if (!g_finds[i]) { g_finds[i] = fo; return 0x40000ULL + (uint64_t)i; }
    }
    closedir(d); free(fo);
    return (uint64_t)-1LL;
}

static void w_FindFirstFileA(CPU64 *c, void *ud)   { (void)ud; c->rax = c->rcx ? start_find((const char *)(uintptr_t)c->rcx, c->rdx, 0) : (uint64_t)-1LL; }
static void w_FindFirstFileExA(CPU64 *c, void *ud) { (void)ud; c->rax = c->rcx ? start_find((const char *)(uintptr_t)c->rcx, c->r8, 0) : (uint64_t)-1LL; }
static void w_FindFirstFileW(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) { c->rax = (uint64_t)-1LL; return; }
    char u8[1024]; w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    c->rax = start_find(u8, c->rdx, 1);
}
static void w_FindFirstFileExW(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) { c->rax = (uint64_t)-1LL; return; }
    char u8[1024]; w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    c->rax = start_find(u8, c->r8, 1);
}
static void w_FindNextFileA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx < 0x40000ULL || c->rcx >= 0x40000ULL + 64) { c->rax = 0; return; }
    WinFindObj *fo = g_finds[c->rcx - 0x40000ULL];
    c->rax = fo ? (uint64_t)fill_find_next(fo, c->rdx, 0) : 0;
}
static void w_FindNextFileW(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx < 0x40000ULL || c->rcx >= 0x40000ULL + 64) { c->rax = 0; return; }
    WinFindObj *fo = g_finds[c->rcx - 0x40000ULL];
    c->rax = fo ? (uint64_t)fill_find_next(fo, c->rdx, 1) : 0;
}
static void w_FindClose(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx >= 0x40000ULL && c->rcx < 0x40000ULL + 64) {
        WinFindObj *fo = g_finds[c->rcx - 0x40000ULL];
        if (fo) { closedir(fo->dir); free(fo); g_finds[c->rcx - 0x40000ULL] = NULL; }
    }
    c->rax = 1;
}

static void w_GetFileSize(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx < 0x20000ULL || c->rcx >= 0x30000ULL) { c->rax = 0xFFFFFFFFU; return; }
    struct stat st;
    if (fstat((int)(c->rcx - 0x20000ULL), &st) != 0) { c->rax = 0xFFFFFFFFU; return; }
    if (c->rdx) W32(c->rdx, (uint32_t)((uint64_t)st.st_size >> 32));
    c->rax = (uint32_t)st.st_size;
}
static void w_SetFilePointer(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx < 0x20000ULL || c->rcx >= 0x30000ULL) { c->rax = 0xFFFFFFFFU; return; }
    int64_t dist = (int32_t)c->rdx;
    if (c->r8) dist = ((int64_t)(int32_t)R32(c->r8) << 32) | (uint32_t)c->rdx;
    int whence = (c->r9 == 1) ? SEEK_CUR : ((c->r9 == 2) ? SEEK_END : SEEK_SET);
    off_t r = lseek((int)(c->rcx - 0x20000ULL), (off_t)dist, whence);
    if (r < 0) { c->rax = 0xFFFFFFFFU; return; }
    if (c->r8) W32(c->r8, (uint32_t)((uint64_t)r >> 32));
    c->rax = (uint32_t)r;
}
static void w_SetEndOfFile(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx < 0x20000ULL || c->rcx >= 0x30000ULL) { c->rax = 0; return; }
    int fd = (int)(c->rcx - 0x20000ULL);
    off_t pos = lseek(fd, 0, SEEK_CUR);
    c->rax = (pos >= 0 && ftruncate(fd, pos) == 0) ? 1 : 0;
}
static void w_GetFileInformationByHandle(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx < 0x20000ULL || c->rcx >= 0x30000ULL || !c->rdx) { c->rax = 0; return; }
    struct stat st;
    if (fstat((int)(c->rcx - 0x20000ULL), &st) != 0) { c->rax = 0; return; }
    memset((void *)(uintptr_t)c->rdx, 0, 52);
    W32(c->rdx + 0, S_ISDIR(st.st_mode) ? 0x10U : 0x80U);
    W32(c->rdx + 32, (uint32_t)((uint64_t)st.st_size >> 32));
    W32(c->rdx + 36, (uint32_t)st.st_size);
    W32(c->rdx + 40, 1);
    c->rax = 1;
}
static void w_DeleteFileA(CPU64 *c, void *ud) {
    (void)ud;
    char px[1024]; win_path_to_posix((const char *)(uintptr_t)c->rcx, px, sizeof(px));
    c->rax = (unlink(px) == 0) ? 1 : 0;
}
static void w_DeleteFileW(CPU64 *c, void *ud) {
    (void)ud;
    char u8[1024], px[1024]; w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    win_path_to_posix(u8, px, sizeof(px));
    c->rax = (unlink(px) == 0) ? 1 : 0;
}
static void w_CryptAcquireContextA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) W64(c->rcx, 0x50001ULL);
    c->rax = 1;
}
static void w_CryptGenRandom(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r8 && c->rdx) arc4random_buf((void *)(uintptr_t)c->r8, (size_t)(uint32_t)c->rdx);
    c->rax = 1;
}
static void w_CryptReleaseContext(CPU64 *c, void *ud) { (void)ud; c->rax = 1; }
static void w_RaiseException(CPU64 *c, void *ud) {
    (void)ud;
    fprintf(stderr, "elf64-recomp: guest RaiseException code=0x%x flags=0x%x\n",
            (uint32_t)c->rcx, (uint32_t)c->rdx);
}

static void w_GetConsoleMode(CPU64 *c, void *ud) { (void)ud; if (c->rdx) W32(c->rdx, 7); c->rax = 1; }
static void w_GetConsoleScreenBufferInfo(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) {
        memset((void *)(uintptr_t)c->rdx, 0, 22);
        W16(c->rdx + 0, 120); W16(c->rdx + 2, 40); /* dwSize */
        W16(c->rdx + 8, 7);                        /* wAttributes */
        W16(c->rdx + 14, 119); W16(c->rdx + 16, 39); /* srWindow Right/Bottom */
        W16(c->rdx + 18, 120); W16(c->rdx + 20, 40); /* dwMaximumWindowSize */
    }
    c->rax = 1;
}

/* ---- Locale / String helpers (MSVC CRT) ---- */
static void w_GetStringTypeW(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *src = (const uint16_t *)(uintptr_t)c->rdx;
    int len = (int)c->r8;
    uint16_t *dst = (uint16_t *)(uintptr_t)c->r9;
    if (len < 0) { len = 0; while (src[len]) len++; len++; }
    for (int i = 0; i < len; i++) {
        uint16_t ch = src[i], fl = 0;
        if (ch < 128) {
            if (isupper(ch)) fl |= 0x0001;
            if (islower(ch)) fl |= 0x0002;
            if (isdigit(ch)) fl |= 0x0004;
            if (isspace(ch)) fl |= 0x0008;
            if (ispunct(ch)) fl |= 0x0010;
            if (iscntrl(ch)) fl |= 0x0020;
            if (ch == ' ' || ch == '\t') fl |= 0x0040;
            if (isxdigit(ch)) fl |= 0x0080;
            if (isalpha(ch)) fl |= 0x0100;
        }
        dst[i] = fl;
    }
    c->rax = 1;
}
static void w_LCMapStringEx(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t flags = (uint32_t)c->rdx;
    const uint16_t *src = (const uint16_t *)(uintptr_t)c->r8;
    int slen = (int)c->r9;
    uint16_t *dst = (uint16_t *)(uintptr_t)win64_arg_i(c, 4);
    int dlen = (int)win64_arg_i(c, 5);
    if (slen < 0) { slen = 0; while (src[slen]) slen++; slen++; }
    if (dlen == 0 || !dst) { c->rax = (uint64_t)slen; return; }
    int n = slen < dlen ? slen : dlen;
    for (int i = 0; i < n; i++) {
        uint16_t ch = src[i];
        if ((flags & 0x100) && ch < 128) ch = (uint16_t)tolower(ch);
        if ((flags & 0x200) && ch < 128) ch = (uint16_t)toupper(ch);
        dst[i] = ch;
    }
    c->rax = (uint64_t)n;
}
static void w_LCMapStringW(CPU64 *c, void *ud) {
    /* Same signature as LCMapStringEx for the first 6 args! */
    w_LCMapStringEx(c, ud);
}
static void w_CompareStringW(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *a = (const uint16_t *)(uintptr_t)c->r8;
    const uint16_t *b = (const uint16_t *)(uintptr_t)win64_arg_i(c, 4);
    while (*a && *a == *b) { a++; b++; }
    c->rax = (*a < *b) ? 1 : ((*a > *b) ? 3 : 2); /* CSTR_LESS_THAN=1, EQUAL=2, GREATER=3 */
}

/* ---- User32 / Advapi32 / BCrypt / Ole32 / WinMM / SteamAPI / Misc ---- */
static void w_wsprintfW(CPU64 *c, void *ud) {
    (void)ud;
    uint16_t *dst = (uint16_t *)(uintptr_t)c->rcx;
    const uint16_t *fmt = (const uint16_t *)(uintptr_t)c->rdx;
    if (!dst || !fmt) { c->rax = 0; return; }
    int slot = 2;
    size_t pos = 0;
    while (*fmt && pos < 1020) {
        if (*fmt != '%') { dst[pos++] = *fmt++; continue; }
        fmt++;
        if (*fmt == '%') { dst[pos++] = '%'; fmt++; continue; }
        while (*fmt && (*fmt == '-' || *fmt == '+' || *fmt == '0' || (*fmt >= '0' && *fmt <= '9'))) fmt++;
        if (*fmt == 'l' || *fmt == 'h') fmt++;
        uint16_t conv = *fmt ? *fmt++ : 0;
        if (conv == 's' || conv == 'S') {
            const uint16_t *ws = (const uint16_t *)(uintptr_t)win64_arg_i(c, slot++);
            if (ws) while (*ws && pos < 1020) dst[pos++] = *ws++;
        } else if (conv == 'c') {
            dst[pos++] = (uint16_t)win64_arg_i(c, slot++);
        } else {
            char tmp[64];
            uint64_t v = win64_arg_i(c, slot++);
            int n = (conv == 'x' || conv == 'X')
                ? snprintf(tmp, sizeof(tmp), (conv == 'X') ? "%X" : "%x", (unsigned)v)
                : snprintf(tmp, sizeof(tmp), (conv == 'u') ? "%u" : "%d", (int)v);
            for (int i = 0; i < n && pos < 1020; i++) dst[pos++] = (uint8_t)tmp[i];
        }
    }
    dst[pos] = 0;
    c->rax = pos;
}

static void w_wsprintfA(CPU64 *c, void *ud) {
    (void)ud;
    char *dst = (char *)(uintptr_t)c->rcx;
    const char *fmt = (const char *)(uintptr_t)c->rdx;
    if (!dst || !fmt) { c->rax = 0; return; }
    int slot = 2;
    size_t pos = 0;
    while (*fmt && pos < 1020) {
        if (*fmt != '%') { dst[pos++] = *fmt++; continue; }
        fmt++;
        if (*fmt == '%') { dst[pos++] = '%'; fmt++; continue; }
        while (*fmt && (*fmt == '-' || *fmt == '+' || *fmt == '0' || (*fmt >= '0' && *fmt <= '9'))) fmt++;
        if (*fmt == 'l' || *fmt == 'h') fmt++;
        char conv = *fmt ? *fmt++ : 0;
        if (conv == 's') {
            const char *s = (const char *)(uintptr_t)win64_arg_i(c, slot++);
            if (s) while (*s && pos < 1020) dst[pos++] = *s++;
        } else if (conv == 'c') {
            dst[pos++] = (char)win64_arg_i(c, slot++);
        } else {
            char tmp[64];
            uint64_t v = win64_arg_i(c, slot++);
            int n = (conv == 'x' || conv == 'X')
                ? snprintf(tmp, sizeof(tmp), (conv == 'X') ? "%X" : "%x", (unsigned)v)
                : snprintf(tmp, sizeof(tmp), (conv == 'u') ? "%u" : "%d", (int)v);
            for (int i = 0; i < n && pos < 1020; i++) dst[pos++] = tmp[i];
        }
    }
    dst[pos] = '\0';
    c->rax = pos;
}

static void w_MessageBoxA(CPU64 *c, void *ud) {
    (void)ud;
    fprintf(stderr, "[MessageBoxA] %s: %s\n",
            c->r8 ? (const char *)(uintptr_t)c->r8 : "",
            c->rdx ? (const char *)(uintptr_t)c->rdx : "");
    c->rax = 1; /* IDOK */
}
static void w_MessageBoxW(CPU64 *c, void *ud) {
    (void)ud;
    char t[256], m[1024];
    w16_to_u8((const uint16_t *)(uintptr_t)c->r8, t, sizeof(t));
    w16_to_u8((const uint16_t *)(uintptr_t)c->rdx, m, sizeof(m));
    fprintf(stderr, "[MessageBoxW] %s: %s\n", t, m);
    c->rax = 1;
}
extern void win32_desktop_size(int *w, int *h);
extern void win32_fit_window_size(SDL_Window *win, int req_w, int req_h);
extern void win32_post_size(uint64_t hwnd, int w, int h);

static void w_GetSystemMetrics(CPU64 *c, void *ud) {
    (void)ud;
    int idx = (int)c->rcx;
    int dw = 1920, dh = 1080;
    win32_desktop_size(&dw, &dh);
    if (idx == 0 || idx == 16 || idx == 78) c->rax = (uint64_t)dw;
    else if (idx == 1 || idx == 17 || idx == 79) c->rax = (uint64_t)dh;
    else if (idx == 80) c->rax = 1; /* SM_CMONITORS */
    else c->rax = 0;
}
static void w_SystemFunction036(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx && c->rdx) arc4random_buf((void *)(uintptr_t)c->rcx, (size_t)(uint32_t)c->rdx);
    c->rax = 1;
}
static void w_BCryptGenRandom(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx && c->r8) arc4random_buf((void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8);
    c->rax = 0; /* STATUS_SUCCESS */
}
static void w_SteamAPI_GetSteamInstallPath(CPU64 *c, void *ud) {
    (void)ud;
    static char path[1024];
    if (!path[0]) {
        const char *home = getenv("HOME");
        snprintf(path, sizeof(path), "%s/Library/Application Support/Steam", home ? home : "");
    }
    c->rax = (uint64_t)(uintptr_t)path;
}

/* ---- Native macOS ARM64 libsteam_api.dylib bridge ---- */
static void *g_steam_dl = NULL;
static int   g_steam_dl_tried = 0;
static uint64_t g_steam_ctx_gen = 1;
static uint64_t g_steam_vt[128];
static int      g_steam_vt_init = 0;

typedef struct {
    uint64_t *lpVtbl;
    void     *real_obj;
    char      ver[48];
} SteamProxy;

static SteamProxy *g_steam_proxies[64];
static int g_steam_proxy_cnt = 0;
static pthread_mutex_t g_steam_mu = PTHREAD_MUTEX_INITIALIZER;

static void *steam_dl(void) {
    if (g_steam_dl_tried) return g_steam_dl;
    g_steam_dl_tried = 1;
    const char *env = getenv("ELF64_STEAM_DYLIB");
    if (env && *env) g_steam_dl = dlopen(env, RTLD_LAZY | RTLD_LOCAL);
    if (!g_steam_dl) {
        const char *home = getenv("HOME");
        if (home && *home) {
            char p[1024];
            snprintf(p, sizeof(p),
                     "%s/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/"
                     "Frameworks/Steam Helper.app/Contents/MacOS/libsteam_api.dylib", home);
            g_steam_dl = dlopen(p, RTLD_LAZY | RTLD_LOCAL);
        }
    }
    return g_steam_dl;
}

static uint64_t steam_wrap_iface(void *real_obj, const char *ver);

static int looks_like_steam_ver(uint64_t va) {
    if (va < 0x100000ULL) return 0;
    const char *s = (const char *)(uintptr_t)va;
    return (strncmp(s, "Steam", 5) == 0 || strncmp(s, "STEAM", 5) == 0);
}

static void steam_noop_cb(void) {}

static void steam_vt_trampoline(CPU64 *c, void *ud) {
    size_t slot = (size_t)(uintptr_t)ud;
    SteamProxy *px = (SteamProxy *)(uintptr_t)c->rcx;
    if (!px || !px->real_obj) { c->rax = 0; return; }
    int is_csteamid_sret =
        ((strncasecmp(px->ver, "SteamUser", 9) == 0 && px->ver[9] >= '0' && px->ver[9] <= '9' && slot == 2) ||
         (strncasecmp(px->ver, "SteamApps", 9) == 0 && slot == 17));
    void **rvt = *(void ***)px->real_obj;
    /* Itanium ABI puts 2 vtable slots (D1, D0) for virtual ~ISteamHTMLSurface(); MSVC puts 1. */
    if (strncmp(px->ver, "STEAMHTMLSURFACE", 16) == 0) {
        if (slot == 0) { c->rax = 0; return; }
        slot += 1;
    }
    /* shortcut: return NULL from ISteamNetworkingSockets::CreateFakeUDPPort (slot 46) because it returns a native ARM64 ISteamNetworkingFakeUDPPort* whose messages contain native m_pfnRelease callbacks; wrap FakeUDPPort + SteamNetworkingMessage_t if Valve SDR FakeIP is needed. */
    if (strncmp(px->ver, "SteamNetworkingSockets", 22) == 0 && slot == 46) {
        c->rax = 0;
        return;
    }
    typedef uint64_t (*Arm64Fn)(uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t);
    Arm64Fn fn = (Arm64Fn)rvt[slot];
    if (is_csteamid_sret) {
        uint64_t id = fn((uint64_t)(uintptr_t)px->real_obj, c->r8, c->r9,
                         win64_arg_i(c, 4), win64_arg_i(c, 5), win64_arg_i(c, 6), 0, 0);
        if (c->rdx) W64(c->rdx, id);
        c->rax = c->rdx;
        return;
    }
    /* Never hand raw guest x86_64 callback pointers (e.g. SetDebugOutputFunction/SetWarningMessageHook) to native ARM64 steamclient.dylib. */
    uint64_t a1 = rt_is_lifted_code(c->rdx) ? (uint64_t)(uintptr_t)steam_noop_cb : c->rdx;
    uint64_t a2 = rt_is_lifted_code(c->r8)  ? (uint64_t)(uintptr_t)steam_noop_cb : c->r8;
    uint64_t a3 = rt_is_lifted_code(c->r9)  ? (uint64_t)(uintptr_t)steam_noop_cb : c->r9;
    uint64_t r = fn((uint64_t)(uintptr_t)px->real_obj, a1, a2, a3,
                    win64_arg_i(c, 4), win64_arg_i(c, 5), win64_arg_i(c, 6), win64_arg_i(c, 7));
    if (r && strncmp(px->ver, "SteamClient", 11) == 0) {
        const char *subver = NULL;
        if (looks_like_steam_ver(c->r9)) subver = (const char *)(uintptr_t)c->r9;
        else if (looks_like_steam_ver(c->r8)) subver = (const char *)(uintptr_t)c->r8;
        if (subver) r = steam_wrap_iface((void *)(uintptr_t)r, subver);
    }
    c->rax = r;
}

static uint64_t steam_wrap_iface(void *real_obj, const char *ver) {
    if (!real_obj) return 0;
    pthread_mutex_lock(&g_steam_mu);
    if (!g_steam_vt_init) {
        for (size_t i = 0; i < 128; i++) {
            g_steam_vt[i] = rt_alloc_dynamic_thunk("ISteam::vcall", steam_vt_trampoline, (void *)(uintptr_t)i);
        }
        g_steam_vt_init = 1;
    }
    for (int i = 0; i < g_steam_proxy_cnt; i++) {
        if (g_steam_proxies[i]->real_obj == real_obj) {
            uint64_t res = (uint64_t)(uintptr_t)g_steam_proxies[i];
            pthread_mutex_unlock(&g_steam_mu);
            return res;
        }
    }
    SteamProxy *px = (SteamProxy *)calloc(1, sizeof(SteamProxy));
    px->lpVtbl = g_steam_vt;
    px->real_obj = real_obj;
    if (ver) snprintf(px->ver, sizeof(px->ver), "%s", ver);
    if (g_steam_proxy_cnt < 64) g_steam_proxies[g_steam_proxy_cnt++] = px;
    pthread_mutex_unlock(&g_steam_mu);
    return (uint64_t)(uintptr_t)px;
}

static void ensure_steam_appid_env(void) {
    if (getenv("SteamAppId") && getenv("SteamAppId")[0]) return;
    const char *root = getenv("ELF64_WIN_ROOT");
    char p[1024];
    snprintf(p, sizeof(p), "%s/steam_appid.txt", (root && *root) ? root : ".");
    FILE *f = fopen(p, "r");
    if (!f) return;
    char buf[32] = {0};
    if (fgets(buf, sizeof(buf), f)) {
        char *nl = strpbrk(buf, "\r\n \t");
        if (nl) *nl = '\0';
        if (buf[0]) { setenv("SteamAppId", buf, 0); setenv("SteamGameId", buf, 0); }
    }
    fclose(f);
}

static void w_SteamAPI_InitSafe(CPU64 *c, void *ud) {
    (void)ud;
    ensure_steam_appid_env();
    void *dl = steam_dl();
    if (!dl) { c->rax = 0; return; }
    typedef bool (*Fn)(void);
    Fn fn = (Fn)dlsym(dl, "SteamAPI_InitSafe");
    bool ok = fn ? fn() : false;
    if (ok) g_steam_ctx_gen++;
    c->rax = ok ? 1 : 0;
}
static void w_SteamAPI_Shutdown(CPU64 *c, void *ud) {
    (void)ud;
    void *dl = steam_dl();
    typedef void (*Fn)(void);
    Fn fn = dl ? (Fn)dlsym(dl, "SteamAPI_Shutdown") : NULL;
    if (fn) fn();
    c->rax = 0;
}
static void w_SteamAPI_RunCallbacks(CPU64 *c, void *ud) {
    (void)ud;
    void *dl = steam_dl();
    typedef void (*Fn)(void);
    Fn fn = dl ? (Fn)dlsym(dl, "SteamAPI_RunCallbacks") : NULL;
    if (fn) fn();
    c->rax = 0;
}
static void w_SteamAPI_GetHSteamUser(CPU64 *c, void *ud) {
    (void)ud;
    void *dl = steam_dl();
    typedef int32_t (*Fn)(void);
    Fn fn = dl ? (Fn)dlsym(dl, "SteamAPI_GetHSteamUser") : NULL;
    c->rax = fn ? (uint64_t)(uint32_t)fn() : 0;
}
static void w_SteamAPI_GetHSteamPipe(CPU64 *c, void *ud) {
    (void)ud;
    void *dl = steam_dl();
    typedef int32_t (*Fn)(void);
    Fn fn = dl ? (Fn)dlsym(dl, "SteamAPI_GetHSteamPipe") : NULL;
    c->rax = fn ? (uint64_t)(uint32_t)fn() : 0;
}
static void w_SteamInternal_CreateInterface(CPU64 *c, void *ud) {
    (void)ud;
    void *dl = steam_dl();
    const char *ver = (const char *)(uintptr_t)c->rcx;
    typedef void *(*Fn)(const char *);
    Fn fn = dl ? (Fn)dlsym(dl, "SteamInternal_CreateInterface") : NULL;
    void *obj = (fn && ver) ? fn(ver) : NULL;
    c->rax = steam_wrap_iface(obj, ver);
}
static void w_SteamInternal_FindOrCreateUserInterface(CPU64 *c, void *ud) {
    (void)ud;
    void *dl = steam_dl();
    int32_t huser = (int32_t)c->rcx;
    const char *ver = (const char *)(uintptr_t)c->rdx;
    typedef void *(*Fn)(int32_t, const char *);
    Fn fn = dl ? (Fn)dlsym(dl, "SteamInternal_FindOrCreateUserInterface") : NULL;
    void *obj = (fn && ver) ? fn(huser, ver) : NULL;
    c->rax = steam_wrap_iface(obj, ver);
}
static void w_SteamInternal_ContextInit(CPU64 *c, void *ud) {
    (void)ud;
    /* Steamworks ContextInitData: [0]=guest init_fn, [8]=counter, [16]=interface_ptr(s). */
    uint64_t ctx = c->rcx;
    if (!ctx) { c->rax = 0; return; }
    uint64_t init_fn = R64(ctx);
    uint64_t gen = R64(ctx + 8);
    if (gen != g_steam_ctx_gen) {
        W64(ctx + 8, g_steam_ctx_gen);
        W64(ctx + 16, 0);
        if (init_fn) {
            uint64_t saved_rcx = c->rcx, saved_rsp = c->rsp;
            c->rcx = ctx + 16;
            c->rsp = (c->rsp - 48ULL) & ~15ULL;
            push64(c, 0ULL);
            rt_call(c, init_fn);
            c->rsp = saved_rsp;
            c->rcx = saved_rcx;
        }
    }
    c->rax = ctx + 16;
}
static void w_CreateMutexA(CPU64 *c, void *ud)     { (void)ud; c->rax = 0x30001ULL; }
static void w_ret_0(CPU64 *c, void *ud)  { (void)ud; c->rax = 0; }
static void w_ret_1(CPU64 *c, void *ud)  { (void)ud; c->rax = 1; }
static void w_ret_err2(CPU64 *c, void *ud){ (void)ud; c->rax = 2; /* ERROR_FILE_NOT_FOUND */ }
static void w_ret_inv(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)-1LL; }

/* ---- Engine Kernel32 / Filesystem / Memory / Process extras ---- */
static void w_GetLongShortPathA(CPU64 *c, void *ud) {
    (void)ud;
    const char *src = (const char *)(uintptr_t)c->rcx;
    char *dst = (char *)(uintptr_t)c->rdx;
    uint32_t cap = (uint32_t)c->r8;
    if (!src) { c->rax = 0; return; }
    size_t n = strlen(src);
    if (!dst || cap <= n) { c->rax = n + 1; return; }
    memcpy(dst, src, n + 1);
    c->rax = n;
}
static void w_GetShortPathW(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *src = (const uint16_t *)(uintptr_t)c->rcx;
    uint16_t *dst = (uint16_t *)(uintptr_t)c->rdx;
    uint32_t cap = (uint32_t)c->r8;
    if (!src) { c->rax = 0; return; }
    size_t n = 0; while (src[n]) n++;
    if (!dst || cap <= n) { c->rax = n + 1; return; }
    memcpy(dst, src, (n + 1) * 2);
    c->rax = n;
}
static void w_GetDiskFreeSpaceExA(CPU64 *c, void *ud) {
    (void)ud;
    char p[2048];
    if (c->rcx) win_path_to_posix((const char *)(uintptr_t)c->rcx, p, sizeof(p));
    else strcpy(p, ".");
    struct statvfs st;
    if (statvfs(p, &st) != 0 && statvfs(".", &st) != 0) { c->rax = 0; return; }
    uint64_t avail = (uint64_t)st.f_bavail * (uint64_t)st.f_frsize;
    uint64_t total = (uint64_t)st.f_blocks * (uint64_t)st.f_frsize;
    uint64_t freeb = (uint64_t)st.f_bfree * (uint64_t)st.f_frsize;
    if (c->rdx) W64(c->rdx, avail);
    if (c->r8)  W64(c->r8, total);
    if (c->r9)  W64(c->r9, freeb);
    c->rax = 1;
}
static void w_GetFileTime(CPU64 *c, void *ud) {
    (void)ud;
    int fd = (c->rcx >= 0x20000ULL && c->rcx < 0x30000ULL) ? (int)(c->rcx - 0x20000ULL) : -1;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) { c->rax = 0; return; }
    uint64_t ft = ((uint64_t)st.st_mtime + 11644473600ULL) * 10000000ULL;
    if (c->rdx) W64(c->rdx, ft);
    if (c->r8)  W64(c->r8, ft);
    if (c->r9)  W64(c->r9, ft);
    c->rax = 1;
}
static void w_GetProcessTimes(CPU64 *c, void *ud) {
    (void)ud;
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    getrusage(RUSAGE_SELF, &ru);
    uint64_t ut = (uint64_t)ru.ru_utime.tv_sec * 10000000ULL + (uint64_t)ru.ru_utime.tv_usec * 10ULL;
    uint64_t kt = (uint64_t)ru.ru_stime.tv_sec * 10000000ULL + (uint64_t)ru.ru_stime.tv_usec * 10ULL;
    if (c->rdx) W64(c->rdx, 0);
    if (c->r8)  W64(c->r8, 0);
    if (c->r9)  W64(c->r9, kt);
    uint64_t p_user = win64_arg_i(c, 4);
    if (p_user) W64(p_user, ut);
    c->rax = 1;
}
static void w_K32GetProcessMemoryInfo(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t out = c->rdx;
    uint32_t cb = (uint32_t)c->r8;
    if (!out || cb < 40) { c->rax = 0; return; }
    memset((void *)(uintptr_t)out, 0, cb);
    W32(out, cb);
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t cnt = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &cnt) == KERN_SUCCESS) {
        if (cb >= 24) W64(out + 16, info.resident_size);
        if (cb >= 64) W64(out + 56, info.virtual_size);
    }
    c->rax = 1;
}
static void w_VirtualQuery(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t addr = c->rcx & ~0xFFFULL;
    uint64_t out = c->rdx;
    size_t len = (size_t)c->r8;
    if (!out || len < 48) { c->rax = 0; return; }
    memset((void *)(uintptr_t)out, 0, 48);
    W64(out + 0, addr);        /* BaseAddress */
    W64(out + 8, addr);        /* AllocationBase */
    W32(out + 16, 0x04);       /* PAGE_READWRITE */
    W64(out + 24, 0x10000ULL); /* RegionSize */
    W32(out + 32, 0x1000);     /* MEM_COMMIT */
    W32(out + 36, 0x04);       /* PAGE_READWRITE */
    W32(out + 40, 0x20000);    /* MEM_PRIVATE */
    c->rax = 48;
}
static void w_RemoveDirectoryW(CPU64 *c, void *ud) {
    (void)ud;
    char u8[2048], p[2048];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    win_path_to_posix(u8, p, sizeof(p));
    c->rax = (rmdir(p) == 0) ? 1 : 0;
}
static void w_MoveFileW(CPU64 *c, void *ud) {
    (void)ud;
    char a8[2048], b8[2048], pa[2048], pb[2048];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, a8, sizeof(a8));
    w16_to_u8((const uint16_t *)(uintptr_t)c->rdx, b8, sizeof(b8));
    win_path_to_posix(a8, pa, sizeof(pa));
    win_path_to_posix(b8, pb, sizeof(pb));
    c->rax = (rename(pa, pb) == 0) ? 1 : 0;
}
static void w_CopyFileW(CPU64 *c, void *ud) {
    (void)ud;
    char a8[2048], b8[2048], pa[2048], pb[2048];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, a8, sizeof(a8));
    w16_to_u8((const uint16_t *)(uintptr_t)c->rdx, b8, sizeof(b8));
    win_path_to_posix(a8, pa, sizeof(pa));
    win_path_to_posix(b8, pb, sizeof(pb));
    int in = open(pa, O_RDONLY);
    if (in < 0) { c->rax = 0; return; }
    int out = open(pb, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); c->rax = 0; return; }
    char buf[8192]; ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) { if (write(out, buf, (size_t)n) != n) break; }
    close(in); close(out);
    c->rax = 1;
}
static void w_CreatePipe(CPU64 *c, void *ud) {
    (void)ud;
    int fds[2];
    if (pipe(fds) != 0) { c->rax = 0; return; }
    if (c->rcx) W64(c->rcx, 0x20000ULL + (uint64_t)fds[0]);
    if (c->rdx) W64(c->rdx, 0x20000ULL + (uint64_t)fds[1]);
    c->rax = 1;
}
static void w_GetTempFileNameW(CPU64 *c, void *ud) {
    (void)ud;
    static uint32_t seq = 1;
    char dir8[1024], pfx8[64], out8[1200];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, dir8, sizeof(dir8));
    w16_to_u8((const uint16_t *)(uintptr_t)c->rdx, pfx8, sizeof(pfx8));
    uint32_t id = (uint32_t)c->r8 ? (uint32_t)c->r8 : seq++;
    snprintf(out8, sizeof(out8), "%s/%s%04x.tmp", dir8[0] ? dir8 : "/tmp", pfx8, id & 0xFFFFU);
    if (c->r9) u8_to_w16(out8, (uint16_t *)(uintptr_t)c->r9, 260);
    c->rax = id;
}

/* ---- RPCRT4 UUIDs ---- */
static void w_UuidCreate(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) {
        uint8_t *u = (uint8_t *)(uintptr_t)c->rcx;
        arc4random_buf(u, 16);
        u[7] = (uint8_t)((u[7] & 0x0F) | 0x40);
        u[8] = (uint8_t)((u[8] & 0x3F) | 0x80);
    }
    c->rax = 0; /* RPC_S_OK */
}
static void w_UuidToStringA(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx || !c->rdx) { c->rax = 87; return; }
    const uint8_t *u = (const uint8_t *)(uintptr_t)c->rcx;
    uint32_t d1 = R32(c->rcx); uint16_t d2 = R16(c->rcx + 4); uint16_t d3 = R16(c->rcx + 6);
    char *s = (char *)malloc(40);
    snprintf(s, 40, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             d1, d2, d3, u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
    W64(c->rdx, (uint64_t)(uintptr_t)s);
    c->rax = 0;
}
static void w_UuidFromStringA(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx || !c->rdx) { c->rax = 1705; return; }
    unsigned d1, d2, d3, b[8];
    if (sscanf((const char *)(uintptr_t)c->rcx,
               "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
               &d1, &d2, &d3, &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7]) != 11) {
        c->rax = 1705; return;
    }
    W32(c->rdx, d1); W16(c->rdx + 4, (uint16_t)d2); W16(c->rdx + 6, (uint16_t)d3);
    uint8_t *u = (uint8_t *)(uintptr_t)c->rdx;
    for (int i = 0; i < 8; i++) u[8 + i] = (uint8_t)b[i];
    c->rax = 0;
}
static void w_UuidEqual(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r8) W32(c->r8, 0);
    c->rax = (c->rcx && c->rdx && memcmp((void *)(uintptr_t)c->rcx, (void *)(uintptr_t)c->rdx, 16) == 0) ? 1 : 0;
}
static void w_RpcStringFreeA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) {
        uint64_t p = R64(c->rcx);
        if (p) free((void *)(uintptr_t)p);
        W64(c->rcx, 0);
    }
    c->rax = 0;
}

/* ---- User32 / GDI32 Window + Display helpers ---- */
static uint64_t g_wnd_long[64][4]; /* 0:STYLE, 1:EXSTYLE, 2:WNDPROC, 3:USERDATA */
static int wnd_slot(uint64_t hwnd) { return (hwnd >= 0x1000 && hwnd < 0x1040) ? (int)(hwnd - 0x1000) : 0; }
static int wnd_idx(int n) {
    if (n == -16) return 0; if (n == -20) return 1; if (n == -4) return 2; return 3;
}
extern uint32_t win32_get_hwnd_style(uint64_t hwnd);
extern uint32_t win32_set_hwnd_style(uint64_t hwnd, uint32_t style);
static void w_GetWindowLongPtr(CPU64 *c, void *ud) {
    (void)ud;
    if ((int)c->rdx == -4) { c->rax = win32_get_wndproc(c->rcx); return; }
    if ((int)c->rdx == -16) { c->rax = win32_get_hwnd_style(c->rcx); return; }
    c->rax = g_wnd_long[wnd_slot(c->rcx)][wnd_idx((int)c->rdx)];
}
static void w_SetWindowLongPtr(CPU64 *c, void *ud) {
    (void)ud;
    if ((int)c->rdx == -4) { c->rax = win32_set_wndproc(c->rcx, c->r8); return; }
    if ((int)c->rdx == -16) { c->rax = win32_set_hwnd_style(c->rcx, (uint32_t)c->r8); return; }
    int s = wnd_slot(c->rcx), idx = wnd_idx((int)c->rdx);
    uint64_t prev = g_wnd_long[s][idx];
    g_wnd_long[s][idx] = c->r8;
    c->rax = prev;
}
extern void win32_get_backbuffer_size(int *w, int *h);
extern void win32_set_hwnd_size(uint64_t hwnd, int w, int h);
extern void win32_get_hwnd_size(uint64_t hwnd, int *w, int *h);
static void w_GetWindowRect(CPU64 *c, void *ud) {
    (void)ud;
    int w = 1280, h = 720;
    win32_get_hwnd_size(c->rcx, &w, &h);
    if (c->rdx) { W32(c->rdx, 0); W32(c->rdx + 4, 0); W32(c->rdx + 8, (uint32_t)w); W32(c->rdx + 12, (uint32_t)h); }
    c->rax = 1;
}
static void w_SetWindowPos(CPU64 *c, void *ud) {
    (void)ud;
    int cx = (int)win64_arg_i(c, 4);
    int cy = (int)win64_arg_i(c, 5);
    uint32_t flags = (uint32_t)win64_arg_i(c, 6);
    SDL_Window *win = win32_hwnd_to_sdl(c->rcx);
    if (win && !(flags & 0x0001U /* SWP_NOSIZE */) && cx > 64 && cy > 64 && cx <= 8192 && cy <= 8192) {
        if (getenv("ELF64_IO_LOG"))
            fprintf(stderr, "[io] SetWindowPos hwnd=0x%llx %dx%d flags=0x%x\n",
                    (unsigned long long)c->rcx, cx, cy, flags);
        win32_set_hwnd_size(c->rcx, cx, cy);
        win32_fit_window_size(win, cx, cy);
        win32_post_size(c->rcx, cx, cy);
    }
    if (win && !getenv("ELF64_HEADLESS")) {
        if (flags & 0x0040U /* SWP_SHOWWINDOW */) { SDL_ShowWindow(win); SDL_RaiseWindow(win); }
        else if (flags & 0x0080U /* SWP_HIDEWINDOW */) { SDL_HideWindow(win); }
    }
    c->rax = 1;
}
static void w_MoveWindow(CPU64 *c, void *ud) {
    (void)ud;
    int w = (int)c->r9;
    int h = (int)win64_arg_i(c, 4);
    SDL_Window *win = win32_hwnd_to_sdl(c->rcx);
    if (win && w > 64 && h > 64 && w <= 8192 && h <= 8192) {
        if (getenv("ELF64_IO_LOG"))
            fprintf(stderr, "[io] MoveWindow hwnd=0x%llx %dx%d\n", (unsigned long long)c->rcx, w, h);
        win32_set_hwnd_size(c->rcx, w, h);
        win32_fit_window_size(win, w, h);
        win32_post_size(c->rcx, w, h);
    }
    c->rax = 1;
}
static void w_EnumDisplaySettingsA(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t mode = (uint32_t)c->rdx;
    uint64_t dm = c->r8;
    if (!dm) { c->rax = 0; return; }
    int dw = 1920, dh = 1080;
    win32_desktop_size(&dw, &dh);
    static const struct { uint32_t w, h; } modes[] = {
        {800, 600}, {1024, 768}, {1280, 720}, {1280, 800},
        {1440, 900}, {1600, 900}, {1680, 1050}, {1920, 1080}
    };
    uint32_t w = (uint32_t)dw, h = (uint32_t)dh;
    if (mode == 0xFFFFFFFFU || mode == 0xFFFFFFFEU) {
        w = (uint32_t)dw; h = (uint32_t)dh;
    } else if (mode < 8) {
        w = modes[mode].w; h = modes[mode].h;
    } else if (mode == 8) {
        w = (uint32_t)dw; h = (uint32_t)dh;
    } else {
        c->rax = 0; return;
    }
    memset((void *)(uintptr_t)dm, 0, 156);
    W16(dm + 36, 156);   /* dmSize */
    W32(dm + 40, 0x001C0000U); /* DM_BITSPERPEL|DM_PELSWIDTH|DM_PELSHEIGHT|DM_DISPLAYFREQUENCY */
    W32(dm + 104, 32);   /* dmBitsPerPel */
    W32(dm + 108, w);    /* dmPelsWidth */
    W32(dm + 112, h);    /* dmPelsHeight */
    W32(dm + 120, 60);   /* dmDisplayFrequency */
    c->rax = 1;
}
static void w_GetDeviceCaps(CPU64 *c, void *ud) {
    (void)ud;
    int idx = (int)c->rdx;
    int dw = 1920, dh = 1080;
    win32_desktop_size(&dw, &dh);
    if (idx == 8) c->rax = (uint64_t)dw;        /* HORZRES */
    else if (idx == 10) c->rax = (uint64_t)dh;  /* VERTRES */
    else if (idx == 12) c->rax = 32;    /* BITSPIXEL */
    else if (idx == 88 || idx == 90) c->rax = 96; /* LOGPIXELSX/Y */
    else if (idx == 116) c->rax = 60;   /* VREFRESH */
    else c->rax = 1;
}
static void w_GetWindowThreadProcessId(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t pid = (uint32_t)getpid();
    if (c->rdx) W32(c->rdx, pid);
    c->rax = pid;
}

/* ---- Winsock2 (ws2_32.dll) POSIX socket bridge ---- */
static _Thread_local int g_wsa_err = 0;
static void win_to_bsd_sa(const uint8_t *wsa, int len, struct sockaddr_storage *out) {
    memset(out, 0, sizeof(*out));
    if (!wsa || len < 2) return;
    if (len > (int)sizeof(*out)) len = (int)sizeof(*out);
    memcpy(out, wsa, (size_t)len);
    uint16_t fam = (uint16_t)wsa[0] | ((uint16_t)wsa[1] << 8);
    ((struct sockaddr *)out)->sa_len = (uint8_t)len;
    ((struct sockaddr *)out)->sa_family = (sa_family_t)(fam == 23 ? AF_INET6 : fam);
}
static void bsd_to_win_sa(const struct sockaddr_storage *in, socklen_t len, uint8_t *wsa) {
    if (!wsa || !len) return;
    memcpy(wsa, in, (size_t)len);
    sa_family_t fam = ((const struct sockaddr *)in)->sa_family;
    uint16_t wfam = (fam == AF_INET6) ? 23 : (uint16_t)fam;
    wsa[0] = (uint8_t)(wfam & 0xFF);
    wsa[1] = (uint8_t)(wfam >> 8);
}
static int posix_to_wsa_err(int e) {
    if (e == EAGAIN || e == EWOULDBLOCK) return 10035;
    if (e == EINPROGRESS) return 10036;
    if (e == EADDRINUSE) return 10048;
    if (e == ECONNREFUSED) return 10061;
    return 10000 + e;
}
static void w_wsa_socket(CPU64 *c, void *ud) {
    (void)ud;
    int af = ((int)c->rcx == 23) ? AF_INET6 : (int)c->rcx;
    int fd = socket(af, (int)c->rdx, (int)c->r8);
    if (fd < 0) { g_wsa_err = posix_to_wsa_err(errno); c->rax = (uint64_t)-1LL; return; }
    c->rax = (uint64_t)fd;
}
static void w_wsa_closesocket(CPU64 *c, void *ud) { (void)ud; c->rax = (close((int)c->rcx) == 0) ? 0 : (uint64_t)-1LL; }
static void w_wsa_bind(CPU64 *c, void *ud) {
    (void)ud;
    struct sockaddr_storage ss;
    int len = (int)c->r8;
    win_to_bsd_sa((const uint8_t *)(uintptr_t)c->rdx, len, &ss);
    int r = bind((int)c->rcx, (struct sockaddr *)&ss, (socklen_t)len);
    if (r < 0) g_wsa_err = posix_to_wsa_err(errno);
    c->rax = (uint64_t)(int64_t)r;
}
static void w_wsa_listen(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)listen((int)c->rcx, (int)c->rdx); }
static void w_wsa_accept(CPU64 *c, void *ud) {
    (void)ud;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int fd = accept((int)c->rcx, c->rdx ? (struct sockaddr *)&ss : NULL, c->r8 ? &sl : NULL);
    if (fd < 0) { g_wsa_err = posix_to_wsa_err(errno); c->rax = (uint64_t)-1LL; return; }
    if (c->rdx) bsd_to_win_sa(&ss, sl, (uint8_t *)(uintptr_t)c->rdx);
    if (c->r8) W32(c->r8, (uint32_t)sl);
    c->rax = (uint64_t)fd;
}
static void w_wsa_recv(CPU64 *c, void *ud) {
    (void)ud;
    ssize_t n = recv((int)c->rcx, (void *)(uintptr_t)c->rdx, (size_t)(int)c->r8, (int)c->r9);
    if (n < 0) g_wsa_err = posix_to_wsa_err(errno);
    c->rax = (uint64_t)(int64_t)n;
}
static void w_wsa_send(CPU64 *c, void *ud) {
    (void)ud;
    ssize_t n = send((int)c->rcx, (const void *)(uintptr_t)c->rdx, (size_t)(int)c->r8, (int)c->r9);
    if (n < 0) g_wsa_err = posix_to_wsa_err(errno);
    c->rax = (uint64_t)(int64_t)n;
}
static void w_wsa_recvfrom(CPU64 *c, void *ud) {
    (void)ud;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    uint64_t from_p = win64_arg_i(c, 4), fromlen_p = win64_arg_i(c, 5);
    ssize_t n = recvfrom((int)c->rcx, (void *)(uintptr_t)c->rdx, (size_t)(int)c->r8, (int)c->r9,
                         from_p ? (struct sockaddr *)&ss : NULL, fromlen_p ? &sl : NULL);
    if (n < 0) { g_wsa_err = posix_to_wsa_err(errno); c->rax = (uint64_t)-1LL; return; }
    if (from_p) bsd_to_win_sa(&ss, sl, (uint8_t *)(uintptr_t)from_p);
    if (fromlen_p) W32(fromlen_p, (uint32_t)sl);
    c->rax = (uint64_t)(int64_t)n;
}
static void w_wsa_sendto(CPU64 *c, void *ud) {
    (void)ud;
    struct sockaddr_storage ss;
    uint64_t to_p = win64_arg_i(c, 4);
    int tolen = (int)win64_arg_i(c, 5);
    win_to_bsd_sa((const uint8_t *)(uintptr_t)to_p, tolen, &ss);
    ssize_t n = sendto((int)c->rcx, (const void *)(uintptr_t)c->rdx, (size_t)(int)c->r8, (int)c->r9,
                       to_p ? (struct sockaddr *)&ss : NULL, (socklen_t)tolen);
    if (n < 0) g_wsa_err = posix_to_wsa_err(errno);
    c->rax = (uint64_t)(int64_t)n;
}
static void w_wsa_setsockopt(CPU64 *c, void *ud) {
    (void)ud;
    int lvl = ((int)c->rdx == 0xFFFF) ? SOL_SOCKET : (int)c->rdx;
    int opt = (int)c->r8;
    if (lvl == SOL_SOCKET && opt == 0x0004) opt = SO_REUSEADDR;
    else if (lvl == SOL_SOCKET && opt == 0x0020) opt = SO_BROADCAST;
    else if (lvl == SOL_SOCKET && opt == 0x1001) opt = SO_SNDBUF;
    else if (lvl == SOL_SOCKET && opt == 0x1002) opt = SO_RCVBUF;
    int r = setsockopt((int)c->rcx, lvl, opt, (const void *)(uintptr_t)c->r9, (socklen_t)(int)win64_arg_i(c, 4));
    c->rax = (uint64_t)(int64_t)r;
}
static void w_wsa_htons(CPU64 *c, void *ud)     { (void)ud; c->rax = htons((uint16_t)c->rcx); }
static void w_wsa_ntohs(CPU64 *c, void *ud)     { (void)ud; c->rax = ntohs((uint16_t)c->rcx); }
static void w_wsa_inet_addr(CPU64 *c, void *ud) { (void)ud; c->rax = c->rcx ? (uint32_t)inet_addr((const char *)(uintptr_t)c->rcx) : 0xFFFFFFFFU; }
static void w_wsa_gethostname(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (c->rcx && gethostname((char *)(uintptr_t)c->rcx, (size_t)(int)c->rdx) == 0) ? 0 : (uint64_t)-1LL;
}
static void w_wsa_GetLastError(CPU64 *c, void *ud) { (void)ud; c->rax = (uint32_t)g_wsa_err; }
static void w_wsa_inet_pton(CPU64 *c, void *ud) {
    (void)ud;
    int af = ((int)c->rcx == 23) ? AF_INET6 : (int)c->rcx;
    c->rax = (uint64_t)(int64_t)inet_pton(af, (const char *)(uintptr_t)c->rdx, (void *)(uintptr_t)c->r8);
}
static void w_wsa_select(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void w_wsa_getaddrinfo(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r9) W64(c->r9, 0);
    c->rax = 11001; /* WSAHOST_NOT_FOUND - shortcut: offline stub until multiplayer needed */
}
static void w_wsa_freeaddrinfo(CPU64 *c, void *ud) { (void)ud; (void)c; }

/* ---- GlobalAlloc / GDI32 DIB+Font / WinMM / User32 / Shell32 / OLE32 ---- */
typedef struct { void *ptr; size_t size; } GlobalSlot;
static GlobalSlot g_globals[256];
static pthread_mutex_t g_glob_mu = PTHREAD_MUTEX_INITIALIZER;

static void w_GlobalAlloc(CPU64 *c, void *ud) {
    (void)ud;
    size_t sz = (size_t)c->rdx;
    if (sz == 0) sz = 16;
    void *p = calloc(1, sz);
    if (!p) { c->rax = 0; return; }
    pthread_mutex_lock(&g_glob_mu);
    for (int i = 0; i < 256; i++) {
        if (!g_globals[i].ptr) { g_globals[i].ptr = p; g_globals[i].size = sz; break; }
    }
    pthread_mutex_unlock(&g_glob_mu);
    c->rax = (uint64_t)(uintptr_t)p;
}
static void w_GlobalLock(CPU64 *c, void *ud)   { (void)ud; c->rax = c->rcx; }
static void w_GlobalUnlock(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void w_GlobalSize(CPU64 *c, void *ud) {
    (void)ud;
    void *p = (void *)(uintptr_t)c->rcx;
    size_t sz = 0;
    pthread_mutex_lock(&g_glob_mu);
    for (int i = 0; i < 256; i++) {
        if (g_globals[i].ptr == p) { sz = g_globals[i].size; break; }
    }
    pthread_mutex_unlock(&g_glob_mu);
    c->rax = sz;
}
static void w_GlobalFree(CPU64 *c, void *ud) {
    (void)ud;
    void *p = (void *)(uintptr_t)c->rcx;
    if (p) {
        pthread_mutex_lock(&g_glob_mu);
        for (int i = 0; i < 256; i++) {
            if (g_globals[i].ptr == p) { g_globals[i].ptr = NULL; g_globals[i].size = 0; break; }
        }
        pthread_mutex_unlock(&g_glob_mu);
        free(p);
    }
    c->rax = 0;
}
static void w_GetLogicalDriveStringsA(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t cap = (uint32_t)c->rcx;
    char *dst = (char *)(uintptr_t)c->rdx;
    if (dst && cap >= 5) { memcpy(dst, "C:\\\0\0", 5); }
    c->rax = 4;
}

typedef struct { int w, h, bpp, top_down; size_t stride; void *bits; } GdiBmp;
typedef struct {
    CTFontRef ct;
    int       height, ascent, descent, leading, ave_w, max_w, weight;
} GdiFont;
typedef struct {
    int      in_use;
    uint64_t hbmp;
    uint64_t hfont;
    uint32_t text_color;
    uint32_t bk_color;
    int      bk_mode;
    uint32_t text_align;
    int      cur_x, cur_y;
} GdiDC;
typedef struct {
    char      family[128];
    CGFontRef cg;
} AddedFont;

#define GDI_MAX_BMPS  2048
#define GDI_MAX_DCS   2048
#define GDI_MAX_FONTS 2048

static GdiBmp    g_gdi_bmps[GDI_MAX_BMPS];
static GdiFont   g_gdi_fonts[GDI_MAX_FONTS];
static GdiDC     g_gdi_dcs[GDI_MAX_DCS];
static AddedFont g_added_fonts[128];
static int       g_added_font_cnt = 0;
static pthread_mutex_t g_gdi_mu = PTHREAD_MUTEX_INITIALIZER;

static int gdi_strcasecmp_nospace(const char *a, const char *b) {
    while (*a || *b) {
        while (*a == ' ' || *a == '-' || *a == '_') a++;
        while (*b == ' ' || *b == '-' || *b == '_') b++;
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        if (!*a) break;
        a++; b++;
    }
    return 0;
}

static void gdi_register_cgfont(CGFontRef cg, const char *fallback_name) {
    if (!cg) return;
    CTFontRef tmp = CTFontCreateWithGraphicsFont(cg, 16.0, NULL, NULL);
    char fam[128] = {0};
    if (tmp) {
        CFStringRef cfs = CTFontCopyFamilyName(tmp);
        if (cfs) {
            CFStringGetCString(cfs, fam, sizeof(fam), kCFStringEncodingUTF8);
            CFRelease(cfs);
        }
        CFRelease(tmp);
    }
    if (!fam[0] && fallback_name) snprintf(fam, sizeof(fam), "%s", fallback_name);
    pthread_mutex_lock(&g_gdi_mu);
    if (g_added_font_cnt < 128) {
        snprintf(g_added_fonts[g_added_font_cnt].family, sizeof(g_added_fonts[0].family), "%s", fam);
        g_added_fonts[g_added_font_cnt].cg = CGFontRetain(cg);
        g_added_font_cnt++;
    }
    pthread_mutex_unlock(&g_gdi_mu);
}

static void w_AddFontResourceA(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) { c->rax = 0; return; }
    char px[1024];
    win_path_to_posix((const char *)(uintptr_t)c->rcx, px, sizeof(px));
    CGDataProviderRef prov = CGDataProviderCreateWithFilename(px);
    if (!prov) { c->rax = 0; return; }
    CGFontRef cg = CGFontCreateWithDataProvider(prov);
    CGDataProviderRelease(prov);
    if (!cg) { c->rax = 0; return; }
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)px, (CFIndex)strlen(px), false);
    if (url) {
        CTFontManagerRegisterFontsForURL(url, kCTFontManagerScopeProcess, NULL);
        CFRelease(url);
    }
    const char *base = strrchr(px, '/');
    gdi_register_cgfont(cg, base ? base + 1 : px);
    CGFontRelease(cg);
    c->rax = 1;
}

static void w_AddFontMemResourceEx(CPU64 *c, void *ud) {
    (void)ud;
    const void *data = (const void *)(uintptr_t)c->rcx;
    uint32_t len = (uint32_t)c->rdx;
    uint64_t p_num = c->r9;
    if (!data || !len) { c->rax = 0; return; }
    void *copy = malloc(len);
    if (!copy) { c->rax = 0; return; }
    memcpy(copy, data, len);
    CGDataProviderRef prov = CGDataProviderCreateWithData(NULL, copy, len, NULL);
    CGFontRef cg = prov ? CGFontCreateWithDataProvider(prov) : NULL;
    if (prov) CGDataProviderRelease(prov);
    if (cg) {
        gdi_register_cgfont(cg, "MemFont");
        CGFontRelease(cg);
        if (p_num) W32(p_num, 1);
        c->rax = 0x53001ULL;
        return;
    }
    free(copy);
    c->rax = 0;
}

static void w_EnumFontFamiliesExA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t lf_va = c->rdx;
    uint64_t proc = c->r8;
    uint64_t lparam = c->r9;
    if (!proc) { c->rax = 1; return; }
    uint8_t *elf = (uint8_t *)calloc(1, 320);
    uint8_t *ntm = (uint8_t *)calloc(1, 128);
    if (lf_va) {
        memcpy(elf, (const void *)(uintptr_t)lf_va, 60);
        memcpy(elf + 60, (const void *)(uintptr_t)(lf_va + 28), 32);
    }
    W32((uint64_t)(uintptr_t)ntm + 0, 16);
    W32((uint64_t)(uintptr_t)ntm + 4, 13);
    W32((uint64_t)(uintptr_t)ntm + 8, 3);
    W32((uint64_t)(uintptr_t)ntm + 20, 8);
    W32((uint64_t)(uintptr_t)ntm + 24, 16);
    W32((uint64_t)(uintptr_t)ntm + 28, 400);
    uint64_t r = rt_invoke_win64(c, proc, (uint64_t)(uintptr_t)elf,
                                 (uint64_t)(uintptr_t)ntm, 4 /* TRUETYPE_FONTTYPE */, lparam, 0, 0);
    free(elf);
    free(ntm);
    c->rax = r;
}

static GdiDC *gdi_dc_get(uint64_t hdc) {
    if (hdc >= 0x51000ULL && hdc < 0x51000ULL + GDI_MAX_DCS) {
        GdiDC *dc = &g_gdi_dcs[hdc - 0x51000ULL];
        if (dc->in_use) return dc;
    }
    return NULL;
}
static GdiBmp *gdi_bmp_get(uint64_t h) {
    if (h >= 0x50000ULL && h < 0x50000ULL + GDI_MAX_BMPS) {
        GdiBmp *b = &g_gdi_bmps[h - 0x50000ULL];
        if (b->bits) return b;
    }
    return NULL;
}
static GdiFont *gdi_font_get(uint64_t h) {
    if (h >= 0x52000ULL && h < 0x52000ULL + GDI_MAX_FONTS) {
        GdiFont *f = &g_gdi_fonts[h - 0x52000ULL];
        if (f->ct) return f;
    }
    return NULL;
}

static void w_CreateCompatibleDC(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    for (int i = 0; i < GDI_MAX_DCS; i++) {
        if (!g_gdi_dcs[i].in_use) {
            memset(&g_gdi_dcs[i], 0, sizeof(g_gdi_dcs[i]));
            g_gdi_dcs[i].in_use = 1;
            g_gdi_dcs[i].text_color = 0x00FFFFFFU;
            g_gdi_dcs[i].bk_color = 0x00000000U;
            pthread_mutex_unlock(&g_gdi_mu);
            c->rax = 0x51000ULL + (uint64_t)i;
            return;
        }
    }
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = 0;
}

static void w_DeleteDC(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx >= 0x51000ULL && c->rcx < 0x51000ULL + GDI_MAX_DCS) {
        pthread_mutex_lock(&g_gdi_mu);
        g_gdi_dcs[c->rcx - 0x51000ULL].in_use = 0;
        pthread_mutex_unlock(&g_gdi_mu);
    }
    c->rax = 1;
}

static void w_CreateFontA(CPU64 *c, void *ud) {
    (void)ud;
    int32_t cHeight = (int32_t)c->rcx;
    int32_t cWeight = (int32_t)win64_arg_i(c, 4);
    uint32_t bItalic = (uint32_t)win64_arg_i(c, 5);
    const char *face = (const char *)(uintptr_t)win64_arg_i(c, 13);
    CGFloat pt = (cHeight < 0) ? (CGFloat)(-cHeight) : (cHeight > 0 ? (CGFloat)cHeight * 0.82 : 16.0);
    if (pt < 4.0) pt = 4.0;

    CTFontRef ct = NULL;
    if (face && *face) {
        pthread_mutex_lock(&g_gdi_mu);
        for (int i = g_added_font_cnt - 1; i >= 0; i--) {
            if (gdi_strcasecmp_nospace(g_added_fonts[i].family, face) == 0) {
                ct = CTFontCreateWithGraphicsFont(g_added_fonts[i].cg, pt, NULL, NULL);
                break;
            }
        }
        pthread_mutex_unlock(&g_gdi_mu);
        if (!ct) {
            const char *mapped = face;
            if (strcasecmp(face, "Tahoma") == 0 || strcasecmp(face, "Segoe UI") == 0 ||
                strcasecmp(face, "MS Shell Dlg") == 0 || strcasecmp(face, "MS Sans Serif") == 0)
                mapped = "Helvetica Neue";
            CFStringRef cfs = CFStringCreateWithCString(NULL, mapped, kCFStringEncodingUTF8);
            if (cfs) {
                CTFontDescriptorRef desc = CTFontDescriptorCreateWithNameAndSize(cfs, pt);
                CFRelease(cfs);
                if (desc) {
                    CTFontRef cand = CTFontCreateWithFontDescriptor(desc, pt, NULL);
                    CFRelease(desc);
                    if (cand) ct = cand;
                }
            }
        }
    }
    if (!ct) ct = CTFontCreateUIFontForLanguage(kCTFontUIFontSystem, pt, NULL);
    CTFontSymbolicTraits traits = 0;
    if (cWeight >= 600) traits |= kCTFontBoldTrait;
    if (bItalic) traits |= kCTFontItalicTrait;
    if (traits && ct) {
        CTFontRef styled = CTFontCreateCopyWithSymbolicTraits(ct, pt, NULL, traits, traits);
        if (styled) { CFRelease(ct); ct = styled; }
    }

    int asc = (int)ceil(CTFontGetAscent(ct));
    int des = (int)ceil(CTFontGetDescent(ct));
    int lead = (int)ceil(CTFontGetLeading(ct));
    if (asc < 1) asc = (int)ceil(pt * 0.8);
    if (des < 1) des = (int)ceil(pt * 0.2);
    int h = asc + des;
    UniChar sample = 'x';
    CGGlyph sg = 0;
    CGSize sadv = { pt * 0.5, 0 };
    if (CTFontGetGlyphsForCharacters(ct, &sample, &sg, 1))
        CTFontGetAdvancesForGlyphs(ct, kCTFontOrientationHorizontal, &sg, &sadv, 1);

    pthread_mutex_lock(&g_gdi_mu);
    for (int i = 0; i < GDI_MAX_FONTS; i++) {
        if (!g_gdi_fonts[i].ct) {
            g_gdi_fonts[i].ct = ct;
            g_gdi_fonts[i].height = h;
            g_gdi_fonts[i].ascent = asc;
            g_gdi_fonts[i].descent = des;
            g_gdi_fonts[i].leading = lead;
            g_gdi_fonts[i].ave_w = (int)ceil(sadv.width);
            g_gdi_fonts[i].max_w = (int)ceil(pt * 1.25);
            g_gdi_fonts[i].weight = cWeight ? cWeight : 400;
            pthread_mutex_unlock(&g_gdi_mu);
            c->rax = 0x52000ULL + (uint64_t)i;
            return;
        }
    }
    pthread_mutex_unlock(&g_gdi_mu);
    CFRelease(ct);
    c->rax = 0;
}

static void w_SelectObject(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    uint64_t h = c->rdx;
    uint64_t prev = 1;
    if (dc) {
        if (h >= 0x50000ULL && h < 0x50000ULL + GDI_MAX_BMPS) { prev = dc->hbmp ? dc->hbmp : 1; dc->hbmp = h; }
        else if (h >= 0x52000ULL && h < 0x52000ULL + GDI_MAX_FONTS) { prev = dc->hfont ? dc->hfont : 1; dc->hfont = h; }
    }
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = prev;
}

static void w_SetTextColor(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    uint32_t prev = dc ? dc->text_color : 0x00FFFFFFU;
    if (dc) dc->text_color = (uint32_t)c->rdx;
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = prev;
}
static void w_GetTextColor(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    c->rax = dc ? dc->text_color : 0x00FFFFFFU;
    pthread_mutex_unlock(&g_gdi_mu);
}
static void w_SetBkColor(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    uint32_t prev = dc ? dc->bk_color : 0;
    if (dc) dc->bk_color = (uint32_t)c->rdx;
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = prev;
}
static void w_GetBkColor(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    c->rax = dc ? dc->bk_color : 0;
    pthread_mutex_unlock(&g_gdi_mu);
}
static void w_SetBkMode(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    int prev = dc ? dc->bk_mode : 1;
    if (dc) dc->bk_mode = (int)c->rdx;
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = (uint64_t)(uint32_t)prev;
}
static void w_SetTextAlign(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    uint32_t prev = dc ? dc->text_align : 0;
    if (dc) dc->text_align = (uint32_t)c->rdx;
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = prev;
}
static void w_MoveToEx(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    if (dc) {
        if (c->r9) { W32(c->r9, (uint32_t)dc->cur_x); W32(c->r9 + 4, (uint32_t)dc->cur_y); }
        dc->cur_x = (int32_t)c->rdx;
        dc->cur_y = (int32_t)c->r8;
    }
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = 1;
}

static void w_CreateDIBSection(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t bmi = c->rdx;
    uint64_t ppv = c->r9;
    int w = bmi ? (int32_t)R32(bmi + 4) : 16;
    int raw_h = bmi ? (int32_t)R32(bmi + 8) : -16;
    int top_down = (raw_h < 0);
    int h = top_down ? -raw_h : raw_h;
    if (w <= 0) w = 16;
    if (h == 0) h = 16;
    int bpp = bmi ? (int)R16(bmi + 14) : 32;
    if (bpp < 8) bpp = 32;
    size_t stride = (((size_t)w * (size_t)bpp + 31) / 32) * 4;
    void *bits = calloc(1, stride * (size_t)h + 64);
    if (ppv) W64(ppv, (uint64_t)(uintptr_t)bits);
    pthread_mutex_lock(&g_gdi_mu);
    for (int i = 0; i < GDI_MAX_BMPS; i++) {
        if (!g_gdi_bmps[i].bits) {
            g_gdi_bmps[i].w = w; g_gdi_bmps[i].h = h; g_gdi_bmps[i].bpp = bpp;
            g_gdi_bmps[i].top_down = top_down; g_gdi_bmps[i].stride = stride; g_gdi_bmps[i].bits = bits;
            pthread_mutex_unlock(&g_gdi_mu);
            c->rax = 0x50000ULL + (uint64_t)i;
            return;
        }
    }
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = 0x50FFFULL;
}
static void w_DeleteObject(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_gdi_mu);
    if (c->rcx >= 0x50000ULL && c->rcx < 0x50000ULL + GDI_MAX_BMPS) {
        size_t idx = (size_t)(c->rcx - 0x50000ULL);
        free(g_gdi_bmps[idx].bits);
        memset(&g_gdi_bmps[idx], 0, sizeof(g_gdi_bmps[idx]));
    } else if (c->rcx >= 0x52000ULL && c->rcx < 0x52000ULL + GDI_MAX_FONTS) {
        size_t idx = (size_t)(c->rcx - 0x52000ULL);
        if (g_gdi_fonts[idx].ct) CFRelease(g_gdi_fonts[idx].ct);
        memset(&g_gdi_fonts[idx], 0, sizeof(g_gdi_fonts[idx]));
    }
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = 1;
}
static void w_GetObjectA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t h = c->rcx;
    int cb = (int)c->rdx;
    uint64_t out = c->r8;
    pthread_mutex_lock(&g_gdi_mu);
    GdiBmp *b = gdi_bmp_get(h);
    if (b && out && cb >= 32) {
        memset((void *)(uintptr_t)out, 0, (size_t)cb);
        W32(out + 4, (uint32_t)b->w);
        W32(out + 8, (uint32_t)b->h);
        W32(out + 12, (uint32_t)b->stride);
        W16(out + 16, 1);
        W16(out + 18, (uint16_t)b->bpp);
        W64(out + 24, (uint64_t)(uintptr_t)b->bits);
        pthread_mutex_unlock(&g_gdi_mu);
        c->rax = 32;
        return;
    }
    pthread_mutex_unlock(&g_gdi_mu);
    c->rax = 0;
}
static void w_GetTextMetricsA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t tm = c->rdx;
    if (!tm) { c->rax = 0; return; }
    memset((void *)(uintptr_t)tm, 0, 56);
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    GdiFont *f = dc ? gdi_font_get(dc->hfont) : NULL;
    int h = f ? f->height : 16, asc = f ? f->ascent : 13, des = f ? f->descent : 3;
    int lead = f ? f->leading : 0, ave = f ? f->ave_w : 8, maxw = f ? f->max_w : 16, wt = f ? f->weight : 400;
    pthread_mutex_unlock(&g_gdi_mu);
    W32(tm + 0, (uint32_t)h);
    W32(tm + 4, (uint32_t)asc);
    W32(tm + 8, (uint32_t)des);
    W32(tm + 12, 0);
    W32(tm + 16, (uint32_t)lead);
    W32(tm + 20, (uint32_t)ave);
    W32(tm + 24, (uint32_t)maxw);
    W32(tm + 28, (uint32_t)wt);
    W8(tm + 48, 32);
    W8(tm + 49, 255);
    W8(tm + 50, 32);
    W8(tm + 51, 32);
    c->rax = 1;
}
static void w_GetCharABCWidths(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t first = (uint32_t)c->rdx, last = (uint32_t)c->r8;
    uint64_t out = c->r9;
    if (!out || last < first || (last - first) > 65536) { c->rax = 0; return; }
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    GdiFont *f = dc ? gdi_font_get(dc->hfont) : NULL;
    CTFontRef ct = f ? (CTFontRef)CFRetain(f->ct) : NULL;
    pthread_mutex_unlock(&g_gdi_mu);
    for (uint32_t i = 0; i <= last - first; i++) {
        uint32_t ch = first + i;
        int32_t a = 0, b = 8, cc = 1;
        if (ct) {
            UniChar uc = (UniChar)ch;
            CGGlyph g = 0;
            if (CTFontGetGlyphsForCharacters(ct, &uc, &g, 1)) {
                CGSize adv = {0, 0};
                CGRect bb = CGRectZero;
                CTFontGetAdvancesForGlyphs(ct, kCTFontOrientationHorizontal, &g, &adv, 1);
                CTFontGetBoundingRectsForGlyphs(ct, kCTFontOrientationHorizontal, &g, &bb, 1);
                int32_t adv_i = (int32_t)llround(adv.width);
                if (bb.size.width > 0.001) {
                    a = (int32_t)floor(bb.origin.x);
                    b = (int32_t)ceil(bb.origin.x + bb.size.width) - a;
                    if (b < 1) b = 1;
                    cc = adv_i - a - b;
                } else {
                    a = 0; b = 0; cc = adv_i;
                }
            } else {
                a = 0; b = 0; cc = (int32_t)ceil(CTFontGetSize(ct) * 0.35);
            }
        }
        W32(out + i * 12ULL + 0, (uint32_t)a);
        W32(out + i * 12ULL + 4, (uint32_t)b);
        W32(out + i * 12ULL + 8, (uint32_t)cc);
    }
    if (ct) CFRelease(ct);
    c->rax = 1;
}
static void w_GetTextExtentPoint32A(CPU64 *c, void *ud) {
    (void)ud;
    const char *s = (const char *)(uintptr_t)c->rdx;
    int len = (int)c->r8;
    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(c->rcx);
    GdiFont *f = dc ? gdi_font_get(dc->hfont) : NULL;
    CTFontRef ct = f ? (CTFontRef)CFRetain(f->ct) : NULL;
    int fh = f ? f->height : 16;
    pthread_mutex_unlock(&g_gdi_mu);
    double w = 0;
    if (ct && s && len > 0) {
        for (int i = 0; i < len; i++) {
            UniChar uc = (UniChar)(uint8_t)s[i];
            CGGlyph g = 0;
            if (CTFontGetGlyphsForCharacters(ct, &uc, &g, 1)) {
                CGSize adv = {0, 0};
                CTFontGetAdvancesForGlyphs(ct, kCTFontOrientationHorizontal, &g, &adv, 1);
                w += adv.width;
            }
        }
    } else if (len > 0) {
        w = len * 8.0;
    }
    if (ct) CFRelease(ct);
    if (c->r9) { W32(c->r9, (uint32_t)llround(w)); W32(c->r9 + 4, (uint32_t)fh); }
    c->rax = 1;
}
static void gdi_ext_text_out(CPU64 *c, int is_wide) {
    uint64_t hdc = c->rcx;
    int32_t x = (int32_t)c->rdx;
    int32_t y = (int32_t)c->r8;
    uint32_t opts = (uint32_t)c->r9;
    uint64_t rect_va = win64_arg_i(c, 4);
    uint64_t str_va = win64_arg_i(c, 5);
    int count = (int32_t)win64_arg_i(c, 6);

    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(hdc);
    GdiBmp *b = dc ? gdi_bmp_get(dc->hbmp) : NULL;
    GdiFont *f = dc ? gdi_font_get(dc->hfont) : NULL;
    if (!dc || !b || !b->bits || b->bpp != 32) {
        pthread_mutex_unlock(&g_gdi_mu);
        c->rax = 1;
        return;
    }
    uint32_t ta = dc->text_align;
    if (ta & 1) { x = dc->cur_x; y = dc->cur_y; }
    uint32_t tc = dc->text_color, bc = dc->bk_color;
    int bw = b->w, bh = b->h, td = b->top_down;
    size_t stride = b->stride;
    void *bits = b->bits;
    CTFontRef ct = f ? (CTFontRef)CFRetain(f->ct) : NULL;
    int asc = f ? f->ascent : 13;
    pthread_mutex_unlock(&g_gdi_mu);

    if ((opts & 2U) && rect_va) {
        int32_t rl = (int32_t)R32(rect_va + 0), rt = (int32_t)R32(rect_va + 4);
        int32_t rr = (int32_t)R32(rect_va + 8), rb = (int32_t)R32(rect_va + 12);
        if (rl < 0) rl = 0; if (rt < 0) rt = 0;
        if (rr > bw) rr = bw; if (rb > bh) rb = bh;
        uint32_t bgra = 0xFF000000U | ((bc & 0xFFU) << 16) | (bc & 0xFF00U) | ((bc >> 16) & 0xFFU);
        for (int py = rt; py < rb; py++) {
            int row = td ? py : (bh - 1 - py);
            uint32_t *dst = (uint32_t *)((uint8_t *)bits + (size_t)row * stride);
            for (int px = rl; px < rr; px++) dst[px] = bgra;
        }
    }

    if (ct && str_va && count > 0) {
        if (count > 256) count = 256;
        UniChar ucs[256];
        CGGlyph glyphs[256];
        for (int i = 0; i < count; i++) {
            ucs[i] = is_wide ? R16(str_va + (uint64_t)i * 2) : (UniChar)R8(str_va + (uint64_t)i);
        }
        CTFontGetGlyphsForCharacters(ct, ucs, glyphs, count);
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGContextRef ctx = CGBitmapContextCreate(bits, (size_t)bw, (size_t)bh, 8, stride, cs,
                                                 kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
        CGColorSpaceRelease(cs);
        if (ctx) {
            if (!td) {
                CGContextTranslateCTM(ctx, 0, (CGFloat)bh);
                CGContextScaleCTM(ctx, 1.0, -1.0);
            }
            CGContextSetAllowsAntialiasing(ctx, true);
            CGContextSetShouldAntialias(ctx, true);
            CGContextSetAllowsFontSmoothing(ctx, false);
            CGContextSetShouldSmoothFonts(ctx, false);
            CGContextSetRGBFillColor(ctx, (CGFloat)(tc & 0xFFU) / 255.0,
                                     (CGFloat)((tc >> 8) & 0xFFU) / 255.0,
                                     (CGFloat)((tc >> 16) & 0xFFU) / 255.0, 1.0);
            CGFloat pen_x = (CGFloat)x;
            CGFloat base_y = (CGFloat)bh - (CGFloat)(y + asc);
            for (int i = 0; i < count; i++) {
                if (glyphs[i]) {
                    CGPoint pt = CGPointMake(pen_x, base_y);
                    CTFontDrawGlyphs(ct, &glyphs[i], &pt, 1, ctx);
                }
                CGSize adv = {0, 0};
                CTFontGetAdvancesForGlyphs(ct, kCTFontOrientationHorizontal, &glyphs[i], &adv, 1);
                pen_x += adv.width;
            }
            CGContextRelease(ctx);
            if (ta & 1) {
                pthread_mutex_lock(&g_gdi_mu);
                GdiDC *dc2 = gdi_dc_get(hdc);
                if (dc2) dc2->cur_x = (int32_t)llround(pen_x);
                pthread_mutex_unlock(&g_gdi_mu);
            }
        }
    }
    if (ct) CFRelease(ct);
    c->rax = 1;
}
static void w_ExtTextOutA(CPU64 *c, void *ud) { (void)ud; gdi_ext_text_out(c, 0); }
static void w_ExtTextOutW(CPU64 *c, void *ud) { (void)ud; gdi_ext_text_out(c, 1); }

static void w_GetGlyphOutlineA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t hdc = c->rcx;
    uint32_t uChar = (uint32_t)c->rdx;
    uint32_t fuFormat = (uint32_t)c->r8;
    uint64_t gm = c->r9;
    uint32_t cb = (uint32_t)win64_arg_i(c, 4);
    uint64_t buf = win64_arg_i(c, 5);

    pthread_mutex_lock(&g_gdi_mu);
    GdiDC *dc = gdi_dc_get(hdc);
    GdiFont *f = dc ? gdi_font_get(dc->hfont) : NULL;
    CTFontRef ct = f ? (CTFontRef)CFRetain(f->ct) : NULL;
    pthread_mutex_unlock(&g_gdi_mu);

    if (!ct) {
        if (gm) {
            memset((void *)(uintptr_t)gm, 0, 20);
            W32(gm + 0, 8); W32(gm + 4, 14); W32(gm + 8, 0); W32(gm + 12, 13);
            W16(gm + 16, 9); W16(gm + 18, 0);
        }
        uint32_t need = 8 * 14;
        if (buf && cb >= need) memset((void *)(uintptr_t)buf, 0, need);
        c->rax = need;
        return;
    }

    UniChar uc = (UniChar)(uChar & 0xFFFFU);
    CGGlyph g = 0;
    CTFontGetGlyphsForCharacters(ct, &uc, &g, 1);
    CGSize adv = {0, 0};
    CGRect bb = CGRectZero;
    if (g) {
        CTFontGetAdvancesForGlyphs(ct, kCTFontOrientationHorizontal, &g, &adv, 1);
        CTFontGetBoundingRectsForGlyphs(ct, kCTFontOrientationHorizontal, &g, &bb, 1);
    }
    int32_t gx = (bb.size.width > 0.001) ? (int32_t)floor(bb.origin.x) : 0;
    int32_t gy = (bb.size.height > 0.001) ? (int32_t)ceil(bb.origin.y + bb.size.height) : 0;
    int32_t bw = (bb.size.width > 0.001) ? (int32_t)ceil(bb.origin.x + bb.size.width) - gx : 0;
    int32_t bh = (bb.size.height > 0.001) ? gy - (int32_t)floor(bb.origin.y) : 0;
    if (bw < 0) bw = 0;
    if (bh < 0) bh = 0;

    if (gm) {
        memset((void *)(uintptr_t)gm, 0, 20);
        W32(gm + 0, (uint32_t)bw);
        W32(gm + 4, (uint32_t)bh);
        W32(gm + 8, (uint32_t)gx);
        W32(gm + 12, (uint32_t)gy);
        W16(gm + 16, (uint16_t)(int16_t)llround(adv.width));
        W16(gm + 18, 0);
    }

    uint32_t fmt = fuFormat & 0x7FU;
    if (fmt == 0 /* GGO_METRICS */ || bw == 0 || bh == 0) {
        CFRelease(ct);
        c->rax = 0;
        return;
    }
    uint32_t pitch = (fmt == 1 /* GGO_BITMAP */) ? (uint32_t)(((bw + 31) / 32) * 4) : (uint32_t)((bw + 3) & ~3);
    uint32_t need = pitch * (uint32_t)bh;
    if (!buf || cb == 0) {
        CFRelease(ct);
        c->rax = need;
        return;
    }
    if (cb < need) {
        CFRelease(ct);
        c->rax = 0xFFFFFFFFULL; /* GDI_ERROR */
        return;
    }

    uint32_t gray_pitch = (uint32_t)((bw + 3) & ~3);
    uint8_t *tmp = (uint8_t *)calloc((size_t)gray_pitch, (size_t)bh);
    if (tmp) {
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceGray();
        CGContextRef ctx = CGBitmapContextCreate(tmp, (size_t)bw, (size_t)bh, 8, gray_pitch, cs, kCGImageAlphaNone);
        CGColorSpaceRelease(cs);
        if (ctx) {
            CGContextSetAllowsAntialiasing(ctx, fmt != 1);
            CGContextSetShouldAntialias(ctx, fmt != 1);
            CGContextSetAllowsFontSmoothing(ctx, false);
            CGContextSetShouldSmoothFonts(ctx, false);
            CGContextSetGrayFillColor(ctx, 1.0, 1.0);
            CGPoint pt = CGPointMake((CGFloat)(-gx), (CGFloat)(bh - gy));
            CTFontDrawGlyphs(ct, &g, &pt, 1, ctx);
            CGContextRelease(ctx);
        }
        uint8_t *dst = (uint8_t *)(uintptr_t)buf;
        memset(dst, 0, need);
        if (fmt == 1) {
            for (int y = 0; y < bh; y++) {
                for (int x = 0; x < bw; x++) {
                    if (tmp[(size_t)y * gray_pitch + (size_t)x] >= 128)
                        dst[(size_t)y * pitch + (size_t)(x >> 3)] |= (uint8_t)(0x80U >> (x & 7));
                }
            }
        } else {
            uint32_t maxv = (fmt == 4) ? 4U : (fmt == 5) ? 16U : 64U;
            for (int y = 0; y < bh; y++) {
                for (int x = 0; x < bw; x++) {
                    uint32_t v = tmp[(size_t)y * gray_pitch + (size_t)x];
                    dst[(size_t)y * pitch + (size_t)x] = (uint8_t)((v * maxv + 127U) / 255U);
                }
            }
        }
        free(tmp);
    }
    CFRelease(ct);
    c->rax = need;
}

static void w_RtlUnwindEx(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t exc_rec = c->r8;
    uint64_t retval = c->r9;
    if (exc_rec && R32(exc_rec) == 0x80000026U /* STATUS_LONGJUMP */) {
        uint64_t jmpbuf_va = R64(exc_rec + 0x20);
        rt_longjmp_unwind(c, jmpbuf_va, retval);
    }
    c->rax = 0;
}
static void w_longjmp(CPU64 *c, void *ud) {
    (void)ud;
    rt_longjmp_unwind(c, c->rcx, c->rdx);
    c->rax = 0;
}
static void w_GetKeyboardLayout(CPU64 *c, void *ud) { (void)ud; c->rax = 0x04090409ULL; }
static void w_GetKeyboardLayoutList(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx >= 1 && c->rdx) W64(c->rdx, 0x04090409ULL);
    c->rax = 1;
}
static void w_RegisterWindowMessageA(CPU64 *c, void *ud) {
    (void)ud;
    static uint32_t msg = 0xC100;
    c->rax = msg++;
}
static void w_GetCursorPos(CPU64 *c, void *ud) {
    (void)ud;
    int x = 640, y = 360;
    win32_get_mouse_xy(&x, &y);
    if (c->rcx) { W32(c->rcx, (uint32_t)x); W32(c->rcx + 4, (uint32_t)y); }
    c->rax = 1;
}
extern uint64_t win32_primary_hwnd(void);
extern uint32_t win32_map_virtual_key(uint32_t code, uint32_t map_type);
extern void     win32_set_mouse_xy(int x, int y);
extern int      win32_show_cursor(int show);
extern uint32_t win32_get_raw_input_data(uint64_t hraw, uint32_t cmd, uint64_t pdata, uint64_t pcb_va);

static void w_SetCursorPos(CPU64 *c, void *ud) {
    (void)ud;
    win32_set_mouse_xy((int)c->rcx, (int)c->rdx);
    if (!SDL_GetRelativeMouseMode() && !getenv("ELF64_HEADLESS")) {
        SDL_Window *w = win32_hwnd_to_sdl(win32_primary_hwnd());
        if (w) SDL_WarpMouseInWindow(w, (int)c->rcx, (int)c->rdx);
    }
    c->rax = 1;
}
static void w_ShowCursor(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(int64_t)win32_show_cursor((int)c->rcx);
}
static uint64_t g_last_hcursor = 1;
static void w_SetCursor(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t prev = g_last_hcursor;
    g_last_hcursor = c->rcx;
    win32_show_cursor(c->rcx != 0);
    c->rax = prev;
}
static void w_GetRawInputData(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = win32_get_raw_input_data(c->rcx, (uint32_t)c->rdx, c->r8, c->r9);
}
static void w_GetKeyState(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = win32_vk_is_down((int)c->rcx) ? 0x8000ULL : 0ULL;
}
static void w_MapVirtualKey(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = win32_map_virtual_key((uint32_t)c->rcx, (uint32_t)c->rdx);
}
static void w_GetForegroundWindow(CPU64 *c, void *ud) { (void)ud; c->rax = win32_primary_hwnd(); }

static SDL_AudioDeviceID g_sdl_audio_dev = 0;
static void w_waveOutOpen(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) W64(c->rcx, 0x60001ULL);
    if (!g_sdl_audio_dev && !getenv("ELF64_HEADLESS") && c->r8) {
        if (!SDL_WasInit(SDL_INIT_AUDIO)) SDL_InitSubSystem(SDL_INIT_AUDIO);
        SDL_AudioSpec want;
        SDL_zero(want);
        uint16_t ch = R16(c->r8 + 2);
        uint32_t hz = R32(c->r8 + 4);
        uint16_t bits = R16(c->r8 + 14);
        want.freq = (hz >= 8000 && hz <= 96000) ? (int)hz : 44100;
        want.channels = (ch >= 1 && ch <= 2) ? (Uint8)ch : 2;
        want.format = (bits == 8) ? AUDIO_U8 : AUDIO_S16LSB;
        want.samples = 1024;
        g_sdl_audio_dev = SDL_OpenAudioDevice(NULL, 0, &want, NULL, 0);
        if (g_sdl_audio_dev) SDL_PauseAudioDevice(g_sdl_audio_dev, 0);
    }
    c->rax = 0; /* MMSYSERR_NOERROR */
}
static void w_waveOutPrepareHeader(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx + 24, R32(c->rdx + 24) | 0x00000002U /* WHDR_PREPARED */);
    c->rax = 0;
}
static void w_waveOutWrite(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) {
        if (g_sdl_audio_dev) {
            uint64_t data_va = R64(c->rdx + 0);
            uint32_t len     = R32(c->rdx + 8);
            if (data_va && len > 0 && SDL_GetQueuedAudioSize(g_sdl_audio_dev) < 65536U) {
                SDL_QueueAudio(g_sdl_audio_dev, (const void *)(uintptr_t)data_va, len);
            }
        }
        W32(c->rdx + 24, R32(c->rdx + 24) | 0x00000001U /* WHDR_DONE */);
    }
    c->rax = 0;
}
static void w_waveOutGetPosition(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx + 4, 0);
    c->rax = 0;
}

/* ---- MMDeviceEnumerator + XAudio2 2.9 -> SDL2 Audio Bridge ---- */
typedef struct { const uint64_t *lpVtbl; } AudioComObj;

typedef struct {
    const uint64_t *lpVtbl;
    uint32_t        channels;
    uint32_t        sample_rate;
} XA2MasterVoice;

typedef struct {
    uint64_t end_byte;
    uint64_t ctx_va;
} XA2PendingBuf;

typedef struct {
    const uint64_t   *lpVtbl;
    SDL_AudioDeviceID dev;
    uint32_t          channels;
    uint32_t          sample_rate;
    uint32_t          bits;
    int               is_float;
    float             volume;
    uint64_t          cb_va;
    uint64_t          total_submitted;
    uint64_t          samples_played;
    XA2PendingBuf     pend[32];
    int               pend_head;
    int               pend_tail;
    int               pend_count;
} XA2SourceVoice;

static uint64_t g_vt_mm_enum[8], g_vt_mm_coll[8], g_vt_mm_dev[8], g_vt_prop_store[8];
static uint64_t g_vt_xa2[16], g_vt_xa2_27[16], g_vt_xa2_master[24], g_vt_xa2_27_master[24], g_vt_xa2_source[32];
static int      g_audio_vt_ready = 0;
static AudioComObj g_mm_enum_obj, g_mm_coll_obj, g_mm_dev_obj, g_prop_store_obj;
static XA2SourceVoice *g_active_xa2_voice = NULL;
static pthread_mutex_t g_xa2_mu = PTHREAD_MUTEX_INITIALIZER;

static uint64_t alloc_utf16_ascii(const char *s) {
    size_t n = strlen(s);
    uint16_t *w = (uint16_t *)calloc(n + 1, sizeof(uint16_t));
    if (!w) return 0;
    for (size_t i = 0; i < n; i++) w[i] = (uint8_t)s[i];
    return (uint64_t)(uintptr_t)w;
}

static void ac_qi(CPU64 *c, void *ud)  { (void)ud; if (c->r8) W64(c->r8, c->rcx); c->rax = 0; }
static void ac_add(CPU64 *c, void *ud) { (void)ud; c->rax = 1; }
static void ac_rel(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void ac_ok(CPU64 *c, void *ud)  { (void)ud; c->rax = 0; }
static void ac_void(CPU64 *c, void *ud){ (void)ud; }

static void mme_EnumAudioEndpoints(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r9) W64(c->r9, (uint64_t)(uintptr_t)&g_mm_coll_obj);
    c->rax = 0;
}
static void mme_GetDefaultAudioEndpoint(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r9) W64(c->r9, (uint64_t)(uintptr_t)&g_mm_dev_obj);
    c->rax = 0;
}
static void mme_GetDevice(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r8) W64(c->r8, (uint64_t)(uintptr_t)&g_mm_dev_obj);
    c->rax = 0;
}
static void mmc_GetCount(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx, 1);
    c->rax = 0;
}
static void mmc_Item(CPU64 *c, void *ud) {
    (void)ud;
    if ((uint32_t)c->rdx == 0 && c->r8) { W64(c->r8, (uint64_t)(uintptr_t)&g_mm_dev_obj); c->rax = 0; }
    else c->rax = 0x80070057ULL;
}
static void mmd_Activate(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t ppv = win64_arg_i(c, 4);
    if (ppv) W64(ppv, 0);
    c->rax = 0x80004002ULL; /* E_NOINTERFACE */
}
static void mmd_OpenPropertyStore(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r8) W64(c->r8, (uint64_t)(uintptr_t)&g_prop_store_obj);
    c->rax = 0;
}
static void mmd_GetId(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W64(c->rdx, alloc_utf16_ascii("default"));
    c->rax = 0;
}
static void mmd_GetState(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx, 1); /* DEVICE_STATE_ACTIVE */
    c->rax = 0;
}
static void ps_GetCount(CPU64 *c, void *ud) { (void)ud; if (c->rdx) W32(c->rdx, 1); c->rax = 0; }
static void ps_GetValue(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r8) {
        memset((void *)(uintptr_t)c->r8, 0, 24);
        W16(c->r8 + 0, 31 /* VT_LPWSTR */);
        W64(c->r8 + 8, alloc_utf16_ascii("Apple Silicon Audio"));
    }
    c->rax = 0;
}

static void xa2_fire_buf_end(CPU64 *c, XA2SourceVoice *v, uint64_t ctx_va) {
    if (!v || !v->cb_va) return;
    uint64_t vt = R64(v->cb_va);
    if (!vt) return;
    uint64_t fn = R64(vt + 0x20); /* IXAudio2VoiceCallback::OnBufferEnd */
    if (fn > 0x10000ULL) rt_invoke_win64(c, fn, v->cb_va, ctx_va, 0, 0, 0, 0);
}

static void xa2_drain_voice(CPU64 *c, XA2SourceVoice *v, int force_all) {
    if (!v) return;
    uint64_t done_ctx[32];
    int n_done = 0;
    pthread_mutex_lock(&g_xa2_mu);
    if (v->pend_count > 0) {
        uint32_t queued = v->dev ? SDL_GetQueuedAudioSize(v->dev) : 0;
        uint64_t played = (v->total_submitted > queued) ? (v->total_submitted - queued) : 0;
        while (v->pend_count > 0 && n_done < 32) {
            XA2PendingBuf top = v->pend[v->pend_head];
            /* Keep ~93ms (16 KiB) pre-buffered in CoreAudio to prevent underrun crackle. */
            if (!force_all && v->dev && top.end_byte > played + 16384ULL) break;
            v->pend_head = (v->pend_head + 1) & 31;
            v->pend_count--;
            done_ctx[n_done++] = top.ctx_va;
        }
    }
    pthread_mutex_unlock(&g_xa2_mu);
    for (int i = 0; i < n_done; i++) xa2_fire_buf_end(c, v, done_ctx[i]);
}

void win32_poll_audio_callbacks(CPU64 *c) {
    XA2SourceVoice *v = g_active_xa2_voice;
    if (v) xa2_drain_voice(c, v, 0);
}

static void xa2_CreateMasteringVoice(CPU64 *c, void *ud) {
    int is_27 = (ud != NULL);
    uint64_t pp = c->rdx;
    uint32_t ch = (uint32_t)c->r8;
    uint32_t hz = (uint32_t)c->r9;
    XA2MasterVoice *mv = (XA2MasterVoice *)calloc(1, sizeof(XA2MasterVoice));
    mv->lpVtbl = is_27 ? g_vt_xa2_27_master : g_vt_xa2_master;
    mv->channels = ch ? ch : 2;
    mv->sample_rate = hz ? hz : 44100;
    if (pp) W64(pp, (uint64_t)(uintptr_t)mv);
    c->rax = 0;
}
static void xa27_GetDeviceCount(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx, 1);
    c->rax = 0;
}
static void xa27_GetDeviceDetails(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t out = c->r8;
    if (!out) { c->rax = 0x80070057ULL; return; }
    memset((void *)(uintptr_t)out, 0, 0x430);
    const char *id = "default";
    const char *nm = "Apple Silicon Audio";
    for (int i = 0; id[i]; i++) W16(out + (uint64_t)i * 2ULL, (uint8_t)id[i]);
    for (int i = 0; nm[i]; i++) W16(out + 0x200ULL + (uint64_t)i * 2ULL, (uint8_t)nm[i]);
    W32(out + 0x400, 0x0FU);   /* GlobalDefaultDevice */
    W16(out + 0x404, 1);       /* WAVE_FORMAT_PCM */
    W16(out + 0x406, 2);       /* nChannels = 2 */
    W32(out + 0x408, 44100);   /* nSamplesPerSec */
    W32(out + 0x40C, 176400);  /* nAvgBytesPerSec */
    W16(out + 0x410, 4);       /* nBlockAlign */
    W16(out + 0x412, 16);      /* wBitsPerSample */
    c->rax = 0;
}
static void xa27m_GetVoiceDetails(CPU64 *c, void *ud) {
    (void)ud;
    XA2MasterVoice *mv = (XA2MasterVoice *)(uintptr_t)c->rcx;
    if (c->rdx && mv) {
        W32(c->rdx + 0, 0);
        W32(c->rdx + 4, mv->channels);
        W32(c->rdx + 8, mv->sample_rate);
    }
}
static void xa2_CreateSourceVoice(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t pp = c->rdx;
    uint64_t wfx = c->r8;
    uint64_t cb_va = win64_arg_i(c, 5);
    XA2SourceVoice *sv = (XA2SourceVoice *)calloc(1, sizeof(XA2SourceVoice));
    sv->lpVtbl = g_vt_xa2_source;
    sv->volume = 1.0f;
    sv->cb_va = cb_va;
    uint16_t tag = wfx ? R16(wfx + 0) : 1;
    uint16_t ch  = wfx ? R16(wfx + 2) : 2;
    uint32_t hz  = wfx ? R32(wfx + 4) : 44100;
    uint16_t bits = wfx ? R16(wfx + 14) : 16;
    int is_flt = (tag == 3) || (tag == 0xFFFE && bits == 32 && wfx && R32(wfx + 24) == 3);
    sv->channels = (ch >= 1 && ch <= 6) ? ch : 2;
    sv->sample_rate = (hz >= 8000 && hz <= 96000) ? hz : 44100;
    sv->bits = (bits == 8 || bits == 16 || bits == 32) ? bits : 16;
    sv->is_float = is_flt;
    if (!getenv("ELF64_HEADLESS")) {
        if (!SDL_WasInit(SDL_INIT_AUDIO)) SDL_InitSubSystem(SDL_INIT_AUDIO);
        SDL_AudioSpec want;
        SDL_zero(want);
        want.freq = (int)sv->sample_rate;
        want.channels = (Uint8)sv->channels;
        want.format = is_flt ? AUDIO_F32LSB : ((sv->bits == 8) ? AUDIO_U8 : AUDIO_S16LSB);
        want.samples = 512;
        sv->dev = SDL_OpenAudioDevice(NULL, 0, &want, NULL, 0);
        if (getenv("ELF64_IO_LOG"))
            fprintf(stderr, "[audio] XAudio2 CreateSourceVoice %uHz %uch %ubit flt=%d dev=%u cb=0x%llx\n",
                    sv->sample_rate, sv->channels, sv->bits, is_flt, (unsigned)sv->dev, (unsigned long long)cb_va);
    }
    g_active_xa2_voice = sv;
    if (pp) W64(pp, (uint64_t)(uintptr_t)sv);
    c->rax = 0;
}
static void xa2_GetPerfData(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) memset((void *)(uintptr_t)c->rdx, 0, 64);
}
static void xa2m_GetVoiceDetails(CPU64 *c, void *ud) {
    (void)ud;
    XA2MasterVoice *mv = (XA2MasterVoice *)(uintptr_t)c->rcx;
    if (c->rdx && mv) {
        W32(c->rdx + 0, 0); W32(c->rdx + 4, 0);
        W32(c->rdx + 8, mv->channels); W32(c->rdx + 12, mv->sample_rate);
    }
}
static void xa2m_GetChannelMask(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx, 3 /* SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT */);
    c->rax = 0;
}
static void xa2s_GetVoiceDetails(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    if (c->rdx && sv) {
        W32(c->rdx + 0, 0); W32(c->rdx + 4, 0);
        W32(c->rdx + 8, sv->channels); W32(c->rdx + 12, sv->sample_rate);
    }
}
static void xa2s_SetVolume(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    if (sv) { float v; memcpy(&v, &c->xmm[1], 4); sv->volume = v; }
    c->rax = 0;
}
static void xa2s_GetVolume(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    if (c->rdx && sv) { uint32_t u; memcpy(&u, &sv->volume, 4); W32(c->rdx, u); }
}
static void xa2s_DestroyVoice(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    if (sv) {
        if (sv->dev) { SDL_CloseAudioDevice(sv->dev); sv->dev = 0; }
        if (g_active_xa2_voice == sv) g_active_xa2_voice = NULL;
    }
}
static void xa2s_Start(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    if (sv && sv->dev) SDL_PauseAudioDevice(sv->dev, 0);
    c->rax = 0;
}
static void xa2s_Stop(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    if (sv && sv->dev) SDL_PauseAudioDevice(sv->dev, 1);
    c->rax = 0;
}
static void xa2s_SubmitSourceBuffer(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    uint64_t buf_va = c->rdx;
    if (sv && buf_va) {
        xa2_drain_voice(c, sv, 0);
        uint32_t bytes  = R32(buf_va + 4);
        uint64_t data   = R64(buf_va + 8);
        uint64_t ctx_va = R64(buf_va + 40);
        pthread_mutex_lock(&g_xa2_mu);
        if (sv->dev && data && bytes > 0) {
            if (!sv->is_float && sv->bits == 16 && sv->volume >= 0.0f && sv->volume < 0.999f) {
                int16_t tmp[2048];
                uint32_t n = bytes / 2;
                const int16_t *src = (const int16_t *)(uintptr_t)data;
                uint32_t pos = 0;
                while (pos < n) {
                    uint32_t chunk = (n - pos > 2048) ? 2048 : (n - pos);
                    for (uint32_t i = 0; i < chunk; i++) tmp[i] = (int16_t)(src[pos + i] * sv->volume);
                    SDL_QueueAudio(sv->dev, tmp, chunk * 2);
                    pos += chunk;
                }
            } else {
                SDL_QueueAudio(sv->dev, (const void *)(uintptr_t)data, bytes);
            }
            sv->total_submitted += bytes;
        }
        uint32_t bpf = (sv->channels ? sv->channels : 2) * ((sv->bits ? sv->bits : 16) / 8);
        if (bpf) sv->samples_played += bytes / bpf;
        if (sv->pend_count < 32) {
            sv->pend[sv->pend_tail] = (XA2PendingBuf){ sv->total_submitted, ctx_va };
            sv->pend_tail = (sv->pend_tail + 1) & 31;
            sv->pend_count++;
        }
        int headless = (sv->dev == 0);
        pthread_mutex_unlock(&g_xa2_mu);
        xa2_drain_voice(c, sv, headless);
    }
    c->rax = 0;
}
static void xa2s_FlushSourceBuffers(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    if (sv) {
        if (sv->dev) SDL_ClearQueuedAudio(sv->dev);
        xa2_drain_voice(c, sv, 1);
    }
    c->rax = 0;
}
static void xa2s_GetState(CPU64 *c, void *ud) {
    (void)ud;
    XA2SourceVoice *sv = (XA2SourceVoice *)(uintptr_t)c->rcx;
    if (sv) xa2_drain_voice(c, sv, 0);
    if (c->rdx && sv) {
        W64(c->rdx + 0, 0);
        W32(c->rdx + 8, (uint32_t)sv->pend_count);
        W64(c->rdx + 16, sv->samples_played);
    }
}
static void xa2s_GetFreqRatio(CPU64 *c, void *ud) { (void)ud; if (c->rdx) W32(c->rdx, 0x3F800000U); }

static void init_audio_vtables(void) {
    if (g_audio_vt_ready) return;
    g_audio_vt_ready = 1;
    uint64_t t_qi   = rt_alloc_dynamic_thunk("Audio::QI", ac_qi, NULL);
    uint64_t t_add  = rt_alloc_dynamic_thunk("Audio::AddRef", ac_add, NULL);
    uint64_t t_rel  = rt_alloc_dynamic_thunk("Audio::Release", ac_rel, NULL);
    uint64_t t_ok   = rt_alloc_dynamic_thunk("Audio::OK", ac_ok, NULL);
    uint64_t t_void = rt_alloc_dynamic_thunk("Audio::Void", ac_void, NULL);
    for (int i = 0; i < 8; i++)  { g_vt_mm_enum[i] = t_ok; g_vt_mm_coll[i] = t_ok; g_vt_mm_dev[i] = t_ok; g_vt_prop_store[i] = t_ok; }
    for (int i = 0; i < 16; i++) { g_vt_xa2[i] = t_ok; g_vt_xa2_27[i] = t_ok; }
    for (int i = 0; i < 24; i++) { g_vt_xa2_master[i] = t_ok; g_vt_xa2_27_master[i] = t_ok; }
    for (int i = 0; i < 32; i++) g_vt_xa2_source[i] = t_ok;
    #define IUNK(vt) do { (vt)[0]=t_qi; (vt)[1]=t_add; (vt)[2]=t_rel; } while(0)
    IUNK(g_vt_mm_enum); IUNK(g_vt_mm_coll); IUNK(g_vt_mm_dev); IUNK(g_vt_prop_store); IUNK(g_vt_xa2); IUNK(g_vt_xa2_27);
    #undef IUNK
    g_vt_mm_enum[3] = rt_alloc_dynamic_thunk("IMMDeviceEnumerator::EnumAudioEndpoints", mme_EnumAudioEndpoints, NULL);
    g_vt_mm_enum[4] = rt_alloc_dynamic_thunk("IMMDeviceEnumerator::GetDefaultAudioEndpoint", mme_GetDefaultAudioEndpoint, NULL);
    g_vt_mm_enum[5] = rt_alloc_dynamic_thunk("IMMDeviceEnumerator::GetDevice", mme_GetDevice, NULL);
    g_vt_mm_coll[3] = rt_alloc_dynamic_thunk("IMMDeviceCollection::GetCount", mmc_GetCount, NULL);
    g_vt_mm_coll[4] = rt_alloc_dynamic_thunk("IMMDeviceCollection::Item", mmc_Item, NULL);
    g_vt_mm_dev[3]  = rt_alloc_dynamic_thunk("IMMDevice::Activate", mmd_Activate, NULL);
    g_vt_mm_dev[4]  = rt_alloc_dynamic_thunk("IMMDevice::OpenPropertyStore", mmd_OpenPropertyStore, NULL);
    g_vt_mm_dev[5]  = rt_alloc_dynamic_thunk("IMMDevice::GetId", mmd_GetId, NULL);
    g_vt_mm_dev[6]  = rt_alloc_dynamic_thunk("IMMDevice::GetState", mmd_GetState, NULL);
    g_vt_prop_store[3] = rt_alloc_dynamic_thunk("IPropertyStore::GetCount", ps_GetCount, NULL);
    g_vt_prop_store[5] = rt_alloc_dynamic_thunk("IPropertyStore::GetValue", ps_GetValue, NULL);
    g_mm_enum_obj.lpVtbl = g_vt_mm_enum; g_mm_coll_obj.lpVtbl = g_vt_mm_coll;
    g_mm_dev_obj.lpVtbl  = g_vt_mm_dev;  g_prop_store_obj.lpVtbl = g_vt_prop_store;

    g_vt_xa2[4]  = t_void;
    g_vt_xa2[5]  = rt_alloc_dynamic_thunk("IXAudio2::CreateSourceVoice", xa2_CreateSourceVoice, NULL);
    g_vt_xa2[7]  = rt_alloc_dynamic_thunk("IXAudio2::CreateMasteringVoice", xa2_CreateMasteringVoice, NULL);
    g_vt_xa2[9]  = t_void;
    g_vt_xa2[11] = rt_alloc_dynamic_thunk("IXAudio2::GetPerformanceData", xa2_GetPerfData, NULL);
    g_vt_xa2[12] = t_void;

    g_vt_xa2_27[3]  = rt_alloc_dynamic_thunk("IXAudio2_27::GetDeviceCount", xa27_GetDeviceCount, NULL);
    g_vt_xa2_27[4]  = rt_alloc_dynamic_thunk("IXAudio2_27::GetDeviceDetails", xa27_GetDeviceDetails, NULL);
    g_vt_xa2_27[7]  = t_void;
    g_vt_xa2_27[8]  = g_vt_xa2[5];
    g_vt_xa2_27[10] = rt_alloc_dynamic_thunk("IXAudio2_27::CreateMasteringVoice", xa2_CreateMasteringVoice, (void *)1);
    g_vt_xa2_27[12] = t_void;
    g_vt_xa2_27[14] = g_vt_xa2[11];
    g_vt_xa2_27[15] = t_void;

    g_vt_xa2_master[0]  = rt_alloc_dynamic_thunk("IXAudio2MasteringVoice::GetVoiceDetails", xa2m_GetVoiceDetails, NULL);
    g_vt_xa2_master[18] = t_void;
    g_vt_xa2_master[19] = rt_alloc_dynamic_thunk("IXAudio2MasteringVoice::GetChannelMask", xa2m_GetChannelMask, NULL);

    g_vt_xa2_27_master[0]  = rt_alloc_dynamic_thunk("IXAudio2MasteringVoice27::GetVoiceDetails", xa27m_GetVoiceDetails, NULL);
    g_vt_xa2_27_master[18] = t_void;

    g_vt_xa2_source[0]  = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::GetVoiceDetails", xa2s_GetVoiceDetails, NULL);
    g_vt_xa2_source[12] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::SetVolume", xa2s_SetVolume, NULL);
    g_vt_xa2_source[13] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::GetVolume", xa2s_GetVolume, NULL);
    g_vt_xa2_source[18] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::DestroyVoice", xa2s_DestroyVoice, NULL);
    g_vt_xa2_source[19] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::Start", xa2s_Start, NULL);
    g_vt_xa2_source[20] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::Stop", xa2s_Stop, NULL);
    g_vt_xa2_source[21] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::SubmitSourceBuffer", xa2s_SubmitSourceBuffer, NULL);
    g_vt_xa2_source[22] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::FlushSourceBuffers", xa2s_FlushSourceBuffers, NULL);
    g_vt_xa2_source[25] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::GetState", xa2s_GetState, NULL);
    g_vt_xa2_source[27] = rt_alloc_dynamic_thunk("IXAudio2SourceVoice::GetFrequencyRatio", xa2s_GetFreqRatio, NULL);
}

static void w_XAudio2Create(CPU64 *c, void *ud) {
    (void)ud;
    init_audio_vtables();
    AudioComObj *xa = (AudioComObj *)calloc(1, sizeof(AudioComObj));
    xa->lpVtbl = g_vt_xa2;
    if (c->rcx) W64(c->rcx, (uint64_t)(uintptr_t)xa);
    if (getenv("ELF64_IO_LOG")) fprintf(stderr, "[audio] XAudio2Create -> %p\n", (void *)xa);
    c->rax = 0;
}

static void w_PropVariantClear(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) {
        if (R16(c->rcx) == 31 /* VT_LPWSTR */) {
            uint64_t p = R64(c->rcx + 8);
            if (p) free((void *)(uintptr_t)p);
        }
        memset((void *)(uintptr_t)c->rcx, 0, 24);
    }
    c->rax = 0;
}

static void w_CoCreateInstance(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t clsid_va = c->rcx;
    uint64_t ppv = win64_arg_i(c, 4);
    /* CLSID_MMDeviceEnumerator = {BCDE0395-E52F-467C-8E3D-C4579291692E} */
    static const uint8_t k_mmdev[16] = {
        0x95,0x03,0xDE,0xBC, 0x2F,0xE5, 0x7C,0x46, 0x8E,0x3D,0xC4,0x57,0x92,0x91,0x69,0x2E
    };
    /* CLSID_XAudio2 (2.7) = {5A508685-A254-4FBA-9B82-9A24B00306AF} */
    static const uint8_t k_xa2_27[16] = {
        0x85,0x86,0x50,0x5A, 0x54,0xA2, 0xBA,0x4F, 0x9B,0x82,0x9A,0x24,0xB0,0x03,0x06,0xAF
    };
    if (clsid_va && memcmp((const void *)(uintptr_t)clsid_va, k_mmdev, 16) == 0) {
        init_audio_vtables();
        if (ppv) W64(ppv, (uint64_t)(uintptr_t)&g_mm_enum_obj);
        c->rax = 0; /* S_OK */
        return;
    }
    if (clsid_va && memcmp((const void *)(uintptr_t)clsid_va, k_xa2_27, 16) == 0) {
        init_audio_vtables();
        AudioComObj *xa = (AudioComObj *)calloc(1, sizeof(AudioComObj));
        xa->lpVtbl = g_vt_xa2_27;
        if (ppv) W64(ppv, (uint64_t)(uintptr_t)xa);
        if (getenv("ELF64_IO_LOG")) fprintf(stderr, "[audio] CoCreateInstance(CLSID_XAudio2_27) -> %p\n", (void *)xa);
        c->rax = 0; /* S_OK */
        return;
    }
    if (ppv) W64(ppv, 0);
    c->rax = 0x80004002ULL; /* E_NOINTERFACE */
}
static void w_CoTaskMemAlloc(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(uintptr_t)malloc(c->rcx ? (size_t)c->rcx : 1);
}
static void w_CoTaskMemRealloc(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(uintptr_t)realloc((void *)(uintptr_t)c->rcx, c->rdx ? (size_t)c->rdx : 1);
}
static void w_CoTaskMemFree(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) free((void *)(uintptr_t)c->rcx);
}
static void w_VariantInit(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) memset((void *)(uintptr_t)c->rcx, 0, 24);
}
static void w_VariantClear(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) memset((void *)(uintptr_t)c->rcx, 0, 24);
    c->rax = 0;
}
static void w_VariantCopy(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx && c->rdx) memcpy((void *)(uintptr_t)c->rcx, (const void *)(uintptr_t)c->rdx, 24);
    c->rax = 0;
}
static uint64_t bstr_alloc_bytes(const void *src, uint32_t byte_len) {
    uint8_t *raw = (uint8_t *)calloc(1, 4 + byte_len + 2);
    if (!raw) return 0;
    memcpy(raw, &byte_len, 4);
    if (src && byte_len) memcpy(raw + 4, src, byte_len);
    return (uint64_t)(uintptr_t)(raw + 4);
}
static void w_SysAllocStringLen(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = bstr_alloc_bytes((const void *)(uintptr_t)c->rcx, (uint32_t)c->rdx * 2u);
}
static void w_SysAllocStringByteLen(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = bstr_alloc_bytes((const void *)(uintptr_t)c->rcx, (uint32_t)c->rdx);
}
static void w_SysAllocString(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) { c->rax = 0; return; }
    const uint16_t *s = (const uint16_t *)(uintptr_t)c->rcx;
    uint32_t n = 0; while (s[n]) n++;
    c->rax = bstr_alloc_bytes(s, n * 2u);
}
static void w_SysFreeString(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) free((uint8_t *)(uintptr_t)c->rcx - 4);
}
static void w_SysStringByteLen(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) { c->rax = 0; return; }
    uint32_t n = 0; memcpy(&n, (const uint8_t *)(uintptr_t)c->rcx - 4, 4);
    c->rax = n;
}
static void w_SysStringLen(CPU64 *c, void *ud) {
    w_SysStringByteLen(c, ud);
    c->rax /= 2;
}
static void w_SysReAllocStringLen(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) { c->rax = 0; return; }
    uint64_t old = R64(c->rcx);
    uint64_t nb = bstr_alloc_bytes((const void *)(uintptr_t)c->rdx, (uint32_t)c->r8 * 2u);
    if (old) free((uint8_t *)(uintptr_t)old - 4);
    W64(c->rcx, nb);
    c->rax = nb ? 1 : 0;
}
static void w_SysReAllocString(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) { c->rax = 0; return; }
    uint32_t n = 0;
    if (c->rdx) { const uint16_t *s = (const uint16_t *)(uintptr_t)c->rdx; while (s[n]) n++; }
    uint64_t old = R64(c->rcx);
    uint64_t nb = c->rdx ? bstr_alloc_bytes((const void *)(uintptr_t)c->rdx, n * 2u) : 0;
    if (old) free((uint8_t *)(uintptr_t)old - 4);
    W64(c->rcx, nb);
    c->rax = 1;
}
static void w_SHGetSpecialFolderPathA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) {
        const char *home = getenv("HOME");
        snprintf((char *)(uintptr_t)c->rdx, 260, "%s/Library/Application Support/elf64-recomp", home ? home : "/tmp");
    }
    c->rax = 1;
}
static void w_wsa_htonl(CPU64 *c, void *ud) { (void)ud; c->rax = htonl((uint32_t)c->rcx); }
static void w_wsa_ntohl(CPU64 *c, void *ud) { (void)ud; c->rax = ntohl((uint32_t)c->rcx); }
static void w_wsa_SetLastError(CPU64 *c, void *ud) { (void)ud; g_wsa_err = (int)c->rcx; }
static void w_wsa_shutdown(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)shutdown((int)c->rcx, (int)c->rdx); }
static void w_wsa_getpeername(CPU64 *c, void *ud) {
    (void)ud;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int r = getpeername((int)c->rcx, (struct sockaddr *)&ss, &sl);
    if (r == 0) {
        if (c->rdx) bsd_to_win_sa(&ss, sl, (uint8_t *)(uintptr_t)c->rdx);
        if (c->r8) W32(c->r8, (uint32_t)sl);
    }
    c->rax = (uint64_t)(int64_t)r;
}
static void w_wsa_getsockopt(CPU64 *c, void *ud) {
    (void)ud;
    int lvl = ((int)c->rdx == 0xFFFF) ? SOL_SOCKET : (int)c->rdx;
    socklen_t sl = (socklen_t)(win64_arg_i(c, 4) ? R32(win64_arg_i(c, 4)) : 4);
    int r = getsockopt((int)c->rcx, lvl, (int)c->r8, (void *)(uintptr_t)c->r9, &sl);
    if (r == 0 && win64_arg_i(c, 4)) W32(win64_arg_i(c, 4), (uint32_t)sl);
    c->rax = (uint64_t)(int64_t)r;
}
static void w_GetComputerNameExW(CPU64 *c, void *ud) {
    (void)ud;
    char host[256] = "macOS";
    gethostname(host, sizeof(host) - 1);
    size_t n = strlen(host);
    uint32_t cap = c->r8 ? R32(c->r8) : 0;
    if (c->rdx && cap > n) {
        u8_to_w16(host, (uint16_t *)(uintptr_t)c->rdx, cap);
        if (c->r8) W32(c->r8, (uint32_t)n);
        c->rax = 1;
    } else {
        if (c->r8) W32(c->r8, (uint32_t)(n + 1));
        c->rax = 0;
    }
}
static void w_CreateIoCompletionPort(CPU64 *c, void *ud) { (void)ud; c->rax = 0x30050ULL; }
static void w_GetQueuedCompletionStatus(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t ms = (uint32_t)win64_arg_i(c, 4);
    if (ms > 0 && ms < 5000) usleep(ms * 1000U);
    else if (ms != 0) usleep(50000);
    c->rax = 0; /* WAIT_TIMEOUT */
}
static void w_CompareStringEx(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *a = (const uint16_t *)(uintptr_t)c->r8;
    int alen = (int)c->r9;
    const uint16_t *b = (const uint16_t *)(uintptr_t)win64_arg_i(c, 4);
    int blen = (int)win64_arg_i(c, 5);
    if (!a || !b) { c->rax = 2; return; }
    int i = 0;
    for (;;) {
        int ea = (alen >= 0) ? (i >= alen) : (a[i] == 0);
        int eb = (blen >= 0) ? (i >= blen) : (b[i] == 0);
        if (ea && eb) { c->rax = 2; return; }
        if (ea) { c->rax = 1; return; }
        if (eb) { c->rax = 3; return; }
        if (a[i] != b[i]) { c->rax = (a[i] < b[i]) ? 1 : 3; return; }
        i++;
    }
}
static void w_GetKeyboardState(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) {
        uint8_t *buf = (uint8_t *)(uintptr_t)c->rcx;
        for (int i = 0; i < 256; i++) buf[i] = win32_vk_is_down(i) ? 0x80 : 0;
    }
    c->rax = 1;
}
static void w_GetWindowInfo(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) {
        memset((void *)(uintptr_t)c->rdx, 0, 60);
        W32(c->rdx + 0, 60);
        W32(c->rdx + 12, 1280); W32(c->rdx + 16, 720);
        W32(c->rdx + 28, 1280); W32(c->rdx + 32, 720);
    }
    c->rax = 1;
}

/* ---- Team Fortress 2 / Source 1 x64: MSVCRT, SDL2, Kernel32, User32, Winsock1 ---- */
static uint8_t g_win_iob[3 * 48];
static void w_iob_func(CPU64 *c, void *ud) {
    (void)ud;
    W32((uint64_t)(uintptr_t)&g_win_iob[0 * 48 + 24], 0);
    W32((uint64_t)(uintptr_t)&g_win_iob[1 * 48 + 24], 1);
    W32((uint64_t)(uintptr_t)&g_win_iob[2 * 48 + 24], 2);
    c->rax = (uint64_t)(uintptr_t)g_win_iob;
}
static FILE *win_file_ptr(uint64_t va) {
    if (!va) return NULL;
    uint64_t base = (uint64_t)(uintptr_t)g_win_iob;
    if (va == base + 0 * 48) return stdin;
    if (va == base + 1 * 48) return stdout;
    if (va == base + 2 * 48) return stderr;
    return (FILE *)(uintptr_t)va;
}
static void w_lc_codepage_func(CPU64 *c, void *ud) { (void)ud; c->rax = 65001; }
static void w_mb_cur_max_func(CPU64 *c, void *ud)  { (void)ud; c->rax = 4; }
static void w_aligned_malloc(CPU64 *c, void *ud) {
    (void)ud;
    size_t sz = c->rcx ? (size_t)c->rcx : 16;
    size_t al = (c->rdx >= 16 && (c->rdx & (c->rdx - 1)) == 0) ? (size_t)c->rdx : 16;
    void *p = NULL;
    if (posix_memalign(&p, al, sz) != 0) p = NULL;
    c->rax = (uint64_t)(uintptr_t)p;
}
static void w_aligned_free(CPU64 *c, void *ud) { (void)ud; if (c->rcx) free((void *)(uintptr_t)c->rcx); }
static void w_errno_ptr(CPU64 *c, void *ud)    { (void)ud; c->rax = (uint64_t)(uintptr_t)&errno; }
static void w_fdopen(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(uintptr_t)fdopen((int)c->rcx, c->rdx ? (const char *)(uintptr_t)c->rdx : "r");
}
static void w_fileno(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    c->rax = f ? (uint64_t)(uint32_t)fileno(f) : (uint64_t)-1LL;
}
static void w_filelengthi64(CPU64 *c, void *ud) {
    (void)ud;
    struct stat st;
    c->rax = (fstat((int)c->rcx, &st) == 0) ? (uint64_t)st.st_size : (uint64_t)-1LL;
}
static void w_fstat64(CPU64 *c, void *ud) {
    (void)ud;
    struct stat st;
    if (!c->rdx || fstat((int)c->rcx, &st) != 0) { c->rax = (uint64_t)-1LL; return; }
    memset((void *)(uintptr_t)c->rdx, 0, 56);
    W16(c->rdx + 6, (uint16_t)st.st_mode);
    W16(c->rdx + 8, 1);
    W64(c->rdx + 24, (uint64_t)st.st_size);
    W64(c->rdx + 32, (uint64_t)st.st_atimespec.tv_sec);
    W64(c->rdx + 40, (uint64_t)st.st_mtimespec.tv_sec);
    W64(c->rdx + 48, (uint64_t)st.st_ctimespec.tv_sec);
    c->rax = 0;
}
static void w_gmtime64(CPU64 *c, void *ud) {
    (void)ud;
    static int32_t win_tm[9];
    time_t t = c->rcx ? (time_t)R64(c->rcx) : time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    win_tm[0] = tm.tm_sec; win_tm[1] = tm.tm_min; win_tm[2] = tm.tm_hour;
    win_tm[3] = tm.tm_mday; win_tm[4] = tm.tm_mon; win_tm[5] = tm.tm_year;
    win_tm[6] = tm.tm_wday; win_tm[7] = tm.tm_yday; win_tm[8] = tm.tm_isdst;
    c->rax = (uint64_t)(uintptr_t)win_tm;
}
static void w_initterm(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t cur = c->rcx, end = c->rdx;
    for (; cur < end; cur += 8) {
        uint64_t fn = R64(cur);
        if (fn > 0x10000ULL) rt_invoke_win64(c, fn, 0, 0, 0, 0, 0, 0);
    }
    c->rax = 0;
}
static void w_lseeki64(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)lseek((int)c->rcx, (off_t)c->rdx, (int)c->r8);
}
static void w_crt_read(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)read((int)c->rcx, (void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8);
}
static void w_crt_write(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)write((int)c->rcx, (const void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8);
}
static void w_strdup(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = c->rcx ? (uint64_t)(uintptr_t)strdup((const char *)(uintptr_t)c->rcx) : 0;
}
static void w_ultoa(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t v = (uint32_t)c->rcx;
    char *dst = (char *)(uintptr_t)c->rdx;
    int radix = (int)c->r8;
    if (dst) {
        if (radix == 16) snprintf(dst, 32, "%x", v);
        else snprintf(dst, 32, "%u", v);
    }
    c->rax = c->rdx;
}
static void w_wcslen(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *s = (const uint16_t *)(uintptr_t)c->rcx;
    size_t n = 0;
    if (s) while (s[n]) n++;
    c->rax = n;
}
static void w_wcscmp(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *a = (const uint16_t *)(uintptr_t)c->rcx;
    const uint16_t *b = (const uint16_t *)(uintptr_t)c->rdx;
    if (!a || !b) { c->rax = a ? 1 : (b ? (uint64_t)-1LL : 0); return; }
    while (*a && *a == *b) { a++; b++; }
    c->rax = (uint64_t)(int64_t)((int)*a - (int)*b);
}
static void w_wcsicmp(CPU64 *c, void *ud) {
    (void)ud;
    const uint16_t *a = (const uint16_t *)(uintptr_t)c->rcx;
    const uint16_t *b = (const uint16_t *)(uintptr_t)c->rdx;
    if (!a || !b) { c->rax = a ? 1 : (b ? (uint64_t)-1LL : 0); return; }
    while (*a && towlower(*a) == towlower(*b)) { a++; b++; }
    c->rax = (uint64_t)(int64_t)((int)towlower(*a) - (int)towlower(*b));
}
static void w_wcsxfrm(CPU64 *c, void *ud) {
    (void)ud;
    uint16_t *dst = (uint16_t *)(uintptr_t)c->rcx;
    const uint16_t *src = (const uint16_t *)(uintptr_t)c->rdx;
    size_t cap = (size_t)c->r8, n = 0;
    if (src) while (src[n]) { if (dst && n + 1 < cap) dst[n] = src[n]; n++; }
    if (dst && cap) dst[n < cap ? n : cap - 1] = 0;
    c->rax = n;
}
static void w_wcsftime(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx && c->rdx) W16(c->rcx, 0);
    c->rax = 0;
}
static void w_wfopen(CPU64 *c, void *ud) {
    (void)ud;
    char u8[1024], px[1024], mode[32], cmode[16];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    win_path_to_posix(u8, px, sizeof(px));
    w16_to_u8((const uint16_t *)(uintptr_t)c->rdx, mode, sizeof(mode));
    size_t j = 0;
    for (size_t i = 0; mode[i] && j + 1 < sizeof(cmode); i++) {
        char ch = mode[i];
        if (ch == 'r' || ch == 'w' || ch == 'a' || ch == '+' || ch == 'b') cmode[j++] = ch;
    }
    if (!j) cmode[j++] = 'r';
    cmode[j] = '\0';
    c->rax = (uint64_t)(uintptr_t)fopen(px, cmode);
}
static void w_atof(CPU64 *c, void *ud) {
    (void)ud;
    c->xmm[0].df[0] = c->rcx ? atof((const char *)(uintptr_t)c->rcx) : 0.0;
}
static void w_ferror(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    c->rax = f ? (uint64_t)(uint32_t)ferror(f) : 0;
}
static void w_fgetpos(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    if (!f || !c->rdx) { c->rax = (uint64_t)-1LL; return; }
    W64(c->rdx, (uint64_t)ftello(f));
    c->rax = 0;
}
static void w_fsetpos(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    if (!f || !c->rdx) { c->rax = (uint64_t)-1LL; return; }
    c->rax = (uint64_t)(int64_t)fseeko(f, (off_t)R64(c->rdx), SEEK_SET);
}
static void w_fputc(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rdx);
    c->rax = f ? (uint64_t)(int64_t)fputc((int)c->rcx, f) : (uint64_t)-1LL;
}
static void w_getc(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    c->rax = f ? (uint64_t)(int64_t)getc(f) : (uint64_t)-1LL;
}
static void w_ungetc(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rdx);
    c->rax = f ? (uint64_t)(int64_t)ungetc((int)c->rcx, f) : (uint64_t)-1LL;
}
static void w_setvbuf(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    if (!f) { c->rax = (uint64_t)-1LL; return; }
    int mode = (c->r8 == 4 /* _IONBF */) ? _IONBF : ((c->r8 == 64) ? _IOLBF : _IOFBF);
    c->rax = (uint64_t)(int64_t)setvbuf(f, (char *)(uintptr_t)c->rdx, mode, (size_t)c->r9);
}
static void w_vfprintf(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    const char *fmt = (const char *)(uintptr_t)c->rdx;
    if (!f || !fmt) { c->rax = 0; return; }
    c->rax = (uint64_t)(int64_t)fputs(fmt, f);
}
static void w_remove(CPU64 *c, void *ud) {
    (void)ud;
    char px[1024];
    win_path_to_posix((const char *)(uintptr_t)c->rcx, px, sizeof(px));
    c->rax = (uint64_t)(int64_t)remove(px);
}
static void w_setlocale(CPU64 *c, void *ud) {
    (void)ud;
    static const char *c_loc = "C";
    c->rax = (uint64_t)(uintptr_t)c_loc;
}
static void w_localeconv(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(uintptr_t)localeconv();
}
static void w_strerror(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(uintptr_t)strerror((int)c->rcx);
}
static void w_strcoll(CPU64 *c, void *ud) {
    (void)ud;
    const char *a = (const char *)(uintptr_t)c->rcx;
    const char *b = (const char *)(uintptr_t)c->rdx;
    c->rax = (a && b) ? (uint64_t)(int64_t)strcmp(a, b) : 0;
}
static void w_strxfrm(CPU64 *c, void *ud) {
    (void)ud;
    char *dst = (char *)(uintptr_t)c->rcx;
    const char *src = (const char *)(uintptr_t)c->rdx;
    size_t cap = (size_t)c->r8;
    size_t n = src ? strlen(src) : 0;
    if (dst && cap) {
        size_t cp = (n < cap - 1) ? n : cap - 1;
        if (src) memcpy(dst, src, cp);
        dst[cp] = '\0';
    }
    c->rax = n;
}
static void w_strftime(CPU64 *c, void *ud) {
    (void)ud;
    char *s = (char *)(uintptr_t)c->rcx;
    size_t mx = (size_t)c->rdx;
    const char *fmt = (const char *)(uintptr_t)c->r8;
    if (!s || !mx || !fmt || !c->r9) { c->rax = 0; return; }
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_sec   = (int)R32(c->r9 + 0);
    tm.tm_min   = (int)R32(c->r9 + 4);
    tm.tm_hour  = (int)R32(c->r9 + 8);
    tm.tm_mday  = (int)R32(c->r9 + 12);
    tm.tm_mon   = (int)R32(c->r9 + 16);
    tm.tm_year  = (int)R32(c->r9 + 20);
    tm.tm_wday  = (int)R32(c->r9 + 24);
    tm.tm_yday  = (int)R32(c->r9 + 28);
    tm.tm_isdst = (int)R32(c->r9 + 32);
    c->rax = strftime(s, mx, fmt, &tm);
}
static void w_towlower(CPU64 *c, void *ud) { (void)ud; c->rax = (uint16_t)towlower((wint_t)(uint16_t)c->rcx); }
static void w_towupper(CPU64 *c, void *ud) { (void)ud; c->rax = (uint16_t)towupper((wint_t)(uint16_t)c->rcx); }
static void w_iswctype(CPU64 *c, void *ud) {
    (void)ud;
    uint16_t wc = (uint16_t)c->rcx;
    uint16_t mask = (uint16_t)c->rdx;
    int r = 0;
    if ((mask & 0x0103) && iswalpha(wc)) r |= 1;
    if ((mask & 0x0004) && iswdigit(wc)) r |= 4;
    if ((mask & 0x0008) && iswspace(wc)) r |= 8;
    if ((mask & 0x0010) && iswpunct(wc)) r |= 16;
    if ((mask & 0x0020) && iswcntrl(wc)) r |= 32;
    if ((mask & 0x0080) && iswxdigit(wc)) r |= 128;
    c->rax = (uint64_t)r;
}

/* Kernel32 extras for TF2 */
static void w_CopyFileA(CPU64 *c, void *ud) {
    (void)ud;
    char sp[1024], dp[1024];
    win_path_to_posix((const char *)(uintptr_t)c->rcx, sp, sizeof(sp));
    win_path_to_posix((const char *)(uintptr_t)c->rdx, dp, sizeof(dp));
    int sfd = open(sp, O_RDONLY);
    if (sfd < 0) { c->rax = 0; return; }
    int dfd = open(dp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) { close(sfd); c->rax = 0; return; }
    char buf[8192];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) (void)write(dfd, buf, (size_t)n);
    close(dfd); close(sfd);
    c->rax = 1;
}
static void w_MoveFileExA(CPU64 *c, void *ud) {
    (void)ud;
    char sp[1024], dp[1024];
    win_path_to_posix((const char *)(uintptr_t)c->rcx, sp, sizeof(sp));
    win_path_to_posix((const char *)(uintptr_t)c->rdx, dp, sizeof(dp));
    c->rax = (rename(sp, dp) == 0) ? 1 : 0;
}
static void w_SetCurrentDirectoryA(CPU64 *c, void *ud) {
    (void)ud;
    char px[1024];
    win_path_to_posix((const char *)(uintptr_t)c->rcx, px, sizeof(px));
    c->rax = (chdir(px) == 0) ? 1 : 0;
}
static void w_GetFullPathNameA(CPU64 *c, void *ud) {
    (void)ud;
    const char *src = (const char *)(uintptr_t)c->rcx;
    uint32_t cap = (uint32_t)c->rdx;
    char *dst = (char *)(uintptr_t)c->r8;
    char px[1024], full[1024], win[1024];
    win_path_to_posix(src, px, sizeof(px));
    if (px[0] == '/') snprintf(full, sizeof(full), "%s", px);
    else {
        char cwd[512];
        if (!getcwd(cwd, sizeof(cwd))) strcpy(cwd, "/tmp");
        snprintf(full, sizeof(full), "%s/%s", cwd, px);
    }
    size_t n = posix_to_win_path(full, win, sizeof(win));
    if (dst && cap > n) {
        memcpy(dst, win, n + 1);
        if (c->r9) {
            char *sl = strrchr(dst, '\\');
            W64(c->r9, (uint64_t)(uintptr_t)(sl ? sl + 1 : dst));
        }
        c->rax = n;
    } else c->rax = n + 1;
}
static void w_GetWindowsDirectoryA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx && c->rdx >= 11) memcpy((void *)(uintptr_t)c->rcx, "C:\\Windows", 11);
    c->rax = 10;
}
static void w_GetEnvironmentVariableW(CPU64 *c, void *ud) {
    (void)ud;
    char name[256];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, name, sizeof(name));
    const char *val = getenv(name);
    if (!val) { c->rax = 0; return; }
    size_t len = strlen(val);
    if (c->rdx && c->r8 > len) {
        u8_to_w16(val, (uint16_t *)(uintptr_t)c->rdx, (size_t)c->r8);
        c->rax = len;
    } else c->rax = len + 1;
}
static void w_GetModuleHandleExA(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t flags = (uint32_t)c->rcx;
    uint64_t base = 0;
    if (flags & 4 /* GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS */) {
        for (size_t i = 0; i < g_rt_module_count; i++) {
            if (c->rdx >= g_rt_modules[i].map_addr && c->rdx < g_rt_modules[i].map_addr + g_rt_modules[i].mem_size) {
                base = g_rt_modules[i].map_addr;
                break;
            }
        }
        if (!base && g_rt_module_count) base = g_rt_modules[0].map_addr;
    } else {
        const char *name = (const char *)(uintptr_t)c->rdx;
        base = rt_find_module_base(name);
        if (!base && name) base = 0x7090000000ULL;
    }
    if (c->r8) W64(c->r8, base);
    c->rax = base ? 1 : 0;
}
static void w_GetLogicalProcessorInformation(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rdx) { c->rax = 0; return; }
    uint32_t cap = R32(c->rdx);
    W32(c->rdx, 32);
    if (!c->rcx || cap < 32) { c->rax = 0; return; }
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 4;
    if (n > 63) n = 63;
    memset((void *)(uintptr_t)c->rcx, 0, 32);
    W64(c->rcx + 0, (1ULL << n) - 1ULL);
    W32(c->rcx + 8, 0 /* RelationProcessorCore */);
    c->rax = 1;
}
static void w_GlobalMemoryStatus(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) return;
    uint64_t phys = 16ULL * 1024 * 1024 * 1024;
    memset((void *)(uintptr_t)c->rcx, 0, 56);
    W32(c->rcx + 0, 56);
    W32(c->rcx + 4, 25);
    W64(c->rcx + 8, phys);
    W64(c->rcx + 16, phys * 3 / 4);
    W64(c->rcx + 24, phys);
    W64(c->rcx + 32, phys * 3 / 4);
    W64(c->rcx + 40, 0x7FFFFFFFFFFFULL);
    W64(c->rcx + 48, 0x7FFFFFFFFFFFULL);
}
static void w_GetTempFileNameA(CPU64 *c, void *ud) {
    (void)ud;
    static uint32_t seq = 1;
    if (c->r9) snprintf((char *)(uintptr_t)c->r9, 260, "C:\\tmp\\tf2_%u.tmp", seq++);
    c->rax = seq;
}
static void w_FileTimeToLocalFileTime(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx && c->rdx) W64(c->rdx, R64(c->rcx));
    c->rax = 1;
}
static void w_FileTimeToDosDateTime(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W16(c->rdx, 0x5421);
    if (c->r8)  W16(c->r8, 0x6000);
    c->rax = 1;
}
static void w_GetDateFormatA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t out = win64_arg_i(c, 4);
    int cap = (int)win64_arg_i(c, 5);
    if (out && cap >= 11) memcpy((void *)(uintptr_t)out, "2026-11-22", 11);
    c->rax = 11;
}
static void w_GetTimeFormatA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t out = win64_arg_i(c, 4);
    int cap = (int)win64_arg_i(c, 5);
    if (out && cap >= 9) memcpy((void *)(uintptr_t)out, "12:00:00", 9);
    c->rax = 9;
}
static void w_lstrcpyA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx && c->rdx) strcpy((char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx);
    c->rax = c->rcx;
}
static void w_lstrcatA(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx && c->rdx) strcat((char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx);
    c->rax = c->rcx;
}

/* User32 extras for TF2 & DXVK */
static void w_SetRect(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) {
        W32(c->rcx + 0, (uint32_t)c->rdx);
        W32(c->rcx + 4, (uint32_t)c->r8);
        W32(c->rcx + 8, (uint32_t)c->r9);
        W32(c->rcx + 12, (uint32_t)win64_arg_i(c, 4));
    }
    c->rax = 1;
}
static void w_OffsetRect(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) {
        int32_t dx = (int32_t)c->rdx, dy = (int32_t)c->r8;
        W32(c->rcx + 0, (uint32_t)((int32_t)R32(c->rcx + 0) + dx));
        W32(c->rcx + 4, (uint32_t)((int32_t)R32(c->rcx + 4) + dy));
        W32(c->rcx + 8, (uint32_t)((int32_t)R32(c->rcx + 8) + dx));
        W32(c->rcx + 12, (uint32_t)((int32_t)R32(c->rcx + 12) + dy));
    }
    c->rax = 1;
}
static void w_MonitorFromPoint(CPU64 *c, void *ud) { (void)ud; c->rax = 0x60001ULL; }
static void w_EnumDisplayMonitors(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t fn = c->r8, data = c->r9;
    if (fn > 0x10000ULL) {
        int dw = 1920, dh = 1080;
        win32_desktop_size(&dw, &dh);
        int32_t rc[4] = { 0, 0, dw, dh };
        rt_invoke_win64(c, fn, 0x60001ULL, 0, (uint64_t)(uintptr_t)rc, data, 0, 0);
    }
    c->rax = 1;
}
static void w_GetMonitorInfoW(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rdx) { c->rax = 0; return; }
    uint32_t cb = R32(c->rdx);
    int dw = 1920, dh = 1080;
    win32_desktop_size(&dw, &dh);
    W32(c->rdx + 4, 0);  W32(c->rdx + 8, 0);  W32(c->rdx + 12, (uint32_t)dw); W32(c->rdx + 16, (uint32_t)dh);
    W32(c->rdx + 20, 0); W32(c->rdx + 24, 0); W32(c->rdx + 28, (uint32_t)dw); W32(c->rdx + 32, (uint32_t)dh);
    W32(c->rdx + 36, 1 /* MONITORINFOF_PRIMARY */);
    if (cb >= 104) u8_to_w16("\\\\.\\DISPLAY1", (uint16_t *)(uintptr_t)(c->rdx + 40), 32);
    c->rax = 1;
}
static void w_EnumDisplayDevicesA(CPU64 *c, void *ud) {
    (void)ud;
    if ((uint32_t)c->rdx != 0 || !c->r8) { c->rax = 0; return; }
    uint32_t cb = R32(c->r8);
    memset((void *)(uintptr_t)c->r8, 0, cb ? cb : 424);
    W32(c->r8 + 0, cb ? cb : 424);
    snprintf((char *)(uintptr_t)(c->r8 + 4), 32, "\\\\.\\DISPLAY1");
    snprintf((char *)(uintptr_t)(c->r8 + 36), 128, "Apple Silicon GPU");
    W32(c->r8 + 164, 0x5 /* DISPLAY_DEVICE_ACTIVE | DISPLAY_DEVICE_PRIMARY_DEVICE */);
    c->rax = 1;
}
static void w_EnumDisplaySettingsW(CPU64 *c, void *ud) {
    (void)ud;
    int idx = (int)c->rdx;
    uint64_t dm = c->r8;
    int dw = 1920, dh = 1080;
    win32_desktop_size(&dw, &dh);
    static const int modes[][2] = {
        {1920, 1080}, {1600, 900}, {1366, 768}, {1280, 720},
        {1440, 900},  {1280, 800}, {1024, 768}, {800, 600}
    };
    int w = dw, h = dh;
    if (idx >= 0) {
        if (idx >= 8) { c->rax = 0; return; }
        w = (idx == 0) ? dw : modes[idx][0];
        h = (idx == 0) ? dh : modes[idx][1];
    }
    if (dm) {
        memset((void *)(uintptr_t)dm, 0, 220);
        W16(dm + 68, 220);
        W32(dm + 72, 0x5C0000);
        W32(dm + 168, 32);
        W32(dm + 172, (uint32_t)w);
        W32(dm + 176, (uint32_t)h);
        W32(dm + 184, 60);
    }
    c->rax = 1;
}
static void w_ret_err87(CPU64 *c, void *ud) { (void)ud; c->rax = 87; /* ERROR_INVALID_PARAMETER */ }
static void w_AllocateLocallyUniqueId(CPU64 *c, void *ud) {
    (void)ud;
    static uint64_t seq = 0x1000;
    if (c->rcx) W64(c->rcx, ++seq);
    c->rax = 1;
}
static void w_RegCreateKeyExA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t phk  = win64_arg_i(c, 7);
    uint64_t disp = win64_arg_i(c, 8);
    if (phk)  W64(phk, 0x70001ULL);
    if (disp) W32(disp, 1 /* REG_CREATED_NEW_KEY */);
    c->rax = 0; /* ERROR_SUCCESS */
}

/* Winsock1 extras (connect, ioctlsocket, gethostbyname) */
static void w_wsa_connect(CPU64 *c, void *ud) {
    (void)ud;
    struct sockaddr_storage ss;
    int len = (int)c->r8;
    win_to_bsd_sa((const uint8_t *)(uintptr_t)c->rdx, len, &ss);
    int r = connect((int)c->rcx, (struct sockaddr *)&ss, (socklen_t)len);
    if (r < 0) g_wsa_err = posix_to_wsa_err(errno);
    c->rax = (uint64_t)(int64_t)r;
}
static void w_wsa_ioctlsocket(CPU64 *c, void *ud) {
    (void)ud;
    int fd = (int)c->rcx;
    uint32_t cmd = (uint32_t)c->rdx;
    uint32_t arg = c->r8 ? R32(c->r8) : 0;
    if (cmd == 0x8004667EU /* FIONBIO */) {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, arg ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
        c->rax = 0;
    } else if (cmd == 0x4004667FU /* FIONREAD */) {
        int n = 0;
        ioctl(fd, FIONREAD, &n);
        if (c->r8) W32(c->r8, (uint32_t)n);
        c->rax = 0;
    } else c->rax = 0;
}
static void w_wsa_gethostbyname(CPU64 *c, void *ud) {
    (void)ud;
    g_wsa_err = 11001;
    c->rax = 0;
}

/* SDL2.dll Win64 wrappers for launcher.dll / inputsystem.dll */
static void w_SDL_SetHint(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)SDL_SetHint((const char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx);
}
static void w_SDL_WasInit(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)SDL_WasInit((Uint32)c->rcx);
}
static void w_SDL_setenv(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)SDL_setenv((const char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx, (int)c->r8);
}
static void w_SDL_GetError(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(uintptr_t)SDL_GetError();
}

/* Additional Win64 MSVCRT stdio/string functions */
static void w_fopen(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx || !c->rdx) { c->rax = 0; return; }
    char px[1024], cmode[16];
    win_path_to_posix((const char *)(uintptr_t)c->rcx, px, sizeof(px));
    const char *mode = (const char *)(uintptr_t)c->rdx;
    size_t j = 0;
    for (size_t i = 0; mode[i] && j + 1 < sizeof(cmode); i++) {
        char ch = mode[i];
        if (ch == 'r' || ch == 'w' || ch == 'a' || ch == '+' || ch == 'b') cmode[j++] = ch;
    }
    if (!j) cmode[j++] = 'r';
    cmode[j] = '\0';
    c->rax = (uint64_t)(uintptr_t)fopen(px, cmode);
}
static void w_fclose(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    if (!f || f == stdin || f == stdout || f == stderr) { c->rax = 0; return; }
    c->rax = (uint64_t)(int64_t)fclose(f);
}
static void w_fflush(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    c->rax = (uint64_t)(int64_t)fflush(f);
}
static void w_fread(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->r9);
    c->rax = (f && c->rcx) ? (uint64_t)fread((void *)(uintptr_t)c->rcx, (size_t)c->rdx, (size_t)c->r8, f) : 0;
}
static void w_fwrite(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->r9);
    c->rax = (f && c->rcx) ? (uint64_t)fwrite((const void *)(uintptr_t)c->rcx, (size_t)c->rdx, (size_t)c->r8, f) : 0;
}
static void w_ftell(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    c->rax = f ? (uint64_t)(int64_t)ftell(f) : (uint64_t)-1LL;
}
static void w_fputs(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rdx);
    c->rax = (f && c->rcx) ? (uint64_t)(int64_t)fputs((const char *)(uintptr_t)c->rcx, f) : (uint64_t)-1LL;
}
static void w_fprintf(CPU64 *c, void *ud) {
    (void)ud;
    FILE *f = win_file_ptr(c->rcx);
    const char *fmt = (const char *)(uintptr_t)c->rdx;
    if (!f || !fmt) { c->rax = 0; return; }
    char buf[2048];
    int slot = 2;
    size_t pos = 0;
    while (*fmt && pos < sizeof(buf) - 64) {
        if (*fmt != '%') { buf[pos++] = *fmt++; continue; }
        fmt++;
        if (*fmt == '%') { buf[pos++] = '%'; fmt++; continue; }
        while (*fmt && (*fmt == '-' || *fmt == '+' || *fmt == '0' || *fmt == '#' || *fmt == '.' || (*fmt >= '0' && *fmt <= '9'))) fmt++;
        if (*fmt == 'l') { fmt++; if (*fmt == 'l') fmt++; }
        else if (*fmt == 'z' || *fmt == 'h' || *fmt == 'I') fmt++;
        char conv = *fmt ? *fmt++ : 0;
        uint64_t v = win64_arg_i(c, slot++);
        if (conv == 's') {
            const char *s = (const char *)(uintptr_t)v;
            if (!s) s = "(null)";
            while (*s && pos < sizeof(buf) - 2) buf[pos++] = *s++;
        } else if (conv == 'c') {
            buf[pos++] = (char)v;
        } else if (conv == 'x' || conv == 'X' || conv == 'p') {
            pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos, (conv == 'X') ? "%llX" : "%llx", (unsigned long long)v);
        } else if (conv == 'u') {
            pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos, "%llu", (unsigned long long)v);
        } else {
            pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos, "%lld", (long long)v);
        }
    }
    buf[pos] = '\0';
    fwrite(buf, 1, pos, f);
    c->rax = pos;
}
static void w_getenv(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = c->rcx ? (uint64_t)(uintptr_t)getenv((const char *)(uintptr_t)c->rcx) : 0;
}
static void w_memchr(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = c->rcx ? (uint64_t)(uintptr_t)memchr((const void *)(uintptr_t)c->rcx, (int)c->rdx, (size_t)c->r8) : 0;
}
static void w_strchr(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = c->rcx ? (uint64_t)(uintptr_t)strchr((const char *)(uintptr_t)c->rcx, (int)c->rdx) : 0;
}
static void w_strrchr(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = c->rcx ? (uint64_t)(uintptr_t)strrchr((const char *)(uintptr_t)c->rcx, (int)c->rdx) : 0;
}
static void w_strstr(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (c->rcx && c->rdx) ? (uint64_t)(uintptr_t)strstr((const char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx) : 0;
}
static void w_strncpy(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx && c->rdx) strncpy((char *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx, (size_t)c->r8);
    c->rax = c->rcx;
}
static void w_strtol(CPU64 *c, void *ud) {
    (void)ud;
    char *endp = NULL;
    long v = c->rcx ? strtol((const char *)(uintptr_t)c->rcx, &endp, (int)c->r8) : 0;
    if (c->rdx) W64(c->rdx, (uint64_t)(uintptr_t)endp);
    c->rax = (uint64_t)(int64_t)(int32_t)v;
}
static void w_strtoul(CPU64 *c, void *ud) {
    (void)ud;
    char *endp = NULL;
    unsigned long v = c->rcx ? strtoul((const char *)(uintptr_t)c->rcx, &endp, (int)c->r8) : 0;
    if (c->rdx) W64(c->rdx, (uint64_t)(uintptr_t)endp);
    c->rax = (uint64_t)(uint32_t)v;
}

/* ---- Source Engine vstdlib.dll Coroutine_* host-thread implementation ----
 * vstdlib.dll implements cooperative coroutines via raw guest stack copying and
 * custom inline longjmp into the middle of lifted functions, which cannot work
 * when lifted C frames live on the host ARM64 stack. Replace with 1:1 pthread
 * + condvar lockstep handoff so each coroutine has real host + guest stacks. */
#define VSTD_MAX_COROS 1024
extern __thread uint32_t g_win32_tid_override;
extern uint32_t win32_current_tid(void);
typedef struct VstdCoro {
    int32_t         id;
    int             in_use;
    uint64_t        fn;
    uint64_t        param;
    uint32_t        owner_tid;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    pthread_t       th;
    int             started;
    int             running;
    int             done;
    int             cancel;
    int             active;
    sigjmp_buf      cancel_jb;
} VstdCoro;

static pthread_mutex_t g_coro_mu = PTHREAD_MUTEX_INITIALIZER;
static VstdCoro       *g_coros[VSTD_MAX_COROS];
static __thread VstdCoro *tls_cur_coro = NULL;

static VstdCoro *coro_lookup(int32_t id) {
    if (id <= 0 || id >= VSTD_MAX_COROS) return NULL;
    pthread_mutex_lock(&g_coro_mu);
    VstdCoro *co = g_coros[id];
    if (co && !co->in_use) co = NULL;
    pthread_mutex_unlock(&g_coro_mu);
    return co;
}

static void *coro_thread_main(void *arg) {
    VstdCoro *co = (VstdCoro *)arg;
    CPU64 cpu;
    rt_init_thread_cpu(&cpu, 2 * 1024 * 1024);
    tls_cur_coro = co;
    g_win32_tid_override = co->owner_tid;
    if (cpu.gs_base) W32(cpu.gs_base + 0x48, co->owner_tid);
    if (sigsetjmp(co->cancel_jb, 0) == 0) {
        rt_invoke_win64(&cpu, co->fn, co->param, 0, 0, 0, 0, 0);
    }
    g_win32_tid_override = 0;
    tls_cur_coro = NULL;
    rt_destroy_thread_cpu(&cpu);
    pthread_mutex_lock(&co->mu);
    co->done = 1;
    co->active = 0;
    co->running = 0;
    pthread_cond_signal(&co->cv);
    pthread_mutex_unlock(&co->mu);
    return NULL;
}

static void w_Coroutine_Create(CPU64 *c, void *ud) {
    (void)ud;
    pthread_mutex_lock(&g_coro_mu);
    int32_t slot = 0;
    for (int32_t i = 1; i < VSTD_MAX_COROS; i++) {
        if (!g_coros[i] || !g_coros[i]->in_use) { slot = i; break; }
    }
    if (!slot) { pthread_mutex_unlock(&g_coro_mu); c->rax = 0; return; }
    VstdCoro *co = g_coros[slot];
    if (!co) {
        co = (VstdCoro *)calloc(1, sizeof(VstdCoro));
        pthread_mutex_init(&co->mu, NULL);
        pthread_cond_init(&co->cv, NULL);
        g_coros[slot] = co;
    }
    co->id = slot;
    co->in_use = 1;
    co->fn = c->rcx;
    co->param = c->rdx;
    co->started = 0;
    co->running = 0;
    co->done = 0;
    co->cancel = 0;
    co->active = 1;
    pthread_mutex_unlock(&g_coro_mu);
    c->rax = (uint64_t)(uint32_t)slot;
}

static void w_Coroutine_Continue(CPU64 *c, void *ud) {
    (void)ud;
    int32_t id = (int32_t)c->rcx;
    VstdCoro *co = coro_lookup(id);
    if (!co) { c->rax = 0; return; }
    pthread_mutex_lock(&co->mu);
    if (!co->active || co->done) {
        pthread_mutex_unlock(&co->mu);
        c->rax = 0;
        return;
    }
    co->owner_tid = win32_current_tid();
    co->running = 1;
    if (!co->started) {
        co->started = 1;
        if (pthread_create(&co->th, NULL, coro_thread_main, co) != 0) {
            co->started = 0; co->running = 0; co->done = 1; co->active = 0;
            pthread_mutex_unlock(&co->mu);
            c->rax = 0;
            return;
        }
    } else {
        pthread_cond_signal(&co->cv);
    }
    while (co->running && !co->done) {
        pthread_cond_wait(&co->cv, &co->mu);
    }
    int still_active = (!co->done && co->active);
    int need_join = (co->done && co->started);
    if (need_join) co->started = 0;
    pthread_mutex_unlock(&co->mu);
    if (need_join) {
        pthread_join(co->th, NULL);
        pthread_mutex_lock(&g_coro_mu);
        co->in_use = 0;
        pthread_mutex_unlock(&g_coro_mu);
    }
    c->rax = (uint64_t)(still_active ? 1 : 0);
}

static void w_Coroutine_YieldToMain(CPU64 *c, void *ud) {
    (void)ud; (void)c;
    VstdCoro *co = tls_cur_coro;
    if (!co) return;
    pthread_mutex_lock(&co->mu);
    co->running = 0;
    pthread_cond_signal(&co->cv);
    while (!co->running && !co->cancel) {
        pthread_cond_wait(&co->cv, &co->mu);
    }
    int do_cancel = co->cancel;
    uint32_t otid = co->owner_tid;
    pthread_mutex_unlock(&co->mu);
    if (do_cancel) siglongjmp(co->cancel_jb, 1);
    g_win32_tid_override = otid;
    if (c && c->gs_base) W32(c->gs_base + 0x48, otid);
}

static void w_Coroutine_Cancel(CPU64 *c, void *ud) {
    (void)ud;
    int32_t id = (int32_t)c->rcx;
    VstdCoro *co = coro_lookup(id);
    if (!co) return;
    pthread_mutex_lock(&co->mu);
    co->cancel = 1;
    co->active = 0;
    int need_join = (co->started && co != tls_cur_coro);
    if (need_join) {
        co->started = 0;
        pthread_cond_signal(&co->cv);
    } else if (!co->started) {
        co->done = 1;
    }
    pthread_mutex_unlock(&co->mu);
    if (need_join) pthread_join(co->th, NULL);
    if (co != tls_cur_coro) {
        pthread_mutex_lock(&g_coro_mu);
        co->in_use = 0;
        pthread_mutex_unlock(&g_coro_mu);
    }
}

static void w_Coroutine_IsActive(CPU64 *c, void *ud) {
    (void)ud;
    VstdCoro *co = coro_lookup((int32_t)c->rcx);
    c->rax = (co && co->active && !co->done) ? 1 : 0;
}
static void w_Coroutine_GetCurrentlyActive(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = tls_cur_coro ? (uint64_t)(uint32_t)tls_cur_coro->id : 0;
}
static void w_Coroutine_GetStackDepth(CPU64 *c, void *ud) { (void)ud; c->rax = 1024; }

void rt_register_win32_extra(void) {
    #define REG(name, fn) rt_register_shim(name, fn, NULL)
    /* Time */
    REG("GetSystemTimeAsFileTime", w_GetSystemTimeAsFileTime);
    REG("GetSystemTime", w_GetSystemTime); REG("GetLocalTime", w_GetLocalTime);
    REG("FileTimeToSystemTime", w_FileTimeToSystemTime); REG("SystemTimeToFileTime", w_SystemTimeToFileTime);
    REG("SystemTimeToTzSpecificLocalTime", w_SystemTimeToTzSpecificLocalTime);
    REG("GetTimeZoneInformation", w_GetTimeZoneInformation);
    /* FLS / Sync / SList / InitOnce */
    REG("FlsAlloc", w_FlsAlloc); REG("FlsGetValue", w_FlsGetValue);
    REG("FlsSetValue", w_FlsSetValue); REG("FlsFree", w_FlsFree);
    REG("InitializeCriticalSectionEx", w_ret_1);
    REG("AcquireSRWLockExclusive", w_AcquireSRWLockExclusive);
    REG("TryAcquireSRWLockExclusive", w_TryAcquireSRWLockExclusive);
    REG("ReleaseSRWLockExclusive", w_ReleaseSRWLockExclusive);
    REG("InitializeConditionVariable", w_InitializeConditionVariable);
    REG("WakeConditionVariable", w_WakeConditionVariable);
    REG("WakeAllConditionVariable", w_WakeAllConditionVariable);
    REG("SleepConditionVariableSRW", w_SleepConditionVariableSRW);
    REG("SleepConditionVariableCS", w_SleepConditionVariableCS);
    REG("InitializeSListHead", w_InitializeSListHead);
    REG("InterlockedFlushSList", w_InterlockedFlushSList);
    REG("InitOnceBeginInitialize", w_InitOnceBeginInitialize);
    REG("InitOnceComplete", w_InitOnceComplete);
    REG("InitOnceExecuteOnce", w_InitOnceExecuteOnce);
    REG("CreateMutexA", w_CreateMutexA); REG("ReleaseMutex", w_ret_1);
    REG("OpenEventA", w_ret_0);
    /* Process / Env / CRT */
    REG("GetCommandLineA", w_GetCommandLineA); REG("GetCommandLineW", w_GetCommandLineW);
    REG("GetEnvironmentStringsW", w_GetEnvironmentStringsW); REG("FreeEnvironmentStringsW", w_FreeEnvironmentStringsW);
    REG("GetEnvironmentVariableA", w_GetEnvironmentVariableA);
    REG("SetEnvironmentVariableA", w_SetEnvironmentVariableA); REG("SetEnvironmentVariableW", w_SetEnvironmentVariableW);
    REG("GetStartupInfoW", w_GetStartupInfoW);
    REG("GetCurrentProcess", w_GetCurrentProcess); REG("GetCurrentThread", w_GetCurrentThread);
    REG("GetThreadId", w_GetThreadId);
    REG("ResumeThread", w_ret_0); REG("SuspendThread", w_ret_0);
    REG("DuplicateHandle", w_ret_1);
    REG("GetCurrentProcessorNumber", w_GetCurrentProcessorNumber);
    REG("EncodePointer", w_EncodePointer); REG("DecodePointer", w_DecodePointer);
    REG("IsDebuggerPresent", w_IsDebuggerPresent); REG("IsProcessorFeaturePresent", w_IsProcessorFeaturePresent);
    REG("GetACP", w_GetACP); REG("GetOEMCP", w_GetOEMCP);
    REG("IsValidCodePage", w_IsValidCodePage); REG("IsValidLocale", w_ret_1); REG("GetCPInfo", w_GetCPInfo);
    REG("GetFileType", w_GetFileType); REG("GetModuleHandleExW", w_GetModuleHandleExW);
    REG("HeapSize", w_HeapSize); REG("_msize", w_msize); REG("LocalFree", w_LocalFree);
    REG("GetLargePageMinimum", w_GetLargePageMinimum);
    REG("GetVersion", w_GetVersion); REG("GetVersionExA", w_GetVersionExA);
    REG("GlobalMemoryStatusEx", w_GlobalMemoryStatusEx);
    REG("GetProcessAffinityMask", w_GetProcessAffinityMask);
    REG("SetProcessAffinityMask", w_ret_1); REG("SetThreadAffinityMask", w_ret_1);
    REG("SetThreadPriority", w_ret_1); REG("GetThreadPriority", w_ret_0);
    REG("SetThreadIdealProcessor", w_ret_0); REG("SetPriorityClass", w_ret_1);
    REG("GetNumaHighestNodeNumber", w_GetNumaHighestNodeNumber);
    REG("GetNumaProcessorNode", w_GetNumaProcessorNode);
    REG("GetNumaNodeProcessorMask", w_GetNumaNodeProcessorMask);
    REG("SwitchToThread", w_SwitchToThread); REG("SleepEx", w_SleepEx);
    REG("SetErrorMode", w_ret_0); REG("SetConsoleCtrlHandler", w_ret_1);
    REG("SetUnhandledExceptionFilter", w_SetUnhandledExceptionFilter);
    REG("UnhandledExceptionFilter", w_UnhandledExceptionFilter);
    REG("RtlCaptureStackBackTrace", w_RtlCaptureStackBackTrace);
    REG("RtlLookupFunctionEntry", w_RtlLookupFunctionEntry);
    REG("RtlCaptureContext", w_RtlCaptureContext); REG("RtlPcToFileHeader", w_RtlPcToFileHeader);
    REG("RtlUnwind", w_RtlUnwindEx); REG("RtlUnwindEx", w_RtlUnwindEx); REG("RtlVirtualUnwind", w_ret_0);
    REG("TerminateProcess", w_TerminateProcess); REG("ExitThread", w_ExitThread);
    REG("FreeLibraryAndExitThread", w_ExitThread);
    /* Filesystem / Console */
    REG("GetCurrentDirectoryA", w_GetCurrentDirectoryA); REG("GetCurrentDirectoryW", w_GetCurrentDirectoryW);
    REG("SetCurrentDirectoryW", w_SetCurrentDirectoryW); REG("GetFullPathNameW", w_GetFullPathNameW);
    REG("GetFileAttributesA", w_GetFileAttributesA); REG("GetFileAttributesW", w_GetFileAttributesW);
    REG("GetFileAttributesExA", w_GetFileAttributesExA); REG("GetFileAttributesExW", w_GetFileAttributesExW);
    REG("CreateDirectoryA", w_CreateDirectoryA); REG("CreateDirectoryW", w_CreateDirectoryW);
    REG("GetTempPathA", w_GetTempPathA); REG("GetTempPathW", w_GetTempPathW);
    REG("CreateFileA", w_CreateFileA); REG("CreateFileW", w_CreateFileW);
    REG("ReadFile", w_ReadFile); REG("GetFileSizeEx", w_GetFileSizeEx);
    REG("SetFilePointerEx", w_SetFilePointerEx); REG("FlushFileBuffers", w_FlushFileBuffers);
    REG("WriteConsoleW", w_WriteConsoleW); REG("OutputDebugStringW", w_OutputDebugStringW);
    REG("GetConsoleMode", w_GetConsoleMode); REG("SetConsoleMode", w_ret_1);
    REG("GetConsoleScreenBufferInfo", w_GetConsoleScreenBufferInfo);
    REG("SetConsoleTextAttribute", w_ret_1); REG("SetConsoleTitleA", w_ret_1);
    REG("GetConsoleTitleA", w_ret_0); REG("SetConsoleScreenBufferSize", w_ret_1);
    REG("SetConsoleWindowInfo", w_ret_1); REG("GetLargestConsoleWindowSize", w_ret_0);
    REG("GetNumberOfConsoleInputEvents", w_ret_0); REG("ReadConsoleInputA", w_ret_0);
    REG("ReadConsoleOutputCharacterA", w_ret_0); REG("WriteConsoleOutputA", w_ret_1);
    REG("WriteConsoleInputA", w_ret_0); REG("ReadConsoleW", w_ret_0); REG("SetStdHandle", w_ret_1);
    REG("GetConsoleOutputCP", w_GetACP); REG("AttachConsole", w_ret_0); REG("AllocConsole", w_ret_0);
    REG("FreeConsole", w_ret_1);
    REG("FindFirstFileA", w_FindFirstFileA); REG("FindFirstFileExA", w_FindFirstFileExA);
    REG("FindFirstFileW", w_FindFirstFileW); REG("FindFirstFileExW", w_FindFirstFileExW);
    REG("FindNextFileA", w_FindNextFileA); REG("FindNextFileW", w_FindNextFileW);
    REG("FindClose", w_FindClose);
    REG("GetFileSize", w_GetFileSize); REG("SetFilePointer", w_SetFilePointer);
    REG("SetEndOfFile", w_SetEndOfFile); REG("GetFileInformationByHandle", w_GetFileInformationByHandle);
    REG("GetFileInformationByHandleEx", w_ret_0);
    REG("DeleteFileA", w_DeleteFileA); REG("DeleteFileW", w_DeleteFileW);
    REG("MoveFileExW", w_ret_0); REG("SetFileAttributesW", w_ret_1);
    REG("AreFileApisANSI", w_ret_1); REG("GetDriveTypeW", w_ret_1);
    REG("GetDiskFreeSpaceA", w_ret_0); REG("GetLocaleInfoEx", w_ret_0);
    REG("FormatMessageA", w_ret_0); REG("FormatMessageW", w_ret_0);
    REG("CreateFileMappingA", w_ret_0); REG("MapViewOfFile", w_ret_0); REG("UnmapViewOfFile", w_ret_1);
    REG("ConnectNamedPipe", w_ret_0); REG("CreateNamedPipeA", w_ret_inv);
    REG("DeviceIoControl", w_ret_0); REG("GetOverlappedResult", w_GetOverlappedResult);
    REG("PeekNamedPipe", w_ret_0); REG("InterlockedPushEntrySList", w_ret_0);
    REG("RaiseException", w_RaiseException);
    REG("CryptAcquireContextA", w_CryptAcquireContextA); REG("CryptAcquireContextW", w_CryptAcquireContextA);
    REG("CryptGenRandom", w_CryptGenRandom); REG("CryptReleaseContext", w_CryptReleaseContext);
    REG("SHGetFileInfoW", w_ret_0);
    REG("SteamAPI_Init", w_SteamAPI_InitSafe); REG("SteamAPI_InitSafe", w_SteamAPI_InitSafe); REG("SteamAPI_GetHSteamUser", w_SteamAPI_GetHSteamUser);
    REG("SteamInternal_ContextInit", w_SteamInternal_ContextInit);
    REG("SteamInternal_FindOrCreateUserInterface", w_SteamInternal_FindOrCreateUserInterface);
    REG("GetStringTypeW", w_GetStringTypeW); REG("LCMapStringEx", w_LCMapStringEx);
    REG("LCMapStringW", w_LCMapStringW); REG("CompareStringW", w_CompareStringW);
    REG("GetLocaleInfoW", w_ret_0); REG("GetUserDefaultLCID", w_ret_0);
    /* User32 / Advapi32 / BCrypt / Ole32 / WinMM / DbgHelp / SteamAPI */
    REG("wsprintfA", w_wsprintfA); REG("wsprintfW", w_wsprintfW);
    REG("MessageBoxA", w_MessageBoxA); REG("MessageBoxW", w_MessageBoxW);
    REG("GetSystemMetrics", w_GetSystemMetrics); REG("FindWindowA", w_ret_0);
    REG("GetDesktopWindow", w_ret_0); REG("GetShellWindow", w_ret_0);
    REG("RegOpenKeyExA", w_ret_err2); REG("RegQueryValueExA", w_ret_err2);
    REG("RegGetValueA", w_ret_err2); REG("RegCloseKey", w_ret_0);
    REG("EventRegister", w_ret_0); REG("EventUnregister", w_ret_0); REG("EventWriteTransfer", w_ret_0);
    REG("SystemFunction036", w_SystemFunction036); REG("BCryptGenRandom", w_BCryptGenRandom);
    REG("CoInitialize", w_ret_0); REG("CoUninitialize", w_ret_0);
    REG("timeBeginPeriod", w_ret_0);
    REG("SetCurrentProcessExplicitAppUserModelID", w_ret_0);
    REG("SHGetFolderPathW", w_ret_err2); REG("ShellExecuteA", w_ret_0);
    REG("GetFileVersionInfoSizeW", w_ret_0); REG("GetFileVersionInfoW", w_ret_0); REG("VerQueryValueW", w_ret_0);
    REG("SteamAPI_GetSteamInstallPath", w_SteamAPI_GetSteamInstallPath);
    REG("ws2_32.dll!#115", w_ret_0); REG("WSAStartup", w_ret_0);
    REG("ws2_32.dll!#116", w_ret_0); REG("WSACleanup", w_ret_0);
    REG("SymInitialize", w_ret_0); REG("SymSetOptions", w_ret_0); REG("SymGetOptions", w_ret_0);
    /* Engine Kernel32 / FS / Memory / Process */
    REG("GetLongPathNameA", w_GetLongShortPathA); REG("GetShortPathNameA", w_GetLongShortPathA);
    REG("GetShortPathNameW", w_GetShortPathW); REG("GetDiskFreeSpaceExA", w_GetDiskFreeSpaceExA);
    REG("GetFileTime", w_GetFileTime); REG("GetProcessTimes", w_GetProcessTimes);
    REG("K32GetProcessMemoryInfo", w_K32GetProcessMemoryInfo);
    REG("VirtualQuery", w_VirtualQuery); REG("VirtualUnlock", w_ret_1);
    REG("RemoveDirectoryW", w_RemoveDirectoryW); REG("MoveFileW", w_MoveFileW);
    REG("CopyFileW", w_CopyFileW); REG("CreatePipe", w_CreatePipe);
    REG("GetTempFileNameW", w_GetTempFileNameW); REG("ReplaceFileW", w_ret_0);
    REG("CreateNamedPipeW", w_ret_inv); REG("DisconnectNamedPipe", w_ret_1);
    REG("SetNamedPipeHandleState", w_ret_0); REG("TransactNamedPipe", w_ret_0); REG("WaitNamedPipeW", w_ret_0);
    REG("LockFileEx", w_ret_1); REG("UnlockFileEx", w_ret_1);
    REG("OpenMutexA", w_ret_0); REG("SetThreadPriorityBoost", w_ret_1);
    REG("EnumSystemLocalesW", w_ret_1); REG("GetDateFormatW", w_ret_0); REG("GetTimeFormatW", w_ret_0);
    REG("GetBinaryTypeW", w_ret_0); REG("CreateProcessA", w_ret_0); REG("CreateProcessW", w_ret_0);
    REG("GetExitCodeProcess", w_ret_0); REG("OpenProcess", w_ret_0); REG("OpenThread", w_ret_0);
    REG("TerminateThread", w_ret_0); REG("GetThreadContext", w_ret_0); REG("SetThreadContext", w_ret_0);
    REG("CreateToolhelp32Snapshot", w_ret_inv); REG("Module32FirstW", w_ret_0); REG("Module32NextW", w_ret_0);
    /* RPCRT4 */
    REG("UuidCreate", w_UuidCreate); REG("UuidToStringA", w_UuidToStringA);
    REG("UuidFromStringA", w_UuidFromStringA); REG("UuidEqual", w_UuidEqual);
    REG("RpcStringFreeA", w_RpcStringFreeA);
    /* User32 / GDI32 / Imm32 */
    REG("GetWindowLongA", w_GetWindowLongPtr); REG("GetWindowLongPtrW", w_GetWindowLongPtr);
    REG("SetWindowLongA", w_SetWindowLongPtr); REG("SetWindowLongPtrW", w_SetWindowLongPtr);
    REG("GetWindowRect", w_GetWindowRect); REG("EnumDisplaySettingsA", w_EnumDisplaySettingsA);
    REG("GetDeviceCaps", w_GetDeviceCaps); REG("GetWindowThreadProcessId", w_GetWindowThreadProcessId);
    REG("AdjustWindowRect", w_ret_1); REG("AdjustWindowRectEx", w_ret_1);
    REG("ChangeDisplaySettingsA", w_ret_0); REG("ChangeDisplaySettingsExA", w_ret_0);
    REG("ClientToScreen", w_ret_1); REG("ScreenToClient", w_ret_1);
    REG("BeginPaint", w_ret_1); REG("EndPaint", w_ret_1); REG("GetDC", w_ret_1); REG("ReleaseDC", w_ret_1);
    REG("InvalidateRect", w_ret_1); REG("IsIconic", w_ret_0); REG("IsWindowVisible", w_ret_1);
    REG("MoveWindow", w_MoveWindow); REG("SetWindowPos", w_SetWindowPos); REG("SetWindowTextA", w_ret_1);
    REG("SetForegroundWindow", w_ret_1); REG("ShowCursor", w_ShowCursor); REG("ReleaseCapture", w_ret_1);
    REG("LoadCursorA", w_ret_1); REG("LoadIconA", w_ret_1); REG("LoadImageA", w_ret_1);
    REG("UnregisterClassW", w_ret_1);
    REG("GetKeyState", w_GetKeyState);
    REG("EnumWindows", w_ret_1); REG("DialogBoxParamA", w_ret_0); REG("EndDialog", w_ret_1);
    REG("GetDlgItemInt", w_ret_0); REG("SetDlgItemInt", w_ret_1); REG("SetDlgItemTextA", w_ret_1);
    REG("ImmIsUIMessageA", w_ret_0);
    /* Winsock2 (ws2_32.dll ordinals + named) */
    REG("ws2_32.dll!#1", w_wsa_accept); REG("accept", w_wsa_accept);
    REG("ws2_32.dll!#2", w_wsa_bind); REG("bind", w_wsa_bind);
    REG("ws2_32.dll!#3", w_wsa_closesocket); REG("closesocket", w_wsa_closesocket);
    REG("ws2_32.dll!#9", w_wsa_htons); REG("htons", w_wsa_htons);
    REG("ws2_32.dll!#10", w_wsa_inet_addr); REG("inet_addr", w_wsa_inet_addr);
    REG("ws2_32.dll!#13", w_wsa_listen); REG("listen", w_wsa_listen);
    REG("ws2_32.dll!#15", w_wsa_ntohs); REG("ntohs", w_wsa_ntohs);
    REG("ws2_32.dll!#16", w_wsa_recv); REG("recv", w_wsa_recv);
    REG("ws2_32.dll!#17", w_wsa_recvfrom); REG("recvfrom", w_wsa_recvfrom);
    REG("ws2_32.dll!#18", w_wsa_select); REG("select", w_wsa_select);
    REG("ws2_32.dll!#19", w_wsa_send); REG("send", w_wsa_send);
    REG("ws2_32.dll!#20", w_wsa_sendto); REG("sendto", w_wsa_sendto);
    REG("ws2_32.dll!#21", w_wsa_setsockopt); REG("setsockopt", w_wsa_setsockopt);
    REG("ws2_32.dll!#23", w_wsa_socket); REG("socket", w_wsa_socket);
    REG("ws2_32.dll!#57", w_wsa_gethostname); REG("gethostname", w_wsa_gethostname);
    REG("ws2_32.dll!#111", w_wsa_GetLastError); REG("WSAGetLastError", w_wsa_GetLastError);
    REG("WSACreateEvent", w_ret_1); REG("WSACloseEvent", w_ret_1); REG("WSASetEvent", w_ret_1);
    REG("WSAEventSelect", w_ret_0); REG("WSAEnumNetworkEvents", w_ret_0); REG("WSAWaitForMultipleEvents", w_ret_0);
    REG("getaddrinfo", w_wsa_getaddrinfo); REG("freeaddrinfo", w_wsa_freeaddrinfo); REG("inet_pton", w_wsa_inet_pton);
    /* Advapi32 / DbgHelp / WinHTTP / WinINet / IPHlpApi / Video64 / SteamAPI */
    REG("OpenProcessToken", w_ret_0); REG("LookupPrivilegeValueA", w_ret_0); REG("AdjustTokenPrivileges", w_ret_0);
    REG("BuildExplicitAccessWithNameW", w_ret_0); REG("BuildSecurityDescriptorW", w_ret_err2);
    REG("ConvertStringSecurityDescriptorToSecurityDescriptorW", w_ret_0); REG("RegDeleteValueA", w_ret_err2);
    REG("MiniDumpWriteDump", w_ret_0); REG("StackWalk64", w_ret_0); REG("SymFromAddr", w_ret_0);
    REG("SymFunctionTableAccess64", w_ret_0); REG("SymGetModuleBase64", w_ret_0);
    REG("GetAdaptersInfo", w_ret_err2);
    REG("WinHttpOpen", w_ret_0); REG("WinHttpConnect", w_ret_0); REG("WinHttpOpenRequest", w_ret_0);
    REG("WinHttpSendRequest", w_ret_0); REG("WinHttpReceiveResponse", w_ret_0);
    REG("WinHttpQueryHeaders", w_ret_0); REG("WinHttpCrackUrl", w_ret_0); REG("WinHttpCloseHandle", w_ret_1);
    REG("InternetOpenA", w_ret_0); REG("InternetOpenUrlA", w_ret_0); REG("InternetReadFile", w_ret_0);
    REG("InternetCloseHandle", w_ret_1); REG("InternetCrackUrlA", w_ret_0);
    REG("HttpQueryInfoA", w_ret_0); REG("InternetSetStatusCallback", w_ret_0);
    REG("VideoPlaybackInitialize", w_ret_0); REG("VideoPlaybackShutdown", w_ret_0);
    REG("SteamAPI_RestartAppIfNecessary", w_ret_0); REG("SteamAPI_Shutdown", w_SteamAPI_Shutdown);
    REG("SteamAPI_RunCallbacks", w_SteamAPI_RunCallbacks); REG("SteamAPI_SetTryCatchCallbacks", w_ret_0);
    REG("SteamAPI_RegisterCallback", w_ret_0); REG("SteamAPI_UnregisterCallback", w_ret_0);
    REG("SteamAPI_RegisterCallResult", w_ret_0); REG("SteamAPI_UnregisterCallResult", w_ret_0);
    REG("SteamInternal_CreateInterface", w_SteamInternal_CreateInterface); REG("SteamInternal_FindOrCreateGameServerInterface", w_ret_0);
    REG("SteamInternal_GameServer_Init", w_ret_0); REG("SteamGameServer_GetHSteamUser", w_ret_0);
    REG("SteamGameServer_RunCallbacks", w_ret_0); REG("SteamGameServer_Shutdown", w_ret_0);
    /* Core engine 18-module shims: Kernel32 Global*, GDI32 DIB/Font, User32, IMM32, WinMM, OLE32, Shell32 */
    REG("GlobalAlloc", w_GlobalAlloc); REG("GlobalLock", w_GlobalLock);
    REG("GlobalUnlock", w_GlobalUnlock); REG("GlobalSize", w_GlobalSize);
    REG("GlobalFree", w_GlobalFree); REG("GetLogicalDriveStringsA", w_GetLogicalDriveStringsA);
    REG("RegCreateKeyExA", w_RegCreateKeyExA); REG("RegEnumKeyExA", w_ret_err2);
    REG("RegQueryInfoKeyA", w_ret_err2); REG("RegSetValueExA", w_ret_0);
    REG("SHDeleteKeyA", w_ret_err2);
    REG("CreateDIBSection", w_CreateDIBSection); REG("DeleteObject", w_DeleteObject);
    REG("GetObjectA", w_GetObjectA); REG("GetTextMetricsA", w_GetTextMetricsA);
    REG("GetCharABCWidthsA", w_GetCharABCWidths); REG("GetCharABCWidthsW", w_GetCharABCWidths);
    REG("GetTextExtentPoint32A", w_GetTextExtentPoint32A); REG("GetGlyphOutlineA", w_GetGlyphOutlineA); REG("GetGlyphOutlineW", w_GetGlyphOutlineA);
    REG("CreateCompatibleDC", w_CreateCompatibleDC); REG("DeleteDC", w_DeleteDC);
    REG("CreateBitmap", w_ret_1); REG("CreateCompatibleBitmap", w_ret_1);
    REG("CreateFontA", w_CreateFontA); REG("CreatePen", w_ret_1);
    REG("CreateRectRgn", w_ret_1); REG("CreateSolidBrush", w_ret_1);
    REG("SelectObject", w_SelectObject); REG("AddFontMemResourceEx", w_AddFontMemResourceEx);
    REG("RemoveFontMemResourceEx", w_ret_1); REG("RemoveFontResourceA", w_ret_1);
    REG("BitBlt", w_ret_1); REG("StretchBlt", w_ret_1); REG("GetDIBits", w_ret_0);
    REG("ExtTextOutA", w_ExtTextOutA); REG("ExtTextOutW", w_ExtTextOutW);
    REG("GetBkColor", w_GetBkColor); REG("SetBkColor", w_SetBkColor); REG("SetBkMode", w_SetBkMode);
    REG("GetTextColor", w_GetTextColor); REG("SetTextColor", w_SetTextColor); REG("SetTextAlign", w_SetTextAlign);
    REG("SetMapMode", w_ret_1); REG("SetRectRgn", w_ret_1); REG("SetViewportOrgEx", w_ret_1);
    REG("MoveToEx", w_MoveToEx); REG("Polygon", w_ret_1); REG("Polyline", w_ret_1);
    REG("GetWindowLongPtrA", w_GetWindowLongPtr); REG("SetWindowLongPtrA", w_SetWindowLongPtr);
    REG("GetKeyboardLayout", w_GetKeyboardLayout); REG("GetKeyboardLayoutList", w_GetKeyboardLayoutList);
    REG("ActivateKeyboardLayout", w_GetKeyboardLayout); REG("LoadKeyboardLayoutA", w_GetKeyboardLayout);
    REG("UnloadKeyboardLayout", w_ret_1); REG("MapVirtualKeyExA", w_MapVirtualKey);
    REG("MapVirtualKeyA", w_MapVirtualKey); REG("MapVirtualKeyExW", w_MapVirtualKey);
    REG("UnregisterClassA", w_ret_1);
    REG("RegisterWindowMessageA", w_RegisterWindowMessageA);
    REG("GetCursorPos", w_GetCursorPos); REG("SetCursorPos", w_SetCursorPos);
    REG("GetFocus", w_GetForegroundWindow); REG("SetFocus", w_GetForegroundWindow);
    REG("GetForegroundWindow", w_GetForegroundWindow); REG("SetActiveWindow", w_GetForegroundWindow);
    REG("GetParent", w_ret_0); REG("WindowFromPoint", w_GetForegroundWindow);
    REG("IsWindowEnabled", w_ret_1); REG("ValidateRect", w_ret_1); REG("FlashWindow", w_ret_1);
    REG("SetWindowTextW", w_ret_1); REG("SetCapture", w_ret_0); REG("SetCursor", w_SetCursor);
    REG("SetTimer", w_ret_1); REG("GetMessageA", w_ret_0); REG("GetGUIThreadInfo", w_ret_0);
    REG("SystemParametersInfoA", w_ret_0); REG("RegisterRawInputDevices", w_ret_1); REG("GetRawInputData", w_GetRawInputData);
    REG("CopyIcon", w_ret_1); REG("CreateIconIndirect", w_ret_1); REG("DestroyCursor", w_ret_1);
    REG("DestroyIcon", w_ret_1); REG("DrawIconEx", w_ret_1); REG("GetIconInfo", w_ret_0);
    REG("LoadCursorFromFileA", w_ret_1);
    REG("OpenClipboard", w_ret_0); REG("CloseClipboard", w_ret_1); REG("EmptyClipboard", w_ret_1);
    REG("GetClipboardData", w_ret_0); REG("SetClipboardData", w_ret_0);
    REG("ImmGetContext", w_ret_0); REG("ImmReleaseContext", w_ret_1);
    REG("ImmGetCandidateListCountW", w_ret_0); REG("ImmGetCandidateListW", w_ret_0);
    REG("ImmGetCompositionStringW", w_ret_0); REG("ImmGetConversionStatus", w_ret_0);
    REG("ImmSetConversionStatus", w_ret_1); REG("ImmGetProperty", w_ret_0);
    REG("ImmNotifyIME", w_ret_1); REG("ImmSetCandidateWindow", w_ret_1);
    REG("waveOutOpen", w_waveOutOpen); REG("waveOutPrepareHeader", w_waveOutPrepareHeader);
    REG("waveOutWrite", w_waveOutWrite); REG("waveOutUnprepareHeader", w_ret_0);
    REG("waveOutReset", w_ret_0); REG("waveOutClose", w_ret_0);
    REG("waveOutGetPosition", w_waveOutGetPosition); REG("PlaySoundA", w_ret_1);
    REG("joyGetNumDevs", w_ret_0); REG("joyGetDevCapsA", w_ret_err2); REG("joyGetPosEx", w_ret_err2);
    REG("dsound.dll!#2", w_ret_0); REG("dsound.dll!#9", w_ret_0);
    REG("DirectSoundEnumerateA", w_ret_0); REG("DirectSoundCreate", w_ret_inv); REG("DirectSoundCaptureCreate", w_ret_inv);
    REG("CoInitializeEx", w_ret_0); REG("OleInitialize", w_ret_0);
    REG("CoCreateInstance", w_CoCreateInstance);
    REG("CoTaskMemAlloc", w_CoTaskMemAlloc); REG("CoTaskMemRealloc", w_CoTaskMemRealloc);
    REG("CoTaskMemFree", w_CoTaskMemFree);
    REG("VariantInit", w_VariantInit); REG("VariantClear", w_VariantClear); REG("VariantCopy", w_VariantCopy);
    REG("SysAllocString", w_SysAllocString); REG("SysAllocStringByteLen", w_SysAllocStringByteLen);
    REG("SysAllocStringLen", w_SysAllocStringLen); REG("SysFreeString", w_SysFreeString);
    REG("SysReAllocString", w_SysReAllocString); REG("SysReAllocStringLen", w_SysReAllocStringLen);
    REG("SysStringByteLen", w_SysStringByteLen); REG("SysStringLen", w_SysStringLen);
    REG("PropVariantClear", w_PropVariantClear); REG("RegisterDragDrop", w_ret_0);
    REG("RevokeDragDrop", w_ret_0); REG("ReleaseStgMedium", w_ret_0);
    REG("oleaut32.dll!#9", w_ret_0);
    REG("DragQueryFileA", w_ret_0); REG("SHGetFileInfoA", w_ret_0);
    REG("SHGetSpecialFolderPathA", w_SHGetSpecialFolderPathA); REG("Shell_NotifyIconA", w_ret_1);
    /* Remaining 24-module game shims: wsock32 ordinals, IMM32, User32, Advapi32 W, Video64, SteamPipe, CompareStringEx */
    REG("CompareStringEx", w_CompareStringEx);
    REG("RegOpenKeyExW", w_ret_err2); REG("RegQueryInfoKeyW", w_ret_err2); REG("RegQueryValueExW", w_ret_err2);
    REG("GetAsyncKeyState", w_GetKeyState); REG("GetKeyboardState", w_GetKeyboardState);
    REG("GetWindowInfo", w_GetWindowInfo); REG("MapVirtualKeyW", w_MapVirtualKey);
    REG("PostQuitMessage", w_ret_0); REG("SendInput", w_ret_0); REG("ToUnicodeEx", w_ret_0);
    REG("ImmAssociateContextEx", w_ret_1); REG("ImmGetIMEFileNameA", w_ret_0);
    REG("ImmGetOpenStatus", w_ret_0); REG("ImmGetVirtualKey", w_ret_0);
    REG("ImmIsUIMessageW", w_ret_0); REG("ImmSetCompositionStringW", w_ret_0);
    REG("ImmSetCompositionWindow", w_ret_1); REG("ImmSetOpenStatus", w_ret_1);
    REG("wsock32.dll!#1", w_wsa_accept); REG("wsock32.dll!#2", w_wsa_bind);
    REG("wsock32.dll!#3", w_wsa_closesocket); REG("wsock32.dll!#8", w_wsa_htonl);
    REG("wsock32.dll!#9", w_wsa_htons); REG("wsock32.dll!#13", w_wsa_listen);
    REG("wsock32.dll!#16", w_wsa_recv); REG("wsock32.dll!#18", w_wsa_select);
    REG("wsock32.dll!#19", w_wsa_send); REG("wsock32.dll!#23", w_wsa_socket);
    REG("wsock32.dll!#115", w_ret_0); REG("wsock32.dll!#116", w_ret_0);
    REG("wsock32.dll!#151", w_ret_0);
    REG("CreateVideoPlayer", w_ret_0); REG("DeleteVideoPlayer", w_ret_0);
    REG("SteamAPI_GetHSteamPipe", w_SteamAPI_GetHSteamPipe); REG("SteamGameServer_GetHSteamPipe", w_ret_0);
    /* engineaudio.dll: WinMM mixer, DirectSound, XAudio2, Steam Audio (phonon) */
    REG("mixerGetNumDevs", w_ret_0); REG("mixerOpen", w_ret_err2); REG("mixerClose", w_ret_0);
    REG("mixerGetDevCapsA", w_ret_err2); REG("mixerGetLineInfoA", w_ret_err2);
    REG("mixerGetLineControlsA", w_ret_err2); REG("mixerGetControlDetailsA", w_ret_err2);
    REG("mixerSetControlDetails", w_ret_err2);
    REG("dsound.dll!#11", w_ret_err2); REG("dsound.dll!#12", w_ret_err2);
    REG("xaudio2_9redist.dll!#1", w_XAudio2Create); REG("XAudio2Create", w_XAudio2Create);
    REG("iplContextCreate", w_ret_err2); REG("iplHRTFCreate", w_ret_err2);
    REG("iplBinauralEffectCreate", w_ret_err2); REG("iplBinauralEffectApply", w_ret_0);
    REG("iplBinauralEffectRelease", w_ret_0); REG("iplDirectEffectCreate", w_ret_err2);
    REG("iplDirectEffectApply", w_ret_0); REG("iplAudioBufferInterleave", w_ret_0);
    REG("DiscordCreate", w_ret_err2);
    /* Panorama Win32 / IOCP / Winsock2 / MSWSock / Shlwapi */
    REG("CreateIoCompletionPort", w_CreateIoCompletionPort);
    REG("GetQueuedCompletionStatus", w_GetQueuedCompletionStatus);
    REG("PostQueuedCompletionStatus", w_ret_1);
    REG("CreateWaitableTimerA", w_CreateMutexA); REG("SetWaitableTimer", w_ret_1);
    REG("CancelIo", w_ret_1); REG("QueueUserAPC", w_ret_1);
    REG("ReadDirectoryChangesW", w_ret_0);
    REG("GetComputerNameExW", w_GetComputerNameExW);
    REG("VerSetConditionMask", w_ret_0); REG("VerifyVersionInfoA", w_ret_1);
    REG("ws2_32.dll!#5", w_wsa_getpeername); REG("ws2_32.dll!#7", w_wsa_getsockopt);
    REG("ws2_32.dll!#8", w_wsa_htonl); REG("ws2_32.dll!#14", w_wsa_ntohl);
    REG("ws2_32.dll!#22", w_wsa_shutdown); REG("ws2_32.dll!#112", w_wsa_SetLastError);
    REG("WSASocketW", w_wsa_socket); REG("WSARecv", w_ret_inv); REG("WSASend", w_ret_inv);
    REG("WSAAddressToStringW", w_ret_inv);
    REG("AcceptEx", w_ret_0); REG("GetAcceptExSockaddrs", w_ret_0);
    REG("timeEndPeriod", w_ret_0); REG("VideoPlaybackRunFrame", w_ret_0);
    REG("GetDlgItem", w_ret_0); REG("AssocQueryStringA", w_ret_err2);
    /* Team Fortress 2 / Source 1 x64: MSVCRT, SDL2, Kernel32, User32, Winsock1, Steam, HarfBuzz, FBX */
    REG("___lc_codepage_func", w_lc_codepage_func); REG("___mb_cur_max_func", w_mb_cur_max_func);
    REG("__iob_func", w_iob_func); REG("__setusermatherr", w_ret_0);
    REG("_aligned_malloc", w_aligned_malloc); REG("_aligned_free", w_aligned_free);
    REG("_amsg_exit", w_TerminateProcess); REG("_assert", w_ret_0);
    REG("_endthreadex", w_ExitThread); REG("_errno", w_errno_ptr);
    REG("_fdopen", w_fdopen); REG("_filelengthi64", w_filelengthi64);
    REG("_fileno", w_fileno); REG("_fstat64", w_fstat64);
    REG("_gmtime64", w_gmtime64); REG("_initterm", w_initterm);
    REG("_lock", w_ret_0); REG("_unlock", w_ret_0);
    REG("_lseeki64", w_lseeki64); REG("_read", w_crt_read); REG("_write", w_crt_write);
    REG("_setjmp", w_ret_0); REG("longjmp", w_longjmp);
    REG("_strdup", w_strdup); REG("_ultoa", w_ultoa);
    REG("_wcsicmp", w_wcsicmp); REG("_wfopen", w_wfopen);
    REG("atof", w_atof); REG("ferror", w_ferror);
    REG("fgetpos", w_fgetpos); REG("fsetpos", w_fsetpos);
    REG("fputc", w_fputc); REG("putc", w_fputc); REG("putwc", w_fputc);
    REG("getc", w_getc); REG("getwc", w_getc);
    REG("ungetc", w_ungetc); REG("ungetwc", w_ungetc);
    REG("iswctype", w_iswctype); REG("towlower", w_towlower); REG("towupper", w_towupper);
    REG("localeconv", w_localeconv); REG("setlocale", w_setlocale);
    REG("remove", w_remove); REG("setvbuf", w_setvbuf); REG("signal", w_ret_0);
    REG("strcoll", w_strcoll); REG("strerror", w_strerror);
    REG("strftime", w_strftime); REG("strxfrm", w_strxfrm);
    REG("vfprintf", w_vfprintf);
    REG("wcscmp", w_wcscmp); REG("wcscoll", w_wcscmp);
    REG("wcsftime", w_wcsftime); REG("wcslen", w_wcslen); REG("wcsxfrm", w_wcsxfrm);
    REG("abort", w_TerminateProcess);
    REG("fopen", w_fopen); REG("fclose", w_fclose); REG("fflush", w_fflush);
    REG("fread", w_fread); REG("fwrite", w_fwrite); REG("ftell", w_ftell);
    REG("fputs", w_fputs); REG("fprintf", w_fprintf);
    REG("getenv", w_getenv); REG("memchr", w_memchr);
    REG("strchr", w_strchr); REG("strrchr", w_strrchr); REG("strstr", w_strstr);
    REG("strcpy", w_lstrcpyA); REG("strcat", w_lstrcatA); REG("strncpy", w_strncpy);
    REG("strtol", w_strtol); REG("strtoul", w_strtoul);
    REG("SDL_GetError", w_SDL_GetError); REG("SDL_InitSubSystem", w_ret_0); REG("SDL_PollEvent", w_ret_0);
    /* Kernel32 TF2 */
    REG("AddVectoredExceptionHandler", w_ret_1); REG("RemoveVectoredExceptionHandler", w_ret_1);
    REG("__C_specific_handler", w_ret_0);
    REG("CopyFileA", w_CopyFileA); REG("MoveFileExA", w_MoveFileExA);
    REG("SetCurrentDirectoryA", w_SetCurrentDirectoryA);
    REG("GetFullPathNameA", w_GetFullPathNameA); REG("GetWindowsDirectoryA", w_GetWindowsDirectoryA);
    REG("GetEnvironmentVariableW", w_GetEnvironmentVariableW);
    REG("GetModuleHandleExA", w_GetModuleHandleExA);
    REG("GetLogicalProcessorInformation", w_GetLogicalProcessorInformation);
    REG("GlobalMemoryStatus", w_GlobalMemoryStatus);
    REG("GetTempFileNameA", w_GetTempFileNameA);
    REG("FileTimeToLocalFileTime", w_FileTimeToLocalFileTime);
    REG("FileTimeToDosDateTime", w_FileTimeToDosDateTime);
    REG("GetConsoleCP", w_GetACP);
    REG("GetDateFormatA", w_GetDateFormatA); REG("GetTimeFormatA", w_GetTimeFormatA);
    REG("GetHandleInformation", w_ret_1); REG("SetHandleInformation", w_ret_1);
    REG("HeapValidate", w_ret_1); REG("HeapWalk", w_ret_0);
    REG("IsDBCSLeadByteEx", w_ret_0); REG("OpenFileMappingW", w_ret_0);
    REG("Process32First", w_ret_0); REG("Process32Next", w_ret_0);
    REG("ReadConsoleInputW", w_ret_0); REG("WinExec", w_ret_0);
    REG("lstrcpyA", w_lstrcpyA); REG("lstrcatA", w_lstrcatA);
    /* User32 / GDI32 / Advapi32 / OLE TF2 */
    REG("ChangeDisplaySettingsExW", w_ret_0);
    REG("DisplayConfigGetDeviceInfo", w_ret_err87);
    REG("GetDisplayConfigBufferSizes", w_ret_err87);
    REG("QueryDisplayConfig", w_ret_err87);
    REG("EnumChildWindows", w_ret_1);
    REG("EnumDisplayDevicesA", w_EnumDisplayDevicesA);
    REG("EnumDisplayMonitors", w_EnumDisplayMonitors);
    REG("EnumDisplaySettingsW", w_EnumDisplaySettingsW);
    REG("GetMonitorInfoW", w_GetMonitorInfoW);
    REG("MonitorFromPoint", w_MonitorFromPoint);
    REG("FillRect", w_ret_1); REG("FlashWindowEx", w_ret_1); REG("UpdateWindow", w_ret_1);
    REG("GetActiveWindow", w_GetForegroundWindow);
    REG("GetDCEx", w_ret_1);
    REG("GetWindowLongW", w_GetWindowLongPtr); REG("SetWindowLongW", w_SetWindowLongPtr);
    REG("IsWindow", w_ret_1); REG("IsWindowUnicode", w_ret_0);
    REG("LoadStringA", w_ret_0); REG("MsgWaitForMultipleObjects", w_ret_0);
    REG("OffsetRect", w_OffsetRect); REG("SetRect", w_SetRect);
    REG("PostMessageA", w_ret_1); REG("PostMessageW", w_ret_1);
    REG("SetProcessDPIAware", w_ret_1);
    REG("AddFontResourceA", w_AddFontResourceA); REG("EnumFontFamiliesExA", w_EnumFontFamiliesExA); REG("GetStockObject", w_ret_1);
    REG("oleaut32.dll!#2", w_SysAllocString);
    REG("oleaut32.dll!#6", w_SysFreeString);
    REG("oleaut32.dll!#8", w_SysStringLen);
    REG("AllocateLocallyUniqueId", w_AllocateLocallyUniqueId);
    REG("RegNotifyChangeKeyValue", w_ret_err2); REG("RegOpenKeyA", w_ret_err2);
    REG("CoSetProxyBlanket", w_ret_0);
    /* Winsock1 (wsock32.dll) ordinals */
    REG("wsock32.dll!#4", w_wsa_connect); REG("wsock32.dll!#7", w_wsa_getsockopt);
    REG("wsock32.dll!#10", w_wsa_inet_addr); REG("wsock32.dll!#12", w_wsa_ioctlsocket);
    REG("wsock32.dll!#14", w_wsa_ntohl); REG("wsock32.dll!#15", w_wsa_ntohs);
    REG("wsock32.dll!#20", w_wsa_sendto); REG("wsock32.dll!#21", w_wsa_setsockopt);
    REG("wsock32.dll!#52", w_wsa_gethostbyname); REG("wsock32.dll!#57", w_wsa_gethostname);
    REG("wsock32.dll!#111", w_wsa_GetLastError);
    /* SteamAPI TF2 */
    REG("SteamAPI_IsSteamRunning", w_ret_1);
    REG("SteamAPI_SetBreakpadAppID", w_ret_0); REG("SteamAPI_SetMiniDumpComment", w_ret_0);
    REG("SteamAPI_UseBreakpadCrashHandler", w_ret_0); REG("SteamAPI_WriteMiniDump", w_ret_0);
    REG("SteamGameServer_BSecure", w_ret_0); REG("SteamGameServer_GetIPCCallCount", w_ret_0);
    /* SDL2.dll TF2 */
    REG("SDL_AddEventWatch", w_ret_0); REG("SDL_DelEventWatch", w_ret_0);
    REG("SDL_GameControllerClose", w_ret_0); REG("SDL_GameControllerGetJoystick", w_ret_0);
    REG("SDL_GameControllerOpen", w_ret_0); REG("SDL_HapticClose", w_ret_0);
    REG("SDL_HapticOpenFromJoystick", w_ret_0); REG("SDL_HapticRumbleInit", w_ret_0);
    REG("SDL_HapticRumblePlay", w_ret_0); REG("SDL_HapticRumbleStop", w_ret_0);
    REG("SDL_IsGameController", w_ret_0); REG("SDL_JoystickClose", w_ret_0);
    REG("SDL_JoystickGetDeviceGUID", w_ret_0); REG("SDL_JoystickGetGUIDString", w_ret_0);
    REG("SDL_JoystickInstanceID", w_ret_0); REG("SDL_JoystickNameForIndex", w_ret_0);
    REG("SDL_JoystickOpen", w_ret_0); REG("SDL_NumJoysticks", w_ret_0);
    REG("SDL_PumpEvents", w_ret_0); REG("SDL_QuitSubSystem", w_ret_0);
    REG("SDL_SetHint", w_SDL_SetHint); REG("SDL_WasInit", w_SDL_WasInit);
    REG("SDL_setenv", w_SDL_setenv);
    /* HarfBuzz optional auto-hinter hooks in libfreetype-6.dll */
    REG("hb_blob_create", w_ret_0); REG("hb_blob_destroy", w_ret_0);
    REG("hb_buffer_add_utf8", w_ret_0); REG("hb_buffer_clear_contents", w_ret_0);
    REG("hb_buffer_create", w_ret_0); REG("hb_buffer_destroy", w_ret_0);
    REG("hb_buffer_get_glyph_infos", w_ret_0); REG("hb_buffer_get_glyph_positions", w_ret_0);
    REG("hb_buffer_get_length", w_ret_0); REG("hb_buffer_guess_segment_properties", w_ret_0);
    REG("hb_face_create", w_ret_0); REG("hb_face_create_for_tables", w_ret_0);
    REG("hb_face_destroy", w_ret_0); REG("hb_face_set_index", w_ret_0);
    REG("hb_face_set_upem", w_ret_0); REG("hb_font_create", w_ret_0);
    REG("hb_font_destroy", w_ret_0); REG("hb_font_get_face", w_ret_0);
    REG("hb_font_set_scale", w_ret_0); REG("hb_ot_layout_collect_lookups", w_ret_0);
    REG("hb_ot_layout_lookup_collect_glyphs", w_ret_0);
    REG("hb_ot_layout_lookup_would_substitute", w_ret_0);
    REG("hb_ot_tags_from_script_and_language", w_ret_0);
    REG("hb_set_create", w_ret_0); REG("hb_set_destroy", w_ret_0);
    REG("hb_set_is_empty", w_ret_1); REG("hb_set_next", w_ret_0);
    REG("hb_set_subtract", w_ret_0); REG("hb_shape", w_ret_0);
    /* Autodesk FBX SDK authoring tool stubs in client.dll */
    REG("??0FbxProperty@fbxsdk@@QEAA@AEBVFbxPropertyHandle@1@@Z", w_ret_0);
    REG("??0FbxStatus@fbxsdk@@QEAA@AEBV01@@Z", w_ret_0);
    REG("??0FbxString@fbxsdk@@QEAA@XZ", w_ret_0);
    REG("??0FbxVector2@fbxsdk@@QEAA@XZ", w_ret_0);
    REG("??0FbxVector4@fbxsdk@@QEAA@XZ", w_ret_0);
    REG("??1FbxCriteria@fbxsdk@@QEAA@XZ", w_ret_0);
    REG("??1FbxProperty@fbxsdk@@QEAA@XZ", w_ret_0);
    REG("??1FbxPropertyHandle@fbxsdk@@QEAA@XZ", w_ret_0);
    REG("??1FbxQuaternion@fbxsdk@@QEAA@XZ", w_ret_0);
    REG("??1FbxString@fbxsdk@@QEAA@XZ", w_ret_0);
    REG("??AFbxQuaternion@fbxsdk@@QEBAAEBNH@Z", w_ret_0);
    REG("??YFbxString@fbxsdk@@QEAAAEBV01@PEBD@Z", w_ret_0);
    REG("?Buffer@FbxString@fbxsdk@@QEAAPEADXZ", w_ret_0);
    REG("?ClassId@FbxAnimLayer@fbxsdk@@2VFbxClassId@2@A", w_ret_0);
    REG("?ClassId@FbxAnimStack@fbxsdk@@2VFbxClassId@2@A", w_ret_0);
    REG("?ClassId@FbxBlendShape@fbxsdk@@2VFbxClassId@2@A", w_ret_0);
    REG("?ClassId@FbxFileTexture@fbxsdk@@2VFbxClassId@2@A", w_ret_0);
    REG("?ClassId@FbxLayeredTexture@fbxsdk@@2VFbxClassId@2@A", w_ret_0);
    REG("?ClassId@FbxSkin@fbxsdk@@2VFbxClassId@2@A", w_ret_0);
    REG("?ClassId@FbxTexture@fbxsdk@@2VFbxClassId@2@A", w_ret_0);
    REG("?Create@FbxIOSettings@fbxsdk@@SAPEAV12@PEAVFbxManager@2@PEBD@Z", w_ret_0);
    REG("?Create@FbxImporter@fbxsdk@@SAPEAV12@PEAVFbxManager@2@PEBD@Z", w_ret_0);
    REG("?Create@FbxManager@fbxsdk@@SAPEAV12@XZ", w_ret_0);
    REG("?Create@FbxScene@fbxsdk@@SAPEAV12@PEAVFbxManager@2@PEBD@Z", w_ret_0);
    REG("?Destroy@FbxObject@fbxsdk@@QEAAX_N@Z", w_ret_0);
    REG("?EvaluateGlobalTransform@FbxNode@fbxsdk@@QEAAAEAVFbxAMatrix@2@VFbxTime@2@W4EPivotSet@12@_N2@Z", w_ret_0);
    REG("?FbxFree@fbxsdk@@YAXPEAX@Z", w_ret_0);
    REG("?FillAnimStackNameArray@FbxDocument@fbxsdk@@QEAAXAEAV?$FbxArray@PEAVFbxString@fbxsdk@@$0BA@@2@@Z", w_ret_0);
    REG("?Find@FbxPropertyHandle@fbxsdk@@QEBA?AV12@PEBD_N@Z", w_ret_0);
    REG("?GetActiveAnimStackName@FbxImporter@fbxsdk@@QEAA?AVFbxString@2@XZ", w_ret_0);
    REG("?GetAnimStackCount@FbxImporter@fbxsdk@@QEAAHXZ", w_ret_0);
    REG("?GetAt@FbxLayerElementArray@fbxsdk@@QEBA_NHPEAPEAXW4EFbxType@2@@Z", w_ret_0);
    REG("?GetBlendShapeChannel@FbxBlendShape@fbxsdk@@QEAAPEAVFbxBlendShapeChannel@2@H@Z", w_ret_0);
    REG("?GetBlendShapeChannelCount@FbxBlendShape@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetChild@FbxNode@fbxsdk@@QEAAPEAV12@H@Z", w_ret_0);
    REG("?GetChildCount@FbxNode@fbxsdk@@QEBAH_N@Z", w_ret_0);
    REG("?GetCluster@FbxSkin@fbxsdk@@QEAAPEAVFbxCluster@2@H@Z", w_ret_0);
    REG("?GetClusterCount@FbxSkin@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetControlPointIndices@FbxCluster@fbxsdk@@QEBAPEAHXZ", w_ret_0);
    REG("?GetControlPointIndices@FbxShape@fbxsdk@@QEBAPEAHXZ", w_ret_0);
    REG("?GetControlPointIndicesCount@FbxCluster@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetControlPointIndicesCount@FbxShape@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetControlPointWeights@FbxCluster@fbxsdk@@QEBAPEANXZ", w_ret_0);
    REG("?GetCount@FbxLayerElementArray@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetDeformer@FbxGeometry@fbxsdk@@QEBAPEAVFbxDeformer@2@HW4EDeformerType@32@PEAVFbxStatus@2@@Z", w_ret_0);
    REG("?GetDeformerCount@FbxGeometry@fbxsdk@@QEBAHW4EDeformerType@FbxDeformer@2@@Z", w_ret_0);
    REG("?GetDirectArray@?$FbxLayerElementTemplate@VFbxVector2@fbxsdk@@@fbxsdk@@QEBAAEAV?$FbxLayerElementArrayTemplate@VFbxVector2@fbxsdk@@@2@XZ", w_ret_0);
    REG("?GetDirectArray@?$FbxLayerElementTemplate@VFbxVector4@fbxsdk@@@fbxsdk@@QEBAAEAV?$FbxLayerElementArrayTemplate@VFbxVector4@fbxsdk@@@2@XZ", w_ret_0);
    REG("?GetDuration@FbxTimeSpan@fbxsdk@@QEBA?AVFbxTime@2@XZ", w_ret_0);
    REG("?GetElementMaterial@FbxGeometryBase@fbxsdk@@QEAAPEAVFbxLayerElementMaterial@2@H@Z", w_ret_0);
    REG("?GetElementMaterialCount@FbxGeometryBase@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetElementNormal@FbxGeometryBase@fbxsdk@@QEAAPEAVFbxLayerElementNormal@2@H@Z", w_ret_0);
    REG("?GetElementNormalCount@FbxGeometryBase@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetElementUV@FbxGeometryBase@fbxsdk@@QEAAPEAVFbxLayerElementUV@2@HW4EType@FbxLayerElement@2@@Z", w_ret_0);
    REG("?GetElementUVCount@FbxGeometryBase@fbxsdk@@QEBAHW4EType@FbxLayerElement@2@@Z", w_ret_0);
    REG("?GetErrorString@FbxStatus@fbxsdk@@QEBAPEBDXZ", w_ret_0);
    REG("?GetFileFormatVersion@FbxManager@fbxsdk@@SAXAEAH00@Z", w_ret_0);
    REG("?GetFileName@FbxFileTexture@fbxsdk@@QEBAPEBDXZ", w_ret_0);
    REG("?GetFileVersion@FbxImporter@fbxsdk@@QEAAXAEAH00@Z", w_ret_0);
    REG("?GetFrameCount@FbxTime@fbxsdk@@QEBA_JW4EMode@12@@Z", w_ret_0);
    REG("?GetFrameRate@FbxImporter@fbxsdk@@QEAA_NAEAW4EMode@FbxTime@2@@Z", w_ret_0);
    REG("?GetFrameRate@FbxTime@fbxsdk@@SANW4EMode@12@@Z", w_ret_0);
    REG("?GetLink@FbxCluster@fbxsdk@@QEAAPEAVFbxNode@2@XZ", w_ret_0);
    REG("?GetLinkMode@FbxCluster@fbxsdk@@QEBA?AW4ELinkMode@12@XZ", w_ret_0);
    REG("?GetMaterial@FbxNode@fbxsdk@@QEBAPEAVFbxSurfaceMaterial@2@H@Z", w_ret_0);
    REG("?GetMaterialCount@FbxNode@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetName@FbxObject@fbxsdk@@QEBAPEBDXZ", w_ret_0);
    REG("?GetNameOnly@FbxObject@fbxsdk@@QEBA?AVFbxString@2@XZ", w_ret_0);
    REG("?GetNode@FbxNodeAttribute@fbxsdk@@QEBAPEAVFbxNode@2@H@Z", w_ret_0);
    REG("?GetNodeAttribute@FbxNode@fbxsdk@@QEAAPEAVFbxNodeAttribute@2@XZ", w_ret_0);
    REG("?GetPolygonCount@FbxMesh@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetPolygonSize@FbxMesh@fbxsdk@@QEBAHH@Z", w_ret_0);
    REG("?GetPolygonVertex@FbxMesh@fbxsdk@@QEBAHHH@Z", w_ret_0);
    REG("?GetQ@FbxAMatrix@fbxsdk@@QEBA?AVFbxQuaternion@2@XZ", w_ret_0);
    REG("?GetRootNode@FbxScene@fbxsdk@@QEBAPEAVFbxNode@2@XZ", w_ret_0);
    REG("?GetSecondDouble@FbxTime@fbxsdk@@QEBANXZ", w_ret_0);
    REG("?GetSrcObject@FbxProperty@fbxsdk@@QEBAPEAVFbxObject@2@AEBVFbxCriteria@2@H@Z", w_ret_0);
    REG("?GetSrcObjectCount@FbxProperty@fbxsdk@@QEBAHAEBVFbxCriteria@2@@Z", w_ret_0);
    REG("?GetT@FbxAMatrix@fbxsdk@@QEBA?AVFbxVector4@2@XZ", w_ret_0);
    REG("?GetTakeInfo@FbxDocument@fbxsdk@@QEBAPEAVFbxTakeInfo@2@AEBVFbxString@2@@Z", w_ret_0);
    REG("?GetTakeInfo@FbxImporter@fbxsdk@@QEAAPEAVFbxTakeInfo@2@H@Z", w_ret_0);
    REG("?GetTargetShape@FbxBlendShapeChannel@fbxsdk@@QEAAPEAVFbxShape@2@H@Z", w_ret_0);
    REG("?GetTargetShapeCount@FbxBlendShapeChannel@fbxsdk@@QEBAHXZ", w_ret_0);
    REG("?GetTextureUVIndex@FbxMesh@fbxsdk@@QEAAHHHW4EType@FbxLayerElement@2@@Z", w_ret_0);
    REG("?GetVersion@FbxManager@fbxsdk@@SAPEBD_N@Z", w_ret_0);
    REG("?Import@FbxImporter@fbxsdk@@QEAA_NPEAVFbxDocument@2@_N@Z", w_ret_0);
    REG("?Is@FbxClassId@fbxsdk@@QEBA_NAEBV12@@Z", w_ret_0);
    REG("?IsFBX@FbxImporter@fbxsdk@@QEAA_NXZ", w_ret_0);
    REG("?ObjectType@FbxCriteria@fbxsdk@@SA?AV12@AEBVFbxClassId@2@@Z", w_ret_0);
    REG("?ParseForGlobalSettings@FbxImporter@fbxsdk@@QEAAX_N@Z", w_ret_0);
    REG("?SetBoolProp@FbxIOSettings@fbxsdk@@QEAAXPEBD_N@Z", w_ret_0);
    REG("?SetCurrentAnimationStack@FbxScene@fbxsdk@@QEAAXPEAVFbxAnimStack@2@@Z", w_ret_0);
    REG("?SetFrame@FbxTime@fbxsdk@@QEAAX_JW4EMode@12@@Z", w_ret_0);
    REG("?sDiffuse@FbxSurfaceMaterial@fbxsdk@@2PEBDEB", w_ret_0);
    /* Source Engine vstdlib.dll Coroutine_* overrides */
    REG("vstdlib.dll!Coroutine_Create", w_Coroutine_Create);
    REG("vstdlib.dll!Coroutine_Continue", w_Coroutine_Continue);
    REG("vstdlib.dll!Coroutine_YieldToMain", w_Coroutine_YieldToMain);
    REG("vstdlib.dll!Coroutine_Cancel", w_Coroutine_Cancel);
    REG("vstdlib.dll!Coroutine_IsActive", w_Coroutine_IsActive);
    REG("vstdlib.dll!Coroutine_GetCurrentlyActive", w_Coroutine_GetCurrentlyActive);
    REG("vstdlib.dll!Coroutine_GetStackDepth", w_Coroutine_GetStackDepth);
    REG("vstdlib.dll!Coroutine_ReleaseThreadMemory", w_ret_0);
    REG("vstdlib.dll!Coroutine_ValidateGlobals", w_ret_0);
    REG("vstdlib.dll!Coroutine_DebugBreak", w_ret_0);
    REG("vstdlib.dll!Coroutine_DebugAssert", w_ret_0);
    #undef REG
}
