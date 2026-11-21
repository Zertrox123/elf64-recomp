#include "runtime64.h"
#include "win64_abi.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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
static void w_SleepConditionVariableSRW(CPU64 *c, void *ud)  { (void)ud; pthread_cond_wait(get_cv(c->rcx), get_srw(c->rdx)); c->rax = 1; }
static void w_SleepConditionVariableCS(CPU64 *c, void *ud)   { (void)ud; pthread_cond_wait(get_cv(c->rcx), get_srw(c->rdx)); c->rax = 1; }
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
static void w_HeapSize(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
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
static void w_GetSystemMetrics(CPU64 *c, void *ud) {
    (void)ud;
    int idx = (int)c->rcx;
    if (idx == 0) c->rax = 1920;
    else if (idx == 1) c->rax = 1080;
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
static uint64_t g_steam_vt[64];
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

static void steam_vt_trampoline(CPU64 *c, void *ud) {
    size_t slot = (size_t)(uintptr_t)ud;
    SteamProxy *px = (SteamProxy *)(uintptr_t)c->rcx;
    if (!px || !px->real_obj) { c->rax = 0; return; }
    void **rvt = *(void ***)px->real_obj;
    typedef uint64_t (*Arm64Fn)(uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t);
    Arm64Fn fn = (Arm64Fn)rvt[slot];
    int is_csteamid_sret =
        ((strncmp(px->ver, "SteamUser", 9) == 0 && px->ver[9] >= '0' && px->ver[9] <= '9' && slot == 2) ||
         (strncmp(px->ver, "SteamApps", 9) == 0 && slot == 17));
    if (is_csteamid_sret) {
        uint64_t id = fn((uint64_t)(uintptr_t)px->real_obj, c->r8, c->r9,
                         win64_arg_i(c, 4), win64_arg_i(c, 5), win64_arg_i(c, 6), 0, 0);
        if (c->rdx) W64(c->rdx, id);
        c->rax = c->rdx;
        return;
    }
    uint64_t r = fn((uint64_t)(uintptr_t)px->real_obj, c->rdx, c->r8, c->r9,
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
        for (size_t i = 0; i < 64; i++) {
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
    if (!root || !*root) return;
    char p[1024];
    snprintf(p, sizeof(p), "%s/steam_appid.txt", root);
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
    void *dl = steam_dl();
    if (!dl) { c->rax = 0; return; }
    ensure_steam_appid_env();
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
static void w_CreateSemaphoreA(CPU64 *c, void *ud) { (void)ud; c->rax = 0x30002ULL; }
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
static void w_GetWindowLongPtr(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = g_wnd_long[wnd_slot(c->rcx)][wnd_idx((int)c->rdx)];
}
static void w_SetWindowLongPtr(CPU64 *c, void *ud) {
    (void)ud;
    int s = wnd_slot(c->rcx), idx = wnd_idx((int)c->rdx);
    uint64_t prev = g_wnd_long[s][idx];
    g_wnd_long[s][idx] = c->r8;
    c->rax = prev;
}
static void w_GetWindowRect(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) { W32(c->rdx, 0); W32(c->rdx + 4, 0); W32(c->rdx + 8, 1280); W32(c->rdx + 12, 720); }
    c->rax = 1;
}
static void w_EnumDisplaySettingsA(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t mode = (uint32_t)c->rdx;
    uint64_t dm = c->r8;
    if (!dm) { c->rax = 0; return; }
    static const struct { uint32_t w, h; } modes[] = { {1280, 720}, {1920, 1080}, {1600, 900}, {1024, 768} };
    uint32_t w = 1280, h = 720;
    if (mode == 0xFFFFFFFFU || mode == 0xFFFFFFFEU) { w = 1920; h = 1080; }
    else if (mode < 4) { w = modes[mode].w; h = modes[mode].h; }
    else { c->rax = 0; return; }
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
    if (idx == 8) c->rax = 1920;        /* HORZRES */
    else if (idx == 10) c->rax = 1080;  /* VERTRES */
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

typedef struct { int w, h, bpp; void *bits; } GdiBmp;
static GdiBmp g_gdi_bmps[128];
static pthread_mutex_t g_gdi_mu = PTHREAD_MUTEX_INITIALIZER;

static void w_CreateDIBSection(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t bmi = c->rdx;
    uint64_t ppv = c->r9;
    int w = bmi ? (int32_t)R32(bmi + 4) : 16;
    int h = bmi ? (int32_t)R32(bmi + 8) : 16;
    if (w <= 0) w = 16;
    if (h < 0) h = -h;
    if (h == 0) h = 16;
    int bpp = bmi ? (int)R16(bmi + 14) : 32;
    if (bpp < 8) bpp = 32;
    size_t stride = (((size_t)w * (size_t)bpp + 31) / 32) * 4;
    void *bits = calloc(1, stride * (size_t)h + 64);
    if (ppv) W64(ppv, (uint64_t)(uintptr_t)bits);
    pthread_mutex_lock(&g_gdi_mu);
    for (int i = 0; i < 128; i++) {
        if (!g_gdi_bmps[i].bits) {
            g_gdi_bmps[i].w = w; g_gdi_bmps[i].h = h; g_gdi_bmps[i].bpp = bpp; g_gdi_bmps[i].bits = bits;
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
    if (c->rcx >= 0x50000ULL && c->rcx < 0x50080ULL) {
        size_t idx = (size_t)(c->rcx - 0x50000ULL);
        pthread_mutex_lock(&g_gdi_mu);
        free(g_gdi_bmps[idx].bits);
        memset(&g_gdi_bmps[idx], 0, sizeof(g_gdi_bmps[idx]));
        pthread_mutex_unlock(&g_gdi_mu);
    }
    c->rax = 1;
}
static void w_GetObjectA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t h = c->rcx;
    int cb = (int)c->rdx;
    uint64_t out = c->r8;
    if (h >= 0x50000ULL && h < 0x50080ULL && out && cb >= 32) {
        size_t idx = (size_t)(h - 0x50000ULL);
        memset((void *)(uintptr_t)out, 0, (size_t)cb);
        W32(out + 4, (uint32_t)g_gdi_bmps[idx].w);
        W32(out + 8, (uint32_t)g_gdi_bmps[idx].h);
        W32(out + 12, (uint32_t)(g_gdi_bmps[idx].w * (g_gdi_bmps[idx].bpp / 8)));
        W16(out + 16, 1);
        W16(out + 18, (uint16_t)g_gdi_bmps[idx].bpp);
        W64(out + 24, (uint64_t)(uintptr_t)g_gdi_bmps[idx].bits);
        c->rax = 32;
        return;
    }
    c->rax = 0;
}
static void w_GetTextMetricsA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t tm = c->rdx;
    if (!tm) { c->rax = 0; return; }
    memset((void *)(uintptr_t)tm, 0, 56);
    W32(tm + 0, 16);  /* tmHeight */
    W32(tm + 4, 13);  /* tmAscent */
    W32(tm + 8, 3);   /* tmDescent */
    W32(tm + 20, 8);  /* tmAveCharWidth */
    W32(tm + 24, 16); /* tmMaxCharWidth */
    W32(tm + 28, 400);/* tmWeight */
    W8(tm + 48, 32);  /* tmFirstChar */
    W8(tm + 49, 126); /* tmLastChar */
    c->rax = 1;
}
static void w_GetCharABCWidths(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t first = (uint32_t)c->rdx, last = (uint32_t)c->r8;
    uint64_t out = c->r9;
    if (!out || last < first || (last - first) > 65536) { c->rax = 0; return; }
    for (uint32_t i = 0; i <= last - first; i++) {
        W32(out + i * 12ULL + 0, 0);
        W32(out + i * 12ULL + 4, 8);
        W32(out + i * 12ULL + 8, 1);
    }
    c->rax = 1;
}
static void w_GetTextExtentPoint32A(CPU64 *c, void *ud) {
    (void)ud;
    int len = (int)c->r8;
    if (c->r9) { W32(c->r9, (uint32_t)(len > 0 ? len * 8 : 0)); W32(c->r9 + 4, 16); }
    c->rax = 1;
}
static void w_GetGlyphOutlineA(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t gm = c->r9;
    uint32_t cb = (uint32_t)win64_arg_i(c, 4);
    uint64_t buf = win64_arg_i(c, 5);
    if (gm) {
        memset((void *)(uintptr_t)gm, 0, 20);
        W32(gm + 0, 8); W32(gm + 4, 14); W32(gm + 8, 0); W32(gm + 12, 13);
        W16(gm + 16, 9); W16(gm + 18, 0);
    }
    uint32_t need = 8 * 14;
    if (buf && cb >= need) memset((void *)(uintptr_t)buf, 0, need);
    c->rax = need;
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
    if (c->rcx) { W32(c->rcx, 640); W32(c->rcx + 4, 360); }
    c->rax = 1;
}
static void w_GetForegroundWindow(CPU64 *c, void *ud) { (void)ud; c->rax = 0x1000ULL; }
static void w_waveOutOpen(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) W64(c->rcx, 0x60001ULL);
    c->rax = 0; /* MMSYSERR_NOERROR */
}
static void w_waveOutPrepareHeader(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx + 24, R32(c->rdx + 24) | 0x00000002U /* WHDR_PREPARED */);
    c->rax = 0;
}
static void w_waveOutWrite(CPU64 *c, void *ud) {
    (void)ud;
    /* Mark buffer immediately done so sound mixer never stalls waiting for playback */
    if (c->rdx) W32(c->rdx + 24, R32(c->rdx + 24) | 0x00000001U /* WHDR_DONE */);
    c->rax = 0;
}
static void w_waveOutGetPosition(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx + 4, 0);
    c->rax = 0;
}
static void w_CoCreateInstance(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t ppv = win64_arg_i(c, 4);
    if (ppv) W64(ppv, 0);
    c->rax = 0x80004002ULL; /* E_NOINTERFACE */
}
static void w_CoTaskMemFree(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rcx) free((void *)(uintptr_t)c->rcx);
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
    if (c->rcx) memset((void *)(uintptr_t)c->rcx, 0, 256);
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
    REG("CreateSemaphoreA", w_CreateSemaphoreA); REG("ReleaseSemaphore", w_ret_1);
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
    REG("HeapSize", w_HeapSize); REG("LocalFree", w_LocalFree);
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
    REG("RtlUnwind", w_ret_0); REG("RtlUnwindEx", w_ret_0); REG("RtlVirtualUnwind", w_ret_0);
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
    REG("DeviceIoControl", w_ret_0); REG("GetOverlappedResult", w_ret_0);
    REG("PeekNamedPipe", w_ret_0); REG("InterlockedPushEntrySList", w_ret_0);
    REG("RaiseException", w_RaiseException);
    REG("CryptAcquireContextA", w_CryptAcquireContextA); REG("CryptAcquireContextW", w_CryptAcquireContextA);
    REG("CryptGenRandom", w_CryptGenRandom); REG("CryptReleaseContext", w_CryptReleaseContext);
    REG("SHGetFileInfoW", w_ret_0);
    REG("SteamAPI_InitSafe", w_SteamAPI_InitSafe); REG("SteamAPI_GetHSteamUser", w_SteamAPI_GetHSteamUser);
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
    REG("MoveWindow", w_ret_1); REG("SetWindowPos", w_ret_1); REG("SetWindowTextA", w_ret_1);
    REG("SetForegroundWindow", w_ret_1); REG("ShowCursor", w_ret_1); REG("ReleaseCapture", w_ret_1);
    REG("LoadCursorA", w_ret_1); REG("LoadIconA", w_ret_1); REG("LoadImageA", w_ret_1);
    REG("RegisterClassW", w_ret_1); REG("UnregisterClassW", w_ret_1);
    REG("CallWindowProcA", w_ret_0); REG("SendMessageA", w_ret_0); REG("GetKeyState", w_ret_0);
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
    REG("RegCreateKeyExA", w_ret_err2); REG("RegEnumKeyExA", w_ret_err2);
    REG("RegQueryInfoKeyA", w_ret_err2); REG("RegSetValueExA", w_ret_err2);
    REG("SHDeleteKeyA", w_ret_err2);
    REG("CreateDIBSection", w_CreateDIBSection); REG("DeleteObject", w_DeleteObject);
    REG("GetObjectA", w_GetObjectA); REG("GetTextMetricsA", w_GetTextMetricsA);
    REG("GetCharABCWidthsA", w_GetCharABCWidths); REG("GetCharABCWidthsW", w_GetCharABCWidths);
    REG("GetTextExtentPoint32A", w_GetTextExtentPoint32A); REG("GetGlyphOutlineA", w_GetGlyphOutlineA);
    REG("CreateCompatibleDC", w_ret_1); REG("DeleteDC", w_ret_1);
    REG("CreateBitmap", w_ret_1); REG("CreateCompatibleBitmap", w_ret_1);
    REG("CreateFontA", w_ret_1); REG("CreatePen", w_ret_1);
    REG("CreateRectRgn", w_ret_1); REG("CreateSolidBrush", w_ret_1);
    REG("SelectObject", w_ret_1); REG("AddFontMemResourceEx", w_ret_1);
    REG("RemoveFontMemResourceEx", w_ret_1); REG("RemoveFontResourceA", w_ret_1);
    REG("BitBlt", w_ret_1); REG("StretchBlt", w_ret_1); REG("GetDIBits", w_ret_0);
    REG("ExtTextOutA", w_ret_1); REG("ExtTextOutW", w_ret_1);
    REG("GetBkColor", w_ret_0); REG("SetBkColor", w_ret_0); REG("SetBkMode", w_ret_1);
    REG("GetTextColor", w_ret_0); REG("SetTextColor", w_ret_0); REG("SetTextAlign", w_ret_0);
    REG("SetMapMode", w_ret_1); REG("SetRectRgn", w_ret_1); REG("SetViewportOrgEx", w_ret_1);
    REG("MoveToEx", w_ret_1); REG("Polygon", w_ret_1); REG("Polyline", w_ret_1);
    REG("GetWindowLongPtrA", w_GetWindowLongPtr); REG("SetWindowLongPtrA", w_SetWindowLongPtr);
    REG("GetKeyboardLayout", w_GetKeyboardLayout); REG("GetKeyboardLayoutList", w_GetKeyboardLayoutList);
    REG("ActivateKeyboardLayout", w_GetKeyboardLayout); REG("LoadKeyboardLayoutA", w_GetKeyboardLayout);
    REG("UnloadKeyboardLayout", w_ret_1); REG("MapVirtualKeyExA", w_ret_0);
    REG("RegisterClassA", w_ret_1); REG("UnregisterClassA", w_ret_1);
    REG("RegisterWindowMessageA", w_RegisterWindowMessageA);
    REG("GetCursorPos", w_GetCursorPos); REG("SetCursorPos", w_ret_1);
    REG("GetFocus", w_GetForegroundWindow); REG("SetFocus", w_GetForegroundWindow);
    REG("GetForegroundWindow", w_GetForegroundWindow); REG("SetActiveWindow", w_GetForegroundWindow);
    REG("GetParent", w_ret_0); REG("WindowFromPoint", w_GetForegroundWindow);
    REG("IsWindowEnabled", w_ret_1); REG("ValidateRect", w_ret_1); REG("FlashWindow", w_ret_1);
    REG("SetWindowTextW", w_ret_1); REG("SetCapture", w_ret_0); REG("SetCursor", w_ret_1);
    REG("SetTimer", w_ret_1); REG("GetMessageA", w_ret_0); REG("GetGUIThreadInfo", w_ret_0);
    REG("SystemParametersInfoA", w_ret_0); REG("RegisterRawInputDevices", w_ret_1); REG("GetRawInputData", w_ret_0);
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
    REG("CoInitializeEx", w_ret_0); REG("OleInitialize", w_ret_0);
    REG("CoCreateInstance", w_CoCreateInstance); REG("CoTaskMemFree", w_CoTaskMemFree);
    REG("PropVariantClear", w_ret_0); REG("RegisterDragDrop", w_ret_0);
    REG("RevokeDragDrop", w_ret_0); REG("ReleaseStgMedium", w_ret_0);
    REG("oleaut32.dll!#9", w_ret_0);
    REG("DragQueryFileA", w_ret_0); REG("SHGetFileInfoA", w_ret_0);
    REG("SHGetSpecialFolderPathA", w_SHGetSpecialFolderPathA); REG("Shell_NotifyIconA", w_ret_1);
    /* Remaining 24-module game shims: wsock32 ordinals, IMM32, User32, Advapi32 W, Video64, SteamPipe, CompareStringEx */
    REG("CompareStringEx", w_CompareStringEx);
    REG("RegOpenKeyExW", w_ret_err2); REG("RegQueryInfoKeyW", w_ret_err2); REG("RegQueryValueExW", w_ret_err2);
    REG("GetAsyncKeyState", w_ret_0); REG("GetKeyboardState", w_GetKeyboardState);
    REG("GetWindowInfo", w_GetWindowInfo); REG("MapVirtualKeyW", w_ret_0);
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
    REG("xaudio2_9redist.dll!#1", w_CoCreateInstance);
    REG("iplContextCreate", w_ret_err2); REG("iplHRTFCreate", w_ret_err2);
    REG("iplBinauralEffectCreate", w_ret_err2); REG("iplBinauralEffectApply", w_ret_0);
    REG("iplBinauralEffectRelease", w_ret_0); REG("iplDirectEffectCreate", w_ret_err2);
    REG("iplDirectEffectApply", w_ret_0); REG("iplAudioBufferInterleave", w_ret_0);
    REG("DiscordCreate", w_ret_err2);
    #undef REG
}
