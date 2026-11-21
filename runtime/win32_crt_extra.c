#include "runtime64.h"
#include "win64_abi.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
static void w_TerminateProcess(CPU64 *c, void *ud)            { (void)ud; c->exit_code = (int)c->rdx; c->halted = 1; c->rax = 1; }
static void w_ExitThread(CPU64 *c, void *ud)                  { (void)ud; c->halted = 1; }

/* ---- Filesystem (CreateFileA/W, ReadFile, GetFileAttributesA/W, Dir, Paths) ---- */
static void w_GetCurrentDirectoryA(CPU64 *c, void *ud) {
    (void)ud;
    char cwd[1024];
    if (!getcwd(cwd, sizeof(cwd))) { c->rax = 0; return; }
    size_t n = strlen(cwd);
    if (c->rdx && c->rcx > n) { memcpy((void *)(uintptr_t)c->rdx, cwd, n + 1); c->rax = n; }
    else c->rax = n + 1;
}
static void w_GetCurrentDirectoryW(CPU64 *c, void *ud) {
    (void)ud;
    char cwd[1024];
    if (!getcwd(cwd, sizeof(cwd))) { c->rax = 0; return; }
    size_t n = strlen(cwd);
    if (c->rdx && c->rcx > n) c->rax = u8_to_w16(cwd, (uint16_t *)(uintptr_t)c->rdx, (size_t)c->rcx);
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
    char u8[1024], px[1024], resolved[1024];
    w16_to_u8((const uint16_t *)(uintptr_t)c->rcx, u8, sizeof(u8));
    win_path_to_posix(u8, px, sizeof(px));
    const char *res = realpath(px, resolved) ? resolved : px;
    size_t n = strlen(res);
    if (c->r8 && c->rdx > n) {
        u8_to_w16(res, (uint16_t *)(uintptr_t)c->r8, (size_t)c->rdx);
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
    ssize_t n = read(fd, (void *)(uintptr_t)c->rdx, (size_t)(uint32_t)c->r8);
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
    static const char *p = "/Users/omarjoudi/Library/Application Support/Steam";
    c->rax = (uint64_t)(uintptr_t)p;
}
static void w_CreateMutexA(CPU64 *c, void *ud)     { (void)ud; c->rax = 0x30001ULL; }
static void w_CreateSemaphoreA(CPU64 *c, void *ud) { (void)ud; c->rax = 0x30002ULL; }
static void w_ret_0(CPU64 *c, void *ud)  { (void)ud; c->rax = 0; }
static void w_ret_1(CPU64 *c, void *ud)  { (void)ud; c->rax = 1; }
static void w_ret_err2(CPU64 *c, void *ud){ (void)ud; c->rax = 2; /* ERROR_FILE_NOT_FOUND */ }
static void w_ret_inv(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)-1LL; }

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
    REG("WaitForSingleObjectEx", w_ret_0); REG("WaitForMultipleObjects", w_ret_0);
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
    REG("FreeConsole", w_ret_1); REG("FindFirstFileW", w_ret_inv); REG("FindFirstFileExW", w_ret_inv);
    REG("FindNextFileW", w_ret_0); REG("FindClose", w_ret_1);
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
    #undef REG
}
