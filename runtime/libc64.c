#include "runtime64.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ---- System V AMD64 variadic printf engine ---- */
typedef struct {
    const CPU64 *c;
    int gp_idx;    /* next integer arg index (0..5 in regs, >=6 on stack) */
    int fp_idx;    /* next fp arg index (0..7 in xmm0..7) */
    int stack_off; /* next stack slot index for overflow args */
} SysVVarArgs;

static void sysv_va_init(SysVVarArgs *va, const CPU64 *c, int first_gp, int first_fp) {
    va->c = c;
    va->gp_idx = first_gp;
    va->fp_idx = first_fp;
    va->stack_off = (first_gp > 6) ? (first_gp - 6) : 0;
}

static uint64_t sysv_va_gp(SysVVarArgs *va) {
    if (va->gp_idx < 6) return sysv_arg_i(va->c, va->gp_idx++);
    uint64_t v = R64(va->c->rsp + 8ULL + (uint64_t)va->stack_off * 8ULL);
    va->stack_off++;
    return v;
}

static double sysv_va_fp(SysVVarArgs *va) {
    if (va->fp_idx < 8) return va->c->xmm[va->fp_idx++].df[0];
    uint64_t u = R64(va->c->rsp + 8ULL + (uint64_t)va->stack_off * 8ULL);
    va->stack_off++;
    double d;
    memcpy(&d, &u, 8);
    return d;
}

static int sysv_vsnprintf(char *out, size_t cap, const char *fmt, SysVVarArgs *va) {
    size_t pos = 0;
    const char *p = fmt;
    while (*p) {
        if (*p != '%') {
            if (pos + 1 < cap) out[pos] = *p;
            pos++;
            p++;
            continue;
        }
        const char *spec_start = p++;
        if (*p == '%') {
            if (pos + 1 < cap) out[pos] = '%';
            pos++;
            p++;
            continue;
        }
        /* Copy single format specifier into small buffer, resolving '*' width/prec. */
        char spec[64];
        size_t sl = 0;
        spec[sl++] = '%';
        while (*p && strchr("-+ #0", *p) && sl < 50) spec[sl++] = *p++;
        int has_w_star = 0, w_val = 0;
        if (*p == '*') { has_w_star = 1; w_val = (int)sysv_va_gp(va); spec[sl++] = '*'; p++; }
        else { while (*p >= '0' && *p <= '9' && sl < 50) spec[sl++] = *p++; }
        int has_p_star = 0, p_val = 0;
        if (*p == '.') {
            spec[sl++] = *p++;
            if (*p == '*') { has_p_star = 1; p_val = (int)sysv_va_gp(va); spec[sl++] = '*'; p++; }
            else { while (*p >= '0' && *p <= '9' && sl < 50) spec[sl++] = *p++; }
        }
        int is_long = 0;
        if (*p == 'l') { is_long = 1; spec[sl++] = *p++; if (*p == 'l') { is_long = 2; spec[sl++] = *p++; } }
        else if (*p == 'z' || *p == 't' || *p == 'j') { is_long = 1; spec[sl++] = *p++; }
        else if (*p == 'h') { spec[sl++] = *p++; if (*p == 'h') spec[sl++] = *p++; }
        char conv = *p ? *p++ : '\0';
        if (!conv) { (void)spec_start; break; }
        spec[sl++] = conv;
        spec[sl] = '\0';

        char tmp[1024];
        int n = 0;
        if (conv == 'f' || conv == 'F' || conv == 'e' || conv == 'E' || conv == 'g' || conv == 'G' || conv == 'a' || conv == 'A') {
            double d = sysv_va_fp(va);
            if (has_w_star && has_p_star) n = snprintf(tmp, sizeof(tmp), spec, w_val, p_val, d);
            else if (has_w_star) n = snprintf(tmp, sizeof(tmp), spec, w_val, d);
            else if (has_p_star) n = snprintf(tmp, sizeof(tmp), spec, p_val, d);
            else n = snprintf(tmp, sizeof(tmp), spec, d);
        } else if (conv == 's') {
            const char *s = (const char *)(uintptr_t)sysv_va_gp(va);
            if (!s) s = "(null)";
            if (has_w_star && has_p_star) n = snprintf(tmp, sizeof(tmp), spec, w_val, p_val, s);
            else if (has_w_star) n = snprintf(tmp, sizeof(tmp), spec, w_val, s);
            else if (has_p_star) n = snprintf(tmp, sizeof(tmp), spec, p_val, s);
            else n = snprintf(tmp, sizeof(tmp), spec, s);
        } else if (conv == 'p') {
            void *ptr = (void *)(uintptr_t)sysv_va_gp(va);
            n = snprintf(tmp, sizeof(tmp), spec, ptr);
        } else if (conv == 'n') {
            int *np = (int *)(uintptr_t)sysv_va_gp(va);
            if (np) *np = (int)pos;
            continue;
        } else {
            uint64_t v = sysv_va_gp(va);
            if (is_long) {
                if (has_w_star && has_p_star) n = snprintf(tmp, sizeof(tmp), spec, w_val, p_val, (long long)v);
                else if (has_w_star) n = snprintf(tmp, sizeof(tmp), spec, w_val, (long long)v);
                else if (has_p_star) n = snprintf(tmp, sizeof(tmp), spec, p_val, (long long)v);
                else n = snprintf(tmp, sizeof(tmp), spec, (long long)v);
            } else {
                if (has_w_star && has_p_star) n = snprintf(tmp, sizeof(tmp), spec, w_val, p_val, (int)v);
                else if (has_w_star) n = snprintf(tmp, sizeof(tmp), spec, w_val, (int)v);
                else if (has_p_star) n = snprintf(tmp, sizeof(tmp), spec, p_val, (int)v);
                else n = snprintf(tmp, sizeof(tmp), spec, (int)v);
            }
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

/* ---- Memory & Strings ---- */
static void sh_malloc(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)malloc((size_t)c->rdi); }
static void sh_calloc(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)calloc((size_t)c->rdi, (size_t)c->rsi); }
static void sh_realloc(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)realloc((void *)(uintptr_t)c->rdi, (size_t)c->rsi); }
static void sh_free(CPU64 *c, void *ud)    { (void)ud; free((void *)(uintptr_t)c->rdi); }
static void sh_posix_memalign(CPU64 *c, void *ud) {
    (void)ud;
    void *p = NULL;
    int r = posix_memalign(&p, (size_t)c->rsi, (size_t)c->rdx);
    if (r == 0 && c->rdi) W64(c->rdi, (uint64_t)(uintptr_t)p);
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_memcpy(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)memcpy((void *)(uintptr_t)c->rdi, (const void *)(uintptr_t)c->rsi, (size_t)c->rdx); }
static void sh_memmove(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)memmove((void *)(uintptr_t)c->rdi, (const void *)(uintptr_t)c->rsi, (size_t)c->rdx); }
static void sh_memset(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)memset((void *)(uintptr_t)c->rdi, (int)c->rsi, (size_t)c->rdx); }
static void sh_memcmp(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(int64_t)memcmp((const void *)(uintptr_t)c->rdi, (const void *)(uintptr_t)c->rsi, (size_t)c->rdx); }
static void sh_memchr(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)memchr((const void *)(uintptr_t)c->rdi, (int)c->rsi, (size_t)c->rdx); }

static void sh_strlen(CPU64 *c, void *ud)  { (void)ud; c->rax = strlen((const char *)(uintptr_t)c->rdi); }
static void sh_strnlen(CPU64 *c, void *ud) { (void)ud; c->rax = strnlen((const char *)(uintptr_t)c->rdi, (size_t)c->rsi); }
static void sh_strcmp(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(int64_t)strcmp((const char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi); }
static void sh_strncmp(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)strncmp((const char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi, (size_t)c->rdx); }
static void sh_strcasecmp(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(int64_t)strcasecmp((const char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi); }
static void sh_strncasecmp(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)strncasecmp((const char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi, (size_t)c->rdx); }
static void sh_strcpy(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)strcpy((char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi); }
static void sh_strncpy(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)strncpy((char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi, (size_t)c->rdx); }
static void sh_strcat(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)strcat((char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi); }
static void sh_strchr(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)strchr((const char *)(uintptr_t)c->rdi, (int)c->rsi); }
static void sh_strrchr(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)strrchr((const char *)(uintptr_t)c->rdi, (int)c->rsi); }
static void sh_strstr(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)strstr((const char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi); }
static void sh_strdup(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(uintptr_t)strdup((const char *)(uintptr_t)c->rdi); }
static void sh_strtol(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)strtol((const char *)(uintptr_t)c->rdi, (char **)(uintptr_t)c->rsi, (int)c->rdx); }
static void sh_strtoul(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)strtoul((const char *)(uintptr_t)c->rdi, (char **)(uintptr_t)c->rsi, (int)c->rdx); }
static void sh_strtod(CPU64 *c, void *ud)  { (void)ud; c->xmm[0].df[0] = strtod((const char *)(uintptr_t)c->rdi, (char **)(uintptr_t)c->rsi); }
static void sh_atoi(CPU64 *c, void *ud)    { (void)ud; c->rax = (uint64_t)(int64_t)atoi((const char *)(uintptr_t)c->rdi); }

/* ---- Stdio ---- */
static void sh_printf(CPU64 *c, void *ud) {
    (void)ud;
    char buf[4096];
    SysVVarArgs va;
    sysv_va_init(&va, c, 1, 0);
    int n = sysv_vsnprintf(buf, sizeof(buf), (const char *)(uintptr_t)c->rdi, &va);
    fwrite(buf, 1, (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1), stdout);
    c->rax = (uint64_t)(int64_t)n;
}
static void sh_fprintf(CPU64 *c, void *ud) {
    (void)ud;
    FILE *fp = (FILE *)(uintptr_t)c->rdi;
    char buf[4096];
    SysVVarArgs va;
    sysv_va_init(&va, c, 2, 0);
    int n = sysv_vsnprintf(buf, sizeof(buf), (const char *)(uintptr_t)c->rsi, &va);
    fwrite(buf, 1, (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1), fp ? fp : stderr);
    c->rax = (uint64_t)(int64_t)n;
}
static void sh_snprintf(CPU64 *c, void *ud) {
    (void)ud;
    SysVVarArgs va;
    sysv_va_init(&va, c, 3, 0);
    int n = sysv_vsnprintf((char *)(uintptr_t)c->rdi, (size_t)c->rsi, (const char *)(uintptr_t)c->rdx, &va);
    c->rax = (uint64_t)(int64_t)n;
}
static void sh_sprintf(CPU64 *c, void *ud) {
    (void)ud;
    SysVVarArgs va;
    sysv_va_init(&va, c, 2, 0);
    int n = sysv_vsnprintf((char *)(uintptr_t)c->rdi, 65536, (const char *)(uintptr_t)c->rsi, &va);
    c->rax = (uint64_t)(int64_t)n;
}
static void sh_puts(CPU64 *c, void *ud)    { (void)ud; c->rax = (uint64_t)(int64_t)puts((const char *)(uintptr_t)c->rdi); }
static void sh_putchar(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)putchar((int)c->rdi); }
static void sh_fputs(CPU64 *c, void *ud)   { (void)ud; c->rax = (uint64_t)(int64_t)fputs((const char *)(uintptr_t)c->rdi, (FILE *)(uintptr_t)c->rsi); }
static void sh_fwrite(CPU64 *c, void *ud)  { (void)ud; c->rax = fwrite((const void *)(uintptr_t)c->rdi, (size_t)c->rsi, (size_t)c->rdx, (FILE *)(uintptr_t)c->rcx); }
static void sh_fread(CPU64 *c, void *ud)   { (void)ud; c->rax = fread((void *)(uintptr_t)c->rdi, (size_t)c->rsi, (size_t)c->rdx, (FILE *)(uintptr_t)c->rcx); }
static void sh_fopen(CPU64 *c, void *ud)   { (void)ud; c->rax = (uint64_t)(uintptr_t)fopen((const char *)(uintptr_t)c->rdi, (const char *)(uintptr_t)c->rsi); }
static void sh_fclose(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(int64_t)fclose((FILE *)(uintptr_t)c->rdi); }
static void sh_fflush(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(int64_t)fflush((FILE *)(uintptr_t)c->rdi); }
static void sh_fseek(CPU64 *c, void *ud)   { (void)ud; c->rax = (uint64_t)(int64_t)fseek((FILE *)(uintptr_t)c->rdi, (long)c->rsi, (int)c->rdx); }
static void sh_ftell(CPU64 *c, void *ud)   { (void)ud; c->rax = (uint64_t)ftell((FILE *)(uintptr_t)c->rdi); }

/* ---- POSIX & Linux x86_64 struct stat (144 bytes) ---- */
static void write_linux_stat64(uint64_t dst, const struct stat *st) {
    uint8_t buf[144];
    memset(buf, 0, sizeof(buf));
    uint64_t v64; uint32_t v32; int64_t s64;
    v64 = (uint64_t)st->st_dev;             memcpy(buf + 0x00, &v64, 8);
    v64 = (uint64_t)st->st_ino;             memcpy(buf + 0x08, &v64, 8);
    v64 = (uint64_t)st->st_nlink;           memcpy(buf + 0x10, &v64, 8);
    v32 = (uint32_t)st->st_mode;            memcpy(buf + 0x18, &v32, 4);
    v32 = (uint32_t)st->st_uid;             memcpy(buf + 0x1c, &v32, 4);
    v32 = (uint32_t)st->st_gid;             memcpy(buf + 0x20, &v32, 4);
    v64 = (uint64_t)st->st_rdev;            memcpy(buf + 0x28, &v64, 8);
    s64 = (int64_t)st->st_size;             memcpy(buf + 0x30, &s64, 8);
    s64 = (int64_t)st->st_blksize;          memcpy(buf + 0x38, &s64, 8);
    s64 = (int64_t)st->st_blocks;           memcpy(buf + 0x40, &s64, 8);
    s64 = (int64_t)st->st_atimespec.tv_sec; memcpy(buf + 0x48, &s64, 8);
    s64 = (int64_t)st->st_atimespec.tv_nsec;memcpy(buf + 0x50, &s64, 8);
    s64 = (int64_t)st->st_mtimespec.tv_sec; memcpy(buf + 0x58, &s64, 8);
    s64 = (int64_t)st->st_mtimespec.tv_nsec;memcpy(buf + 0x60, &s64, 8);
    s64 = (int64_t)st->st_ctimespec.tv_sec; memcpy(buf + 0x68, &s64, 8);
    s64 = (int64_t)st->st_ctimespec.tv_nsec;memcpy(buf + 0x70, &s64, 8);
    memcpy((void *)(uintptr_t)dst, buf, sizeof(buf));
}

static void sh_stat(CPU64 *c, void *ud) {
    (void)ud;
    struct stat st;
    int r = stat((const char *)(uintptr_t)c->rdi, &st);
    if (r == 0 && c->rsi) write_linux_stat64(c->rsi, &st);
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_lstat(CPU64 *c, void *ud) {
    (void)ud;
    struct stat st;
    int r = lstat((const char *)(uintptr_t)c->rdi, &st);
    if (r == 0 && c->rsi) write_linux_stat64(c->rsi, &st);
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_fstat(CPU64 *c, void *ud) {
    (void)ud;
    struct stat st;
    int r = fstat((int)c->rdi, &st);
    if (r == 0 && c->rsi) write_linux_stat64(c->rsi, &st);
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_xstat(CPU64 *c, void *ud) {
    (void)ud;
    struct stat st;
    int r = stat((const char *)(uintptr_t)c->rsi, &st);
    if (r == 0 && c->rdx) write_linux_stat64(c->rdx, &st);
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_fxstat(CPU64 *c, void *ud) {
    (void)ud;
    struct stat st;
    int r = fstat((int)c->rsi, &st);
    if (r == 0 && c->rdx) write_linux_stat64(c->rdx, &st);
    c->rax = (uint64_t)(int64_t)r;
}

static void sh_open(CPU64 *c, void *ud) {
    (void)ud;
    int lf = (int)c->rsi;
    int mf = lf & 3;
    if (lf & 0x40)   mf |= O_CREAT;
    if (lf & 0x80)   mf |= O_EXCL;
    if (lf & 0x200)  mf |= O_TRUNC;
    if (lf & 0x400)  mf |= O_APPEND;
    if (lf & 0x800)  mf |= O_NONBLOCK;
    if (lf & 0x80000) mf |= O_CLOEXEC;
    c->rax = (uint64_t)(int64_t)open((const char *)(uintptr_t)c->rdi, mf, (mode_t)c->rdx);
}
static void sh_close(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)(int64_t)close((int)c->rdi); }
static void sh_read(CPU64 *c, void *ud)   { (void)ud; c->rax = (uint64_t)read((int)c->rdi, (void *)(uintptr_t)c->rsi, (size_t)c->rdx); }
static void sh_write(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)write((int)c->rdi, (const void *)(uintptr_t)c->rsi, (size_t)c->rdx); }
static void sh_lseek(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)lseek((int)c->rdi, (off_t)c->rsi, (int)c->rdx); }
static void sh_access(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)access((const char *)(uintptr_t)c->rdi, (int)c->rsi); }
static void sh_unlink(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)unlink((const char *)(uintptr_t)c->rdi); }
static void sh_getcwd(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)getcwd((char *)(uintptr_t)c->rdi, (size_t)c->rsi); }
static void sh_getenv(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)getenv((const char *)(uintptr_t)c->rdi); }
static void sh_isatty(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)isatty((int)c->rdi); }

static void sh_mmap(CPU64 *c, void *ud) {
    (void)ud;
    int lf = (int)c->rcx;
    int mf = 0;
    if (lf & 0x01) mf |= MAP_SHARED;
    if (lf & 0x02) mf |= MAP_PRIVATE;
    if (lf & 0x10) mf |= MAP_FIXED;
    if (lf & 0x20) mf |= MAP_ANON;
    void *p = mmap((void *)(uintptr_t)c->rdi, (size_t)c->rsi, (int)c->rdx, mf, (int)c->r8, (off_t)c->r9);
    c->rax = (uint64_t)(uintptr_t)p;
}
static void sh_munmap(CPU64 *c, void *ud)   { (void)ud; c->rax = (uint64_t)(int64_t)munmap((void *)(uintptr_t)c->rdi, (size_t)c->rsi); }
static void sh_mprotect(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)mprotect((void *)(uintptr_t)c->rdi, (size_t)c->rsi, (int)c->rdx); }

/* ---- Time ---- */
static void sh_clock_gettime(CPU64 *c, void *ud) {
    (void)ud;
    clockid_t cid = CLOCK_REALTIME;
    if (c->rdi == 1 || c->rdi == 6) cid = CLOCK_MONOTONIC;
    else if (c->rdi == 4) cid = CLOCK_MONOTONIC_RAW;
    struct timespec ts;
    int r = clock_gettime(cid, &ts);
    if (r == 0 && c->rsi) {
        W64(c->rsi + 0, (uint64_t)ts.tv_sec);
        W64(c->rsi + 8, (uint64_t)ts.tv_nsec);
    }
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_gettimeofday(CPU64 *c, void *ud) {
    (void)ud;
    struct timeval tv;
    int r = gettimeofday(&tv, NULL);
    if (r == 0 && c->rdi) {
        W64(c->rdi + 0, (uint64_t)tv.tv_sec);
        W64(c->rdi + 8, (uint64_t)tv.tv_usec);
    }
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_usleep(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(int64_t)usleep((useconds_t)c->rdi); }
static void sh_nanosleep(CPU64 *c, void *ud) {
    (void)ud;
    struct timespec req, rem;
    req.tv_sec = (time_t)R64(c->rdi);
    req.tv_nsec = (long)R64(c->rdi + 8);
    int r = nanosleep(&req, &rem);
    if (r != 0 && c->rsi) {
        W64(c->rsi, (uint64_t)rem.tv_sec);
        W64(c->rsi + 8, (uint64_t)rem.tv_nsec);
    }
    c->rax = (uint64_t)(int64_t)r;
}

/* ---- qsort with host->guest comparator callback ---- */
static _Thread_local uint64_t g_qsort_guest_cmp = 0;

static int host_qsort_trampoline(const void *a, const void *b) {
    uint64_t r = rt_invoke64(g_tls_cpu, g_qsort_guest_cmp,
                             (uint64_t)(uintptr_t)a, (uint64_t)(uintptr_t)b,
                             0, 0, 0, 0);
    return (int)(int32_t)r;
}

static void sh_qsort(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t prev = g_qsort_guest_cmp;
    g_qsort_guest_cmp = c->rcx;
    qsort((void *)(uintptr_t)c->rdi, (size_t)c->rsi, (size_t)c->rdx, host_qsort_trampoline);
    g_qsort_guest_cmp = prev;
}

/* ---- Pthreads (side-table for Linux 40B mutex / 48B cond vs macOS 64B/48B) ---- */
typedef struct {
    uint64_t         guest_addr;
    pthread_mutex_t *mu;
} MutexPtrEntry;

typedef struct {
    uint64_t        guest_addr;
    pthread_cond_t *cv;
} CondPtrEntry;

static pthread_mutex_t g_sync_map_mu = PTHREAD_MUTEX_INITIALIZER;
static MutexPtrEntry  *g_mup = NULL;
static size_t          g_mup_n = 0, g_mup_cap = 0;
static CondPtrEntry   *g_cvp = NULL;
static size_t          g_cvp_n = 0, g_cvp_cap = 0;

/* shortcut: linear scan over mutex/cond map; switch to open-addressing hash map once a real game exceeds ~256 live locks. */
static pthread_mutex_t *lookup_mutex(uint64_t addr, int create) {
    pthread_mutex_lock(&g_sync_map_mu);
    for (size_t i = 0; i < g_mup_n; i++) {
        if (g_mup[i].guest_addr == addr) {
            pthread_mutex_t *m = g_mup[i].mu;
            pthread_mutex_unlock(&g_sync_map_mu);
            return m;
        }
    }
    if (!create) { pthread_mutex_unlock(&g_sync_map_mu); return NULL; }
    if (g_mup_n == g_mup_cap) {
        g_mup_cap = g_mup_cap ? g_mup_cap * 2 : 64;
        g_mup = (MutexPtrEntry *)realloc(g_mup, g_mup_cap * sizeof(MutexPtrEntry));
    }
    pthread_mutex_t *m = (pthread_mutex_t *)calloc(1, sizeof(pthread_mutex_t));
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(m, &attr);
    pthread_mutexattr_destroy(&attr);
    g_mup[g_mup_n].guest_addr = addr;
    g_mup[g_mup_n].mu = m;
    g_mup_n++;
    pthread_mutex_unlock(&g_sync_map_mu);
    return m;
}

static pthread_cond_t *lookup_cond(uint64_t addr, int create) {
    pthread_mutex_lock(&g_sync_map_mu);
    for (size_t i = 0; i < g_cvp_n; i++) {
        if (g_cvp[i].guest_addr == addr) {
            pthread_cond_t *cv = g_cvp[i].cv;
            pthread_mutex_unlock(&g_sync_map_mu);
            return cv;
        }
    }
    if (!create) { pthread_mutex_unlock(&g_sync_map_mu); return NULL; }
    if (g_cvp_n == g_cvp_cap) {
        g_cvp_cap = g_cvp_cap ? g_cvp_cap * 2 : 64;
        g_cvp = (CondPtrEntry *)realloc(g_cvp, g_cvp_cap * sizeof(CondPtrEntry));
    }
    pthread_cond_t *cv = (pthread_cond_t *)calloc(1, sizeof(pthread_cond_t));
    pthread_cond_init(cv, NULL);
    g_cvp[g_cvp_n].guest_addr = addr;
    g_cvp[g_cvp_n].cv = cv;
    g_cvp_n++;
    pthread_mutex_unlock(&g_sync_map_mu);
    return cv;
}

typedef struct {
    uint64_t start_fn;
    uint64_t arg;
} GuestThreadStart;

static void *guest_thread_trampoline(void *p) {
    GuestThreadStart st = *(GuestThreadStart *)p;
    free(p);
    CPU64 cpu;
    rt_init_thread_cpu(&cpu, 4 * 1024 * 1024);
    uint64_t res = rt_invoke64(&cpu, st.start_fn, st.arg, 0, 0, 0, 0, 0);
    rt_destroy_thread_cpu(&cpu);
    return (void *)(uintptr_t)res;
}

static void sh_pthread_create(CPU64 *c, void *ud) {
    (void)ud;
    GuestThreadStart *st = (GuestThreadStart *)malloc(sizeof(GuestThreadStart));
    st->start_fn = c->rdx;
    st->arg = c->rcx;
    pthread_t tid = 0;
    int r = pthread_create(&tid, NULL, guest_thread_trampoline, st);
    if (r == 0 && c->rdi) W64(c->rdi, (uint64_t)(uintptr_t)tid);
    if (r != 0) free(st);
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_pthread_join(CPU64 *c, void *ud) {
    (void)ud;
    void *ret = NULL;
    int r = pthread_join((pthread_t)(uintptr_t)c->rdi, &ret);
    if (r == 0 && c->rsi) W64(c->rsi, (uint64_t)(uintptr_t)ret);
    c->rax = (uint64_t)(int64_t)r;
}
static void sh_pthread_self(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)pthread_self(); }
static void sh_pthread_mutex_init(CPU64 *c, void *ud)   { (void)ud; lookup_mutex(c->rdi, 1); c->rax = 0; }
static void sh_pthread_mutex_destroy(CPU64 *c, void *ud){ (void)ud; c->rax = 0; }
static void sh_pthread_mutex_lock(CPU64 *c, void *ud)   { (void)ud; c->rax = (uint64_t)pthread_mutex_lock(lookup_mutex(c->rdi, 1)); }
static void sh_pthread_mutex_trylock(CPU64 *c, void *ud){ (void)ud; c->rax = (uint64_t)pthread_mutex_trylock(lookup_mutex(c->rdi, 1)); }
static void sh_pthread_mutex_unlock(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)pthread_mutex_unlock(lookup_mutex(c->rdi, 1)); }
static void sh_pthread_cond_init(CPU64 *c, void *ud)    { (void)ud; lookup_cond(c->rdi, 1); c->rax = 0; }
static void sh_pthread_cond_destroy(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void sh_pthread_cond_wait(CPU64 *c, void *ud)    { (void)ud; c->rax = (uint64_t)pthread_cond_wait(lookup_cond(c->rdi, 1), lookup_mutex(c->rsi, 1)); }
static void sh_pthread_cond_signal(CPU64 *c, void *ud)  { (void)ud; c->rax = (uint64_t)pthread_cond_signal(lookup_cond(c->rdi, 1)); }
static void sh_pthread_cond_broadcast(CPU64 *c, void *ud){ (void)ud; c->rax = (uint64_t)pthread_cond_broadcast(lookup_cond(c->rdi, 1)); }

/* ---- dlopen / dlsym / errno / lifecycle ---- */
static void sh_dlopen(CPU64 *c, void *ud) {
    (void)ud;
    const char *path = (const char *)(uintptr_t)c->rdi;
    /* Return sentinel handle 1 for libvulkan/libSDL2/NULL so dlsym resolves through our shim registry. */
    if (!path || strstr(path, "vulkan") || strstr(path, "SDL2") || strstr(path, "libc")) {
        c->rax = 1ULL;
        return;
    }
    void *h = dlopen(path, RTLD_LAZY);
    c->rax = (uint64_t)(uintptr_t)h;
}
static void sh_dlsym(CPU64 *c, void *ud) {
    (void)ud;
    const char *name = (const char *)(uintptr_t)c->rsi;
    if (!name) { c->rax = 0; return; }
    /* 1. Guest exports */
    uint64_t exp = rt_lookup_export(name);
    if (exp) { c->rax = exp; return; }
    /* 2. Registered host shims */
    void *sud = NULL;
    RTShimFn fn = rt_find_shim(name, &sud);
    if (fn) {
        c->rax = rt_alloc_dynamic_thunk(name, fn, sud);
        return;
    }
    c->rax = 0;
}
static void sh_dlclose(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void sh_dlerror(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }

static void sh_errno_location(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)&errno; }
static void sh_stack_chk_fail(CPU64 *c, void *ud) {
    (void)ud;
    fprintf(stderr, "elf64-recomp: *** stack smashing detected *** (rip=0x%llx)\n", (unsigned long long)c->rip);
    abort();
}
static void sh_cxa_atexit(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }
static void sh_exit(CPU64 *c, void *ud)  { (void)ud; c->exit_code = (int)c->rdi; c->halted = 1; }
static void sh_abort(CPU64 *c, void *ud) { (void)ud; (void)c; abort(); }

/* ---- Math ---- */
static void sh_sin(CPU64 *c, void *ud)   { (void)ud; c->xmm[0].df[0] = sin(c->xmm[0].df[0]); }
static void sh_cos(CPU64 *c, void *ud)   { (void)ud; c->xmm[0].df[0] = cos(c->xmm[0].df[0]); }
static void sh_tan(CPU64 *c, void *ud)   { (void)ud; c->xmm[0].df[0] = tan(c->xmm[0].df[0]); }
static void sh_sqrt(CPU64 *c, void *ud)  { (void)ud; c->xmm[0].df[0] = sqrt(c->xmm[0].df[0]); }
static void sh_pow(CPU64 *c, void *ud)   { (void)ud; c->xmm[0].df[0] = pow(c->xmm[0].df[0], c->xmm[1].df[0]); }
static void sh_exp(CPU64 *c, void *ud)   { (void)ud; c->xmm[0].df[0] = exp(c->xmm[0].df[0]); }
static void sh_log(CPU64 *c, void *ud)   { (void)ud; c->xmm[0].df[0] = log(c->xmm[0].df[0]); }
static void sh_floor(CPU64 *c, void *ud) { (void)ud; c->xmm[0].df[0] = floor(c->xmm[0].df[0]); }
static void sh_ceil(CPU64 *c, void *ud)  { (void)ud; c->xmm[0].df[0] = ceil(c->xmm[0].df[0]); }
static void sh_atan2(CPU64 *c, void *ud) { (void)ud; c->xmm[0].df[0] = atan2(c->xmm[0].df[0], c->xmm[1].df[0]); }
static void sh_sinf(CPU64 *c, void *ud)  { (void)ud; c->xmm[0].f[0] = sinf(c->xmm[0].f[0]); }
static void sh_cosf(CPU64 *c, void *ud)  { (void)ud; c->xmm[0].f[0] = cosf(c->xmm[0].f[0]); }
static void sh_sqrtf(CPU64 *c, void *ud) { (void)ud; c->xmm[0].f[0] = sqrtf(c->xmm[0].f[0]); }
static void sh_powf(CPU64 *c, void *ud)  { (void)ud; c->xmm[0].f[0] = powf(c->xmm[0].f[0], c->xmm[1].f[0]); }

/* ---- libgcc 128-bit helpers (SysV AMD64: a=rdi:rsi, b=rdx:rcx, ret=rax:rdx) ---- */
static void sh_divti3(CPU64 *c, void *ud) {
    (void)ud;
    __int128 a = ((__int128)(int64_t)c->rsi << 64) | (__uint128_t)c->rdi;
    __int128 b = ((__int128)(int64_t)c->rcx << 64) | (__uint128_t)c->rdx;
    __int128 q = a / b;
    c->rax = (uint64_t)q;
    c->rdx = (uint64_t)(q >> 64);
}
static void sh_udivti3(CPU64 *c, void *ud) {
    (void)ud;
    __uint128_t a = ((__uint128_t)c->rsi << 64) | c->rdi;
    __uint128_t b = ((__uint128_t)c->rcx << 64) | c->rdx;
    __uint128_t q = a / b;
    c->rax = (uint64_t)q;
    c->rdx = (uint64_t)(q >> 64);
}
static void sh_modti3(CPU64 *c, void *ud) {
    (void)ud;
    __int128 a = ((__int128)(int64_t)c->rsi << 64) | (__uint128_t)c->rdi;
    __int128 b = ((__int128)(int64_t)c->rcx << 64) | (__uint128_t)c->rdx;
    __int128 r = a % b;
    c->rax = (uint64_t)r;
    c->rdx = (uint64_t)(r >> 64);
}
static void sh_umodti3(CPU64 *c, void *ud) {
    (void)ud;
    __uint128_t a = ((__uint128_t)c->rsi << 64) | c->rdi;
    __uint128_t b = ((__uint128_t)c->rcx << 64) | c->rdx;
    __uint128_t r = a % b;
    c->rax = (uint64_t)r;
    c->rdx = (uint64_t)(r >> 64);
}

void rt_register_libc64(void) {
    #define REG(name, fn) rt_register_shim(name, fn, NULL)
    REG("malloc", sh_malloc); REG("calloc", sh_calloc); REG("realloc", sh_realloc); REG("free", sh_free);
    REG("posix_memalign", sh_posix_memalign);
    REG("memcpy", sh_memcpy); REG("memmove", sh_memmove); REG("memset", sh_memset);
    REG("memcmp", sh_memcmp); REG("memchr", sh_memchr);
    REG("strlen", sh_strlen); REG("strnlen", sh_strnlen); REG("strcmp", sh_strcmp); REG("strncmp", sh_strncmp);
    REG("strcasecmp", sh_strcasecmp); REG("strncasecmp", sh_strncasecmp);
    REG("strcpy", sh_strcpy); REG("strncpy", sh_strncpy); REG("strcat", sh_strcat);
    REG("strchr", sh_strchr); REG("strrchr", sh_strrchr); REG("strstr", sh_strstr); REG("strdup", sh_strdup);
    REG("strtol", sh_strtol); REG("strtoul", sh_strtoul); REG("strtod", sh_strtod); REG("atoi", sh_atoi);

    REG("printf", sh_printf); REG("fprintf", sh_fprintf); REG("snprintf", sh_snprintf); REG("sprintf", sh_sprintf);
    REG("puts", sh_puts); REG("putchar", sh_putchar); REG("fputs", sh_fputs);
    REG("fwrite", sh_fwrite); REG("fread", sh_fread); REG("fopen", sh_fopen); REG("fclose", sh_fclose);
    REG("fflush", sh_fflush); REG("fseek", sh_fseek); REG("ftell", sh_ftell);

    REG("stat", sh_stat); REG("lstat", sh_lstat); REG("fstat", sh_fstat);
    REG("__xstat", sh_xstat); REG("__fxstat", sh_fxstat);
    REG("open", sh_open); REG("open64", sh_open); REG("close", sh_close);
    REG("read", sh_read); REG("write", sh_write); REG("lseek", sh_lseek); REG("lseek64", sh_lseek);
    REG("access", sh_access); REG("unlink", sh_unlink); REG("getcwd", sh_getcwd);
    REG("getenv", sh_getenv); REG("isatty", sh_isatty);
    REG("mmap", sh_mmap); REG("mmap64", sh_mmap); REG("munmap", sh_munmap); REG("mprotect", sh_mprotect);

    REG("clock_gettime", sh_clock_gettime); REG("gettimeofday", sh_gettimeofday);
    REG("usleep", sh_usleep); REG("nanosleep", sh_nanosleep);
    REG("qsort", sh_qsort);

    REG("pthread_create", sh_pthread_create); REG("pthread_join", sh_pthread_join); REG("pthread_self", sh_pthread_self);
    REG("pthread_mutex_init", sh_pthread_mutex_init); REG("pthread_mutex_destroy", sh_pthread_mutex_destroy);
    REG("pthread_mutex_lock", sh_pthread_mutex_lock); REG("pthread_mutex_trylock", sh_pthread_mutex_trylock);
    REG("pthread_mutex_unlock", sh_pthread_mutex_unlock);
    REG("pthread_cond_init", sh_pthread_cond_init); REG("pthread_cond_destroy", sh_pthread_cond_destroy);
    REG("pthread_cond_wait", sh_pthread_cond_wait); REG("pthread_cond_signal", sh_pthread_cond_signal);
    REG("pthread_cond_broadcast", sh_pthread_cond_broadcast);

    REG("dlopen", sh_dlopen); REG("dlsym", sh_dlsym); REG("dlclose", sh_dlclose); REG("dlerror", sh_dlerror);
    REG("__errno_location", sh_errno_location); REG("__stack_chk_fail", sh_stack_chk_fail);
    REG("__cxa_atexit", sh_cxa_atexit); REG("atexit", sh_cxa_atexit);
    REG("exit", sh_exit); REG("_exit", sh_exit); REG("abort", sh_abort);

    REG("sin", sh_sin); REG("cos", sh_cos); REG("tan", sh_tan); REG("sqrt", sh_sqrt);
    REG("pow", sh_pow); REG("exp", sh_exp); REG("log", sh_log); REG("floor", sh_floor);
    REG("ceil", sh_ceil); REG("atan2", sh_atan2);
    REG("sinf", sh_sinf); REG("cosf", sh_cosf); REG("sqrtf", sh_sqrtf); REG("powf", sh_powf);
    REG("__divti3", sh_divti3); REG("__udivti3", sh_udivti3);
    REG("__modti3", sh_modti3); REG("__umodti3", sh_umodti3);
    #undef REG
}
