#ifndef ELF64_RECOMP_CPU64_H
#define ELF64_RECOMP_CPU64_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <math.h>

typedef union {
    uint8_t  b[16];
    int8_t   sb[16];
    uint16_t w[8];
    int16_t  sw[8];
    uint32_t d[4];
    int32_t  sd[4];
    uint64_t q[2];
    int64_t  sq[2];
    float    f[4];
    double   df[2];
} Xmm128;

typedef struct CPU64 {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8,  r9,  r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip;
    uint64_t fs_base;
    uint64_t gs_base;
    Xmm128   xmm[16];
    uint32_t mxcsr;
    uint8_t  cf, zf, sf, of, pf, af, df;
    int      halted;
    int      exit_code;
} CPU64;

/* Unified 64-bit direct memory access (unaligned-safe; compiles to single LDR/STR). */
static inline uint8_t  R8(uint64_t a)  { uint8_t  v; memcpy(&v, (const void *)(uintptr_t)a, 1); return v; }
static inline uint16_t R16(uint64_t a) { uint16_t v; memcpy(&v, (const void *)(uintptr_t)a, 2); return v; }
static inline uint32_t R32(uint64_t a) { uint32_t v; memcpy(&v, (const void *)(uintptr_t)a, 4); return v; }
static inline uint64_t R64(uint64_t a) { uint64_t v; memcpy(&v, (const void *)(uintptr_t)a, 8); return v; }
static inline Xmm128   R128(uint64_t a){ Xmm128   v; memcpy(&v, (const void *)(uintptr_t)a, 16); return v; }

static inline void W8(uint64_t a, uint8_t v)   { memcpy((void *)(uintptr_t)a, &v, 1); }
static inline void W16(uint64_t a, uint16_t v) { memcpy((void *)(uintptr_t)a, &v, 2); }
static inline void W32(uint64_t a, uint32_t v) { memcpy((void *)(uintptr_t)a, &v, 4); }
static inline void W64(uint64_t a, uint64_t v) { memcpy((void *)(uintptr_t)a, &v, 8); }
static inline void W128(uint64_t a, Xmm128 v)  { memcpy((void *)(uintptr_t)a, &v, 16); }

/* Sub-register writes: 32-bit zero-extends to 64-bit; 8/16-bit preserve upper bits. */
#define SET8L(r, v) ((r) = ((r) & ~0xFFULL) | (uint64_t)(uint8_t)(v))
#define SET8H(r, v) ((r) = ((r) & ~0xFF00ULL) | ((uint64_t)(uint8_t)(v) << 8))
#define SET16(r, v) ((r) = ((r) & ~0xFFFFULL) | (uint64_t)(uint16_t)(v))
#define SET32(r, v) ((r) = (uint64_t)(uint32_t)(v))
#define SET64(r, v) ((r) = (uint64_t)(v))

#define GET8L(r) ((uint8_t)((r) & 0xFFULL))
#define GET8H(r) ((uint8_t)(((r) >> 8) & 0xFFULL))
#define GET16(r) ((uint16_t)((r) & 0xFFFFULL))
#define GET32(r) ((uint32_t)((r) & 0xFFFFFFFFULL))
#define GET64(r) ((uint64_t)(r))

/* Stack helpers */
static inline void push64(CPU64 *c, uint64_t v) { c->rsp -= 8; W64(c->rsp, v); }
static inline uint64_t pop64(CPU64 *c) { uint64_t v = R64(c->rsp); c->rsp += 8; return v; }

/* System V AMD64 argument extraction (valid at shim entry, [rsp] = return addr). */
static inline uint64_t sysv_arg_i(const CPU64 *c, int idx) {
    switch (idx) {
        case 0: return c->rdi;
        case 1: return c->rsi;
        case 2: return c->rdx;
        case 3: return c->rcx;
        case 4: return c->r8;
        case 5: return c->r9;
        default: return R64(c->rsp + 8ULL + (uint64_t)(idx - 6) * 8ULL);
    }
}

static inline double sysv_arg_d(const CPU64 *c, int idx) {
    if (idx < 8) return c->xmm[idx].df[0];
    return 0.0;
}

static inline float sysv_arg_f(const CPU64 *c, int idx) {
    if (idx < 8) return c->xmm[idx].f[0];
    return 0.0f;
}

/* Parity of low 8 bits (1 if even number of 1 bits). */
static inline uint8_t calc_pf(uint64_t v) {
    uint8_t x = (uint8_t)v;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return (uint8_t)((~x) & 1);
}

/* Generic width-parameterized flag updates */
static inline uint64_t f_add(CPU64 *c, uint64_t a, uint64_t b, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    a &= mask; b &= mask;
    uint64_t r = (a + b) & mask;
    c->cf = (r < a);
    c->of = (((~(a ^ b)) & (a ^ r) & sign) != 0);
    c->zf = (r == 0);
    c->sf = ((r & sign) != 0);
    c->pf = calc_pf(r);
    c->af = (((a ^ b ^ r) & 0x10) != 0);
    return r;
}

static inline uint64_t f_adc(CPU64 *c, uint64_t a, uint64_t b, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t cin = c->cf ? 1ULL : 0ULL;
    a &= mask; b &= mask;
    __uint128_t sum = (__uint128_t)a + (__uint128_t)b + (__uint128_t)cin;
    uint64_t r = (uint64_t)sum & mask;
    c->cf = (bits == 64) ? (sum > ~0ULL) : ((sum >> bits) != 0);
    c->of = (((~(a ^ b)) & (a ^ r) & sign) != 0);
    c->zf = (r == 0);
    c->sf = ((r & sign) != 0);
    c->pf = calc_pf(r);
    c->af = (((a ^ b ^ r) & 0x10) != 0);
    return r;
}

static inline uint64_t f_sub(CPU64 *c, uint64_t a, uint64_t b, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    a &= mask; b &= mask;
    uint64_t r = (a - b) & mask;
    c->cf = (a < b);
    c->of = ((((a ^ b) & (a ^ r)) & sign) != 0);
    c->zf = (r == 0);
    c->sf = ((r & sign) != 0);
    c->pf = calc_pf(r);
    c->af = (((a ^ b ^ r) & 0x10) != 0);
    return r;
}

static inline uint64_t f_sbb(CPU64 *c, uint64_t a, uint64_t b, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t cin = c->cf ? 1ULL : 0ULL;
    a &= mask; b &= mask;
    __uint128_t sub = (__uint128_t)b + (__uint128_t)cin;
    uint64_t r = (uint64_t)((__uint128_t)a - sub) & mask;
    c->cf = ((__uint128_t)a < sub);
    c->of = ((((a ^ b) & (a ^ r)) & sign) != 0);
    c->zf = (r == 0);
    c->sf = ((r & sign) != 0);
    c->pf = calc_pf(r);
    c->af = (((a ^ b ^ r) & 0x10) != 0);
    return r;
}

static inline uint64_t f_inc(CPU64 *c, uint64_t a, int bits) {
    uint8_t old_cf = c->cf;
    uint64_t r = f_add(c, a, 1, bits);
    c->cf = old_cf;
    return r;
}

static inline uint64_t f_dec(CPU64 *c, uint64_t a, int bits) {
    uint8_t old_cf = c->cf;
    uint64_t r = f_sub(c, a, 1, bits);
    c->cf = old_cf;
    return r;
}

static inline uint64_t f_logic(CPU64 *c, uint64_t r, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    r &= mask;
    c->cf = 0;
    c->of = 0;
    c->zf = (r == 0);
    c->sf = ((r & sign) != 0);
    c->pf = calc_pf(r);
    return r;
}

static inline uint64_t f_shl(CPU64 *c, uint64_t a, uint64_t cnt, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    a &= mask;
    cnt &= (bits == 64) ? 63U : 31U;
    if (cnt == 0) return a;
    uint64_t r = (cnt >= (uint64_t)bits) ? 0ULL : ((a << cnt) & mask);
    c->cf = (cnt <= (uint64_t)bits) ? (uint8_t)((a >> (bits - cnt)) & 1ULL) : 0;
    if (cnt == 1) c->of = (uint8_t)(((r & sign) != 0) ^ c->cf);
    c->zf = (r == 0);
    c->sf = ((r & sign) != 0);
    c->pf = calc_pf(r);
    return r;
}

static inline uint64_t f_shr(CPU64 *c, uint64_t a, uint64_t cnt, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    a &= mask;
    cnt &= (bits == 64) ? 63U : 31U;
    if (cnt == 0) return a;
    uint64_t r = (cnt >= (uint64_t)bits) ? 0ULL : (a >> cnt);
    c->cf = (cnt <= (uint64_t)bits) ? (uint8_t)((a >> (cnt - 1)) & 1ULL) : 0;
    if (cnt == 1) c->of = (uint8_t)((a & sign) != 0);
    c->zf = (r == 0);
    c->sf = ((r & sign) != 0);
    c->pf = calc_pf(r);
    return r;
}

static inline uint64_t f_sar(CPU64 *c, uint64_t a, uint64_t cnt, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    a &= mask;
    cnt &= (bits == 64) ? 63U : 31U;
    if (cnt == 0) return a;
    int64_t sa = (bits == 64) ? (int64_t)a : ((a & sign) ? (int64_t)(a | ~mask) : (int64_t)a);
    uint64_t r;
    if (cnt >= (uint64_t)bits) {
        r = (sa < 0) ? mask : 0ULL;
        c->cf = (sa < 0) ? 1 : 0;
    } else {
        r = (uint64_t)(sa >> cnt) & mask;
        c->cf = (uint8_t)((sa >> (cnt - 1)) & 1);
    }
    if (cnt == 1) c->of = 0;
    c->zf = (r == 0);
    c->sf = ((r & sign) != 0);
    c->pf = calc_pf(r);
    return r;
}

static inline uint64_t f_rol(CPU64 *c, uint64_t a, uint64_t cnt, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    a &= mask;
    cnt &= (bits == 64) ? 63U : 31U;
    if (cnt == 0) return a;
    uint64_t rc = cnt % (uint64_t)bits;
    uint64_t r = (rc == 0) ? a : (((a << rc) | (a >> ((uint64_t)bits - rc))) & mask);
    c->cf = (uint8_t)(r & 1ULL);
    if (cnt == 1) c->of = (uint8_t)(((r & sign) != 0) ^ c->cf);
    return r;
}

static inline uint64_t f_ror(CPU64 *c, uint64_t a, uint64_t cnt, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1ULL);
    uint64_t sign = 1ULL << (bits - 1);
    a &= mask;
    cnt &= (bits == 64) ? 63U : 31U;
    if (cnt == 0) return a;
    uint64_t rc = cnt % (uint64_t)bits;
    uint64_t r = (rc == 0) ? a : (((a >> rc) | (a << ((uint64_t)bits - rc))) & mask);
    c->cf = (uint8_t)((r & sign) != 0);
    if (cnt == 1) c->of = (uint8_t)(((r & sign) != 0) ^ (((r << 1) & sign) != 0));
    return r;
}

static inline void f_ucomi_f(CPU64 *c, float a, float b) {
    c->of = 0; c->sf = 0; c->af = 0;
    if (isnan(a) || isnan(b)) { c->zf = 1; c->pf = 1; c->cf = 1; }
    else if (a > b)           { c->zf = 0; c->pf = 0; c->cf = 0; }
    else if (a < b)           { c->zf = 0; c->pf = 0; c->cf = 1; }
    else                      { c->zf = 1; c->pf = 0; c->cf = 0; }
}

static inline void f_ucomi_d(CPU64 *c, double a, double b) {
    c->of = 0; c->sf = 0; c->af = 0;
    if (isnan(a) || isnan(b)) { c->zf = 1; c->pf = 1; c->cf = 1; }
    else if (a > b)           { c->zf = 0; c->pf = 0; c->cf = 0; }
    else if (a < b)           { c->zf = 0; c->pf = 0; c->cf = 1; }
    else                      { c->zf = 1; c->pf = 0; c->cf = 0; }
}

/* SSE4.2 PCMPISTRI (implicit-length string compare -> index in ECX + CF/ZF/SF/OF). */
static inline void f_pcmpistri(CPU64 *c, Xmm128 a, Xmm128 b, uint8_t imm) {
    int is_word = (imm & 1) != 0;
    int is_signed = (imm & 2) != 0;
    int agg = (imm >> 2) & 3;
    int pol = (imm >> 4) & 3;
    int msb = (imm >> 6) & 1;
    int nlanes = is_word ? 8 : 16;

    int alen = 0, blen = 0;
    while (alen < nlanes && (is_word ? a.w[alen] : a.b[alen]) != 0) alen++;
    while (blen < nlanes && (is_word ? b.w[blen] : b.b[blen]) != 0) blen++;

    int32_t av[16], bv[16];
    for (int i = 0; i < nlanes; i++) {
        av[i] = is_word ? (is_signed ? (int32_t)a.sw[i] : (int32_t)a.w[i])
                        : (is_signed ? (int32_t)a.sb[i] : (int32_t)a.b[i]);
        bv[i] = is_word ? (is_signed ? (int32_t)b.sw[i] : (int32_t)b.w[i])
                        : (is_signed ? (int32_t)b.sb[i] : (int32_t)b.b[i]);
    }

    uint32_t res = 0;
    if (agg == 0) { /* Equal any */
        for (int j = 0; j < blen; j++) {
            for (int i = 0; i < alen; i++) {
                if (av[i] == bv[j]) { res |= (1U << j); break; }
            }
        }
    } else if (agg == 1) { /* Ranges */
        for (int j = 0; j < blen; j++) {
            for (int i = 0; i + 1 < alen; i += 2) {
                if (bv[j] >= av[i] && bv[j] <= av[i + 1]) { res |= (1U << j); break; }
            }
        }
    } else if (agg == 2) { /* Equal each */
        for (int j = 0; j < nlanes; j++) {
            int in_a = j < alen, in_b = j < blen;
            if ((!in_a && !in_b) || (in_a && in_b && av[j] == bv[j])) res |= (1U << j);
        }
    } else { /* Equal ordered (substring match, imm=0x0c) */
        for (int j = 0; j < nlanes; j++) {
            int ok = 1;
            for (int i = 0; i < alen; i++) {
                int k = i + j;
                if (k >= nlanes) break;
                if (k >= blen || av[i] != bv[k]) { ok = 0; break; }
            }
            if (ok && (alen == 0 || j < blen)) res |= (1U << j);
        }
    }

    uint32_t full_mask = (1U << nlanes) - 1U;
    if (pol == 1) res = (~res) & full_mask;
    else if (pol == 3) {
        uint32_t valid_b = blen ? ((1U << blen) - 1U) : 0U;
        res = ((~res) & valid_b) | (res & ~valid_b);
    }

    c->cf = (res != 0);
    c->zf = (blen < nlanes);
    c->sf = (alen < nlanes);
    c->of = (uint8_t)(res & 1U);
    c->af = 0; c->pf = 0;

    if (res == 0) {
        SET32(c->rcx, (uint32_t)nlanes);
    } else if (msb) {
        SET32(c->rcx, (uint32_t)(31 - __builtin_clz(res)));
    } else {
        SET32(c->rcx, (uint32_t)__builtin_ctz(res));
    }
}

#endif /* ELF64_RECOMP_CPU64_H */
