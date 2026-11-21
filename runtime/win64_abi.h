#ifndef ELF64_RECOMP_WIN64_ABI_H
#define ELF64_RECOMP_WIN64_ABI_H

#include "cpu64.h"

/* Win64 x86_64 calling convention:
 *   args 0..3: rcx, rdx, r8, r9 (or xmm0..xmm3 for float/double)
 *   args 4+:   [rsp + 8 + idx*8] (skipping 8B retaddr + 32B shadow space)
 */
static inline uint64_t win64_arg_i(const CPU64 *c, int idx) {
    switch (idx) {
        case 0: return c->rcx;
        case 1: return c->rdx;
        case 2: return c->r8;
        case 3: return c->r9;
        default: return R64(c->rsp + 8ULL + (uint64_t)idx * 8ULL);
    }
}

static inline float win64_arg_f(const CPU64 *c, int idx) {
    if (idx < 4) return c->xmm[idx].f[0];
    uint32_t u = R32(c->rsp + 8ULL + (uint64_t)idx * 8ULL);
    float f;
    memcpy(&f, &u, 4);
    return f;
}

static inline double win64_arg_d(const CPU64 *c, int idx) {
    if (idx < 4) return c->xmm[idx].df[0];
    uint64_t u = R64(c->rsp + 8ULL + (uint64_t)idx * 8ULL);
    double d;
    memcpy(&d, &u, 8);
    return d;
}

struct SDL_Window;
struct SDL_Window *win32_hwnd_to_sdl(uint64_t hwnd);

#endif /* ELF64_RECOMP_WIN64_ABI_H */
