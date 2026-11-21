#include "linux64_min.h"

int g_lib_scale = 10;
int g_ctor_ran = 0;

__attribute__((constructor))
static void libcalc_init(void) {
    g_ctor_ran = 1337;
}

/* Exercises 64x64->128 imul/idiv and 32->64 zero-extension. */
int64_t lib_mix64(int64_t a, int64_t b) {
    __int128 prod = (__int128)a * (__int128)b;
    int64_t q = (int64_t)(prod / 7);
    uint32_t lo = (uint32_t)(a ^ b);
    uint64_t zext = (uint64_t)lo; /* must zero-extend upper 32 bits */
    return q + (int64_t)(zext & 0xFF) + g_lib_scale;
}

/* Non-trivial switch compiled into an x86_64 PIC jump table under -O2. */
__attribute__((noinline))
int lib_switch(int k) {
    volatile int acc = 0;
    switch (k) {
        case 0: acc = 11; break;
        case 1: acc = 29; break;
        case 2: acc = 47; break;
        case 3: acc = 71; break;
        case 4: acc = 101; break;
        case 5: acc = 139; break;
        case 6: acc = 191; break;
        case 7: acc = 251; break;
        default: acc = -1; break;
    }
    return acc;
}

float lib_dot4(const float *a, const float *b) {
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3];
}

double lib_hypot(double x, double y) {
    return sqrt(x * x + y * y);
}
