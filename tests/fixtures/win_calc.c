#include "win64_min.h"

int _fltused = 1;
static int g_dll_attached = 0;

BOOL DllMain(HMODULE hMod, DWORD reason, void *reserved) {
    (void)hMod; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_dll_attached = 9001;
    }
    return TRUE;
}

__declspec(dllexport) int win_dll_attached(void) {
    return g_dll_attached;
}

/* 6-arg Win64 function testing 4 reg args (rcx,rdx,r8,r9) + 2 stack args past 32B shadow space. */
__declspec(dllexport) int64_t win_sum6(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f) {
    return a * 1 + b * 2 + c * 3 + d * 4 + e * 5 + f * 6;
}

__declspec(dllexport) double win_lerp(double a, double b, double t) {
    return a + (b - a) * t;
}
