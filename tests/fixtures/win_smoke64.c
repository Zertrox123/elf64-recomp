#include "win64_min.h"

int _fltused = 1;

__declspec(dllimport) int     win_dll_attached(void);
__declspec(dllimport) int64_t win_sum6(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f);
__declspec(dllimport) double  win_lerp(double a, double b, double t);

static int cmp_i32(const void *pa, const void *pb) {
    int32_t a = *(const int32_t *)pa;
    int32_t b = *(const int32_t *)pb;
    return (a > b) - (a < b);
}

typedef struct {
    CRITICAL_SECTION cs;
    int64_t          cs_sum;
    volatile int64_t atomic_sum;
    DWORD            tls_idx;
} WinThreadCtx;

static DWORD win_worker(void *param) {
    WinThreadCtx *ctx = (WinThreadCtx *)param;
    TlsSetValue(ctx->tls_idx, (void *)0xBEEF);
    for (int i = 0; i < 400; i++) {
        EnterCriticalSection(&ctx->cs);
        ctx->cs_sum += 5;
        LeaveCriticalSection(&ctx->cs);
        __sync_fetch_and_add(&ctx->atomic_sum, 1);
    }
    return (TlsGetValue(ctx->tls_idx) == (void *)0xBEEF) ? 0 : 1;
}

/* Read Windows TEB self-pointer via gs:[0x30]. */
static uint64_t read_teb_self(void) {
    uint64_t teb;
    __asm__ volatile("mov %%gs:0x30, %0" : "=r"(teb));
    return teb;
}

int main(void) {
    if (win_dll_attached() != 9001) {
        printf("FAIL: DllMain attached=%d\n", win_dll_attached());
        ExitProcess(1);
    }

    int64_t s6 = win_sum6(10, 20, 30, 40, 50, 60);
    /* 10 + 40 + 90 + 160 + 250 + 360 = 910 */
    if (s6 != 910) {
        printf("FAIL: win_sum6=%lld\n", s6);
        ExitProcess(2);
    }

    double lr = win_lerp(10.0, 20.0, 0.25); /* 12.5 */
    if (lr < 12.49 || lr > 12.51) {
        printf("FAIL: win_lerp=%.2f\n", lr);
        ExitProcess(3);
    }

    uint64_t teb = read_teb_self();
    if (teb == 0) {
        printf("FAIL: gs:[0x30] TEB is NULL\n");
        ExitProcess(4);
    }

    /* HeapAlloc + VirtualAlloc */
    HANDLE heap = GetProcessHeap();
    uint32_t *hbuf = (uint32_t *)HeapAlloc(heap, 0x08, 64);
    if (!hbuf || hbuf[0] != 0) { printf("FAIL: HeapAlloc\n"); ExitProcess(5); }
    hbuf[0] = 0x12345678u;
    HeapFree(heap, 0, hbuf);

    uint8_t *vbuf = (uint8_t *)VirtualAlloc(NULL, 65536, 0x3000, 0x04);
    if (!vbuf) { printf("FAIL: VirtualAlloc\n"); ExitProcess(6); }
    vbuf[4096] = 0xAA;
    VirtualFree(vbuf, 65536, 0x8000);

    /* QPC */
    int64_t freq = 0, t0 = 0, t1 = 0;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    QueryPerformanceCounter(&t1);
    if (freq <= 0 || t1 < t0) { printf("FAIL: QPC\n"); ExitProcess(7); }

    /* Dynamic GetModuleHandleA + GetProcAddress into guest DLL */
    HMODULE hcalc = GetModuleHandleA("win_calc.dll");
    typedef int64_t (*Sum6Fn)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
    Sum6Fn pSum6 = (Sum6Fn)GetProcAddress(hcalc, "win_sum6");
    if (!pSum6 || pSum6(1, 1, 1, 1, 1, 1) != 21) {
        printf("FAIL: GetProcAddress win_sum6\n");
        ExitProcess(8);
    }

    /* qsort Win64 host->guest callback */
    int32_t arr[6] = {99, -4, 17, 0, 5, -20};
    qsort(arr, 6, sizeof(int32_t), cmp_i32);
    if (arr[0] != -20 || arr[5] != 99) {
        printf("FAIL: qsort\n");
        ExitProcess(9);
    }

    /* CreateThread + CRITICAL_SECTION + TlsAlloc across 4 threads */
    WinThreadCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    InitializeCriticalSection(&ctx.cs);
    ctx.tls_idx = TlsAlloc();
    HANDLE th[4];
    for (int i = 0; i < 4; i++) {
        DWORD tid = 0;
        th[i] = CreateThread(NULL, 0, win_worker, &ctx, 0, &tid);
        if (!th[i]) { printf("FAIL: CreateThread\n"); ExitProcess(10); }
    }
    for (int i = 0; i < 4; i++) {
        WaitForSingleObject(th[i], INFINITE);
        CloseHandle(th[i]);
    }
    TlsFree(ctx.tls_idx);
    DeleteCriticalSection(&ctx.cs);
    if (ctx.cs_sum != 8000 || ctx.atomic_sum != 1600) {
        printf("FAIL: threads cs=%lld atomic=%lld\n", ctx.cs_sum, ctx.atomic_sum);
        ExitProcess(11);
    }

    printf("WIN_SMOKE64 PASS dll=%d sum6=%lld lerp=%.2f teb=0x%llx threads=%lld/%lld\n",
           win_dll_attached(), s6, lr, (unsigned long long)teb, ctx.cs_sum, ctx.atomic_sum);
    ExitProcess(0);
    return 0;
}
