#include "linux64_min.h"

extern int g_lib_scale;
extern int g_ctor_ran;
extern int64_t lib_mix64(int64_t a, int64_t b);
extern int lib_switch(int k);
extern float lib_dot4(const float *a, const float *b);
extern double lib_hypot(double x, double y);

static int cmp_i32(const void *pa, const void *pb) {
    int32_t a = *(const int32_t *)pa;
    int32_t b = *(const int32_t *)pb;
    return (a > b) - (a < b);
}

typedef struct {
    linux_pthread_mutex_t mu;
    int64_t               mu_sum;
    volatile int64_t      atomic_sum;
} ThreadCtx;

static void *worker_fn(void *arg) {
    ThreadCtx *ctx = (ThreadCtx *)arg;
    for (int i = 0; i < 500; i++) {
        pthread_mutex_lock(&ctx->mu);
        ctx->mu_sum += 3;
        pthread_mutex_unlock(&ctx->mu);
        __sync_fetch_and_add(&ctx->atomic_sum, 1);
    }
    return (void *)(uint64_t)42;
}

/* Exercises stack protector (fs:0x28 canary) with a local char buffer. */
__attribute__((noinline))
static int stack_canary_check(const char *src) {
    char buf[64];
    size_t n = strlen(src);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, src, n);
    buf[n] = '\0';
    return (int)strlen(buf);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    if (g_ctor_ran != 1337) {
        printf("FAIL: ctor=%d\n", g_ctor_ran);
        return 1;
    }

    int64_t mix = lib_mix64(1000003LL, 700001LL);
    /* 1000003 * 700001 = 700003100003; / 7 = 100000442857; (1000003^700001)&0xff = 34; + 10 = 100000442901 */
    if (mix != 100000442901LL) {
        printf("FAIL: mix=%lld\n", (long long)mix);
        return 2;
    }

    int sw_sum = 0;
    for (int i = 0; i < 9; i++) sw_sum += lib_switch(i);
    /* 11+29+47+71+101+139+191+251+(-1) = 839 */
    if (sw_sum != 839) {
        printf("FAIL: sw_sum=%d\n", sw_sum);
        return 3;
    }

    float va[4] = {1.5f, 2.0f, -3.0f, 4.5f};
    float vb[4] = {2.0f, 3.0f,  4.0f, 2.0f};
    float dot = lib_dot4(va, vb); /* 3 + 6 - 12 + 9 = 6.0 */
    double hyp = lib_hypot(3.0, 4.0); /* 5.0 */
    if (dot < 5.99f || dot > 6.01f || hyp < 4.99 || hyp > 5.01) {
        printf("FAIL: fp dot=%.4f hyp=%.4f\n", (double)dot, hyp);
        return 4;
    }

    if (stack_canary_check("hello-elf64-recomp") != 18) {
        printf("FAIL: canary\n");
        return 5;
    }

    int32_t arr[8] = {42, -7, 100, 0, 19, -55, 8, 3};
    qsort(arr, 8, sizeof(int32_t), cmp_i32);
    int32_t expect[8] = {-55, -7, 0, 3, 8, 19, 42, 100};
    for (int i = 0; i < 8; i++) {
        if (arr[i] != expect[i]) {
            printf("FAIL: qsort idx=%d got=%d\n", i, arr[i]);
            return 6;
        }
    }

    struct linux_stat64 st;
    memset(&st, 0, sizeof(st));
    if (stat("/etc/hosts", &st) != 0 || st.st_size <= 0) {
        printf("FAIL: stat size=%lld\n", (long long)st.st_size);
        return 7;
    }

    ThreadCtx tctx;
    memset(&tctx, 0, sizeof(tctx));
    pthread_mutex_init(&tctx.mu, NULL);
    linux_pthread_t th[4];
    for (int i = 0; i < 4; i++) {
        if (pthread_create(&th[i], NULL, worker_fn, &tctx) != 0) {
            printf("FAIL: pthread_create %d\n", i);
            return 8;
        }
    }
    for (int i = 0; i < 4; i++) {
        void *ret = NULL;
        if (pthread_join(th[i], &ret) != 0 || (uint64_t)ret != 42) {
            printf("FAIL: pthread_join %d ret=%p\n", i, ret);
            return 9;
        }
    }
    pthread_mutex_destroy(&tctx.mu);
    if (tctx.mu_sum != 6000 || tctx.atomic_sum != 2000) {
        printf("FAIL: threads mu=%lld atomic=%lld\n", (long long)tctx.mu_sum, (long long)tctx.atomic_sum);
        return 10;
    }

    printf("SMOKE64 PASS mix=%lld sw=%d dot=%.2f hyp=%.2f hosts=%lldB threads=%lld/%lld\n",
           (long long)mix, sw_sum, (double)dot, hyp, (long long)st.st_size,
           (long long)tctx.mu_sum, (long long)tctx.atomic_sum);
    return 0;
}
