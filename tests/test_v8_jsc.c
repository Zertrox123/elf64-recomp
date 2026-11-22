/* Standalone UBSan-clean test for the MSVC x64 V8 -> JavaScriptCore bridge. */
#include "runtime64.h"
#include "win64_abi.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void guest_add_cb(CPU64 *c);

/* Minimal manifest symbols required by runtime64.c */
const RTModuleSpec g_rt_modules[1] = { {0} };
const size_t       g_rt_module_count = 0;
const RTImportSpec g_rt_imports[1] = { {0} };
const size_t       g_rt_import_count = 0;
const RTImportSpec g_rt_data_imports[1] = { {0} };
const size_t       g_rt_data_import_count = 0;
const RTCopyReloc  g_rt_copy_relocs[1] = { {0} };
const size_t       g_rt_copy_reloc_count = 0;
const RTIrelative  g_rt_irelatives[1] = { {0} };
const size_t       g_rt_irelative_count = 0;
const uint64_t     g_rt_init_array[1] = { 0 };
const size_t       g_rt_init_array_count = 0;
const RTExportSpec g_rt_exports[1] = { {0} };
const size_t       g_rt_export_count = 0;
const RTFuncEntry  g_rt_funcs[1] = { {0x70001000ULL, guest_add_cb} };
const size_t       g_rt_func_count = 1;
const RTDllInit    g_rt_dll_inits[1] = { {0} };
const size_t       g_rt_dll_init_count = 0;
const uint64_t     g_rt_entry_addr = 0;
const uint64_t     g_rt_main_addr = 0;
const uint64_t     g_rt_total_tls_size = 0;
const uint64_t     g_rt_data_import_base = 0;
const int          g_rt_is_win64 = 1;

static uint8_t g_stack[65536];
static CPU64   g_cpu;

static void call_shim(const char *sym, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4) {
    void *ud = NULL;
    RTShimFn fn = rt_find_shim(sym, &ud);
    assert(fn != NULL);
    uint64_t sp = ((uint64_t)(uintptr_t)(g_stack + sizeof(g_stack) - 128)) & ~15ULL;
    W64(sp + 0x28, a4);
    g_cpu.rsp = sp;
    g_cpu.rcx = a0; g_cpu.rdx = a1; g_cpu.r8 = a2; g_cpu.r9 = a3;
    fn(&g_cpu, ud);
}

/* Lifted-style guest FunctionCallback: returns info[0] + info[1] as v8::Integer */
static void guest_add_cb(CPU64 *c) {
    uint64_t info = c->rcx;
    uint64_t imp  = R64(info + 0);
    uint64_t vals = R64(info + 8);
    int32_t  len  = (int32_t)R32(info + 16);
    assert(len == 2);
    uint64_t iso  = R64(imp + 8);

    uint64_t sret_ctx = 0;
    call_shim("?GetCurrentContext@Isolate@v8@@QEAA?AV?$Local@VContext@v8@@@2@XZ", iso, (uint64_t)(uintptr_t)&sret_ctx, 0, 0, 0);

    uint64_t m0[2] = {0}, m1[2] = {0};
    call_shim("?Int32Value@Value@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z", vals + 0, (uint64_t)(uintptr_t)m0, sret_ctx, 0, 0);
    call_shim("?Int32Value@Value@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z", vals + 8, (uint64_t)(uintptr_t)m1, sret_ctx, 0, 0);
    assert((m0[0] & 0xFF) == 1 && (m1[0] & 0xFF) == 1);
    int32_t sum = (int32_t)(m0[0] >> 32) + (int32_t)(m1[0] >> 32);

    uint64_t sret_num = 0;
    call_shim("?New@Integer@v8@@SA?AV?$Local@VInteger@v8@@@2@PEAVIsolate@2@H@Z",
              (uint64_t)(uintptr_t)&sret_num, iso, (uint64_t)(uint32_t)sum, 0, 0);
    /* Write tagged Address into FunctionCallbackInfo ReturnValue slot (implicit_args[3]) */
    W64(imp + 0x18, R64(sret_num));
    c->rip = pop64(c);
}

int main(void) {
    char *argv[] = {"test_v8_jsc", NULL};
    rt_init(1, argv, NULL);

    /* 1. Initialize V8 + Isolate */
    call_shim("?Initialize@V8@v8@@CA_NH@Z", 0, 0, 0, 0, 0);
    assert(g_cpu.rax == 1);
    uint8_t params[128];
    call_shim("??0CreateParams@Isolate@v8@@QEAA@XZ", (uint64_t)(uintptr_t)params, 0, 0, 0, 0);
    call_shim("?New@Isolate@v8@@SAPEAV12@AEBUCreateParams@12@@Z", (uint64_t)(uintptr_t)params, 0, 0, 0, 0);
    uint64_t iso = g_cpu.rax;
    assert(iso != 0);
    call_shim("?Enter@Isolate@v8@@QEAAXXZ", iso, 0, 0, 0, 0);

    /* Verify inline V8 Isolate root offsets (+0x140 Undef, +0x150 Null, +0x158 True, +0x160 False) */
    uint64_t undef_addr = R64(iso + 0x140);
    uint64_t null_addr  = R64(iso + 0x150);
    uint64_t true_addr  = R64(iso + 0x158);
    uint64_t false_addr = R64(iso + 0x160);
    assert((undef_addr & 3) == 1 && (null_addr & 3) == 1 && (true_addr & 3) == 1 && (false_addr & 3) == 1);
    assert((R32(undef_addr + 0x17) >> 1) == 5);
    assert((R32(null_addr  + 0x17) >> 1) == 3);
    assert((R32(true_addr  + 0x17) >> 1) == 1);
    assert((R32(false_addr + 0x17) >> 1) == 0);

    /* 2. HandleScope + Context */
    uint64_t hscope[4] = {0};
    call_shim("??0HandleScope@v8@@QEAA@PEAVIsolate@1@@Z", (uint64_t)(uintptr_t)hscope, iso, 0, 0, 0);
    uint64_t ctx_h = 0;
    call_shim("?New@Context@v8@@SA?AV?$Local@VContext@v8@@@2@PEAVIsolate@2@PEAVExtensionConfiguration@2@V?$MaybeLocal@VObjectTemplate@v8@@@2@V?$MaybeLocal@VValue@v8@@@2@UDeserializeInternalFieldsCallback@2@PEAVMicrotaskQueue@2@@Z",
              (uint64_t)(uintptr_t)&ctx_h, iso, 0, 0, 0);
    assert(ctx_h != 0);
    call_shim("?Enter@Context@v8@@QEAAXXZ", ctx_h, 0, 0, 0, 0);

    /* 3. Verify String::NewFromUtf8 + inline IsString() (instance_type < 0x80) */
    const char *src = "(function(a,b){ return a * b + 2; })(5, 8)";
    uint64_t str_h = 0;
    call_shim("?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z",
              (uint64_t)(uintptr_t)&str_h, iso, (uint64_t)(uintptr_t)src, 0, (uint64_t)(int64_t)-1);
    assert(str_h != 0);
    uint64_t str_addr = R64(str_h);
    uint64_t cage = str_addr & 0xFFFFFFFF00000000ULL;
    uint32_t map_c = R32(str_addr - 1);
    assert(R16(cage + map_c + 7) < 0x80);

    /* 4. Script::Compile + Script::Run -> 42 */
    uint64_t scr_h = 0, res_h = 0;
    call_shim("?Compile@Script@v8@@SA?AV?$MaybeLocal@VScript@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VString@v8@@@2@PEAVScriptOrigin@2@@Z",
              (uint64_t)(uintptr_t)&scr_h, ctx_h, str_h, 0, 0);
    assert(scr_h != 0);
    call_shim("?Run@Script@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@@Z",
              scr_h, (uint64_t)(uintptr_t)&res_h, ctx_h, 0, 0);
    assert(res_h != 0);
    uint64_t maybe_i[2] = {0};
    call_shim("?Int32Value@Value@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z",
              res_h, (uint64_t)(uintptr_t)maybe_i, ctx_h, 0, 0);
    assert((maybe_i[0] & 0xFF) == 1 && (int32_t)(maybe_i[0] >> 32) == 42);

    /* 5. ObjectTemplate + InternalField + External round-trip */
    uint64_t ot_h = 0, inst_h = 0, ext_h = 0, got_h = 0;
    call_shim("?New@ObjectTemplate@v8@@SA?AV?$Local@VObjectTemplate@v8@@@2@PEAVIsolate@2@V?$Local@VFunctionTemplate@v8@@@2@@Z",
              (uint64_t)(uintptr_t)&ot_h, iso, 0, 0, 0);
    call_shim("?SetInternalFieldCount@ObjectTemplate@v8@@QEAAXH@Z", ot_h, 1, 0, 0, 0);
    call_shim("?NewInstance@ObjectTemplate@v8@@QEAA?AV?$MaybeLocal@VObject@v8@@@2@V?$Local@VContext@v8@@@2@@Z",
              ot_h, (uint64_t)(uintptr_t)&inst_h, ctx_h, 0, 0);
    call_shim("?New@External@v8@@SA?AV?$Local@VExternal@v8@@@2@PEAVIsolate@2@PEAX@Z",
              (uint64_t)(uintptr_t)&ext_h, iso, 0xCAFEBABEULL, 0, 0);
    call_shim("?SetInternalField@Object@v8@@QEAAXHV?$Local@VValue@v8@@@2@@Z", inst_h, 0, ext_h, 0, 0);
    call_shim("?SlowGetInternalField@Object@v8@@AEAA?AV?$Local@VValue@v8@@@2@H@Z",
              inst_h, (uint64_t)(uintptr_t)&got_h, 0, 0, 0);
    call_shim("?Value@External@v8@@QEBAPEAXXZ", got_h, 0, 0, 0, 0);
    assert(g_cpu.rax == 0xCAFEBABEULL);

    /* 6. JSON::Parse + TryCatch on invalid JS */
    uint64_t jstr_h = 0, jobj_h = 0, jout_h = 0;
    const char *js_json = "{\"ok\":true,\"n\":7}";
    call_shim("?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z",
              (uint64_t)(uintptr_t)&jstr_h, iso, (uint64_t)(uintptr_t)js_json, 0, (uint64_t)(int64_t)-1);
    call_shim("?Parse@JSON@v8@@SA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VString@v8@@@2@@Z",
              (uint64_t)(uintptr_t)&jobj_h, ctx_h, jstr_h, 0, 0);
    assert(jobj_h != 0);
    call_shim("?Stringify@JSON@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@V?$Local@VString@v8@@@2@@Z",
              (uint64_t)(uintptr_t)&jout_h, ctx_h, jobj_h, 0, 0);
    uint64_t u8[2] = {0};
    call_shim("??0Utf8Value@String@v8@@QEAA@PEAVIsolate@2@V?$Local@VValue@v8@@@2@@Z",
              (uint64_t)(uintptr_t)u8, iso, jout_h, 0, 0);
    assert(strstr((const char *)(uintptr_t)u8[0], "\"ok\":true") != NULL);
    call_shim("??1Utf8Value@String@v8@@QEAA@XZ", (uint64_t)(uintptr_t)u8, 0, 0, 0, 0);

    uint64_t tc[8] = {0};
    call_shim("??0TryCatch@v8@@QEAA@PEAVIsolate@1@@Z", (uint64_t)(uintptr_t)tc, iso, 0, 0, 0);
    uint64_t bad_h = 0, bad_scr = 0;
    const char *bad_js = "function( {";
    call_shim("?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z",
              (uint64_t)(uintptr_t)&bad_h, iso, (uint64_t)(uintptr_t)bad_js, 0, (uint64_t)(int64_t)-1);
    call_shim("?Compile@Script@v8@@SA?AV?$MaybeLocal@VScript@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VString@v8@@@2@PEAVScriptOrigin@2@@Z",
              (uint64_t)(uintptr_t)&bad_scr, ctx_h, bad_h, 0, 0);
    assert(bad_scr == 0);
    call_shim("?HasCaught@TryCatch@v8@@QEBA_NXZ", (uint64_t)(uintptr_t)tc, 0, 0, 0, 0);
    assert(g_cpu.rax == 1);
    call_shim("??1TryCatch@v8@@QEAA@XZ", (uint64_t)(uintptr_t)tc, 0, 0, 0, 0);

    /* 7. FunctionTemplate guest callback invoked from JS: hostAdd(20, 22) == 42 */
    uint64_t ft_h = 0, fn_h = 0, g_h = 0, k_h = 0, call_s_h = 0, call_scr = 0, call_res = 0;
    uint64_t mb_set[2] = {0};
    call_shim("?New@FunctionTemplate@v8@@SA?AV?$Local@VFunctionTemplate@v8@@@2@PEAVIsolate@2@P6AXAEBV?$FunctionCallbackInfo@VValue@v8@@@2@@ZV?$Local@VValue@v8@@@2@V?$Local@VSignature@v8@@@2@HW4ConstructorBehavior@2@W4SideEffectType@2@PEBVCFunction@2@GGG@Z",
              (uint64_t)(uintptr_t)&ft_h, iso, 0x70001000ULL, 0, 0);
    call_shim("?GetFunction@FunctionTemplate@v8@@QEAA?AV?$MaybeLocal@VFunction@v8@@@2@V?$Local@VContext@v8@@@2@@Z",
              ft_h, (uint64_t)(uintptr_t)&fn_h, ctx_h, 0, 0);
    call_shim("?Global@Context@v8@@QEAA?AV?$Local@VObject@v8@@@2@XZ",
              ctx_h, (uint64_t)(uintptr_t)&g_h, 0, 0, 0);
    const char *kname = "hostAdd";
    call_shim("?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z",
              (uint64_t)(uintptr_t)&k_h, iso, (uint64_t)(uintptr_t)kname, 0, (uint64_t)(int64_t)-1);
    call_shim("?Set@Object@v8@@QEAA?AV?$Maybe@_N@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@1@Z",
              g_h, (uint64_t)(uintptr_t)mb_set, ctx_h, k_h, fn_h);
    const char *call_js = "hostAdd(20, 22)";
    call_shim("?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z",
              (uint64_t)(uintptr_t)&call_s_h, iso, (uint64_t)(uintptr_t)call_js, 0, (uint64_t)(int64_t)-1);
    call_shim("?Compile@Script@v8@@SA?AV?$MaybeLocal@VScript@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VString@v8@@@2@PEAVScriptOrigin@2@@Z",
              (uint64_t)(uintptr_t)&call_scr, ctx_h, call_s_h, 0, 0);
    call_shim("?Run@Script@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@@Z",
              call_scr, (uint64_t)(uintptr_t)&call_res, ctx_h, 0, 0);
    uint64_t maybe_cb[2] = {0};
    call_shim("?Int32Value@Value@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z",
              call_res, (uint64_t)(uintptr_t)maybe_cb, ctx_h, 0, 0);
    assert((maybe_cb[0] & 0xFF) == 1 && (int32_t)(maybe_cb[0] >> 32) == 42);

    call_shim("??1HandleScope@v8@@QEAA@XZ", (uint64_t)(uintptr_t)hscope, 0, 0, 0, 0);

    /* 8. Win32 keymap + IMMDeviceEnumerator + XAudio2Create (headless) */
    setenv("ELF64_HEADLESS", "1", 1);
    call_shim("MapVirtualKeyExA", 'W', 0, 0, 0, 0);
    assert(g_cpu.rax == 0x11);
    call_shim("MapVirtualKeyExA", 0x01, 1, 0, 0, 0);
    assert(g_cpu.rax == 0x1B);
    static const uint8_t k_mmdev[16] = {
        0x95,0x03,0xDE,0xBC, 0x2F,0xE5, 0x7C,0x46, 0x8E,0x3D,0xC4,0x57,0x92,0x91,0x69,0x2E
    };
    uint64_t mm_enum = 0, xa2 = 0, mv = 0;
    call_shim("CoCreateInstance", (uint64_t)(uintptr_t)k_mmdev, 0, 1, 0, (uint64_t)(uintptr_t)&mm_enum);
    assert(g_cpu.rax == 0 && mm_enum != 0);
    call_shim("XAudio2Create", (uint64_t)(uintptr_t)&xa2, 0, 0, 0, 0);
    assert(g_cpu.rax == 0 && xa2 != 0);
    uint64_t xa2_vt = R64(xa2);
    assert(rt_invoke_win64(&g_cpu, R64(xa2_vt + 7 * 8), xa2, (uint64_t)(uintptr_t)&mv, 2, 44100, 0, 0) == 0);
    assert(mv != 0);
    uint32_t vdet[4] = {0};
    rt_invoke_win64(&g_cpu, R64(R64(mv)), mv, (uint64_t)(uintptr_t)vdet, 0, 0, 0, 0);
    assert(vdet[2] == 2 && vdet[3] == 44100);

    printf("V8_JSC_TEST PASS (eval=42, ext=0xcafebabe, json=ok, trycatch=ok, cb=42, io+xa2=ok)\n");
    return 0;
}
