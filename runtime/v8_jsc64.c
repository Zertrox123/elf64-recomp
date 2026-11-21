/* MSVC x64 V8 C++ ABI bridge backed by macOS JavaScriptCore.framework.
 *
 * Implements the pointer-compressed V8 handle/object layout expected by
 * inline V8 headers (IsString, IsNullOrUndefined, Isolate roots at +0x140..+0x160,
 * FunctionCallbackInfo / PropertyCallbackInfo layouts, SlowGetInternalField)
 * while delegating JS compilation, execution, objects, arrays, JSON, and
 * C++ callbacks to native Apple Silicon JavaScriptCore.
 */
#include "runtime64.h"
#include "win64_abi.h"

#ifdef __APPLE__
#include <JavaScriptCore/JavaScriptCore.h>
#endif

#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifdef __APPLE__

/* ---- Pointer-compressed V8 heap cage ---- */
#define V8_CAGE_SIZE     (16u * 1024u * 1024u)
#define V8_MAX_OBJS      200000u
#define V8_MAX_HANDLES   262144u
#define V8_MAX_GLOBALS   65536u
#define V8_MAX_FIELDS    16
#define V8_MAX_TMPL_PROPS 256
#define V8_MAX_TMPL_ACCS  128

enum V8Kind {
    V8K_UNDEF = 0, V8K_HOLE, V8K_NULL, V8K_BOOL, V8K_NUM, V8K_STR,
    V8K_OBJ, V8K_FUNC, V8K_ARR, V8K_DATE, V8K_BIGINT, V8K_EXT,
    V8K_AB, V8K_U8, V8K_CTX, V8K_FTMPL, V8K_OTMPL, V8K_SIG,
    V8K_SCRIPT, V8K_MSG, V8K_STACK, V8K_FRAME
};

typedef struct V8FakeMap {
    uint8_t  pad0[8];
    uint16_t instance_type; /* read at *(uint16_t*)(cage + map_comp + 7) since map_comp is +1 tagged */
    uint8_t  pad1[22];
} V8FakeMap;

typedef struct V8Obj {
    uint32_t   map_comp;        /* +0x00: low 32 bits of tagged V8FakeMap */
    uint32_t   kind;            /* +0x04: enum V8Kind */
    JSValueRef jsv;             /* +0x08: JSC JSValueRef */
    void      *aux;             /* +0x10: metadata / external ptr */
    uint32_t   oddball_smi;     /* +0x18: Oddball kind << 1 (False=0, True=2, Null=6, Undef=10) */
    uint32_t   flags;           /* +0x1C */
    double     num_val;         /* +0x20 */
    uint64_t   aux2;            /* +0x28 */
    uint64_t   pad[2];          /* +0x30..0x3F (64 bytes) */
} V8Obj;

typedef struct V8Isolate V8Isolate;
typedef struct V8Context V8Context;
typedef struct V8Tmpl    V8Tmpl;

typedef struct V8TryCatchNode {
    uint64_t guest_tc;
    uint64_t exc_addr;          /* tagged V8Addr of caught exception, or 0 */
    char    *msg_str;
    char    *src_name;
    int      line;
    int      col;
    struct V8TryCatchNode *prev;
} V8TryCatchNode;

/* Layout matches MSVC V8 Isolate root offsets (+0x140..+0x160). */
struct V8Isolate {
    uint8_t  pad0[0x140];
    uint64_t root_undef;        /* +0x140: kUndefinedValueRootIndex */
    uint64_t root_hole;         /* +0x148: kTheHoleValueRootIndex */
    uint64_t root_null;         /* +0x150: kNullValueRootIndex */
    uint64_t root_true;         /* +0x158: kTrueValueRootIndex */
    uint64_t root_false;        /* +0x160: kFalseValueRootIndex */
    uint8_t  pad1[0x98];        /* -> +0x200 */
    JSContextGroupRef group;
    V8Context *default_ctx;
    V8Context *ctx_stack[64];
    int        ctx_depth;
    uint64_t  *handles;
    uint32_t   handle_top;
    uint64_t  *globals;
    uint8_t   *global_used;
    uint32_t   global_hint;
    V8TryCatchNode *tc_top;
    uint64_t   fatal_cb;
    uint64_t   pending_exc;     /* tagged V8Addr set by ThrowException */
};

struct V8Context {
    V8Isolate         *iso;
    JSGlobalContextRef jsc;
    uint64_t           sec_token; /* tagged V8Addr */
    uint64_t           global_addr;
    V8Tmpl            *global_tmpl;
};

typedef struct V8TmplProp {
    char    *name;
    uint64_t val_addr;          /* tagged V8Addr (value, FunctionTemplate, or ObjectTemplate) */
} V8TmplProp;

typedef struct V8TmplAcc {
    char    *name;
    uint64_t getter_cb;         /* guest AccessorGetterCallback or FunctionTemplate addr */
    uint64_t setter_cb;         /* guest AccessorSetterCallback or FunctionTemplate addr */
    uint64_t data_addr;         /* tagged V8Addr */
    bool     is_ftmpl;          /* true = SetAccessorProperty(FunctionTemplate), false = SetAccessor */
} V8TmplAcc;

struct V8Tmpl {
    bool       is_func;
    V8Isolate *iso;
    uint64_t   fn_cb;           /* guest FunctionCallback */
    uint64_t   fn_data;         /* tagged V8Addr */
    char      *class_name;
    V8Tmpl    *inst_tmpl;       /* FunctionTemplate::InstanceTemplate */
    V8Tmpl    *ctor_tmpl;       /* ObjectTemplate's constructor FunctionTemplate */
    int        internal_field_count;
    /* NamedPropertyHandlerConfiguration */
    uint64_t   named_getter;
    uint64_t   named_setter;
    uint64_t   named_query;
    uint64_t   named_deleter;
    uint64_t   named_enumerator;
    uint64_t   named_data;      /* tagged V8Addr */
    /* Properties and accessors */
    V8TmplProp props[V8_MAX_TMPL_PROPS];
    int        nprops;
    V8TmplAcc  accs[V8_MAX_TMPL_ACCS];
    int        naccs;
};

typedef struct V8InstData {
    V8Isolate *iso;
    V8Tmpl    *tmpl;
    uint64_t   fn_cb;
    uint64_t   fn_data;
    int        internal_field_count;
    uint64_t   internal_fields[V8_MAX_FIELDS];
    JSObjectRef js_obj;
} V8InstData;

typedef struct V8ScriptData {
    char *source;
    char *origin_name;
    int   line_offset;
} V8ScriptData;

typedef struct V8BackingStore {
    void    *data;
    size_t   byte_length;
    uint64_t deleter_cb;
    uint64_t deleter_data;
} V8BackingStore;

typedef struct V8MsgData {
    char *message;
    char *resource_name;
    char *source_line;
    int   line;
    int   col;
} V8MsgData;

typedef struct V8StackData {
    int   count;
    char *func_names[16];
    char *script_names[16];
    int   lines[16];
    int   cols[16];
} V8StackData;

static uint8_t  *g_cage = NULL;
static uint64_t  g_cage_base = 0;
static V8FakeMap *g_map_str = NULL, *g_map_odd = NULL, *g_map_num = NULL, *g_map_obj = NULL;
static V8Obj    *g_objs = NULL;
static uint32_t  g_obj_next = 8; /* 0..4 reserved for oddballs */
static V8Isolate *g_cur_iso = NULL;
static JSClassRef g_v8_obj_class = NULL;
static JSClassRef g_v8_fn_class = NULL;
static __thread CPU64 *tls_v8_cpu = NULL;
static pthread_mutex_t g_v8_mu = PTHREAD_MUTEX_INITIALIZER;

static inline uint64_t v8_tag(const void *p) { return (uint64_t)(uintptr_t)p + 1ULL; }
static inline uint32_t v8_comp(const void *p) { return (uint32_t)(((uint64_t)(uintptr_t)p + 1ULL) & 0xFFFFFFFFULL); }

static inline V8Obj *v8_untag(uint64_t addr) {
    if (!addr || !g_cage) return NULL;
    uint64_t raw = addr & ~1ULL;
    if (raw < (uint64_t)(uintptr_t)g_objs || raw >= (uint64_t)(uintptr_t)(g_objs + V8_MAX_OBJS))
        return NULL;
    return (V8Obj *)(uintptr_t)raw;
}

static inline V8Obj *v8_from_local(uint64_t handle_ptr) {
    if (!handle_ptr) return NULL;
    uint64_t addr = R64(handle_ptr);
    return v8_untag(addr);
}

static uint64_t v8_alloc_handle(V8Isolate *iso, uint64_t addr) {
    if (!iso) iso = g_cur_iso;
    if (!iso || !addr) return 0;
    uint32_t idx = iso->handle_top;
    if (idx >= V8_MAX_HANDLES) idx = iso->handle_top = 0;
    iso->handles[idx] = addr;
    iso->handle_top = idx + 1;
    return (uint64_t)(uintptr_t)&iso->handles[idx];
}

static V8Obj *v8_alloc_obj(V8FakeMap *map, uint32_t kind) {
    pthread_mutex_lock(&g_v8_mu);
    uint32_t idx = g_obj_next++;
    if (g_obj_next >= V8_MAX_OBJS) g_obj_next = 8; /* shortcut: wraps after 200k objects, upgrade to mark-sweep if long sessions exceed pool */
    pthread_mutex_unlock(&g_v8_mu);
    V8Obj *o = &g_objs[idx];
    memset(o, 0, sizeof(*o));
    o->map_comp = v8_comp(map);
    o->kind = kind;
    return o;
}

static void v8_init_cage(void) {
    if (g_cage) return;
    /* Allocate a 16 MB cage that never crosses a 4 GB boundary so pointer compression matches. */
    void *tries[8] = {0};
    int ntry = 0;
    for (int i = 0; i < 8; i++) {
        void *p = mmap(NULL, V8_CAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (p == MAP_FAILED) break;
        uint64_t lo = (uint64_t)(uintptr_t)p;
        uint64_t hi = lo + V8_CAGE_SIZE - 1;
        if ((lo & 0xFFFFFFFF00000000ULL) == (hi & 0xFFFFFFFF00000000ULL)) {
            g_cage = (uint8_t *)p;
            g_cage_base = lo & 0xFFFFFFFF00000000ULL;
            break;
        }
        tries[ntry++] = p;
    }
    for (int i = 0; i < ntry; i++) munmap(tries[i], V8_CAGE_SIZE);
    if (!g_cage) { fprintf(stderr, "v8_jsc64: failed to allocate cage\n"); abort(); }

    g_map_str = (V8FakeMap *)(g_cage + 0x000); g_map_str->instance_type = 0x0000;
    g_map_odd = (V8FakeMap *)(g_cage + 0x040); g_map_odd->instance_type = 0x0083;
    g_map_num = (V8FakeMap *)(g_cage + 0x080); g_map_num->instance_type = 0x0082;
    g_map_obj = (V8FakeMap *)(g_cage + 0x0C0); g_map_obj->instance_type = 0x0400;
    g_objs    = (V8Obj     *)(g_cage + 0x100);

    /* Fixed singleton oddballs at indices 0..4 */
    g_objs[0].map_comp = v8_comp(g_map_odd); g_objs[0].kind = V8K_UNDEF; g_objs[0].oddball_smi = 5u << 1;
    g_objs[1].map_comp = v8_comp(g_map_odd); g_objs[1].kind = V8K_HOLE;  g_objs[1].oddball_smi = 4u << 1;
    g_objs[2].map_comp = v8_comp(g_map_odd); g_objs[2].kind = V8K_NULL;  g_objs[2].oddball_smi = 3u << 1;
    g_objs[3].map_comp = v8_comp(g_map_odd); g_objs[3].kind = V8K_BOOL;  g_objs[3].oddball_smi = 1u << 1; g_objs[3].num_val = 1.0;
    g_objs[4].map_comp = v8_comp(g_map_odd); g_objs[4].kind = V8K_BOOL;  g_objs[4].oddball_smi = 0u << 1; g_objs[4].num_val = 0.0;
}

static inline JSGlobalContextRef v8_active_jsc(V8Isolate *iso, uint64_t ctx_handle) {
    if (ctx_handle) {
        V8Obj *co = v8_from_local(ctx_handle);
        if (co && co->kind == V8K_CTX && co->aux) return ((V8Context *)co->aux)->jsc;
    }
    if (!iso) iso = g_cur_iso;
    if (iso && iso->ctx_depth > 0) return iso->ctx_stack[iso->ctx_depth - 1]->jsc;
    if (iso && iso->default_ctx) return iso->default_ctx->jsc;
    return NULL;
}

static char *jsc_str_to_cstr(JSStringRef s, size_t *out_len) {
    if (!s) { if (out_len) *out_len = 0; return strdup(""); }
    size_t max_sz = JSStringGetMaximumUTF8CStringSize(s);
    char *buf = (char *)malloc(max_sz + 1);
    size_t n = JSStringGetUTF8CString(s, buf, max_sz);
    if (n > 0) n--; /* strip NUL */
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

static char *jsc_val_to_cstr(JSContextRef ctx, JSValueRef v, size_t *out_len) {
    if (!ctx || !v) { if (out_len) *out_len = 0; return strdup(""); }
    JSValueRef exc = NULL;
    JSStringRef s = JSValueToStringCopy(ctx, v, &exc);
    char *res = jsc_str_to_cstr(s, out_len);
    if (s) JSStringRelease(s);
    return res;
}

static uint64_t v8_wrap_jsv(V8Isolate *iso, JSContextRef ctx, JSValueRef v);
static JSValueRef v8_unwrap_jsv(JSContextRef ctx, uint64_t addr);
static JSObjectRef v8_instantiate_tmpl(V8Isolate *iso, JSContextRef ctx, V8Tmpl *tmpl);

/* ---- Re-entrant Win64 guest callback invocation ---- */
static uint64_t v8_call_win64(CPU64 *c, uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    if (!c || !fn) return 0;
    CPU64 saved = *c;
    c->rsp = (c->rsp - 64ULL) & ~15ULL;
    push64(c, 0ULL);
    c->rcx = a0; c->rdx = a1; c->r8 = a2; c->r9 = a3;
    rt_call(c, fn);
    uint64_t ret = c->rax;
    *c = saved;
    return ret;
}

/* ---- Record JSC exception into active TryCatch ---- */
static void v8_record_exception(V8Isolate *iso, JSContextRef ctx, JSValueRef exc) {
    if (!iso || !exc) return;
    if (getenv("ELF64_V8_TRACE")) {
        char *emsg = jsc_val_to_cstr(ctx, exc, NULL);
        fprintf(stderr, "[v8] exception: %s\n", emsg);
        free(emsg);
        if (ctx && JSValueIsObject(ctx, exc)) {
            JSObjectRef eo = JSValueToObject(ctx, exc, NULL);
            if (eo) {
                JSStringRef sk = JSStringCreateWithUTF8CString("stack");
                JSValueRef sv = JSObjectGetProperty(ctx, eo, sk, NULL);
                JSStringRelease(sk);
                if (sv && !JSValueIsUndefined(ctx, sv)) {
                    char *st = jsc_val_to_cstr(ctx, sv, NULL);
                    fprintf(stderr, "[v8] stack:\n%s\n", st);
                    free(st);
                }
            }
        }
    }
    uint64_t exc_addr = v8_wrap_jsv(iso, ctx, exc);
    if (iso->tc_top) {
        iso->tc_top->exc_addr = exc_addr;
        free(iso->tc_top->msg_str);
        iso->tc_top->msg_str = jsc_val_to_cstr(ctx, exc, NULL);
        iso->tc_top->line = 1;
        iso->tc_top->col = 0;
        if (ctx && JSValueIsObject(ctx, exc)) {
            JSObjectRef eo = JSValueToObject(ctx, exc, NULL);
            if (eo) {
                JSStringRef lk = JSStringCreateWithUTF8CString("line");
                JSValueRef lv = JSObjectGetProperty(ctx, eo, lk, NULL);
                JSStringRelease(lk);
                if (lv && JSValueIsNumber(ctx, lv)) iso->tc_top->line = (int)JSValueToNumber(ctx, lv, NULL);
                JSStringRef ck = JSStringCreateWithUTF8CString("column");
                JSValueRef cv = JSObjectGetProperty(ctx, eo, ck, NULL);
                JSStringRelease(ck);
                if (cv && JSValueIsNumber(ctx, cv)) iso->tc_top->col = (int)JSValueToNumber(ctx, cv, NULL);
            }
        }
    }
}

/* ---- Wrap / unwrap between JSC JSValueRef and V8Obj ---- */
static uint64_t v8_wrap_jsv(V8Isolate *iso, JSContextRef ctx, JSValueRef v) {
    if (!iso) iso = g_cur_iso;
    if (!ctx || !v) return v8_tag(&g_objs[0]);
    JSType t = JSValueGetType(ctx, v);
    switch (t) {
        case kJSTypeUndefined: return v8_tag(&g_objs[0]);
        case kJSTypeNull:      return v8_tag(&g_objs[2]);
        case kJSTypeBoolean:   return JSValueToBoolean(ctx, v) ? v8_tag(&g_objs[3]) : v8_tag(&g_objs[4]);
        case kJSTypeNumber: {
            V8Obj *o = v8_alloc_obj(g_map_num, V8K_NUM);
            o->jsv = v; JSValueProtect(ctx, v);
            o->num_val = JSValueToNumber(ctx, v, NULL);
            return v8_tag(o);
        }
        case kJSTypeString: {
            V8Obj *o = v8_alloc_obj(g_map_str, V8K_STR);
            o->jsv = v; JSValueProtect(ctx, v);
            return v8_tag(o);
        }
        case kJSTypeObject: {
            JSObjectRef jo = JSValueToObject(ctx, v, NULL);
            uint32_t kind = V8K_OBJ;
            if (jo && JSObjectIsFunction(ctx, jo)) kind = V8K_FUNC;
            else if (JSValueIsArray(ctx, v)) kind = V8K_ARR;
            else if (JSValueIsDate(ctx, v)) kind = V8K_DATE;
            V8Obj *o = v8_alloc_obj(g_map_obj, kind);
            o->jsv = v; JSValueProtect(ctx, v);
            if (kind == V8K_DATE) o->num_val = JSValueToNumber(ctx, v, NULL);
            return v8_tag(o);
        }
        default: {
            V8Obj *o = v8_alloc_obj(g_map_obj, V8K_OBJ);
            o->jsv = v; JSValueProtect(ctx, v);
            return v8_tag(o);
        }
    }
}

static JSValueRef v8_unwrap_jsv(JSContextRef ctx, uint64_t addr) {
    if (!ctx) return NULL;
    V8Obj *o = v8_untag(addr);
    if (!o) return JSValueMakeUndefined(ctx);
    if (o->jsv) return o->jsv;
    switch (o->kind) {
        case V8K_UNDEF: case V8K_HOLE: return JSValueMakeUndefined(ctx);
        case V8K_NULL:  return JSValueMakeNull(ctx);
        case V8K_BOOL:  return JSValueMakeBoolean(ctx, o->num_val != 0.0);
        case V8K_NUM:   return JSValueMakeNumber(ctx, o->num_val);
        case V8K_BIGINT: return JSValueMakeNumber(ctx, o->num_val);
        case V8K_STR: {
            JSStringRef s = JSStringCreateWithUTF8CString(o->aux ? (const char *)o->aux : "");
            JSValueRef v = JSValueMakeString(ctx, s);
            JSStringRelease(s);
            o->jsv = v; JSValueProtect(ctx, v);
            return v;
        }
        case V8K_FTMPL:
        case V8K_OTMPL: {
            JSObjectRef jo = v8_instantiate_tmpl(g_cur_iso, ctx, (V8Tmpl *)o->aux);
            o->jsv = jo; if (jo) JSValueProtect(ctx, jo);
            return jo ? (JSValueRef)jo : JSValueMakeUndefined(ctx);
        }
        case V8K_EXT: {
            /* Wrap External in an opaque JSObject holding its pointer in aux */
            V8InstData *d = (V8InstData *)calloc(1, sizeof(V8InstData));
            d->iso = g_cur_iso;
            d->fn_data = addr;
            JSObjectRef jo = JSObjectMake(ctx, g_v8_obj_class, d);
            d->js_obj = jo;
            o->jsv = jo; JSValueProtect(ctx, jo);
            return jo;
        }
        default: return JSValueMakeUndefined(ctx);
    }
}

/* ---- Invoke guest FunctionCallback from JSC ---- */
static JSValueRef v8_invoke_fn_cb(JSContextRef ctx, V8Isolate *iso, uint64_t fn_cb, uint64_t fn_data,
                                  JSObjectRef this_obj, JSObjectRef holder_obj,
                                  size_t argc, const JSValueRef argv[], JSValueRef *exception, bool is_ctor) {
    if (!iso) iso = g_cur_iso;
    if (!fn_cb || !tls_v8_cpu) return JSValueMakeUndefined(ctx);

    uint64_t holder_addr = holder_obj ? v8_wrap_jsv(iso, ctx, holder_obj) : iso->root_undef;
    uint64_t this_addr   = this_obj   ? v8_wrap_jsv(iso, ctx, this_obj)   : holder_addr;

    uint64_t implicit_args[6];
    implicit_args[0] = holder_addr;                      /* kHolderIndex */
    implicit_args[1] = (uint64_t)(uintptr_t)iso;         /* kIsolateIndex */
    implicit_args[2] = iso->root_undef;                  /* kReturnValueDefaultValueIndex */
    implicit_args[3] = iso->root_undef;                  /* kReturnValueIndex */
    implicit_args[4] = fn_data ? fn_data : iso->root_undef; /* kDataIndex */
    implicit_args[5] = is_ctor ? holder_addr : iso->root_undef; /* kNewTargetIndex */

    /* values_[-1] = This(), values_[0..argc-1] = args[0..argc-1] */
    uint64_t vals_buf[66];
    size_t n = argc > 64 ? 64 : argc;
    vals_buf[0] = this_addr;
    for (size_t i = 0; i < n; i++) vals_buf[1 + i] = v8_wrap_jsv(iso, ctx, argv[i]);

    struct {
        uint64_t implicit_args;
        uint64_t values;
        int32_t  length;
        int32_t  pad;
    } info;
    info.implicit_args = (uint64_t)(uintptr_t)implicit_args;
    info.values        = (uint64_t)(uintptr_t)&vals_buf[1];
    info.length        = (int32_t)n;
    info.pad           = 0;

    iso->pending_exc = 0;
    v8_call_win64(tls_v8_cpu, fn_cb, (uint64_t)(uintptr_t)&info, 0, 0, 0);

    if (iso->pending_exc) {
        JSValueRef ex = v8_unwrap_jsv(ctx, iso->pending_exc);
        iso->pending_exc = 0;
        if (exception) *exception = ex;
        return JSValueMakeUndefined(ctx);
    }
    return v8_unwrap_jsv(ctx, implicit_args[3]);
}

/* ---- Invoke guest PropertyCallback (getter/setter) from JSC ---- */
static JSValueRef v8_invoke_prop_getter(JSContextRef ctx, V8Isolate *iso, uint64_t cb, uint64_t data_addr,
                                        JSObjectRef obj, JSStringRef prop_name, JSValueRef *exception, bool *was_set) {
    if (was_set) *was_set = false;
    if (!iso) iso = g_cur_iso;
    if (!cb || !tls_v8_cpu) return NULL;

    uint64_t obj_addr = v8_wrap_jsv(iso, ctx, obj);
    uint64_t prop_addr = v8_wrap_jsv(iso, ctx, JSValueMakeString(ctx, prop_name));
    uint64_t prop_h = v8_alloc_handle(iso, prop_addr);

    uint64_t args[7];
    args[0] = 0;                                        /* kShouldThrowOnErrorIndex */
    args[1] = obj_addr;                                 /* kHolderIndex */
    args[2] = (uint64_t)(uintptr_t)iso;                 /* kIsolateIndex */
    args[3] = iso->root_undef;                          /* kReturnValueDefaultValueIndex */
    args[4] = iso->root_hole;                           /* sentinel to detect if callback set ReturnValue */
    args[5] = data_addr ? data_addr : iso->root_undef;  /* kDataIndex */
    args[6] = obj_addr;                                 /* kThisIndex */

    uint64_t info_ptr = (uint64_t)(uintptr_t)args;      /* PropertyCallbackInfo has { Address* args_; } */
    iso->pending_exc = 0;
    v8_call_win64(tls_v8_cpu, cb, prop_h, (uint64_t)(uintptr_t)&info_ptr, 0, 0);

    if (iso->pending_exc) {
        JSValueRef ex = v8_unwrap_jsv(ctx, iso->pending_exc);
        iso->pending_exc = 0;
        if (exception) *exception = ex;
        if (was_set) *was_set = true;
        return JSValueMakeUndefined(ctx);
    }
    if (args[4] != iso->root_hole) {
        if (was_set) *was_set = true;
        return v8_unwrap_jsv(ctx, args[4]);
    }
    return NULL;
}

static bool v8_invoke_prop_setter(JSContextRef ctx, V8Isolate *iso, uint64_t cb, uint64_t data_addr,
                                  JSObjectRef obj, JSStringRef prop_name, JSValueRef val, JSValueRef *exception) {
    if (!iso) iso = g_cur_iso;
    if (!cb || !tls_v8_cpu) return false;

    uint64_t obj_addr = v8_wrap_jsv(iso, ctx, obj);
    uint64_t prop_addr = v8_wrap_jsv(iso, ctx, JSValueMakeString(ctx, prop_name));
    uint64_t val_addr  = v8_wrap_jsv(iso, ctx, val);
    uint64_t prop_h = v8_alloc_handle(iso, prop_addr);
    uint64_t val_h  = v8_alloc_handle(iso, val_addr);

    uint64_t args[7];
    args[0] = 0;
    args[1] = obj_addr;
    args[2] = (uint64_t)(uintptr_t)iso;
    args[3] = iso->root_undef;
    args[4] = iso->root_hole;
    args[5] = data_addr ? data_addr : iso->root_undef;
    args[6] = obj_addr;

    uint64_t info_ptr = (uint64_t)(uintptr_t)args;
    iso->pending_exc = 0;
    v8_call_win64(tls_v8_cpu, cb, prop_h, val_h, (uint64_t)(uintptr_t)&info_ptr, 0);

    if (iso->pending_exc) {
        JSValueRef ex = v8_unwrap_jsv(ctx, iso->pending_exc);
        iso->pending_exc = 0;
        if (exception) *exception = ex;
        return true;
    }
    return true;
}

/* ---- JSC custom class callbacks ---- */
static JSValueRef jsc_cb_get_prop(JSContextRef ctx, JSObjectRef obj, JSStringRef name, JSValueRef *exception) {
    V8InstData *d = (V8InstData *)JSObjectGetPrivate(obj);
    if (!d || !d->tmpl) return NULL;
    V8Tmpl *t = d->tmpl;
    char *cname = jsc_str_to_cstr(name, NULL);

    /* 1. Explicit SetAccessor / SetAccessorProperty */
    for (int i = t->naccs - 1; i >= 0; i--) {
        if (strcmp(t->accs[i].name, cname) == 0 && t->accs[i].getter_cb) {
            free(cname);
            if (t->accs[i].is_ftmpl) {
                V8Obj *fo = v8_untag(t->accs[i].getter_cb);
                V8Tmpl *ft = (fo && fo->kind == V8K_FTMPL) ? (V8Tmpl *)fo->aux : NULL;
                if (ft && ft->fn_cb)
                    return v8_invoke_fn_cb(ctx, d->iso, ft->fn_cb, ft->fn_data, obj, obj, 0, NULL, exception, false);
                return JSValueMakeUndefined(ctx);
            }
            bool was_set = false;
            JSValueRef r = v8_invoke_prop_getter(ctx, d->iso, t->accs[i].getter_cb, t->accs[i].data_addr,
                                                 obj, name, exception, &was_set);
            return was_set ? r : JSValueMakeUndefined(ctx);
        }
    }
    /* 2. NamedPropertyHandlerConfiguration getter */
    if (t->named_getter) {
        /* Skip built-in JS reflection properties so JSC handles them normally */
        if (strcmp(cname, "toString") != 0 && strcmp(cname, "valueOf") != 0 &&
            strcmp(cname, "constructor") != 0 && strcmp(cname, "__proto__") != 0 &&
            strcmp(cname, "hasOwnProperty") != 0 && strcmp(cname, "then") != 0) {
            bool was_set = false;
            JSValueRef r = v8_invoke_prop_getter(ctx, d->iso, t->named_getter, t->named_data,
                                                 obj, name, exception, &was_set);
            if (was_set) { free(cname); return r; }
        }
    }
    free(cname);
    return NULL;
}

static bool jsc_cb_set_prop(JSContextRef ctx, JSObjectRef obj, JSStringRef name, JSValueRef val, JSValueRef *exception) {
    V8InstData *d = (V8InstData *)JSObjectGetPrivate(obj);
    if (!d || !d->tmpl) return false;
    V8Tmpl *t = d->tmpl;
    char *cname = jsc_str_to_cstr(name, NULL);

    for (int i = t->naccs - 1; i >= 0; i--) {
        if (strcmp(t->accs[i].name, cname) == 0) {
            free(cname);
            if (!t->accs[i].setter_cb) return true;
            if (t->accs[i].is_ftmpl) {
                V8Obj *fo = v8_untag(t->accs[i].setter_cb);
                V8Tmpl *ft = (fo && fo->kind == V8K_FTMPL) ? (V8Tmpl *)fo->aux : NULL;
                if (ft && ft->fn_cb)
                    v8_invoke_fn_cb(ctx, d->iso, ft->fn_cb, ft->fn_data, obj, obj, 1, &val, exception, false);
                return true;
            }
            return v8_invoke_prop_setter(ctx, d->iso, t->accs[i].setter_cb, t->accs[i].data_addr,
                                         obj, name, val, exception);
        }
    }
    if (t->named_setter) {
        free(cname);
        return v8_invoke_prop_setter(ctx, d->iso, t->named_setter, t->named_data,
                                     obj, name, val, exception);
    }
    free(cname);
    return false;
}

static JSValueRef jsc_cb_call_fn(JSContextRef ctx, JSObjectRef fn, JSObjectRef this_obj,
                                 size_t argc, const JSValueRef argv[], JSValueRef *exception) {
    V8InstData *d = (V8InstData *)JSObjectGetPrivate(fn);
    if (!d) return JSValueMakeUndefined(ctx);
    uint64_t cb = d->fn_cb ? d->fn_cb : (d->tmpl ? d->tmpl->fn_cb : 0);
    uint64_t dt = d->fn_cb ? d->fn_data : (d->tmpl ? d->tmpl->fn_data : 0);
    return v8_invoke_fn_cb(ctx, d->iso, cb, dt, this_obj, this_obj ? this_obj : fn, argc, argv, exception, false);
}

static JSObjectRef jsc_cb_call_ctor(JSContextRef ctx, JSObjectRef ctor,
                                    size_t argc, const JSValueRef argv[], JSValueRef *exception) {
    V8InstData *d = (V8InstData *)JSObjectGetPrivate(ctor);
    if (!d || !d->tmpl) return JSObjectMake(ctx, NULL, NULL);
    V8Tmpl *inst_t = d->tmpl->inst_tmpl;
    JSObjectRef inst = inst_t ? v8_instantiate_tmpl(d->iso, ctx, inst_t) : JSObjectMake(ctx, g_v8_obj_class, calloc(1, sizeof(V8InstData)));
    if (d->tmpl->fn_cb) {
        JSValueRef r = v8_invoke_fn_cb(ctx, d->iso, d->tmpl->fn_cb, d->tmpl->fn_data, inst, inst, argc, argv, exception, true);
        if (r && JSValueIsObject(ctx, r)) {
            JSObjectRef ro = JSValueToObject(ctx, r, NULL);
            if (ro) return ro;
        }
    }
    return inst;
}

static void jsc_cb_finalize(JSObjectRef obj) {
    V8InstData *d = (V8InstData *)JSObjectGetPrivate(obj);
    free(d);
}

static void v8_init_jsc_classes(void) {
    if (g_v8_obj_class) return;
    JSClassDefinition def = kJSClassDefinitionEmpty;
    def.className = "V8Object";
    def.getProperty = jsc_cb_get_prop;
    def.setProperty = jsc_cb_set_prop;
    def.finalize    = jsc_cb_finalize;
    g_v8_obj_class = JSClassCreate(&def);

    JSClassDefinition fdef = kJSClassDefinitionEmpty;
    fdef.className = "V8Function";
    fdef.getProperty = jsc_cb_get_prop;
    fdef.setProperty = jsc_cb_set_prop;
    fdef.callAsFunction = jsc_cb_call_fn;
    fdef.callAsConstructor = jsc_cb_call_ctor;
    fdef.finalize = jsc_cb_finalize;
    g_v8_fn_class = JSClassCreate(&fdef);
}

static void v8_apply_tmpl_props(V8Isolate *iso, JSContextRef ctx, JSObjectRef target, V8Tmpl *tmpl) {
    if (!tmpl || !target) return;
    for (int i = 0; i < tmpl->nprops; i++) {
        JSStringRef k = JSStringCreateWithUTF8CString(tmpl->props[i].name);
        JSValueRef v = v8_unwrap_jsv(ctx, tmpl->props[i].val_addr);
        JSObjectSetProperty(ctx, target, k, v ? v : JSValueMakeUndefined(ctx), kJSPropertyAttributeNone, NULL);
        JSStringRelease(k);
    }
}

static void v8_set_function_proto(JSContextRef ctx, JSObjectRef jo) {
    if (!ctx || !jo) return;
    JSObjectRef g = JSContextGetGlobalObject(ctx);
    JSStringRef fk = JSStringCreateWithUTF8CString("Function");
    JSValueRef fv = JSObjectGetProperty(ctx, g, fk, NULL);
    JSStringRelease(fk);
    if (fv && JSValueIsObject(ctx, fv)) {
        JSObjectRef fo = JSValueToObject(ctx, fv, NULL);
        JSStringRef pk = JSStringCreateWithUTF8CString("prototype");
        JSValueRef pv = JSObjectGetProperty(ctx, fo, pk, NULL);
        JSStringRelease(pk);
        if (pv && JSValueIsObject(ctx, pv)) JSObjectSetPrototype(ctx, jo, pv);
    }
}

static JSObjectRef v8_instantiate_tmpl(V8Isolate *iso, JSContextRef ctx, V8Tmpl *tmpl) {
    v8_init_jsc_classes();
    V8InstData *d = (V8InstData *)calloc(1, sizeof(V8InstData));
    d->iso = iso ? iso : g_cur_iso;
    d->tmpl = tmpl;
    if (tmpl) {
        d->fn_cb = tmpl->fn_cb;
        d->fn_data = tmpl->fn_data;
        d->internal_field_count = tmpl->internal_field_count;
    }
    bool is_fn = (tmpl && (tmpl->is_func || tmpl->fn_cb));
    JSObjectRef jo = JSObjectMake(ctx, is_fn ? g_v8_fn_class : g_v8_obj_class, d);
    if (is_fn) v8_set_function_proto(ctx, jo);
    d->js_obj = jo;
    if (tmpl) v8_apply_tmpl_props(d->iso, ctx, jo, tmpl);
    return jo;
}

/* ---- Helpers for MSVC sret return conventions ---- */
static inline void ret_sret64(CPU64 *c, uint64_t sret, uint64_t val) {
    if (sret) W64(sret, val);
    c->rax = sret;
}
static inline void ret_maybe_bool(CPU64 *c, uint64_t sret, bool has, bool val) {
    if (sret) { W8(sret, has ? 1 : 0); W8(sret + 1, val ? 1 : 0); }
    c->rax = sret;
}
static inline void ret_maybe_i32(CPU64 *c, uint64_t sret, bool has, uint32_t val) {
    if (sret) { W8(sret, has ? 1 : 0); W32(sret + 4, val); }
    c->rax = sret;
}
static inline void ret_maybe_f64(CPU64 *c, uint64_t sret, bool has, double val) {
    uint64_t bits = 0; memcpy(&bits, &val, 8);
    if (sret) { W8(sret, has ? 1 : 0); W64(sret + 8, bits); }
    c->rax = sret;
}

/* ============================================================================
 * 1. V8 global / Platform / Isolate / HandleScope / TryCatch
 * ============================================================================ */

static void v8_GetVersion(CPU64 *c, void *ud) {
    (void)ud;
    static const char ver[] = "10.0.0-jsc";
    c->rax = (uint64_t)(uintptr_t)ver;
}
static void v8_InitTrue(CPU64 *c, void *ud) { (void)ud; v8_init_cage(); v8_init_jsc_classes(); c->rax = 1; }
static void v8_Noop(CPU64 *c, void *ud)     { (void)ud; c->rax = 0; }

static void v8_NewDefaultPlatform(CPU64 *c, void *ud) {
    (void)ud;
    /* Static returning std::unique_ptr<Platform> via sret in rcx */
    static uint64_t dummy_platform_vt[16];
    static uint64_t dummy_platform = (uint64_t)(uintptr_t)dummy_platform_vt;
    ret_sret64(c, c->rcx, (uint64_t)(uintptr_t)&dummy_platform);
}

static void v8_CreateParams_ctor(CPU64 *c, void *ud) {
    (void)ud;
    /* Zero-init Isolate::CreateParams (size ~96 bytes; zeroing 80 bytes safely) */
    if (c->rcx) memset((void *)(uintptr_t)c->rcx, 0, 80);
    c->rax = c->rcx;
}
static void v8_CreateParams_dtor(CPU64 *c, void *ud) { (void)ud; (void)c; }

static void v8_Isolate_New(CPU64 *c, void *ud) {
    (void)ud;
    v8_init_cage();
    v8_init_jsc_classes();
    V8Isolate *iso = (V8Isolate *)calloc(1, sizeof(V8Isolate));
    iso->root_undef = v8_tag(&g_objs[0]);
    iso->root_hole  = v8_tag(&g_objs[1]);
    iso->root_null  = v8_tag(&g_objs[2]);
    iso->root_true  = v8_tag(&g_objs[3]);
    iso->root_false = v8_tag(&g_objs[4]);
    iso->group      = JSContextGroupCreate();
    iso->handles    = (uint64_t *)calloc(V8_MAX_HANDLES, sizeof(uint64_t));
    iso->globals    = (uint64_t *)calloc(V8_MAX_GLOBALS, sizeof(uint64_t));
    iso->global_used = (uint8_t *)calloc(V8_MAX_GLOBALS, 1);

    /* Create a default JSC context so String/Object/Array work even before Context::New */
    V8Context *dctx = (V8Context *)calloc(1, sizeof(V8Context));
    dctx->iso = iso;
    dctx->jsc = JSGlobalContextCreateInGroup(iso->group, NULL);
    iso->default_ctx = dctx;
    g_cur_iso = iso;
    c->rax = (uint64_t)(uintptr_t)iso;
}
static void v8_Isolate_Dispose(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rcx;
    if (iso && iso == g_cur_iso) g_cur_iso = NULL;
    /* Keep allocations intact to avoid dangling pointers during shutdown */
}
static void v8_Isolate_Enter(CPU64 *c, void *ud) { (void)ud; if (c->rcx) g_cur_iso = (V8Isolate *)(uintptr_t)c->rcx; }
static void v8_Isolate_Exit(CPU64 *c, void *ud)  { (void)ud; (void)c; }
static void v8_Isolate_GetCurrent(CPU64 *c, void *ud) { (void)ud; c->rax = (uint64_t)(uintptr_t)g_cur_iso; }
static void v8_IsolateFromObj(CPU64 *c, void *ud)     { (void)ud; c->rax = (uint64_t)(uintptr_t)g_cur_iso; }
static void v8_Isolate_SetFatal(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rcx;
    if (iso) iso->fatal_cb = c->rdx;
}
static void v8_Isolate_GetCurrentContext(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rcx;
    if (!iso) iso = g_cur_iso;
    V8Context *ctx = (iso && iso->ctx_depth > 0) ? iso->ctx_stack[iso->ctx_depth - 1] : (iso ? iso->default_ctx : NULL);
    if (!ctx) { ret_sret64(c, c->rdx, 0); return; }
    V8Obj *co = v8_alloc_obj(g_map_obj, V8K_CTX);
    co->aux = ctx;
    ret_sret64(c, c->rdx, v8_alloc_handle(iso, v8_tag(co)));
}
static void v8_Isolate_ThrowException(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rcx;
    uint64_t sret = c->rdx;
    uint64_t exc_h = c->r8;
    if (!iso) iso = g_cur_iso;
    uint64_t addr = exc_h ? R64(exc_h) : (iso ? iso->root_undef : 0);
    if (iso) {
        iso->pending_exc = addr;
        JSContextRef jsc = v8_active_jsc(iso, 0);
        if (iso->tc_top && jsc) v8_record_exception(iso, jsc, v8_unwrap_jsv(jsc, addr));
    }
    ret_sret64(c, sret, v8_alloc_handle(iso, iso ? iso->root_undef : 0));
}
static void v8_Isolate_IdleNotif(CPU64 *c, void *ud) { (void)ud; c->rax = 1; }
static void v8_Isolate_CtxDisposed(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }

/* HandleScope / EscapableHandleScope / Globalize */
static void v8_HandleScope_ctor(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    if (!iso) iso = g_cur_iso;
    if (c->rcx) {
        W64(c->rcx + 0, (uint64_t)(uintptr_t)iso);
        W64(c->rcx + 8, iso ? (uint64_t)iso->handle_top : 0);
        W64(c->rcx + 16, 0);
    }
    c->rax = c->rcx;
}
static void v8_EscapableHandleScope_ctor(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    if (!iso) iso = g_cur_iso;
    uint64_t esc_slot = iso ? v8_alloc_handle(iso, iso->root_undef) : 0;
    if (c->rcx) {
        W64(c->rcx + 0, (uint64_t)(uintptr_t)iso);
        W64(c->rcx + 8, iso ? (uint64_t)iso->handle_top : 0);
        W64(c->rcx + 16, esc_slot);
    }
    c->rax = c->rcx;
}
static void v8_HandleScope_dtor(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) return;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)R64(c->rcx + 0);
    uint32_t prev = (uint32_t)R64(c->rcx + 8);
    if (iso && prev <= iso->handle_top) iso->handle_top = prev;
}
static void v8_HandleScope_CreateHandle(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rcx;
    c->rax = v8_alloc_handle(iso, c->rdx);
}
static void v8_Escapable_Escape(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t val_slot = c->rdx;
    uint64_t esc_slot = c->rcx ? R64(c->rcx + 16) : 0;
    if (esc_slot && val_slot) {
        W64(esc_slot, R64(val_slot));
        c->rax = esc_slot;
    } else {
        c->rax = val_slot;
    }
}
static void v8_GlobalizeReference(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rcx;
    if (!iso) iso = g_cur_iso;
    uint64_t src = c->rdx;
    if (!iso || !src) { c->rax = 0; return; }
    uint64_t val = R64(src);
    for (uint32_t i = 0; i < V8_MAX_GLOBALS; i++) {
        uint32_t idx = (iso->global_hint + i) % V8_MAX_GLOBALS;
        if (!iso->global_used[idx]) {
            iso->global_used[idx] = 1;
            iso->globals[idx] = val;
            iso->global_hint = (idx + 1) % V8_MAX_GLOBALS;
            c->rax = (uint64_t)(uintptr_t)&iso->globals[idx];
            return;
        }
    }
    c->rax = 0;
}
static void v8_DisposeGlobal(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = g_cur_iso;
    uint64_t gptr = c->rcx;
    if (!iso || !gptr) return;
    uintptr_t base = (uintptr_t)iso->globals;
    if (gptr >= base && gptr < base + V8_MAX_GLOBALS * sizeof(uint64_t)) {
        uint32_t idx = (uint32_t)((gptr - base) / sizeof(uint64_t));
        iso->global_used[idx] = 0;
        iso->globals[idx] = 0;
    }
}

/* TryCatch */
static void v8_TryCatch_ctor(CPU64 *c, void *ud) {
    (void)ud;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    if (!iso) iso = g_cur_iso;
    V8TryCatchNode *n = (V8TryCatchNode *)calloc(1, sizeof(V8TryCatchNode));
    n->guest_tc = c->rcx;
    if (iso) { n->prev = iso->tc_top; iso->tc_top = n; }
    if (c->rcx) W64(c->rcx, (uint64_t)(uintptr_t)n);
    c->rax = c->rcx;
}
static void v8_TryCatch_dtor(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) return;
    V8TryCatchNode *n = (V8TryCatchNode *)(uintptr_t)R64(c->rcx);
    V8Isolate *iso = g_cur_iso;
    if (iso && iso->tc_top == n) iso->tc_top = n->prev;
    if (n) { free(n->msg_str); free(n->src_name); free(n); }
}
static void v8_TryCatch_HasCaught(CPU64 *c, void *ud) {
    (void)ud;
    V8TryCatchNode *n = c->rcx ? (V8TryCatchNode *)(uintptr_t)R64(c->rcx) : NULL;
    c->rax = (n && n->exc_addr != 0) ? 1 : 0;
}
static void v8_TryCatch_Reset(CPU64 *c, void *ud) {
    (void)ud;
    V8TryCatchNode *n = c->rcx ? (V8TryCatchNode *)(uintptr_t)R64(c->rcx) : NULL;
    if (n) { n->exc_addr = 0; free(n->msg_str); n->msg_str = NULL; }
}
static void v8_TryCatch_Exception(CPU64 *c, void *ud) {
    (void)ud;
    V8TryCatchNode *n = c->rcx ? (V8TryCatchNode *)(uintptr_t)R64(c->rcx) : NULL;
    uint64_t h = (n && n->exc_addr) ? v8_alloc_handle(g_cur_iso, n->exc_addr) : 0;
    ret_sret64(c, c->rdx, h);
}
static void v8_TryCatch_Message(CPU64 *c, void *ud) {
    (void)ud;
    V8TryCatchNode *n = c->rcx ? (V8TryCatchNode *)(uintptr_t)R64(c->rcx) : NULL;
    if (!n || !n->exc_addr) { ret_sret64(c, c->rdx, 0); return; }
    V8MsgData *m = (V8MsgData *)calloc(1, sizeof(V8MsgData));
    m->message = strdup(n->msg_str ? n->msg_str : "JS Error");
    m->resource_name = strdup(n->src_name ? n->src_name : "<panorama>");
    m->source_line = strdup("");
    m->line = n->line > 0 ? n->line : 1;
    m->col = n->col;
    V8Obj *mo = v8_alloc_obj(g_map_obj, V8K_MSG);
    mo->aux = m;
    ret_sret64(c, c->rdx, v8_alloc_handle(g_cur_iso, v8_tag(mo)));
}
static void v8_TryCatch_StackTrace(CPU64 *c, void *ud) {
    (void)ud;
    V8TryCatchNode *n = c->rcx ? (V8TryCatchNode *)(uintptr_t)R64(c->rcx) : NULL;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!n || !n->exc_addr || !jsc) { ret_sret64(c, c->rdx, 0); return; }
    JSStringRef s = JSStringCreateWithUTF8CString(n->msg_str ? n->msg_str : "");
    JSValueRef sv = JSValueMakeString(jsc, s);
    JSStringRelease(s);
    ret_sret64(c, c->rdx, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, sv)));
}

/* ============================================================================
 * 2. Context
 * ============================================================================ */

static void v8_Context_New(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev_cpu = tls_v8_cpu; tls_v8_cpu = c;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    if (!iso) iso = g_cur_iso;
    uint64_t global_tmpl_h = c->r9;

    V8Context *vctx = (V8Context *)calloc(1, sizeof(V8Context));
    vctx->iso = iso;
    V8Obj *gto = v8_from_local(global_tmpl_h);
    V8Tmpl *gt = (gto && (gto->kind == V8K_OTMPL || gto->kind == V8K_FTMPL)) ? (V8Tmpl *)gto->aux : NULL;
    vctx->global_tmpl = gt;

    v8_init_jsc_classes();
    vctx->jsc = JSGlobalContextCreateInGroup(iso->group, gt ? g_v8_obj_class : NULL);
    JSObjectRef gobj = JSContextGetGlobalObject(vctx->jsc);
    if (gt && gobj) {
        V8InstData *d = (V8InstData *)calloc(1, sizeof(V8InstData));
        d->iso = iso; d->tmpl = gt; d->internal_field_count = gt->internal_field_count; d->js_obj = gobj;
        JSObjectSetPrivate(gobj, d);
        v8_apply_tmpl_props(iso, vctx->jsc, gobj, gt);
    }
    vctx->global_addr = v8_wrap_jsv(iso, vctx->jsc, gobj);
    vctx->sec_token = iso->root_undef;

    V8Obj *co = v8_alloc_obj(g_map_obj, V8K_CTX);
    co->aux = vctx;
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_tag(co)));
    tls_v8_cpu = prev_cpu;
}
static void v8_Context_Enter(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *co = v8_from_local(c->rcx);
    if (co && co->kind == V8K_CTX && co->aux) {
        V8Context *vctx = (V8Context *)co->aux;
        V8Isolate *iso = vctx->iso ? vctx->iso : g_cur_iso;
        if (iso && iso->ctx_depth < 64) iso->ctx_stack[iso->ctx_depth++] = vctx;
    }
}
static void v8_Context_Exit(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *co = v8_from_local(c->rcx);
    V8Isolate *iso = (co && co->kind == V8K_CTX && co->aux) ? ((V8Context *)co->aux)->iso : g_cur_iso;
    if (iso && iso->ctx_depth > 0) iso->ctx_depth--;
}
static void v8_Context_GetIsolate(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *co = v8_from_local(c->rcx);
    V8Isolate *iso = (co && co->kind == V8K_CTX && co->aux) ? ((V8Context *)co->aux)->iso : g_cur_iso;
    c->rax = (uint64_t)(uintptr_t)iso;
}
static void v8_Context_Global(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *co = v8_from_local(c->rcx);
    V8Context *vctx = (co && co->kind == V8K_CTX) ? (V8Context *)co->aux : NULL;
    if (!vctx) { ret_sret64(c, c->rdx, 0); return; }
    ret_sret64(c, c->rdx, v8_alloc_handle(vctx->iso, vctx->global_addr));
}
static void v8_Context_GetSecToken(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *co = v8_from_local(c->rcx);
    V8Context *vctx = (co && co->kind == V8K_CTX) ? (V8Context *)co->aux : NULL;
    uint64_t tok = vctx ? vctx->sec_token : (g_cur_iso ? g_cur_iso->root_undef : 0);
    ret_sret64(c, c->rdx, v8_alloc_handle(g_cur_iso, tok));
}
static void v8_Context_SetSecToken(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *co = v8_from_local(c->rcx);
    V8Context *vctx = (co && co->kind == V8K_CTX) ? (V8Context *)co->aux : NULL;
    if (vctx && c->rdx) vctx->sec_token = R64(c->rdx);
}

/* ============================================================================
 * 3. Primitives: String, Number, Integer, BigInt, Boolean, External, Date
 * ============================================================================ */

static uint64_t v8_make_str_handle(V8Isolate *iso, const char *s, int len) {
    if (!iso) iso = g_cur_iso;
    if (!s) { s = ""; len = 0; }
    if (len < 0) len = (int)strlen(s);
    char *copy = (char *)malloc((size_t)len + 1);
    memcpy(copy, s, (size_t)len);
    copy[len] = '\0';
    JSContextRef jsc = v8_active_jsc(iso, 0);
    V8Obj *o = v8_alloc_obj(g_map_str, V8K_STR);
    o->aux = copy;
    o->aux2 = (uint64_t)len;
    if (jsc) {
        JSStringRef js = JSStringCreateWithUTF8CString(copy);
        o->jsv = JSValueMakeString(jsc, js);
        JSValueProtect(jsc, o->jsv);
        JSStringRelease(js);
    }
    return v8_alloc_handle(iso, v8_tag(o));
}

static void v8_String_NewFromUtf8(CPU64 *c, void *ud) {
    (void)ud;
    /* Static: rcx=sret, rdx=iso, r8=data, r9=type, arg4=length */
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    const char *data = (const char *)(uintptr_t)c->r8;
    int len = (int)(int32_t)win64_arg_i(c, 4);
    ret_sret64(c, sret, v8_make_str_handle(iso, data, len));
}
static void v8_String_NewExternalOneByte(CPU64 *c, void *ud) {
    (void)ud;
    /* Static: rcx=sret, rdx=iso, r8=ExternalOneByteStringResource* */
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    uint64_t res = c->r8;
    if (!res) { ret_sret64(c, sret, 0); return; }
    uint64_t vt = R64(res);
    uint64_t data_fn = vt ? R64(vt + 0x28) : 0; /* slot 5: data() */
    uint64_t len_fn  = vt ? R64(vt + 0x30) : 0; /* slot 6: length() */
    const char *ptr = data_fn ? (const char *)(uintptr_t)v8_call_win64(c, data_fn, res, 0, 0, 0) : "";
    int len = len_fn ? (int)v8_call_win64(c, len_fn, res, 0, 0, 0) : -1;
    ret_sret64(c, sret, v8_make_str_handle(iso, ptr, len));
}
static void v8_Utf8Value_ctor(CPU64 *c, void *ud) {
    (void)ud;
    /* Member: rcx=this, rdx=iso, r8=Local<Value> */
    uint64_t self = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    uint64_t val_h = c->r8;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    size_t len = 0;
    char *str = NULL;
    if (val_h) {
        V8Obj *o = v8_from_local(val_h);
        if (o && o->kind == V8K_STR && o->aux) {
            len = (size_t)o->aux2;
            str = (char *)malloc(len + 1);
            memcpy(str, o->aux, len + 1);
        } else if (o && jsc) {
            str = jsc_val_to_cstr(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &len);
        }
    }
    if (!str) { str = strdup(""); len = 0; }
    if (self) {
        W64(self + 0, (uint64_t)(uintptr_t)str);
        W32(self + 8, (uint32_t)len);
    }
    c->rax = self;
}
static void v8_Utf8Value_dtor(CPU64 *c, void *ud) {
    (void)ud;
    if (!c->rcx) return;
    char *s = (char *)(uintptr_t)R64(c->rcx);
    free(s);
    W64(c->rcx, 0);
}

static void v8_Number_New(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    double val = win64_arg_d(c, 2);
    JSContextRef jsc = v8_active_jsc(iso, 0);
    V8Obj *o = v8_alloc_obj(g_map_num, V8K_NUM);
    o->num_val = val;
    if (jsc) { o->jsv = JSValueMakeNumber(jsc, val); JSValueProtect(jsc, o->jsv); }
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_tag(o)));
}
static void v8_Integer_New(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    double val = (double)(int32_t)c->r8;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    V8Obj *o = v8_alloc_obj(g_map_num, V8K_NUM);
    o->num_val = val;
    if (jsc) { o->jsv = JSValueMakeNumber(jsc, val); JSValueProtect(jsc, o->jsv); }
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_tag(o)));
}
static void v8_Integer_NewUnsigned(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    double val = (double)(uint32_t)c->r8;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    V8Obj *o = v8_alloc_obj(g_map_num, V8K_NUM);
    o->num_val = val;
    if (jsc) { o->jsv = JSValueMakeNumber(jsc, val); JSValueProtect(jsc, o->jsv); }
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_tag(o)));
}
static void v8_BigInt_New(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    double val = (double)(int64_t)c->r8;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    V8Obj *o = v8_alloc_obj(g_map_num, V8K_BIGINT);
    o->num_val = val;
    if (jsc) { o->jsv = JSValueMakeNumber(jsc, val); JSValueProtect(jsc, o->jsv); }
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_tag(o)));
}
static void v8_Date_New(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->rdx);
    double ms = win64_arg_d(c, 2);
    if (!jsc) { ret_sret64(c, sret, 0); return; }
    JSValueRef arg = JSValueMakeNumber(jsc, ms);
    JSObjectRef d = JSObjectMakeDate(jsc, 1, &arg, NULL);
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_DATE);
    o->jsv = d; if (d) JSValueProtect(jsc, d);
    o->num_val = ms;
    ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_tag(o)));
}
static void v8_External_New(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_EXT);
    o->aux = (void *)(uintptr_t)c->r8;
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_tag(o)));
}
static void v8_External_Value(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    c->rax = (o && o->kind == V8K_EXT) ? (uint64_t)(uintptr_t)o->aux : 0;
}
static void v8_Boolean_Value(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    c->rax = (o && o->kind == V8K_BOOL && o->num_val != 0.0) ? 1 : 0;
}
static void v8_Number_Value(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    double d = o ? o->num_val : 0.0;
    c->xmm[0].df[0] = d;
}

/* ============================================================================
 * 4. Value type predicates & conversions
 * ============================================================================ */

static void v8_Value_IsArray(CPU64 *c, void *ud)   { (void)ud; V8Obj *o = v8_from_local(c->rcx); c->rax = (o && o->kind == V8K_ARR) ? 1 : 0; }
static void v8_Value_IsBoolean(CPU64 *c, void *ud) { (void)ud; V8Obj *o = v8_from_local(c->rcx); c->rax = (o && o->kind == V8K_BOOL) ? 1 : 0; }
static void v8_Value_IsDate(CPU64 *c, void *ud)    { (void)ud; V8Obj *o = v8_from_local(c->rcx); c->rax = (o && o->kind == V8K_DATE) ? 1 : 0; }
static void v8_Value_IsExternal(CPU64 *c, void *ud){ (void)ud; V8Obj *o = v8_from_local(c->rcx); c->rax = (o && o->kind == V8K_EXT) ? 1 : 0; }
static void v8_Value_IsFunction(CPU64 *c, void *ud){ (void)ud; V8Obj *o = v8_from_local(c->rcx); c->rax = (o && o->kind == V8K_FUNC) ? 1 : 0; }
static void v8_Value_IsNumber(CPU64 *c, void *ud)  { (void)ud; V8Obj *o = v8_from_local(c->rcx); c->rax = (o && o->kind == V8K_NUM) ? 1 : 0; }
static void v8_Value_IsInt32(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    c->rax = (o && o->kind == V8K_NUM && o->num_val == (double)(int32_t)o->num_val) ? 1 : 0;
}
static void v8_Value_IsUint32(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    c->rax = (o && o->kind == V8K_NUM && o->num_val >= 0.0 && o->num_val == (double)(uint32_t)o->num_val) ? 1 : 0;
}
static void v8_Value_IsObject(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    c->rax = (o && (o->kind == V8K_OBJ || o->kind == V8K_FUNC || o->kind == V8K_ARR ||
                    o->kind == V8K_DATE || o->kind == V8K_AB || o->kind == V8K_U8)) ? 1 : 0;
}
static void v8_Value_BooleanValue(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc((V8Isolate *)(uintptr_t)c->rdx, 0);
    if (!o || !jsc) { c->rax = 0; return; }
    c->rax = JSValueToBoolean(jsc, v8_unwrap_jsv(jsc, v8_tag(o))) ? 1 : 0;
}
static void v8_Value_ToBoolean(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->r8;
    if (!iso) iso = g_cur_iso;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    bool b = (o && jsc) ? JSValueToBoolean(jsc, v8_unwrap_jsv(jsc, v8_tag(o))) : false;
    ret_sret64(c, c->rdx, v8_alloc_handle(iso, b ? iso->root_true : iso->root_false));
}
static void v8_Value_Int32Value(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!o || !jsc) { ret_maybe_i32(c, c->rdx, false, 0); return; }
    JSValueRef exc = NULL;
    double d = JSValueToNumber(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    if (exc) { ret_maybe_i32(c, c->rdx, false, 0); return; }
    int32_t v = (isnan(d) || isinf(d)) ? 0 : (int32_t)(int64_t)d;
    ret_maybe_i32(c, c->rdx, true, (uint32_t)v);
}
static void v8_Value_Uint32Value(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!o || !jsc) { ret_maybe_i32(c, c->rdx, false, 0); return; }
    JSValueRef exc = NULL;
    double d = JSValueToNumber(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    if (exc) { ret_maybe_i32(c, c->rdx, false, 0); return; }
    uint32_t v = (isnan(d) || isinf(d)) ? 0u : (uint32_t)(int64_t)d;
    ret_maybe_i32(c, c->rdx, true, v);
}
static void v8_Value_NumberValue(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!o || !jsc) { ret_maybe_f64(c, c->rdx, false, 0.0); return; }
    JSValueRef exc = NULL;
    double d = JSValueToNumber(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    if (exc) { ret_maybe_f64(c, c->rdx, false, 0.0); return; }
    ret_maybe_f64(c, c->rdx, true, d);
}
static void v8_Value_ToNumber(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!o || !jsc) { ret_sret64(c, c->rdx, 0); return; }
    JSValueRef exc = NULL;
    double d = JSValueToNumber(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    if (exc) { ret_sret64(c, c->rdx, 0); return; }
    ret_sret64(c, c->rdx, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, JSValueMakeNumber(jsc, d))));
}
static void v8_Value_ToUint32(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!o || !jsc) { ret_sret64(c, c->rdx, 0); return; }
    JSValueRef exc = NULL;
    double d = JSValueToNumber(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    if (exc) { ret_sret64(c, c->rdx, 0); return; }
    uint32_t u = (isnan(d) || isinf(d)) ? 0u : (uint32_t)(int64_t)d;
    ret_sret64(c, c->rdx, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, JSValueMakeNumber(jsc, (double)u))));
}
static void v8_Value_ToString(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!o || !jsc) { ret_sret64(c, c->rdx, 0); return; }
    JSValueRef exc = NULL;
    JSStringRef s = JSValueToStringCopy(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    if (exc || !s) { ret_sret64(c, c->rdx, 0); return; }
    JSValueRef sv = JSValueMakeString(jsc, s);
    JSStringRelease(s);
    ret_sret64(c, c->rdx, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, sv)));
}
static void v8_Value_ToObject(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!o || !jsc) { ret_sret64(c, c->rdx, 0); return; }
    JSValueRef exc = NULL;
    JSObjectRef jo = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    if (exc || !jo) { ret_sret64(c, c->rdx, 0); return; }
    ret_sret64(c, c->rdx, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, jo)));
}
static void v8_Value_StrictEquals(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *a = v8_from_local(c->rcx);
    V8Obj *b = v8_from_local(c->rdx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (!a || !b || !jsc) { c->rax = (a == b) ? 1 : 0; return; }
    c->rax = JSValueIsStrictEqual(jsc, v8_unwrap_jsv(jsc, v8_tag(a)), v8_unwrap_jsv(jsc, v8_tag(b))) ? 1 : 0;
}
static void v8_Value_TypeOf(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->r8;
    const char *tn = "undefined";
    if (o) {
        switch (o->kind) {
            case V8K_UNDEF: tn = "undefined"; break;
            case V8K_BOOL:  tn = "boolean"; break;
            case V8K_NUM:   tn = "number"; break;
            case V8K_BIGINT:tn = "bigint"; break;
            case V8K_STR:   tn = "string"; break;
            case V8K_FUNC:  tn = "function"; break;
            default:        tn = "object"; break;
        }
    }
    ret_sret64(c, c->rdx, v8_make_str_handle(iso, tn, -1));
}

/* ============================================================================
 * 5. Object, Array, ArrayBuffer, Uint8Array, Function
 * ============================================================================ */

static void v8_Object_New(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    JSObjectRef jo = jsc ? JSObjectMake(jsc, NULL, NULL) : NULL;
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_wrap_jsv(iso, jsc, jo)));
}
static void v8_Object_Get_Key(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    V8Obj *o = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    V8Obj *k = v8_from_local(c->r9);
    if (!o || !k || !jsc) { ret_sret64(c, sret, 0); tls_v8_cpu = prev; return; }
    JSValueRef exc = NULL;
    JSObjectRef jo = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    JSStringRef ks = JSValueToStringCopy(jsc, v8_unwrap_jsv(jsc, v8_tag(k)), &exc);
    JSValueRef res = (jo && ks && !exc) ? JSObjectGetProperty(jsc, jo, ks, &exc) : NULL;
    if (ks) JSStringRelease(ks);
    if (exc) { v8_record_exception(g_cur_iso, jsc, exc); ret_sret64(c, sret, 0); }
    else     { ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, res))); }
    tls_v8_cpu = prev;
}
static void v8_Object_Get_Idx(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    V8Obj *o = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    uint32_t idx = (uint32_t)c->r9;
    if (!o || !jsc) { ret_sret64(c, sret, 0); tls_v8_cpu = prev; return; }
    JSValueRef exc = NULL;
    JSObjectRef jo = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    JSValueRef res = (jo && !exc) ? JSObjectGetPropertyAtIndex(jsc, jo, idx, &exc) : NULL;
    if (exc) { v8_record_exception(g_cur_iso, jsc, exc); ret_sret64(c, sret, 0); }
    else     { ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, res))); }
    tls_v8_cpu = prev;
}
static void v8_Object_Set_Key(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    V8Obj *o = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    V8Obj *k = v8_from_local(c->r9);
    V8Obj *v = v8_from_local(win64_arg_i(c, 4));
    if (!o || !k || !jsc) { ret_maybe_bool(c, sret, false, false); tls_v8_cpu = prev; return; }
    JSValueRef exc = NULL;
    JSObjectRef jo = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    JSStringRef ks = JSValueToStringCopy(jsc, v8_unwrap_jsv(jsc, v8_tag(k)), &exc);
    JSValueRef jv = v ? v8_unwrap_jsv(jsc, v8_tag(v)) : JSValueMakeUndefined(jsc);
    if (jo && ks && !exc) JSObjectSetProperty(jsc, jo, ks, jv, kJSPropertyAttributeNone, &exc);
    if (ks) JSStringRelease(ks);
    if (exc) { v8_record_exception(g_cur_iso, jsc, exc); ret_maybe_bool(c, sret, false, false); }
    else     { ret_maybe_bool(c, sret, true, true); }
    tls_v8_cpu = prev;
}
static void v8_Object_Set_Idx(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    V8Obj *o = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    uint32_t idx = (uint32_t)c->r9;
    V8Obj *v = v8_from_local(win64_arg_i(c, 4));
    if (!o || !jsc) { ret_maybe_bool(c, sret, false, false); tls_v8_cpu = prev; return; }
    JSValueRef exc = NULL;
    JSObjectRef jo = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    JSValueRef jv = v ? v8_unwrap_jsv(jsc, v8_tag(v)) : JSValueMakeUndefined(jsc);
    if (jo && !exc) JSObjectSetPropertyAtIndex(jsc, jo, idx, jv, &exc);
    if (exc) { v8_record_exception(g_cur_iso, jsc, exc); ret_maybe_bool(c, sret, false, false); }
    else     { ret_maybe_bool(c, sret, true, true); }
    tls_v8_cpu = prev;
}
static void v8_Object_Delete(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    V8Obj *k = v8_from_local(c->r9);
    if (!o || !k || !jsc) { ret_maybe_bool(c, sret, false, false); return; }
    JSValueRef exc = NULL;
    JSObjectRef jo = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), &exc);
    JSStringRef ks = JSValueToStringCopy(jsc, v8_unwrap_jsv(jsc, v8_tag(k)), &exc);
    bool ok = (jo && ks && !exc) ? JSObjectDeleteProperty(jsc, jo, ks, &exc) : false;
    if (ks) JSStringRelease(ks);
    ret_maybe_bool(c, sret, !exc, ok);
}
static void v8_Object_GetPropertyNames(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    if (!o || !jsc) { ret_sret64(c, sret, 0); return; }
    JSObjectRef jo = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), NULL);
    JSObjectRef arr = JSObjectMakeArray(jsc, 0, NULL, NULL);
    if (jo && arr) {
        JSPropertyNameArrayRef names = JSObjectCopyPropertyNames(jsc, jo);
        size_t n = JSPropertyNameArrayGetCount(names);
        for (size_t i = 0; i < n; i++) {
            JSValueRef s = JSValueMakeString(jsc, JSPropertyNameArrayGetNameAtIndex(names, i));
            JSObjectSetPropertyAtIndex(jsc, arr, (unsigned)i, s, NULL);
        }
        JSPropertyNameArrayRelease(names);
    }
    ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, arr)));
}
static void v8_Object_InternalFieldCount(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (!o || !jsc || !o->jsv || !JSValueIsObject(jsc, o->jsv)) { c->rax = 0; return; }
    JSObjectRef jo = JSValueToObject(jsc, o->jsv, NULL);
    V8InstData *d = jo ? (V8InstData *)JSObjectGetPrivate(jo) : NULL;
    c->rax = d ? (uint64_t)(int64_t)d->internal_field_count : 0;
}
static void v8_Object_SetInternalField(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    int idx = (int)(int32_t)c->rdx;
    uint64_t val_h = c->r8;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (!o || !jsc || !o->jsv || idx < 0 || idx >= V8_MAX_FIELDS) return;
    JSObjectRef jo = JSValueToObject(jsc, o->jsv, NULL);
    V8InstData *d = jo ? (V8InstData *)JSObjectGetPrivate(jo) : NULL;
    if (d) {
        d->internal_fields[idx] = val_h ? R64(val_h) : (g_cur_iso ? g_cur_iso->root_undef : 0);
        if (idx >= d->internal_field_count) d->internal_field_count = idx + 1;
    }
}
static void v8_Object_SlowGetInternalField(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    int idx = (int)(int32_t)c->r8;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    uint64_t addr = g_cur_iso ? g_cur_iso->root_undef : 0;
    if (o && jsc && o->jsv && idx >= 0 && idx < V8_MAX_FIELDS) {
        JSObjectRef jo = JSValueToObject(jsc, o->jsv, NULL);
        V8InstData *d = jo ? (V8InstData *)JSObjectGetPrivate(jo) : NULL;
        if (d && d->internal_fields[idx]) addr = d->internal_fields[idx];
    }
    ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, addr));
}
static void v8_Object_CallAsConstructor(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    V8Obj *o = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    int argc = (int)(int32_t)c->r9;
    uint64_t argv_ptr = win64_arg_i(c, 4);
    if (!o || !jsc) { ret_sret64(c, sret, 0); tls_v8_cpu = prev; return; }
    JSObjectRef jo = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(o)), NULL);
    JSValueRef args[64];
    int n = (argc > 64) ? 64 : (argc < 0 ? 0 : argc);
    for (int i = 0; i < n; i++) {
        uint64_t h = argv_ptr ? R64(argv_ptr + (uint64_t)i * 8ULL) : 0;
        args[i] = h ? v8_unwrap_jsv(jsc, R64(h)) : JSValueMakeUndefined(jsc);
    }
    JSValueRef exc = NULL;
    JSObjectRef res = jo ? JSObjectCallAsConstructor(jsc, jo, (size_t)n, args, &exc) : NULL;
    if (exc || !res) { v8_record_exception(g_cur_iso, jsc, exc); ret_sret64(c, sret, 0); }
    else             { ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, res))); }
    tls_v8_cpu = prev;
}

/* Array / ArrayBuffer / Uint8Array */
static void v8_Array_New_Len(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    int len = (int)(int32_t)c->r8;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    JSObjectRef arr = jsc ? JSObjectMakeArray(jsc, 0, NULL, NULL) : NULL;
    if (jsc && arr && len > 0) {
        JSStringRef lk = JSStringCreateWithUTF8CString("length");
        JSObjectSetProperty(jsc, arr, lk, JSValueMakeNumber(jsc, (double)len), kJSPropertyAttributeNone, NULL);
        JSStringRelease(lk);
    }
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_wrap_jsv(iso, jsc, arr)));
}
static void v8_Array_New_Elems(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    uint64_t elems = c->r8;
    size_t len = (size_t)c->r9;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    JSObjectRef arr = jsc ? JSObjectMakeArray(jsc, 0, NULL, NULL) : NULL;
    if (jsc && arr && elems) {
        for (size_t i = 0; i < len; i++) {
            uint64_t h = R64(elems + i * 8ULL);
            JSValueRef v = h ? v8_unwrap_jsv(jsc, R64(h)) : JSValueMakeUndefined(jsc);
            JSObjectSetPropertyAtIndex(jsc, arr, (unsigned)i, v, NULL);
        }
    }
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_wrap_jsv(iso, jsc, arr)));
}
static void v8_Array_Length(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (!o || !jsc || !o->jsv) { c->rax = 0; return; }
    JSObjectRef jo = JSValueToObject(jsc, o->jsv, NULL);
    if (!jo) { c->rax = 0; return; }
    JSStringRef lk = JSStringCreateWithUTF8CString("length");
    JSValueRef lv = JSObjectGetProperty(jsc, jo, lk, NULL);
    JSStringRelease(lk);
    c->rax = (lv && JSValueIsNumber(jsc, lv)) ? (uint32_t)JSValueToNumber(jsc, lv, NULL) : 0;
}
static void v8_ArrayBuffer_NewBackingStore(CPU64 *c, void *ud) {
    (void)ud;
    /* Static returning std::unique_ptr<BackingStore>: rcx=sret, rdx=data, r8=len, r9=deleter, arg4=deleter_data */
    V8BackingStore *bs = (V8BackingStore *)calloc(1, sizeof(V8BackingStore));
    bs->data = (void *)(uintptr_t)c->rdx;
    bs->byte_length = (size_t)c->r8;
    bs->deleter_cb = c->r9;
    bs->deleter_data = win64_arg_i(c, 4);
    ret_sret64(c, c->rcx, (uint64_t)(uintptr_t)bs);
}
static void v8_BackingStore_dtor(CPU64 *c, void *ud) { (void)ud; (void)c; }
static void v8_ArrayBuffer_New(CPU64 *c, void *ud) {
    (void)ud;
    /* Static: rcx=sret, rdx=iso, r8=&std::shared_ptr<BackingStore> */
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    V8BackingStore *bs = c->r8 ? (V8BackingStore *)(uintptr_t)R64(c->r8) : NULL;
    JSContextRef jsc = v8_active_jsc(iso, 0);
    JSObjectRef ab = (jsc && bs && bs->data)
        ? JSObjectMakeArrayBufferWithBytesNoCopy(jsc, bs->data, bs->byte_length, NULL, NULL, NULL)
        : (jsc ? JSObjectMakeTypedArray(jsc, kJSTypedArrayTypeUint8Array, 0, NULL) : NULL);
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_AB);
    o->jsv = ab; if (ab && jsc) JSValueProtect(jsc, ab);
    o->aux = bs;
    ret_sret64(c, sret, v8_alloc_handle(iso, v8_tag(o)));
}
static void v8_Uint8Array_New(CPU64 *c, void *ud) {
    (void)ud;
    /* Static: rcx=sret, rdx=Local<ArrayBuffer>, r8=byte_offset, r9=length */
    uint64_t sret = c->rcx;
    V8Obj *abo = v8_from_local(c->rdx);
    size_t off = (size_t)c->r8;
    size_t len = (size_t)c->r9;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    JSObjectRef ta = NULL;
    if (jsc && abo && abo->jsv) {
        JSObjectRef ab = JSValueToObject(jsc, abo->jsv, NULL);
        ta = ab ? JSObjectMakeTypedArrayWithArrayBufferAndOffset(jsc, kJSTypedArrayTypeUint8Array, ab, off, len, NULL) : NULL;
    }
    if (!ta && jsc) ta = JSObjectMakeTypedArray(jsc, kJSTypedArrayTypeUint8Array, len, NULL);
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_U8);
    o->jsv = ta; if (ta && jsc) JSValueProtect(jsc, ta);
    ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_tag(o)));
}
static void v8_Allocator_Reallocate(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(uintptr_t)realloc((void *)(uintptr_t)c->rdx, (size_t)c->r9);
}

/* Function */
static void v8_Function_New(CPU64 *c, void *ud) {
    (void)ud;
    /* Static: rcx=sret, rdx=ctx, r8=cb, r9=data */
    uint64_t sret = c->rcx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->rdx);
    uint64_t fn_cb = c->r8;
    uint64_t data_h = c->r9;
    if (!jsc) { ret_sret64(c, sret, 0); return; }
    v8_init_jsc_classes();
    V8InstData *d = (V8InstData *)calloc(1, sizeof(V8InstData));
    d->iso = g_cur_iso;
    d->fn_cb = fn_cb;
    d->fn_data = data_h ? R64(data_h) : (g_cur_iso ? g_cur_iso->root_undef : 0);
    JSObjectRef jo = JSObjectMake(jsc, g_v8_fn_class, d);
    v8_set_function_proto(jsc, jo);
    d->js_obj = jo;
    ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, jo)));
}
static void v8_Function_Call(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    /* Member: rcx=this, rdx=sret, r8=ctx, r9=recv, arg4=argc, arg5=argv */
    V8Obj *fo = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    V8Obj *ro = v8_from_local(c->r9);
    int argc = (int)(int32_t)win64_arg_i(c, 4);
    uint64_t argv_ptr = win64_arg_i(c, 5);
    if (!fo || !jsc) { ret_sret64(c, sret, 0); tls_v8_cpu = prev; return; }
    JSObjectRef fn = JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(fo)), NULL);
    JSObjectRef recv = (ro && ro->kind != V8K_UNDEF && ro->kind != V8K_NULL)
                       ? JSValueToObject(jsc, v8_unwrap_jsv(jsc, v8_tag(ro)), NULL) : NULL;
    JSValueRef args[64];
    int n = (argc > 64) ? 64 : (argc < 0 ? 0 : argc);
    for (int i = 0; i < n; i++) {
        uint64_t h = argv_ptr ? R64(argv_ptr + (uint64_t)i * 8ULL) : 0;
        args[i] = h ? v8_unwrap_jsv(jsc, R64(h)) : JSValueMakeUndefined(jsc);
    }
    JSValueRef exc = NULL;
    JSValueRef res = (fn && JSObjectIsFunction(jsc, fn))
                     ? JSObjectCallAsFunction(jsc, fn, recv, (size_t)n, args, &exc) : NULL;
    if (exc || !res) { v8_record_exception(g_cur_iso, jsc, exc); ret_sret64(c, sret, 0); }
    else             { ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, res))); }
    tls_v8_cpu = prev;
}
static void v8_Function_GetName(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *fo = v8_from_local(c->rcx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (fo && jsc && fo->jsv) {
        JSObjectRef jo = JSValueToObject(jsc, fo->jsv, NULL);
        if (jo) {
            JSStringRef nk = JSStringCreateWithUTF8CString("name");
            JSValueRef nv = JSObjectGetProperty(jsc, jo, nk, NULL);
            JSStringRelease(nk);
            if (nv && JSValueIsString(jsc, nv)) {
                ret_sret64(c, c->rdx, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, nv)));
                return;
            }
        }
    }
    ret_sret64(c, c->rdx, v8_make_str_handle(g_cur_iso, "", 0));
}

/* ============================================================================
 * 6. Templates (Template, ObjectTemplate, FunctionTemplate, Signature)
 * ============================================================================ */

static void v8_ObjectTemplate_New(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    V8Tmpl *t = (V8Tmpl *)calloc(1, sizeof(V8Tmpl));
    t->iso = iso ? iso : g_cur_iso;
    V8Obj *co = v8_from_local(c->r8);
    if (co && co->kind == V8K_FTMPL) t->ctor_tmpl = (V8Tmpl *)co->aux;
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_OTMPL);
    o->aux = t;
    ret_sret64(c, sret, v8_alloc_handle(t->iso, v8_tag(o)));
}
static void v8_FunctionTemplate_New(CPU64 *c, void *ud) {
    (void)ud;
    /* Static: rcx=sret, rdx=iso, r8=callback, r9=data */
    uint64_t sret = c->rcx;
    V8Isolate *iso = (V8Isolate *)(uintptr_t)c->rdx;
    V8Tmpl *t = (V8Tmpl *)calloc(1, sizeof(V8Tmpl));
    t->is_func = true;
    t->iso = iso ? iso : g_cur_iso;
    t->fn_cb = c->r8;
    t->fn_data = c->r9 ? R64(c->r9) : (t->iso ? t->iso->root_undef : 0);
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_FTMPL);
    o->aux = t;
    ret_sret64(c, sret, v8_alloc_handle(t->iso, v8_tag(o)));
}
static void v8_FunctionTemplate_InstanceTemplate(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *fo = v8_from_local(c->rcx);
    V8Tmpl *ft = (fo && fo->kind == V8K_FTMPL) ? (V8Tmpl *)fo->aux : NULL;
    if (!ft) { ret_sret64(c, c->rdx, 0); return; }
    if (!ft->inst_tmpl) {
        ft->inst_tmpl = (V8Tmpl *)calloc(1, sizeof(V8Tmpl));
        ft->inst_tmpl->iso = ft->iso;
        ft->inst_tmpl->ctor_tmpl = ft;
    }
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_OTMPL);
    o->aux = ft->inst_tmpl;
    ret_sret64(c, c->rdx, v8_alloc_handle(ft->iso, v8_tag(o)));
}
static void v8_FunctionTemplate_SetClassName(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *fo = v8_from_local(c->rcx);
    V8Tmpl *ft = (fo && fo->kind == V8K_FTMPL) ? (V8Tmpl *)fo->aux : NULL;
    V8Obj *no = v8_from_local(c->rdx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (ft && no && jsc) {
        free(ft->class_name);
        ft->class_name = jsc_val_to_cstr(jsc, v8_unwrap_jsv(jsc, v8_tag(no)), NULL);
    }
}
static void v8_FunctionTemplate_GetFunction(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    V8Obj *fo = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    V8Tmpl *ft = (fo && fo->kind == V8K_FTMPL) ? (V8Tmpl *)fo->aux : NULL;
    if (!ft || !jsc) { ret_sret64(c, sret, 0); tls_v8_cpu = prev; return; }
    JSObjectRef fn = v8_instantiate_tmpl(ft->iso, jsc, ft);
    ret_sret64(c, sret, v8_alloc_handle(ft->iso, v8_wrap_jsv(ft->iso, jsc, fn)));
    tls_v8_cpu = prev;
}
static void v8_ObjectTemplate_NewInstance(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    V8Obj *oo = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    V8Tmpl *ot = (oo && oo->kind == V8K_OTMPL) ? (V8Tmpl *)oo->aux : NULL;
    if (!ot || !jsc) { ret_sret64(c, sret, 0); tls_v8_cpu = prev; return; }
    JSObjectRef obj = v8_instantiate_tmpl(ot->iso, jsc, ot);
    ret_sret64(c, sret, v8_alloc_handle(ot->iso, v8_wrap_jsv(ot->iso, jsc, obj)));
    tls_v8_cpu = prev;
}
static void v8_Template_Set(CPU64 *c, void *ud) {
    (void)ud;
    /* Member: rcx=this, rdx=Local<Name>, r8=Local<Data>, r9=PropertyAttribute */
    V8Obj *to = v8_from_local(c->rcx);
    V8Tmpl *t = (to && (to->kind == V8K_OTMPL || to->kind == V8K_FTMPL)) ? (V8Tmpl *)to->aux : NULL;
    V8Obj *no = v8_from_local(c->rdx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (!t || !no || !jsc || !c->r8 || t->nprops >= V8_MAX_TMPL_PROPS) return;
    t->props[t->nprops].name = jsc_val_to_cstr(jsc, v8_unwrap_jsv(jsc, v8_tag(no)), NULL);
    t->props[t->nprops].val_addr = R64(c->r8);
    t->nprops++;
}
static void v8_ObjectTemplate_SetAccessor(CPU64 *c, void *ud) {
    (void)ud;
    /* Member: rcx=this, rdx=name, r8=getter, r9=setter, arg4=data */
    V8Obj *to = v8_from_local(c->rcx);
    V8Tmpl *t = (to && (to->kind == V8K_OTMPL || to->kind == V8K_FTMPL)) ? (V8Tmpl *)to->aux : NULL;
    V8Obj *no = v8_from_local(c->rdx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (!t || !no || !jsc || t->naccs >= V8_MAX_TMPL_ACCS) return;
    uint64_t data_h = win64_arg_i(c, 4);
    V8TmplAcc *a = &t->accs[t->naccs++];
    a->name = jsc_val_to_cstr(jsc, v8_unwrap_jsv(jsc, v8_tag(no)), NULL);
    a->getter_cb = c->r8;
    a->setter_cb = c->r9;
    a->data_addr = data_h ? R64(data_h) : (t->iso ? t->iso->root_undef : 0);
    a->is_ftmpl = false;
}
static void v8_Template_SetAccessorProperty(CPU64 *c, void *ud) {
    (void)ud;
    /* Member: rcx=this, rdx=name, r8=getter_ft, r9=setter_ft */
    V8Obj *to = v8_from_local(c->rcx);
    V8Tmpl *t = (to && (to->kind == V8K_OTMPL || to->kind == V8K_FTMPL)) ? (V8Tmpl *)to->aux : NULL;
    V8Obj *no = v8_from_local(c->rdx);
    JSContextRef jsc = v8_active_jsc(g_cur_iso, 0);
    if (!t || !no || !jsc || t->naccs >= V8_MAX_TMPL_ACCS) return;
    V8TmplAcc *a = &t->accs[t->naccs++];
    a->name = jsc_val_to_cstr(jsc, v8_unwrap_jsv(jsc, v8_tag(no)), NULL);
    a->getter_cb = c->r8 ? R64(c->r8) : 0;
    a->setter_cb = c->r9 ? R64(c->r9) : 0;
    a->data_addr = 0;
    a->is_ftmpl = true;
}
static void v8_ObjectTemplate_SetCallAsFn(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *to = v8_from_local(c->rcx);
    V8Tmpl *t = (to && to->kind == V8K_OTMPL) ? (V8Tmpl *)to->aux : NULL;
    if (!t) return;
    t->fn_cb = c->rdx;
    t->fn_data = c->r8 ? R64(c->r8) : (t->iso ? t->iso->root_undef : 0);
}
static void v8_ObjectTemplate_SetInternalFieldCount(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *to = v8_from_local(c->rcx);
    V8Tmpl *t = (to && to->kind == V8K_OTMPL) ? (V8Tmpl *)to->aux : NULL;
    if (t) t->internal_field_count = (int)(int32_t)c->rdx;
}
static void v8_ObjectTemplate_SetHandler(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *to = v8_from_local(c->rcx);
    V8Tmpl *t = (to && to->kind == V8K_OTMPL) ? (V8Tmpl *)to->aux : NULL;
    uint64_t cfg = c->rdx;
    if (!t || !cfg) return;
    /* NamedPropertyHandlerConfiguration: [0]=getter, [8]=setter, [16]=query, [24]=deleter, [32]=enumerator, [40]=definer, [48]=descriptor, [56]=data */
    t->named_getter     = R64(cfg + 0);
    t->named_setter     = R64(cfg + 8);
    t->named_query      = R64(cfg + 16);
    t->named_deleter    = R64(cfg + 24);
    t->named_enumerator = R64(cfg + 32);
    uint64_t data_h     = R64(cfg + 56);
    t->named_data       = data_h ? R64(data_h) : (t->iso ? t->iso->root_undef : 0);
}
static void v8_Signature_New(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_SIG);
    o->aux = (void *)(uintptr_t)c->r8;
    ret_sret64(c, c->rcx, v8_alloc_handle((V8Isolate *)(uintptr_t)c->rdx, v8_tag(o)));
}

/* ============================================================================
 * 7. Script, ScriptCompiler, UnboundScript, JSON
 * ============================================================================ */

static uint64_t v8_compile_common(V8Isolate *iso, JSContextRef jsc, uint64_t src_h, const char *origin_name) {
    V8Obj *so = v8_from_local(src_h);
    if (!so || !jsc) return 0;
    char *code = jsc_val_to_cstr(jsc, v8_unwrap_jsv(jsc, v8_tag(so)), NULL);
    JSStringRef jcode = JSStringCreateWithUTF8CString(code);
    JSStringRef jurl  = JSStringCreateWithUTF8CString(origin_name ? origin_name : "<panorama>");
    JSValueRef exc = NULL;
    bool ok = JSCheckScriptSyntax(jsc, jcode, jurl, 1, &exc);
    JSStringRelease(jcode);
    JSStringRelease(jurl);
    if (!ok || exc) {
        if (iso && iso->tc_top) {
            free(iso->tc_top->src_name);
            iso->tc_top->src_name = strdup(origin_name ? origin_name : "<panorama>");
        }
        v8_record_exception(iso, jsc, exc);
        free(code);
        return 0;
    }
    V8ScriptData *sd = (V8ScriptData *)calloc(1, sizeof(V8ScriptData));
    sd->source = code;
    sd->origin_name = strdup(origin_name ? origin_name : "<panorama>");
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_SCRIPT);
    o->aux = sd;
    return v8_alloc_handle(iso, v8_tag(o));
}

static void v8_Script_Compile(CPU64 *c, void *ud) {
    (void)ud;
    /* Static: rcx=sret, rdx=ctx, r8=source_str, r9=ScriptOrigin* */
    uint64_t sret = c->rcx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->rdx);
    char *oname = NULL;
    if (c->r9 && jsc) {
        uint64_t rn_h = R64(c->r9 + 8);
        V8Obj *ro = v8_from_local(rn_h);
        if (ro) oname = jsc_val_to_cstr(jsc, v8_unwrap_jsv(jsc, v8_tag(ro)), NULL);
    }
    ret_sret64(c, sret, v8_compile_common(g_cur_iso, jsc, c->r8, oname));
    free(oname);
}
static void v8_ScriptCompiler_Compile(CPU64 *c, void *ud) {
    (void)ud;
    /* Static: rcx=sret, rdx=ctx, r8=Source* ([0]=Local<String> source_string, [8]=Local<Value> resource_name) */
    uint64_t sret = c->rcx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->rdx);
    uint64_t src_struct = c->r8;
    if (!src_struct || !jsc) { ret_sret64(c, sret, 0); return; }
    uint64_t src_h = R64(src_struct + 0);
    uint64_t rn_h  = R64(src_struct + 8);
    char *oname = NULL;
    V8Obj *ro = v8_from_local(rn_h);
    if (ro) oname = jsc_val_to_cstr(jsc, v8_unwrap_jsv(jsc, v8_tag(ro)), NULL);
    ret_sret64(c, sret, v8_compile_common(g_cur_iso, jsc, src_h, oname));
    free(oname);
}
static void v8_Script_Run(CPU64 *c, void *ud) {
    (void)ud;
    CPU64 *prev = tls_v8_cpu; tls_v8_cpu = c;
    V8Obj *so = v8_from_local(c->rcx);
    uint64_t sret = c->rdx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->r8);
    V8ScriptData *sd = (so && so->kind == V8K_SCRIPT) ? (V8ScriptData *)so->aux : NULL;
    if (!sd || !jsc) { ret_sret64(c, sret, 0); tls_v8_cpu = prev; return; }
    JSStringRef jcode = JSStringCreateWithUTF8CString(sd->source);
    JSStringRef jurl  = JSStringCreateWithUTF8CString(sd->origin_name ? sd->origin_name : "<panorama>");
    JSValueRef exc = NULL;
    JSValueRef res = JSEvaluateScript(jsc, jcode, NULL, jurl, 1, &exc);
    JSStringRelease(jcode);
    JSStringRelease(jurl);
    if (exc || !res) {
        if (g_cur_iso && g_cur_iso->tc_top) {
            free(g_cur_iso->tc_top->src_name);
            g_cur_iso->tc_top->src_name = strdup(sd->origin_name ? sd->origin_name : "<panorama>");
        }
        v8_record_exception(g_cur_iso, jsc, exc);
        ret_sret64(c, sret, 0);
    } else {
        ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, res)));
    }
    tls_v8_cpu = prev;
}
static void v8_Script_GetUnbound(CPU64 *c, void *ud) {
    (void)ud;
    ret_sret64(c, c->rdx, c->rcx);
}
static void v8_UnboundScript_Bind(CPU64 *c, void *ud) {
    (void)ud;
    ret_sret64(c, c->rdx, c->rcx);
}
static void v8_JSON_Parse(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->rdx);
    V8Obj *so = v8_from_local(c->r8);
    if (!jsc || !so) { ret_sret64(c, sret, 0); return; }
    JSValueRef exc = NULL;
    JSStringRef s = JSValueToStringCopy(jsc, v8_unwrap_jsv(jsc, v8_tag(so)), &exc);
    JSValueRef res = (s && !exc) ? JSValueMakeFromJSONString(jsc, s) : NULL;
    if (s) JSStringRelease(s);
    if (!res) { ret_sret64(c, sret, 0); return; }
    ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, res)));
}
static void v8_JSON_Stringify(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sret = c->rcx;
    JSContextRef jsc = v8_active_jsc(g_cur_iso, c->rdx);
    V8Obj *vo = v8_from_local(c->r8);
    if (!jsc || !vo) { ret_sret64(c, sret, 0); return; }
    JSValueRef exc = NULL;
    JSStringRef s = JSValueCreateJSONString(jsc, v8_unwrap_jsv(jsc, v8_tag(vo)), 0, &exc);
    if (!s || exc) { ret_sret64(c, sret, 0); return; }
    JSValueRef sv = JSValueMakeString(jsc, s);
    JSStringRelease(s);
    ret_sret64(c, sret, v8_alloc_handle(g_cur_iso, v8_wrap_jsv(g_cur_iso, jsc, sv)));
}

/* ============================================================================
 * 8. Message, StackTrace, StackFrame, Extension, Inspector stubs
 * ============================================================================ */

static void v8_Message_GetLineNumber(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *mo = v8_from_local(c->rcx);
    V8MsgData *m = (mo && mo->kind == V8K_MSG) ? (V8MsgData *)mo->aux : NULL;
    ret_maybe_i32(c, c->rdx, true, (uint32_t)(m ? m->line : 1));
}
static void v8_Message_GetStartColumn(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *mo = v8_from_local(c->rcx);
    V8MsgData *m = (mo && mo->kind == V8K_MSG) ? (V8MsgData *)mo->aux : NULL;
    c->rax = m ? (uint64_t)(int64_t)m->col : 0;
}
static void v8_Message_GetSourceLine(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *mo = v8_from_local(c->rcx);
    V8MsgData *m = (mo && mo->kind == V8K_MSG) ? (V8MsgData *)mo->aux : NULL;
    ret_sret64(c, c->rdx, v8_make_str_handle(g_cur_iso, (m && m->source_line) ? m->source_line : "", -1));
}
static void v8_Message_GetScriptOrigin(CPU64 *c, void *ud) {
    (void)ud;
    /* ScriptOrigin returned by sret in rdx: [0]=isolate_, [8]=resource_name_, [16..47]=0 */
    V8Obj *mo = v8_from_local(c->rcx);
    V8MsgData *m = (mo && mo->kind == V8K_MSG) ? (V8MsgData *)mo->aux : NULL;
    uint64_t sret = c->rdx;
    if (sret) {
        memset((void *)(uintptr_t)sret, 0, 48);
        W64(sret + 0, (uint64_t)(uintptr_t)g_cur_iso);
        W64(sret + 8, v8_make_str_handle(g_cur_iso, (m && m->resource_name) ? m->resource_name : "<panorama>", -1));
    }
    c->rax = sret;
}

static void v8_StackTrace_Current(CPU64 *c, void *ud) {
    (void)ud;
    V8StackData *sd = (V8StackData *)calloc(1, sizeof(V8StackData));
    sd->count = 0;
    V8Obj *o = v8_alloc_obj(g_map_obj, V8K_STACK);
    o->aux = sd;
    ret_sret64(c, c->rcx, v8_alloc_handle((V8Isolate *)(uintptr_t)c->rdx, v8_tag(o)));
}
static void v8_StackTrace_GetFrameCount(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *so = v8_from_local(c->rcx);
    V8StackData *sd = (so && so->kind == V8K_STACK) ? (V8StackData *)so->aux : NULL;
    c->rax = sd ? (uint64_t)sd->count : 0;
}
static void v8_StackTrace_GetFrame(CPU64 *c, void *ud) {
    (void)ud;
    V8Obj *fo = v8_alloc_obj(g_map_obj, V8K_FRAME);
    fo->aux2 = c->r9;
    ret_sret64(c, c->rdx, v8_alloc_handle((V8Isolate *)(uintptr_t)c->r8, v8_tag(fo)));
}
static void v8_StackFrame_GetStr(CPU64 *c, void *ud) {
    (void)ud;
    ret_sret64(c, c->rdx, v8_make_str_handle(g_cur_iso, "<js>", 4));
}
static void v8_StackFrame_GetLocation(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) { W32(c->rdx + 0, 1); W32(c->rdx + 4, 0); }
    c->rax = c->rdx;
}

static void v8_ToLocalEmpty(CPU64 *c, void *ud) {
    (void)ud; (void)c;
    fprintf(stderr, "v8_jsc64: warning: MaybeLocal::ToLocalChecked on empty value\n");
}
static void v8_Inspector_CreateNull(CPU64 *c, void *ud) {
    (void)ud;
    ret_sret64(c, c->rcx, 0);
}
static void v8_Extension_ctor(CPU64 *c, void *ud) { (void)ud; c->rax = c->rcx; }

#endif /* __APPLE__ */

void rt_register_v8_jsc_64(void) {
#ifdef __APPLE__
    #define REG(name, fn) rt_register_shim((name), (fn), NULL)

    /* Constructors & Destructors */
    REG("??0CreateParams@Isolate@v8@@QEAA@XZ", v8_CreateParams_ctor);
    REG("??1CreateParams@Isolate@v8@@QEAA@XZ", v8_CreateParams_dtor);
    REG("??0HandleScope@v8@@QEAA@PEAVIsolate@1@@Z", v8_HandleScope_ctor);
    REG("??1HandleScope@v8@@QEAA@XZ", v8_HandleScope_dtor);
    REG("??0EscapableHandleScope@v8@@QEAA@PEAVIsolate@1@@Z", v8_EscapableHandleScope_ctor);
    REG("??0TryCatch@v8@@QEAA@PEAVIsolate@1@@Z", v8_TryCatch_ctor);
    REG("??1TryCatch@v8@@QEAA@XZ", v8_TryCatch_dtor);
    REG("??0Utf8Value@String@v8@@QEAA@PEAVIsolate@2@V?$Local@VValue@v8@@@2@@Z", v8_Utf8Value_ctor);
    REG("??1Utf8Value@String@v8@@QEAA@XZ", v8_Utf8Value_dtor);
    REG("??0Extension@v8@@QEAA@PEBD0HPEAPEBDH@Z", v8_Extension_ctor);
    REG("??1BackingStore@v8@@QEAA@XZ", v8_BackingStore_dtor);
    REG("??1CachedData@ScriptCompiler@v8@@QEAA@XZ", v8_Noop);
    REG("??1ConsumeCodeCacheTask@ScriptCompiler@v8@@QEAA@XZ", v8_Noop);

    /* V8 / Platform / Internal */
    REG("?GetVersion@V8@v8@@SAPEBDXZ", v8_GetVersion);
    REG("?Initialize@V8@v8@@CA_NH@Z", v8_InitTrue);
    REG("?InitializeICU@V8@v8@@SA_NPEBD@Z", v8_InitTrue);
    REG("?InitializePlatform@V8@v8@@SAXPEAVPlatform@2@@Z", v8_Noop);
    REG("?SetFlagsFromString@V8@v8@@SAXPEBD_K@Z", v8_Noop);
    REG("?RegisterExtension@v8@@YAXV?$unique_ptr@VExtension@v8@@U?$default_delete@VExtension@v8@@@std@@@std@@@Z", v8_Noop);
    REG("?ConfigureDefaults@ResourceConstraints@v8@@QEAAX_K0@Z", v8_Noop);
    REG("?NewDefaultPlatform@platform@v8@@YA?AV?$unique_ptr@VPlatform@v8@@U?$default_delete@VPlatform@v8@@@std@@@std@@HW4IdleTaskSupport@12@W4InProcessStackDumping@12@V?$unique_ptr@VTracingController@v8@@U?$default_delete@VTracingController@v8@@@std@@@4@@Z", v8_NewDefaultPlatform);
    REG("?NotifyIsolateShutdown@platform@v8@@YAXPEAVPlatform@2@PEAVIsolate@2@@Z", v8_Noop);
    REG("?CreateHandle@HandleScope@v8@@KAPEA_KPEAVIsolate@internal@2@_K@Z", v8_HandleScope_CreateHandle);
    REG("?Escape@EscapableHandleScope@v8@@AEAAPEA_KPEA_K@Z", v8_Escapable_Escape);
    REG("?GlobalizeReference@api_internal@v8@@YAPEA_KPEAVIsolate@internal@2@PEA_K@Z", v8_GlobalizeReference);
    REG("?DisposeGlobal@api_internal@v8@@YAXPEA_K@Z", v8_DisposeGlobal);
    REG("?IsolateFromNeverReadOnlySpaceObject@internal@v8@@YAPEAVIsolate@12@_K@Z", v8_IsolateFromObj);
    REG("?FromJustIsNothing@api_internal@v8@@YAXXZ", v8_ToLocalEmpty);
    REG("?ToLocalEmpty@api_internal@v8@@YAXXZ", v8_ToLocalEmpty);
    REG("?VerifyHostDefinedOptions@ScriptOrigin@v8@@AEBAXXZ", v8_Noop);

    /* Isolate */
    REG("?New@Isolate@v8@@SAPEAV12@AEBUCreateParams@12@@Z", v8_Isolate_New);
    REG("?Dispose@Isolate@v8@@QEAAXXZ", v8_Isolate_Dispose);
    REG("?Enter@Isolate@v8@@QEAAXXZ", v8_Isolate_Enter);
    REG("?Exit@Isolate@v8@@QEAAXXZ", v8_Isolate_Exit);
    REG("?GetCurrent@Isolate@v8@@SAPEAV12@XZ", v8_Isolate_GetCurrent);
    REG("?GetCurrentContext@Isolate@v8@@QEAA?AV?$Local@VContext@v8@@@2@XZ", v8_Isolate_GetCurrentContext);
    REG("?ThrowException@Isolate@v8@@QEAA?AV?$Local@VValue@v8@@@2@V32@@Z", v8_Isolate_ThrowException);
    REG("?SetFatalErrorHandler@Isolate@v8@@QEAAXP6AXPEBD0@Z@Z", v8_Isolate_SetFatal);
    REG("?IdleNotificationDeadline@Isolate@v8@@QEAA_NN@Z", v8_Isolate_IdleNotif);
    REG("?ContextDisposedNotification@Isolate@v8@@QEAAH_N@Z", v8_Isolate_CtxDisposed);

    /* Context */
    REG("?New@Context@v8@@SA?AV?$Local@VContext@v8@@@2@PEAVIsolate@2@PEAVExtensionConfiguration@2@V?$MaybeLocal@VObjectTemplate@v8@@@2@V?$MaybeLocal@VValue@v8@@@2@UDeserializeInternalFieldsCallback@2@PEAVMicrotaskQueue@2@@Z", v8_Context_New);
    REG("?Enter@Context@v8@@QEAAXXZ", v8_Context_Enter);
    REG("?Exit@Context@v8@@QEAAXXZ", v8_Context_Exit);
    REG("?GetIsolate@Context@v8@@QEAAPEAVIsolate@2@XZ", v8_Context_GetIsolate);
    REG("?Global@Context@v8@@QEAA?AV?$Local@VObject@v8@@@2@XZ", v8_Context_Global);
    REG("?GetSecurityToken@Context@v8@@QEAA?AV?$Local@VValue@v8@@@2@XZ", v8_Context_GetSecToken);
    REG("?SetSecurityToken@Context@v8@@QEAAXV?$Local@VValue@v8@@@2@@Z", v8_Context_SetSecToken);

    /* TryCatch */
    REG("?HasCaught@TryCatch@v8@@QEBA_NXZ", v8_TryCatch_HasCaught);
    REG("?Reset@TryCatch@v8@@QEAAXXZ", v8_TryCatch_Reset);
    REG("?Exception@TryCatch@v8@@QEBA?AV?$Local@VValue@v8@@@2@XZ", v8_TryCatch_Exception);
    REG("?Message@TryCatch@v8@@QEBA?AV?$Local@VMessage@v8@@@2@XZ", v8_TryCatch_Message);
    REG("?StackTrace@TryCatch@v8@@QEBA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_TryCatch_StackTrace);

    /* String / Primitives */
    REG("?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z", v8_String_NewFromUtf8);
    REG("?NewFromUtf8Literal@String@v8@@CA?AV?$Local@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z", v8_String_NewFromUtf8);
    REG("?NewFromOneByte@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBEW4NewStringType@2@H@Z", v8_String_NewFromUtf8);
    REG("?NewExternalOneByte@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEAVExternalOneByteStringResource@12@@Z", v8_String_NewExternalOneByte);
    REG("?New@Number@v8@@SA?AV?$Local@VNumber@v8@@@2@PEAVIsolate@2@N@Z", v8_Number_New);
    REG("?New@Integer@v8@@SA?AV?$Local@VInteger@v8@@@2@PEAVIsolate@2@H@Z", v8_Integer_New);
    REG("?NewFromUnsigned@Integer@v8@@SA?AV?$Local@VInteger@v8@@@2@PEAVIsolate@2@I@Z", v8_Integer_NewUnsigned);
    REG("?New@BigInt@v8@@SA?AV?$Local@VBigInt@v8@@@2@PEAVIsolate@2@_J@Z", v8_BigInt_New);
    REG("?New@Date@v8@@SA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@N@Z", v8_Date_New);
    REG("?New@External@v8@@SA?AV?$Local@VExternal@v8@@@2@PEAVIsolate@2@PEAX@Z", v8_External_New);
    REG("?Value@External@v8@@QEBAPEAXXZ", v8_External_Value);
    REG("?Value@Boolean@v8@@QEBA_NXZ", v8_Boolean_Value);
    REG("?Value@Number@v8@@QEBANXZ", v8_Number_Value);
    REG("?ValueOf@Date@v8@@QEBANXZ", v8_Number_Value);

    /* Value predicates & conversions */
    REG("?IsArray@Value@v8@@QEBA_NXZ", v8_Value_IsArray);
    REG("?IsBoolean@Value@v8@@QEBA_NXZ", v8_Value_IsBoolean);
    REG("?IsDate@Value@v8@@QEBA_NXZ", v8_Value_IsDate);
    REG("?IsExternal@Value@v8@@QEBA_NXZ", v8_Value_IsExternal);
    REG("?IsFunction@Value@v8@@QEBA_NXZ", v8_Value_IsFunction);
    REG("?IsInt32@Value@v8@@QEBA_NXZ", v8_Value_IsInt32);
    REG("?IsNumber@Value@v8@@QEBA_NXZ", v8_Value_IsNumber);
    REG("?IsObject@Value@v8@@QEBA_NXZ", v8_Value_IsObject);
    REG("?IsUint32@Value@v8@@QEBA_NXZ", v8_Value_IsUint32);
    REG("?BooleanValue@Value@v8@@QEBA_NPEAVIsolate@2@@Z", v8_Value_BooleanValue);
    REG("?ToBoolean@Value@v8@@QEBA?AV?$Local@VBoolean@v8@@@2@PEAVIsolate@2@@Z", v8_Value_ToBoolean);
    REG("?Int32Value@Value@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z", v8_Value_Int32Value);
    REG("?Uint32Value@Value@v8@@QEBA?AV?$Maybe@I@2@V?$Local@VContext@v8@@@2@@Z", v8_Value_Uint32Value);
    REG("?NumberValue@Value@v8@@QEBA?AV?$Maybe@N@2@V?$Local@VContext@v8@@@2@@Z", v8_Value_NumberValue);
    REG("?ToNumber@Value@v8@@QEBA?AV?$MaybeLocal@VNumber@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_Value_ToNumber);
    REG("?ToUint32@Value@v8@@QEBA?AV?$MaybeLocal@VUint32@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_Value_ToUint32);
    REG("?ToString@Value@v8@@QEBA?AV?$MaybeLocal@VString@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_Value_ToString);
    REG("?ToObject@Value@v8@@QEBA?AV?$MaybeLocal@VObject@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_Value_ToObject);
    REG("?StrictEquals@Value@v8@@QEBA_NV?$Local@VValue@v8@@@2@@Z", v8_Value_StrictEquals);
    REG("?TypeOf@Value@v8@@QEAA?AV?$Local@VString@v8@@@2@PEAVIsolate@2@@Z", v8_Value_TypeOf);

    /* Object, Array, ArrayBuffer, Uint8Array, Function */
    REG("?New@Object@v8@@SA?AV?$Local@VObject@v8@@@2@PEAVIsolate@2@@Z", v8_Object_New);
    REG("?Get@Object@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@@Z", v8_Object_Get_Key);
    REG("?Get@Object@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@I@Z", v8_Object_Get_Idx);
    REG("?Set@Object@v8@@QEAA?AV?$Maybe@_N@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@1@Z", v8_Object_Set_Key);
    REG("?Set@Object@v8@@QEAA?AV?$Maybe@_N@2@V?$Local@VContext@v8@@@2@IV?$Local@VValue@v8@@@2@@Z", v8_Object_Set_Idx);
    REG("?Delete@Object@v8@@QEAA?AV?$Maybe@_N@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@@Z", v8_Object_Delete);
    REG("?GetPropertyNames@Object@v8@@QEAA?AV?$MaybeLocal@VArray@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_Object_GetPropertyNames);
    REG("?InternalFieldCount@Object@v8@@QEBAHXZ", v8_Object_InternalFieldCount);
    REG("?SetInternalField@Object@v8@@QEAAXHV?$Local@VValue@v8@@@2@@Z", v8_Object_SetInternalField);
    REG("?SlowGetInternalField@Object@v8@@AEAA?AV?$Local@VValue@v8@@@2@H@Z", v8_Object_SlowGetInternalField);
    REG("?CallAsConstructor@Object@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@HQEAV?$Local@VValue@v8@@@2@@Z", v8_Object_CallAsConstructor);
    REG("?New@Array@v8@@SA?AV?$Local@VArray@v8@@@2@PEAVIsolate@2@H@Z", v8_Array_New_Len);
    REG("?New@Array@v8@@SA?AV?$Local@VArray@v8@@@2@PEAVIsolate@2@PEAV?$Local@VValue@v8@@@2@_K@Z", v8_Array_New_Elems);
    REG("?Length@Array@v8@@QEBAIXZ", v8_Array_Length);
    REG("?NewBackingStore@ArrayBuffer@v8@@SA?AV?$unique_ptr@VBackingStore@v8@@U?$default_delete@VBackingStore@v8@@@std@@@std@@PEAX_KP6AX010@Z0@Z", v8_ArrayBuffer_NewBackingStore);
    REG("?New@ArrayBuffer@v8@@SA?AV?$Local@VArrayBuffer@v8@@@2@PEAVIsolate@2@V?$shared_ptr@VBackingStore@v8@@@std@@@Z", v8_ArrayBuffer_New);
    REG("?New@Uint8Array@v8@@SA?AV?$Local@VUint8Array@v8@@@2@V?$Local@VArrayBuffer@v8@@@2@_K1@Z", v8_Uint8Array_New);
    REG("?Reallocate@Allocator@ArrayBuffer@v8@@UEAAPEAXPEAX_K1@Z", v8_Allocator_Reallocate);
    REG("?New@Function@v8@@SA?AV?$MaybeLocal@VFunction@v8@@@2@V?$Local@VContext@v8@@@2@P6AXAEBV?$FunctionCallbackInfo@VValue@v8@@@2@@ZV?$Local@VValue@v8@@@2@HW4ConstructorBehavior@2@W4SideEffectType@2@@Z", v8_Function_New);
    REG("?Call@Function@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@HQEAV52@@Z", v8_Function_Call);
    REG("?GetName@Function@v8@@QEBA?AV?$Local@VValue@v8@@@2@XZ", v8_Function_GetName);

    /* Templates */
    REG("?New@ObjectTemplate@v8@@SA?AV?$Local@VObjectTemplate@v8@@@2@PEAVIsolate@2@V?$Local@VFunctionTemplate@v8@@@2@@Z", v8_ObjectTemplate_New);
    REG("?New@FunctionTemplate@v8@@SA?AV?$Local@VFunctionTemplate@v8@@@2@PEAVIsolate@2@P6AXAEBV?$FunctionCallbackInfo@VValue@v8@@@2@@ZV?$Local@VValue@v8@@@2@V?$Local@VSignature@v8@@@2@HW4ConstructorBehavior@2@W4SideEffectType@2@PEBVCFunction@2@GGG@Z", v8_FunctionTemplate_New);
    REG("?InstanceTemplate@FunctionTemplate@v8@@QEAA?AV?$Local@VObjectTemplate@v8@@@2@XZ", v8_FunctionTemplate_InstanceTemplate);
    REG("?SetClassName@FunctionTemplate@v8@@QEAAXV?$Local@VString@v8@@@2@@Z", v8_FunctionTemplate_SetClassName);
    REG("?GetFunction@FunctionTemplate@v8@@QEAA?AV?$MaybeLocal@VFunction@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_FunctionTemplate_GetFunction);
    REG("?NewInstance@ObjectTemplate@v8@@QEAA?AV?$MaybeLocal@VObject@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_ObjectTemplate_NewInstance);
    REG("?Set@Template@v8@@QEAAXV?$Local@VName@v8@@@2@V?$Local@VData@v8@@@2@W4PropertyAttribute@2@@Z", v8_Template_Set);
    REG("?SetAccessor@ObjectTemplate@v8@@QEAAXV?$Local@VString@v8@@@2@P6AX0AEBV?$PropertyCallbackInfo@VValue@v8@@@2@@ZP6AX0V?$Local@VValue@v8@@@2@AEBV?$PropertyCallbackInfo@X@2@@Z3W4AccessControl@2@W4PropertyAttribute@2@W4SideEffectType@2@8@Z", v8_ObjectTemplate_SetAccessor);
    REG("?SetAccessorProperty@Template@v8@@QEAAXV?$Local@VName@v8@@@2@V?$Local@VFunctionTemplate@v8@@@2@1W4PropertyAttribute@2@W4AccessControl@2@@Z", v8_Template_SetAccessorProperty);
    REG("?SetCallAsFunctionHandler@ObjectTemplate@v8@@QEAAXP6AXAEBV?$FunctionCallbackInfo@VValue@v8@@@2@@ZV?$Local@VValue@v8@@@2@@Z", v8_ObjectTemplate_SetCallAsFn);
    REG("?SetInternalFieldCount@ObjectTemplate@v8@@QEAAXH@Z", v8_ObjectTemplate_SetInternalFieldCount);
    REG("?SetHandler@ObjectTemplate@v8@@QEAAXAEBUNamedPropertyHandlerConfiguration@2@@Z", v8_ObjectTemplate_SetHandler);
    REG("?New@Signature@v8@@SA?AV?$Local@VSignature@v8@@@2@PEAVIsolate@2@V?$Local@VFunctionTemplate@v8@@@2@@Z", v8_Signature_New);

    /* Script, ScriptCompiler, JSON */
    REG("?Compile@Script@v8@@SA?AV?$MaybeLocal@VScript@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VString@v8@@@2@PEAVScriptOrigin@2@@Z", v8_Script_Compile);
    REG("?Compile@ScriptCompiler@v8@@SA?AV?$MaybeLocal@VScript@v8@@@2@V?$Local@VContext@v8@@@2@PEAVSource@12@W4CompileOptions@12@W4NoCacheReason@12@@Z", v8_ScriptCompiler_Compile);
    REG("?Run@Script@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_Script_Run);
    REG("?GetUnboundScript@Script@v8@@QEAA?AV?$Local@VUnboundScript@v8@@@2@XZ", v8_Script_GetUnbound);
    REG("?BindToCurrentContext@UnboundScript@v8@@QEAA?AV?$Local@VScript@v8@@@2@XZ", v8_UnboundScript_Bind);
    REG("?Parse@JSON@v8@@SA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VString@v8@@@2@@Z", v8_JSON_Parse);
    REG("?Stringify@JSON@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@V?$Local@VString@v8@@@2@@Z", v8_JSON_Stringify);

    /* Message, StackTrace, StackFrame, Inspector */
    REG("?GetLineNumber@Message@v8@@QEBA?AV?$Maybe@H@2@V?$Local@VContext@v8@@@2@@Z", v8_Message_GetLineNumber);
    REG("?GetStartColumn@Message@v8@@QEBAHXZ", v8_Message_GetStartColumn);
    REG("?GetSourceLine@Message@v8@@QEBA?AV?$MaybeLocal@VString@v8@@@2@V?$Local@VContext@v8@@@2@@Z", v8_Message_GetSourceLine);
    REG("?GetScriptOrigin@Message@v8@@QEBA?AVScriptOrigin@2@XZ", v8_Message_GetScriptOrigin);
    REG("?CurrentStackTrace@StackTrace@v8@@SA?AV?$Local@VStackTrace@v8@@@2@PEAVIsolate@2@HW4StackTraceOptions@12@@Z", v8_StackTrace_Current);
    REG("?GetFrameCount@StackTrace@v8@@QEBAHXZ", v8_StackTrace_GetFrameCount);
    REG("?GetFrame@StackTrace@v8@@QEBA?AV?$Local@VStackFrame@v8@@@2@PEAVIsolate@2@I@Z", v8_StackTrace_GetFrame);
    REG("?GetFunctionName@StackFrame@v8@@QEBA?AV?$Local@VString@v8@@@2@XZ", v8_StackFrame_GetStr);
    REG("?GetScriptName@StackFrame@v8@@QEBA?AV?$Local@VString@v8@@@2@XZ", v8_StackFrame_GetStr);
    REG("?GetLocation@StackFrame@v8@@QEBA?AVLocation@2@XZ", v8_StackFrame_GetLocation);
    REG("?create@StringBuffer@v8_inspector@@SA?AV?$unique_ptr@VStringBuffer@v8_inspector@@U?$default_delete@VStringBuffer@v8_inspector@@@std@@@std@@VStringView@2@@Z", v8_Inspector_CreateNull);
    REG("?create@V8Inspector@v8_inspector@@SA?AV?$unique_ptr@VV8Inspector@v8_inspector@@U?$default_delete@VV8Inspector@v8_inspector@@@std@@@std@@PEAVIsolate@v8@@PEAVV8InspectorClient@2@@Z", v8_Inspector_CreateNull);

    #undef REG
#endif
}
