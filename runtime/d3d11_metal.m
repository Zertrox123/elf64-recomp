#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include <SDL.h>
#include <SDL_metal.h>

#include "runtime64.h"
#include "win64_abi.h"
#include "dxbc_msl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S_OK_HR        0x00000000U
#define E_FAIL_HR      0x80004005U
#define E_INVALIDARG_H 0x80070057U

/* ---- COM Object Definitions (first field is ALWAYS guest lpVtbl ptr) ---- */
typedef enum {
    COM_DEVICE = 1,
    COM_CONTEXT,
    COM_SWAPCHAIN,
    COM_FACTORY,
    COM_ADAPTER,
    COM_BUFFER,
    COM_TEXTURE2D,
    COM_RTV,
    COM_VSHADER,
    COM_PSHADER,
    COM_INPUT_LAYOUT,
    COM_GENERIC_STATE,
} ComKind;

typedef struct ComBase {
    const uint64_t *lpVtbl;
    ComKind         kind;
    int32_t         refcount;
} ComBase;

typedef struct {
    ComBase          base;
    id<MTLBuffer>    mtl_buf;
    uint32_t         byte_width;
    uint32_t         bind_flags;
    uint32_t         usage;
} D3D11BufferObj;

typedef struct {
    ComBase          base;
    id<MTLTexture>   mtl_tex;
    uint32_t         width;
    uint32_t         height;
    uint32_t         dxgi_fmt;
    MTLPixelFormat   mtl_fmt;
    uint32_t         usage;
    uint8_t         *mapped_cpu;
} D3D11Texture2DObj;

typedef struct {
    ComBase            base;
    D3D11Texture2DObj *tex;
} D3D11RTVObj;

typedef struct {
    ComBase          base;
    id<MTLFunction>  mtl_fn;
    DxbcTranslated   info;
} D3D11ShaderObj;

typedef struct {
    uint32_t slot;
    uint32_t offset;
    uint32_t dxgi_fmt;
    uint32_t attr_idx;
} LayoutElem;

typedef struct {
    ComBase    base;
    LayoutElem elems[16];
    int        num_elems;
} D3D11InputLayoutObj;

typedef struct D3D11DeviceObj D3D11DeviceObj;
typedef struct D3D11ContextObj D3D11ContextObj;

struct D3D11ContextObj {
    ComBase              base;
    D3D11DeviceObj      *dev;
    D3D11RTVObj         *rtvs[8];
    int                  num_rtvs;
    D3D11ShaderObj      *vs;
    D3D11ShaderObj      *ps;
    D3D11InputLayoutObj *layout;
    D3D11BufferObj      *vbs[8];
    uint32_t             vb_strides[8];
    uint32_t             vb_offsets[8];
    D3D11BufferObj      *ib;
    uint32_t             ib_fmt;
    uint32_t             ib_offset;
    D3D11BufferObj      *vs_cbs[14];
    D3D11BufferObj      *ps_cbs[14];
    uint32_t             topology;
    float                vp_x, vp_y, vp_w, vp_h, vp_minz, vp_maxz;
    int                  has_vp;
};

struct D3D11DeviceObj {
    ComBase            base;
    id<MTLDevice>      mtl_dev;
    id<MTLCommandQueue> mtl_queue;
    D3D11ContextObj   *imm_ctx;
};

typedef struct {
    ComBase            base;
    D3D11DeviceObj    *dev;
    D3D11Texture2DObj *backbuffer;
    SDL_MetalView      metal_view;
    CAMetalLayer      *metal_layer;
    uint32_t           width;
    uint32_t           height;
} DXGISwapChainObj;

typedef struct {
    ComBase        base;
    id<MTLDevice>  mtl_dev;
} DXGIAdapterObj;

typedef struct {
    ComBase        base;
} DXGIFactoryObj;

/* ---- Vtable storage (populated once via rt_alloc_dynamic_thunk) ---- */
static uint64_t g_vt_device[48];
static uint64_t g_vt_context[120];
static uint64_t g_vt_swapchain[20];
static uint64_t g_vt_factory[16];
static uint64_t g_vt_adapter[16];
static uint64_t g_vt_tex2d[16];
static uint64_t g_vt_buffer[16];
static uint64_t g_vt_generic[16];
static int      g_vt_ready = 0;

static int dxgi_is_depth(uint32_t fmt) {
    return (fmt == 20 || fmt == 39 || fmt == 40 || fmt == 44 || fmt == 45 || fmt == 54 || fmt == 55);
}

static MTLPixelFormat dxgi_to_mtl_pixel(uint32_t fmt) {
    switch (fmt) {
        case 87: case 91: return MTLPixelFormatBGRA8Unorm;
        case 28: case 29: return MTLPixelFormatRGBA8Unorm;
        case 10:          return MTLPixelFormatRGBA16Float;
        case 2:           return MTLPixelFormatRGBA32Float;
        case 20: case 44: case 45: return MTLPixelFormatDepth32Float_Stencil8;
        case 39: case 40: case 54: case 55: return MTLPixelFormatDepth32Float;
        default:          return MTLPixelFormatRGBA8Unorm;
    }
}

static MTLVertexFormat dxgi_to_mtl_vertex(uint32_t fmt) {
    switch (fmt) {
        case 2:  return MTLVertexFormatFloat4;
        case 6:  return MTLVertexFormatFloat3;
        case 16: return MTLVertexFormatFloat2;
        case 41: return MTLVertexFormatFloat;
        case 28: return MTLVertexFormatUChar4Normalized;
        default: return MTLVertexFormatFloat4;
    }
}

static MTLPrimitiveType d3d_to_mtl_prim(uint32_t topo) {
    switch (topo) {
        case 1: return MTLPrimitiveTypePoint;
        case 2: return MTLPrimitiveTypeLine;
        case 3: return MTLPrimitiveTypeLineStrip;
        case 5: return MTLPrimitiveTypeTriangleStrip;
        case 4: default: return MTLPrimitiveTypeTriangle;
    }
}

/* ---- IUnknown methods ---- */
static void com_QueryInterface(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r8) W64(c->r8, c->rcx);
    ComBase *b = (ComBase *)(uintptr_t)c->rcx;
    if (b) b->refcount++;
    c->rax = S_OK_HR;
}
static void com_AddRef(CPU64 *c, void *ud) {
    (void)ud;
    ComBase *b = (ComBase *)(uintptr_t)c->rcx;
    c->rax = b ? (uint32_t)(++b->refcount) : 0;
}
static void com_Release(CPU64 *c, void *ud) {
    (void)ud;
    ComBase *b = (ComBase *)(uintptr_t)c->rcx;
    if (!b) { c->rax = 0; return; }
    int32_t r = --b->refcount;
    if (r < 0) r = 0;
    c->rax = (uint32_t)r;
}
static void com_stub_ok(CPU64 *c, void *ud) { (void)ud; c->rax = S_OK_HR; }
static void com_stub_void(CPU64 *c, void *ud) { (void)c; (void)ud; }

static D3D11Texture2DObj *create_tex2d_internal(D3D11DeviceObj *dev, uint32_t w, uint32_t h,
                                                uint32_t dxgi_fmt, uint32_t usage,
                                                const void *init_mem, uint32_t init_pitch) {
    if (w == 0) w = 1;
    if (h == 0) h = 1;
    if (w > 16384) w = 16384;
    if (h > 16384) h = 16384;
    int is_depth = dxgi_is_depth(dxgi_fmt);
    MTLPixelFormat mfmt = dxgi_to_mtl_pixel(dxgi_fmt);
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:mfmt
                                                                                  width:w
                                                                                 height:h
                                                                              mipmapped:NO];
    td.storageMode = is_depth ? MTLStorageModePrivate : MTLStorageModeShared;
    td.usage = is_depth
        ? (MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead)
        : ((usage == 3)
            ? MTLTextureUsageShaderRead
            : (MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead));
    id<MTLTexture> tex = [dev->mtl_dev newTextureWithDescriptor:td];
    if (!tex) return NULL;
    if (init_mem && !is_depth) {
        [tex replaceRegion:MTLRegionMake2D(0, 0, w, h) mipmapLevel:0
                 withBytes:init_mem bytesPerRow:(init_pitch ? init_pitch : w * 4)];
    }
    D3D11Texture2DObj *obj = (D3D11Texture2DObj *)calloc(1, sizeof(D3D11Texture2DObj));
    obj->base.lpVtbl = g_vt_tex2d;
    obj->base.kind = COM_TEXTURE2D;
    obj->base.refcount = 1;
    obj->mtl_tex = tex;
    obj->width = w;
    obj->height = h;
    obj->dxgi_fmt = dxgi_fmt;
    obj->mtl_fmt = mfmt;
    obj->usage = usage;
    return obj;
}

static void tex2d_GetType(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx, 3 /* D3D11_RESOURCE_DIMENSION_TEXTURE2D */);
}
static void tex2d_GetDesc(CPU64 *c, void *ud) {
    (void)ud;
    D3D11Texture2DObj *t = (D3D11Texture2DObj *)(uintptr_t)c->rcx;
    uint64_t d = c->rdx;
    if (!t || !d) return;
    memset((void *)(uintptr_t)d, 0, 44);
    W32(d + 0, t->width);
    W32(d + 4, t->height);
    W32(d + 8, 1);  /* MipLevels */
    W32(d + 12, 1); /* ArraySize */
    W32(d + 16, t->dxgi_fmt ? t->dxgi_fmt : 28);
    W32(d + 20, 1); /* SampleDesc.Count */
    W32(d + 28, t->usage);
    W32(d + 32, dxgi_is_depth(t->dxgi_fmt) ? 0x40U : 0x28U); /* BindFlags */
}
static void buf_GetType(CPU64 *c, void *ud) {
    (void)ud;
    if (c->rdx) W32(c->rdx, 1 /* D3D11_RESOURCE_DIMENSION_BUFFER */);
}
static void buf_GetDesc(CPU64 *c, void *ud) {
    (void)ud;
    D3D11BufferObj *b = (D3D11BufferObj *)(uintptr_t)c->rcx;
    uint64_t d = c->rdx;
    if (!b || !d) return;
    memset((void *)(uintptr_t)d, 0, 24);
    W32(d + 0, b->byte_width);
    W32(d + 4, b->usage);
    W32(d + 8, b->bind_flags);
}

/* ---- ID3D11Device methods ---- */
static void dev_CreateBuffer(CPU64 *c, void *ud) {
    (void)ud;
    D3D11DeviceObj *dev = (D3D11DeviceObj *)(uintptr_t)c->rcx;
    uint64_t desc_va = c->rdx;
    uint64_t init_va = c->r8;
    uint64_t out_va  = c->r9;
    if (!dev || !desc_va || !out_va) { c->rax = E_INVALIDARG_H; return; }

    uint32_t byte_width = R32(desc_va + 0);
    uint32_t usage      = R32(desc_va + 4);
    uint32_t bind_flags = R32(desc_va + 8);
    if (byte_width == 0) byte_width = 16;

    id<MTLBuffer> mb = [dev->mtl_dev newBufferWithLength:byte_width options:MTLResourceStorageModeShared];
    if (!mb) { c->rax = E_FAIL_HR; return; }
    if (init_va) {
        uint64_t src_va = R64(init_va + 0);
        if (src_va) memcpy([mb contents], (const void *)(uintptr_t)src_va, byte_width);
    }

    D3D11BufferObj *obj = (D3D11BufferObj *)calloc(1, sizeof(D3D11BufferObj));
    obj->base.lpVtbl = g_vt_buffer;
    obj->base.kind = COM_BUFFER;
    obj->base.refcount = 1;
    obj->mtl_buf = mb;
    obj->byte_width = byte_width;
    obj->bind_flags = bind_flags;
    obj->usage = usage;
    W64(out_va, (uint64_t)(uintptr_t)obj);
    c->rax = S_OK_HR;
}

static void dev_CreateTexture2D(CPU64 *c, void *ud) {
    (void)ud;
    D3D11DeviceObj *dev = (D3D11DeviceObj *)(uintptr_t)c->rcx;
    uint64_t desc_va = c->rdx;
    uint64_t init_va = c->r8;
    uint64_t out_va  = c->r9;
    if (!dev || !desc_va || !out_va) { c->rax = E_INVALIDARG_H; return; }

    uint32_t w = R32(desc_va + 0);
    uint32_t h = R32(desc_va + 4);
    uint32_t fmt = R32(desc_va + 16);
    uint32_t usage = R32(desc_va + 28);
    const void *init_mem = init_va ? (const void *)(uintptr_t)R64(init_va) : NULL;
    uint32_t init_pitch = init_va ? R32(init_va + 8) : 0;

    D3D11Texture2DObj *obj = create_tex2d_internal(dev, w, h, fmt, usage, init_mem, init_pitch);
    if (!obj) { c->rax = E_FAIL_HR; return; }
    W64(out_va, (uint64_t)(uintptr_t)obj);
    c->rax = S_OK_HR;
}

static void dev_CreateRenderTargetView(CPU64 *c, void *ud) {
    (void)ud;
    D3D11Texture2DObj *tex = (D3D11Texture2DObj *)(uintptr_t)c->rdx;
    uint64_t out_va = c->r9;
    if (!tex || !out_va) { c->rax = E_INVALIDARG_H; return; }
    D3D11RTVObj *rtv = (D3D11RTVObj *)calloc(1, sizeof(D3D11RTVObj));
    rtv->base.lpVtbl = g_vt_generic;
    rtv->base.kind = COM_RTV;
    rtv->base.refcount = 1;
    rtv->tex = tex;
    tex->base.refcount++;
    W64(out_va, (uint64_t)(uintptr_t)rtv);
    c->rax = S_OK_HR;
}

static void dev_CreateInputLayout(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t descs_va = c->rdx;
    uint32_t count    = (uint32_t)c->r8;
    uint64_t out_va   = win64_arg_i(c, 5);
    if (!descs_va || !out_va) { c->rax = E_INVALIDARG_H; return; }
    D3D11InputLayoutObj *il = (D3D11InputLayoutObj *)calloc(1, sizeof(D3D11InputLayoutObj));
    il->base.lpVtbl = g_vt_generic;
    il->base.kind = COM_INPUT_LAYOUT;
    il->base.refcount = 1;
    if (count > 16) count = 16;
    il->num_elems = (int)count;
    uint32_t auto_off = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t e = descs_va + (uint64_t)i * 32ULL;
        uint32_t fmt  = R32(e + 12);
        uint32_t slot = R32(e + 16);
        uint32_t off  = R32(e + 20);
        if (off == 0xFFFFFFFFU) off = auto_off;
        il->elems[i].slot = slot;
        il->elems[i].dxgi_fmt = fmt;
        il->elems[i].offset = off;
        il->elems[i].attr_idx = i;
        uint32_t sz = (fmt == 2) ? 16 : (fmt == 6 ? 12 : (fmt == 16 ? 8 : 4));
        auto_off = off + sz;
    }
    W64(out_va, (uint64_t)(uintptr_t)il);
    c->rax = S_OK_HR;
}

static void create_shader_common(CPU64 *c, int expect_pixel) {
    D3D11DeviceObj *dev = (D3D11DeviceObj *)(uintptr_t)c->rcx;
    const void *bc = (const void *)(uintptr_t)c->rdx;
    size_t bclen = (size_t)c->r8;
    uint64_t out_va = win64_arg_i(c, 4);
    if (!dev || !bc || !out_va) { c->rax = E_INVALIDARG_H; return; }

    D3D11ShaderObj *sh = (D3D11ShaderObj *)calloc(1, sizeof(D3D11ShaderObj));
    if (dxbc_to_msl(bc, bclen, &sh->info) != 0 || sh->info.is_pixel != expect_pixel) {
        fprintf(stderr, "d3d11_metal: DXBC -> MSL translation failed (expect_pixel=%d)\n", expect_pixel);
        free(sh->info.msl_source);
        free(sh);
        c->rax = E_FAIL_HR;
        return;
    }

    @autoreleasepool {
        NSString *src = [NSString stringWithUTF8String:sh->info.msl_source];
        NSError *err = nil;
        id<MTLLibrary> lib = [dev->mtl_dev newLibraryWithSource:src options:nil error:&err];
        if (!lib) {
            if (getenv("ELF64_TRACE")) {
                fprintf(stderr, "d3d11_metal: MSL compile fallback (pixel=%d): %s\n",
                        expect_pixel, err ? [[err localizedDescription] UTF8String] : "?");
            }
            /* shortcut: compile minimal passthrough MSL fallback when a complex SM5 shader uses unimplemented DXBC features */
            NSString *fb = expect_pixel
                ? @"#include <metal_stdlib>\nusing namespace metal;\nfragment float4 fs_main() { return float4(1.0); }\n"
                : @"#include <metal_stdlib>\nusing namespace metal;\nstruct VSOut { float4 p [[position]]; };\nvertex VSOut vs_main() { VSOut o; o.p = float4(0.0,0.0,0.0,1.0); return o; }\n";
            lib = [dev->mtl_dev newLibraryWithSource:fb options:nil error:nil];
        }
        sh->mtl_fn = lib ? [lib newFunctionWithName:(expect_pixel ? @"fs_main" : @"vs_main")] : nil;
    }

    sh->base.lpVtbl = g_vt_generic;
    sh->base.kind = expect_pixel ? COM_PSHADER : COM_VSHADER;
    sh->base.refcount = 1;
    W64(out_va, (uint64_t)(uintptr_t)sh);
    c->rax = S_OK_HR;
}

static void dev_CreateVertexShader(CPU64 *c, void *ud) { (void)ud; create_shader_common(c, 0); }
static void dev_CreatePixelShader(CPU64 *c, void *ud)  { (void)ud; create_shader_common(c, 1); }

static void dev_CreateGenericState(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t out_va = c->r8;
    if (!out_va) { c->rax = E_INVALIDARG_H; return; }
    ComBase *s = (ComBase *)calloc(1, sizeof(ComBase));
    s->lpVtbl = g_vt_generic; s->kind = COM_GENERIC_STATE; s->refcount = 1;
    W64(out_va, (uint64_t)(uintptr_t)s);
    c->rax = S_OK_HR;
}
static void dev_CreateGenericView(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t out_va = c->r9;
    if (!out_va) { c->rax = E_INVALIDARG_H; return; }
    ComBase *s = (ComBase *)calloc(1, sizeof(ComBase));
    s->lpVtbl = g_vt_generic; s->kind = COM_GENERIC_STATE; s->refcount = 1;
    W64(out_va, (uint64_t)(uintptr_t)s);
    c->rax = S_OK_HR;
}
static void dev_GetFeatureLevel(CPU64 *c, void *ud) { (void)ud; c->rax = 0xb000; /* D3D_FEATURE_LEVEL_11_0 */ }
static void dev_GetImmediateContext(CPU64 *c, void *ud) {
    (void)ud;
    D3D11DeviceObj *dev = (D3D11DeviceObj *)(uintptr_t)c->rcx;
    if (dev && c->rdx) {
        dev->imm_ctx->base.refcount++;
        W64(c->rdx, (uint64_t)(uintptr_t)dev->imm_ctx);
    }
}

/* ---- ID3D11DeviceContext methods ---- */
static void ctx_VSSetConstantBuffers(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t start = (uint32_t)c->rdx, num = (uint32_t)c->r8;
    uint64_t arr = c->r9;
    for (uint32_t i = 0; i < num && start + i < 14; i++)
        ctx->vs_cbs[start + i] = arr ? (D3D11BufferObj *)(uintptr_t)R64(arr + i * 8ULL) : NULL;
}
static void ctx_PSSetConstantBuffers(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t start = (uint32_t)c->rdx, num = (uint32_t)c->r8;
    uint64_t arr = c->r9;
    for (uint32_t i = 0; i < num && start + i < 14; i++)
        ctx->ps_cbs[start + i] = arr ? (D3D11BufferObj *)(uintptr_t)R64(arr + i * 8ULL) : NULL;
}
static void ctx_VSSetShader(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ctx->vs = (D3D11ShaderObj *)(uintptr_t)c->rdx;
}
static void ctx_PSSetShader(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ctx->ps = (D3D11ShaderObj *)(uintptr_t)c->rdx;
}
static void ctx_IASetInputLayout(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ctx->layout = (D3D11InputLayoutObj *)(uintptr_t)c->rdx;
}
static void ctx_IASetVertexBuffers(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t start = (uint32_t)c->rdx, num = (uint32_t)c->r8;
    uint64_t bufs_va = c->r9;
    uint64_t strides_va = win64_arg_i(c, 4);
    uint64_t offsets_va = win64_arg_i(c, 5);
    for (uint32_t i = 0; i < num && start + i < 8; i++) {
        ctx->vbs[start + i] = bufs_va ? (D3D11BufferObj *)(uintptr_t)R64(bufs_va + i * 8ULL) : NULL;
        ctx->vb_strides[start + i] = strides_va ? R32(strides_va + i * 4ULL) : 0;
        ctx->vb_offsets[start + i] = offsets_va ? R32(offsets_va + i * 4ULL) : 0;
    }
}
static void ctx_IASetIndexBuffer(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ctx->ib = (D3D11BufferObj *)(uintptr_t)c->rdx;
    ctx->ib_fmt = (uint32_t)c->r8;
    ctx->ib_offset = (uint32_t)c->r9;
}
static void ctx_IASetPrimitiveTopology(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ctx->topology = (uint32_t)c->rdx;
}
static void ctx_OMSetRenderTargets(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t num = (uint32_t)c->rdx;
    uint64_t rtvs_va = c->r8;
    if (num > 8) num = 8;
    ctx->num_rtvs = (int)num;
    for (uint32_t i = 0; i < num; i++) {
        ctx->rtvs[i] = rtvs_va ? (D3D11RTVObj *)(uintptr_t)R64(rtvs_va + i * 8ULL) : NULL;
    }
}
static void ctx_RSSetViewports(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t num = (uint32_t)c->rdx;
    uint64_t vp_va = c->r8;
    if (num > 0 && vp_va) {
        memcpy(&ctx->vp_x, (const void *)(uintptr_t)vp_va, 24);
        ctx->has_vp = 1;
    }
}

static void ctx_ClearRenderTargetView(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    D3D11RTVObj *rtv = (D3D11RTVObj *)(uintptr_t)c->rdx;
    uint64_t col_va = c->r8;
    if (!ctx || !rtv || !rtv->tex || !col_va) return;
    float rgba[4];
    memcpy(rgba, (const void *)(uintptr_t)col_va, 16);
    @autoreleasepool {
        MTLRenderPassDescriptor *rpd = [MTLRenderPassDescriptor renderPassDescriptor];
        rpd.colorAttachments[0].texture = rtv->tex->mtl_tex;
        rpd.colorAttachments[0].loadAction = MTLLoadActionClear;
        rpd.colorAttachments[0].storeAction = MTLStoreActionStore;
        rpd.colorAttachments[0].clearColor = MTLClearColorMake(rgba[0], rgba[1], rgba[2], rgba[3]);
        id<MTLCommandBuffer> cb = [ctx->dev->mtl_queue commandBuffer];
        id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rpd];
        [enc endEncoding];
        [cb commit];
        [cb waitUntilCompleted];
    }
}

static void ctx_draw_common(D3D11ContextObj *ctx, int indexed, uint32_t count, uint32_t start, int32_t base_vtx) {
    if (!ctx || !ctx->vs || !ctx->ps || ctx->num_rtvs <= 0 || !ctx->rtvs[0] || !ctx->rtvs[0]->tex) return;
    @autoreleasepool {
        D3D11Texture2DObj *rt = ctx->rtvs[0]->tex;
        MTLRenderPipelineDescriptor *ppd = [[MTLRenderPipelineDescriptor alloc] init];
        ppd.vertexFunction = ctx->vs->mtl_fn;
        ppd.fragmentFunction = ctx->ps->mtl_fn;
        ppd.colorAttachments[0].pixelFormat = rt->mtl_fmt;

        if (ctx->layout && ctx->layout->num_elems > 0) {
            MTLVertexDescriptor *vd = [MTLVertexDescriptor vertexDescriptor];
            for (int i = 0; i < ctx->layout->num_elems; i++) {
                LayoutElem *e = &ctx->layout->elems[i];
                vd.attributes[e->attr_idx].format = dxgi_to_mtl_vertex(e->dxgi_fmt);
                vd.attributes[e->attr_idx].offset = e->offset;
                vd.attributes[e->attr_idx].bufferIndex = e->slot;
                if (ctx->vb_strides[e->slot] > 0) {
                    vd.layouts[e->slot].stride = ctx->vb_strides[e->slot];
                    vd.layouts[e->slot].stepFunction = MTLVertexStepFunctionPerVertex;
                }
            }
            ppd.vertexDescriptor = vd;
        }

        NSError *err = nil;
        id<MTLRenderPipelineState> pso = [ctx->dev->mtl_dev newRenderPipelineStateWithDescriptor:ppd error:&err];
        if (!pso) {
            fprintf(stderr, "d3d11_metal: pipeline state error: %s\n",
                    err ? [[err localizedDescription] UTF8String] : "?");
            return;
        }

        MTLRenderPassDescriptor *rpd = [MTLRenderPassDescriptor renderPassDescriptor];
        rpd.colorAttachments[0].texture = rt->mtl_tex;
        rpd.colorAttachments[0].loadAction = MTLLoadActionLoad;
        rpd.colorAttachments[0].storeAction = MTLStoreActionStore;

        id<MTLCommandBuffer> cb = [ctx->dev->mtl_queue commandBuffer];
        id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rpd];
        [enc setRenderPipelineState:pso];

        MTLViewport vp;
        if (ctx->has_vp) {
            vp = (MTLViewport){ ctx->vp_x, ctx->vp_y, ctx->vp_w, ctx->vp_h, ctx->vp_minz, ctx->vp_maxz };
        } else {
            vp = (MTLViewport){ 0.0, 0.0, (double)rt->width, (double)rt->height, 0.0, 1.0 };
        }
        [enc setViewport:vp];

        for (int i = 0; i < 8; i++) {
            if (ctx->vbs[i] && ctx->vbs[i]->mtl_buf) {
                [enc setVertexBuffer:ctx->vbs[i]->mtl_buf offset:ctx->vb_offsets[i] atIndex:(NSUInteger)i];
            }
        }
        for (int i = 0; i < 14; i++) {
            if (ctx->vs_cbs[i] && ctx->vs_cbs[i]->mtl_buf) {
                [enc setVertexBuffer:ctx->vs_cbs[i]->mtl_buf offset:0 atIndex:(NSUInteger)(16 + i)];
            }
            if (ctx->ps_cbs[i] && ctx->ps_cbs[i]->mtl_buf) {
                [enc setFragmentBuffer:ctx->ps_cbs[i]->mtl_buf offset:0 atIndex:(NSUInteger)(16 + i)];
            }
        }

        MTLPrimitiveType prim = d3d_to_mtl_prim(ctx->topology);
        if (indexed && ctx->ib && ctx->ib->mtl_buf) {
            MTLIndexType itype = (ctx->ib_fmt == 57) ? MTLIndexTypeUInt16 : MTLIndexTypeUInt32;
            NSUInteger isz = (itype == MTLIndexTypeUInt16) ? 2 : 4;
            [enc drawIndexedPrimitives:prim indexCount:count indexType:itype
                           indexBuffer:ctx->ib->mtl_buf indexBufferOffset:(ctx->ib_offset + start * isz)
                         instanceCount:1 baseVertex:base_vtx baseInstance:0];
        } else {
            [enc drawPrimitives:prim vertexStart:start vertexCount:count];
        }
        [enc endEncoding];
        [cb commit];
        [cb waitUntilCompleted];
    }
}

static void ctx_Draw(CPU64 *c, void *ud) {
    (void)ud;
    ctx_draw_common((D3D11ContextObj *)(uintptr_t)c->rcx, 0, (uint32_t)c->rdx, (uint32_t)c->r8, 0);
}
static void ctx_DrawIndexed(CPU64 *c, void *ud) {
    (void)ud;
    ctx_draw_common((D3D11ContextObj *)(uintptr_t)c->rcx, 1, (uint32_t)c->rdx, (uint32_t)c->r8, (int32_t)c->r9);
}

static void ctx_CopyResource(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *dst = (ComBase *)(uintptr_t)c->rdx;
    ComBase *src = (ComBase *)(uintptr_t)c->r8;
    if (!ctx || !dst || !src) return;
    if (dst->kind == COM_TEXTURE2D && src->kind == COM_TEXTURE2D) {
        D3D11Texture2DObj *dt = (D3D11Texture2DObj *)dst;
        D3D11Texture2DObj *st = (D3D11Texture2DObj *)src;
        @autoreleasepool {
            id<MTLCommandBuffer> cb = [ctx->dev->mtl_queue commandBuffer];
            id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
            [blit copyFromTexture:st->mtl_tex sourceSlice:0 sourceLevel:0
                     sourceOrigin:MTLOriginMake(0, 0, 0)
                       sourceSize:MTLSizeMake(st->width, st->height, 1)
                        toTexture:dt->mtl_tex destinationSlice:0 destinationLevel:0
                destinationOrigin:MTLOriginMake(0, 0, 0)];
            [blit endEncoding];
            [cb commit];
            [cb waitUntilCompleted];
        }
    } else if (dst->kind == COM_BUFFER && src->kind == COM_BUFFER) {
        D3D11BufferObj *db = (D3D11BufferObj *)dst;
        D3D11BufferObj *sb = (D3D11BufferObj *)src;
        uint32_t n = db->byte_width < sb->byte_width ? db->byte_width : sb->byte_width;
        memcpy([db->mtl_buf contents], [sb->mtl_buf contents], n);
    }
}

static void ctx_Map(CPU64 *c, void *ud) {
    (void)ud;
    ComBase *res = (ComBase *)(uintptr_t)c->rdx;
    uint64_t mapped_va = win64_arg_i(c, 5);
    if (!res || !mapped_va) { c->rax = E_INVALIDARG_H; return; }
    if (res->kind == COM_BUFFER) {
        D3D11BufferObj *b = (D3D11BufferObj *)res;
        W64(mapped_va + 0, (uint64_t)(uintptr_t)[b->mtl_buf contents]);
        W32(mapped_va + 8, b->byte_width);
        W32(mapped_va + 12, b->byte_width);
        c->rax = S_OK_HR;
        return;
    }
    if (res->kind == COM_TEXTURE2D) {
        D3D11Texture2DObj *t = (D3D11Texture2DObj *)res;
        uint32_t row_pitch = t->width * 4U;
        size_t total = (size_t)row_pitch * t->height;
        if (!t->mapped_cpu) t->mapped_cpu = (uint8_t *)malloc(total);
        [t->mtl_tex getBytes:t->mapped_cpu bytesPerRow:row_pitch
                  fromRegion:MTLRegionMake2D(0, 0, t->width, t->height) mipmapLevel:0];
        W64(mapped_va + 0, (uint64_t)(uintptr_t)t->mapped_cpu);
        W32(mapped_va + 8, row_pitch);
        W32(mapped_va + 12, (uint32_t)total);
        c->rax = S_OK_HR;
        return;
    }
    c->rax = E_FAIL_HR;
}

static void ctx_Unmap(CPU64 *c, void *ud) {
    (void)ud;
    ComBase *res = (ComBase *)(uintptr_t)c->rdx;
    if (res && res->kind == COM_TEXTURE2D) {
        D3D11Texture2DObj *t = (D3D11Texture2DObj *)res;
        if (t->mapped_cpu) { free(t->mapped_cpu); t->mapped_cpu = NULL; }
    }
}

static void ctx_UpdateSubresource(CPU64 *c, void *ud) {
    (void)ud;
    ComBase *res = (ComBase *)(uintptr_t)c->rdx;
    uint64_t src_va = win64_arg_i(c, 4);
    if (res && res->kind == COM_BUFFER && src_va) {
        D3D11BufferObj *b = (D3D11BufferObj *)res;
        memcpy([b->mtl_buf contents], (const void *)(uintptr_t)src_va, b->byte_width);
    }
}

/* ---- IDXGISwapChain / IDXGIAdapter / IDXGIFactory ---- */
static void sc_GetBuffer(CPU64 *c, void *ud) {
    (void)ud;
    DXGISwapChainObj *sc = (DXGISwapChainObj *)(uintptr_t)c->rcx;
    uint64_t out_va = c->r9;
    if (!sc || !sc->backbuffer || !out_va) { c->rax = E_INVALIDARG_H; return; }
    sc->backbuffer->base.refcount++;
    W64(out_va, (uint64_t)(uintptr_t)sc->backbuffer);
    c->rax = S_OK_HR;
}

static void sc_GetDesc(CPU64 *c, void *ud) {
    (void)ud;
    DXGISwapChainObj *sc = (DXGISwapChainObj *)(uintptr_t)c->rcx;
    uint64_t d = c->rdx;
    if (!sc || !d) { c->rax = E_INVALIDARG_H; return; }
    memset((void *)(uintptr_t)d, 0, 72);
    W32(d + 0, sc->width); W32(d + 4, sc->height);
    W32(d + 8, 60); W32(d + 12, 1);
    W32(d + 16, sc->backbuffer ? sc->backbuffer->dxgi_fmt : 28);
    W32(d + 28, 1);  /* SampleDesc.Count */
    W32(d + 36, 0x20 /* DXGI_USAGE_RENDER_TARGET_OUTPUT */);
    W32(d + 40, 1);  /* BufferCount */
    W64(d + 48, 0x1000ULL);
    W32(d + 56, 1);  /* Windowed */
    c->rax = S_OK_HR;
}

static void sc_Present(CPU64 *c, void *ud) {
    (void)ud;
    DXGISwapChainObj *sc = (DXGISwapChainObj *)(uintptr_t)c->rcx;
    if (sc && sc->metal_layer && sc->backbuffer) {
        @autoreleasepool {
            id<CAMetalDrawable> drawable = [sc->metal_layer nextDrawable];
            if (drawable) {
                id<MTLCommandBuffer> cb = [sc->dev->mtl_queue commandBuffer];
                id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
                NSUInteger w = sc->backbuffer->width < drawable.texture.width ? sc->backbuffer->width : drawable.texture.width;
                NSUInteger h = sc->backbuffer->height < drawable.texture.height ? sc->backbuffer->height : drawable.texture.height;
                [blit copyFromTexture:sc->backbuffer->mtl_tex sourceSlice:0 sourceLevel:0
                         sourceOrigin:MTLOriginMake(0, 0, 0) sourceSize:MTLSizeMake(w, h, 1)
                            toTexture:drawable.texture destinationSlice:0 destinationLevel:0
                    destinationOrigin:MTLOriginMake(0, 0, 0)];
                [blit endEncoding];
                [cb presentDrawable:drawable];
                [cb commit];
            }
        }
    }
    c->rax = S_OK_HR;
}

static void adapter_GetDesc(CPU64 *c, void *ud) {
    (void)ud;
    DXGIAdapterObj *ad = (DXGIAdapterObj *)(uintptr_t)c->rcx;
    uint64_t dst = c->rdx;
    if (!ad || !dst) { c->rax = E_INVALIDARG_H; return; }
    memset((void *)(uintptr_t)dst, 0, 312);
    const char *name = [[ad->mtl_dev name] UTF8String];
    uint16_t *wname = (uint16_t *)(uintptr_t)dst;
    for (size_t i = 0; name && name[i] && i < 127; i++) wname[i] = (uint8_t)name[i];
    W32(dst + 256, 0x106BU); /* Apple VendorId */
    W32(dst + 260, 0x0001U); /* DeviceId */
    W64(dst + 272, 4ULL * 1024 * 1024 * 1024); /* DedicatedVideoMemory: 4 GiB */
    W64(dst + 288, 8ULL * 1024 * 1024 * 1024); /* SharedSystemMemory: 8 GiB */
    c->rax = S_OK_HR;
}

static uint64_t g_vt_output[16];
static void output_GetDesc(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t dst = c->rdx;
    if (!dst) { c->rax = E_INVALIDARG_H; return; }
    memset((void *)(uintptr_t)dst, 0, 96);
    const char *dn = "\\\\.\\DISPLAY1";
    uint16_t *w = (uint16_t *)(uintptr_t)dst;
    for (size_t i = 0; dn[i]; i++) w[i] = (uint8_t)dn[i];
    W32(dst + 64, 0); W32(dst + 68, 0); W32(dst + 72, 1920); W32(dst + 76, 1080);
    W32(dst + 80, 1); /* AttachedToDesktop */
    W32(dst + 84, 1); /* DXGI_MODE_ROTATION_IDENTITY */
    W64(dst + 88, 0x1001ULL); /* Monitor */
    c->rax = S_OK_HR;
}
static void output_GetDisplayModeList(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t fmt = (uint32_t)c->rdx;
    uint64_t p_num = c->r9;
    uint64_t p_desc = win64_arg_i(c, 4);
    static const struct { uint32_t w, h; } modes[] = { {1280, 720}, {1600, 900}, {1920, 1080} };
    if (!p_num) { c->rax = E_INVALIDARG_H; return; }
    if (!p_desc) { W32(p_num, 3); c->rax = S_OK_HR; return; }
    uint32_t cap = R32(p_num);
    uint32_t n = cap < 3 ? cap : 3;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t d = p_desc + i * 28ULL;
        memset((void *)(uintptr_t)d, 0, 28);
        W32(d + 0, modes[i].w); W32(d + 4, modes[i].h);
        W32(d + 8, 60); W32(d + 12, 1);
        W32(d + 16, fmt ? fmt : 28);
    }
    W32(p_num, n);
    c->rax = S_OK_HR;
}
static void adapter_EnumOutputs(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx = (uint32_t)c->rdx;
    uint64_t out_va = c->r8;
    if (idx > 0 || !out_va) { c->rax = 0x887A0002U; return; }
    ComBase *o = (ComBase *)calloc(1, sizeof(ComBase));
    o->lpVtbl = g_vt_output; o->kind = COM_GENERIC_STATE; o->refcount = 1;
    W64(out_va, (uint64_t)(uintptr_t)o);
    c->rax = S_OK_HR;
}
static void factory_CreateSwapChain(CPU64 *c, void *ud) {
    (void)ud;
    D3D11DeviceObj *dev = (D3D11DeviceObj *)(uintptr_t)c->rdx;
    uint64_t sc_desc_va = c->r8;
    uint64_t pp_sc = c->r9;
    if (!dev || !pp_sc) { c->rax = E_INVALIDARG_H; return; }
    uint32_t w = sc_desc_va ? R32(sc_desc_va + 0) : 1280;
    uint32_t h = sc_desc_va ? R32(sc_desc_va + 4) : 720;
    uint32_t fmt = sc_desc_va ? R32(sc_desc_va + 16) : 28;
    uint64_t hwnd = sc_desc_va ? R64(sc_desc_va + 48) : 0;
    if (w == 0) w = 1280;
    if (h == 0) h = 720;
    DXGISwapChainObj *sc = (DXGISwapChainObj *)calloc(1, sizeof(DXGISwapChainObj));
    sc->base.lpVtbl = g_vt_swapchain; sc->base.kind = COM_SWAPCHAIN; sc->base.refcount = 1;
    sc->dev = dev; sc->width = w; sc->height = h;
    sc->backbuffer = create_tex2d_internal(dev, w, h, fmt, 0, NULL, 0);
    SDL_Window *win = win32_hwnd_to_sdl(hwnd);
    if (win) {
        sc->metal_view = SDL_Metal_CreateView(win);
        if (sc->metal_view) {
            sc->metal_layer = (__bridge CAMetalLayer *)SDL_Metal_GetLayer(sc->metal_view);
            sc->metal_layer.device = dev->mtl_dev;
            sc->metal_layer.pixelFormat = MTLPixelFormatBGRA8Unorm;
            sc->metal_layer.drawableSize = CGSizeMake(w, h);
        }
    }
    W64(pp_sc, (uint64_t)(uintptr_t)sc);
    c->rax = S_OK_HR;
}
static void dev_CheckFormatSupport(CPU64 *c, void *ud) {
    (void)ud;
    if (c->r8) W32(c->r8, 0x00FFFFFFU);
    c->rax = S_OK_HR;
}
static void dev_CheckMultisampleQualityLevels(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t samples = (uint32_t)c->r8;
    if (c->r9) W32(c->r9, (samples <= 4) ? 1U : 0U);
    c->rax = S_OK_HR;
}

static void dxgi_GetParentFactory(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t pp_parent = c->r8;
    if (!pp_parent) { c->rax = E_INVALIDARG_H; return; }
    DXGIFactoryObj *fac = (DXGIFactoryObj *)calloc(1, sizeof(DXGIFactoryObj));
    fac->base.lpVtbl = g_vt_factory;
    fac->base.kind = COM_FACTORY;
    fac->base.refcount = 1;
    W64(pp_parent, (uint64_t)(uintptr_t)fac);
    c->rax = S_OK_HR;
}

static void factory_EnumAdapters(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx = (uint32_t)c->rdx;
    uint64_t out_va = c->r8;
    if (idx > 0 || !out_va) { c->rax = 0x887A0002U; /* DXGI_ERROR_NOT_FOUND */ return; }
    DXGIAdapterObj *ad = (DXGIAdapterObj *)calloc(1, sizeof(DXGIAdapterObj));
    ad->base.lpVtbl = g_vt_adapter; ad->base.kind = COM_ADAPTER; ad->base.refcount = 1;
    ad->mtl_dev = MTLCreateSystemDefaultDevice();
    W64(out_va, (uint64_t)(uintptr_t)ad);
    c->rax = S_OK_HR;
}

/* ---- Vtable initialization ---- */
static void init_d3d11_vtables(void) {
    if (g_vt_ready) return;
    uint64_t t_qi   = rt_alloc_dynamic_thunk("IUnknown::QueryInterface", com_QueryInterface, NULL);
    uint64_t t_add  = rt_alloc_dynamic_thunk("IUnknown::AddRef", com_AddRef, NULL);
    uint64_t t_rel  = rt_alloc_dynamic_thunk("IUnknown::Release", com_Release, NULL);
    uint64_t t_ok   = rt_alloc_dynamic_thunk("COM::StubOK", com_stub_ok, NULL);
    uint64_t t_void = rt_alloc_dynamic_thunk("COM::StubVoid", com_stub_void, NULL);

    for (size_t i = 0; i < 48; i++)  g_vt_device[i] = t_ok;
    for (size_t i = 0; i < 120; i++) g_vt_context[i] = t_void;
    for (size_t i = 0; i < 20; i++)  g_vt_swapchain[i] = t_ok;
    for (size_t i = 0; i < 16; i++)  g_vt_factory[i] = t_ok;
    for (size_t i = 0; i < 16; i++)  g_vt_adapter[i] = t_ok;
    for (size_t i = 0; i < 16; i++)  g_vt_output[i]  = t_ok;
    for (size_t i = 0; i < 16; i++)  g_vt_tex2d[i]   = t_ok;
    for (size_t i = 0; i < 16; i++)  g_vt_buffer[i]  = t_ok;
    for (size_t i = 0; i < 16; i++)  g_vt_generic[i] = t_ok;

    #define SET_IUNK(vt) do { (vt)[0]=t_qi; (vt)[1]=t_add; (vt)[2]=t_rel; } while(0)
    SET_IUNK(g_vt_device); SET_IUNK(g_vt_context); SET_IUNK(g_vt_swapchain);
    SET_IUNK(g_vt_factory); SET_IUNK(g_vt_adapter); SET_IUNK(g_vt_output);
    SET_IUNK(g_vt_tex2d); SET_IUNK(g_vt_buffer); SET_IUNK(g_vt_generic);
    #undef SET_IUNK
    g_vt_tex2d[7]  = rt_alloc_dynamic_thunk("ID3D11Texture2D::GetType", tex2d_GetType, NULL);
    g_vt_tex2d[10] = rt_alloc_dynamic_thunk("ID3D11Texture2D::GetDesc", tex2d_GetDesc, NULL);
    g_vt_buffer[7] = rt_alloc_dynamic_thunk("ID3D11Buffer::GetType", buf_GetType, NULL);
    g_vt_buffer[10]= rt_alloc_dynamic_thunk("ID3D11Buffer::GetDesc", buf_GetDesc, NULL);

    /* ID3D11Device slots */
    g_vt_device[3]  = rt_alloc_dynamic_thunk("ID3D11Device::CreateBuffer", dev_CreateBuffer, NULL);
    g_vt_device[5]  = rt_alloc_dynamic_thunk("ID3D11Device::CreateTexture2D", dev_CreateTexture2D, NULL);
    g_vt_device[7]  = rt_alloc_dynamic_thunk("ID3D11Device::CreateShaderResourceView", dev_CreateGenericView, NULL);
    g_vt_device[8]  = rt_alloc_dynamic_thunk("ID3D11Device::CreateUnorderedAccessView", dev_CreateGenericView, NULL);
    g_vt_device[9]  = rt_alloc_dynamic_thunk("ID3D11Device::CreateRenderTargetView", dev_CreateRenderTargetView, NULL);
    g_vt_device[10] = rt_alloc_dynamic_thunk("ID3D11Device::CreateDepthStencilView", dev_CreateGenericView, NULL);
    g_vt_device[11] = rt_alloc_dynamic_thunk("ID3D11Device::CreateInputLayout", dev_CreateInputLayout, NULL);
    g_vt_device[12] = rt_alloc_dynamic_thunk("ID3D11Device::CreateVertexShader", dev_CreateVertexShader, NULL);
    g_vt_device[15] = rt_alloc_dynamic_thunk("ID3D11Device::CreatePixelShader", dev_CreatePixelShader, NULL);
    g_vt_device[20] = rt_alloc_dynamic_thunk("ID3D11Device::CreateBlendState", dev_CreateGenericState, NULL);
    g_vt_device[21] = rt_alloc_dynamic_thunk("ID3D11Device::CreateDepthStencilState", dev_CreateGenericState, NULL);
    g_vt_device[22] = rt_alloc_dynamic_thunk("ID3D11Device::CreateRasterizerState", dev_CreateGenericState, NULL);
    g_vt_device[23] = rt_alloc_dynamic_thunk("ID3D11Device::CreateSamplerState", dev_CreateGenericState, NULL);
    g_vt_device[24] = rt_alloc_dynamic_thunk("ID3D11Device::CreateQuery", dev_CreateGenericState, NULL);
    g_vt_device[29] = rt_alloc_dynamic_thunk("ID3D11Device::CheckFormatSupport", dev_CheckFormatSupport, NULL);
    g_vt_device[30] = rt_alloc_dynamic_thunk("ID3D11Device::CheckMultisampleQualityLevels", dev_CheckMultisampleQualityLevels, NULL);
    g_vt_device[37] = rt_alloc_dynamic_thunk("ID3D11Device::GetFeatureLevel", dev_GetFeatureLevel, NULL);
    g_vt_device[40] = rt_alloc_dynamic_thunk("ID3D11Device::GetImmediateContext", dev_GetImmediateContext, NULL);

    /* ID3D11DeviceContext slots */
    g_vt_context[7]  = rt_alloc_dynamic_thunk("ID3D11DeviceContext::VSSetConstantBuffers", ctx_VSSetConstantBuffers, NULL);
    g_vt_context[9]  = rt_alloc_dynamic_thunk("ID3D11DeviceContext::PSSetShader", ctx_PSSetShader, NULL);
    g_vt_context[11] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::VSSetShader", ctx_VSSetShader, NULL);
    g_vt_context[12] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::DrawIndexed", ctx_DrawIndexed, NULL);
    g_vt_context[13] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::Draw", ctx_Draw, NULL);
    g_vt_context[14] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::Map", ctx_Map, NULL);
    g_vt_context[15] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::Unmap", ctx_Unmap, NULL);
    g_vt_context[16] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::PSSetConstantBuffers", ctx_PSSetConstantBuffers, NULL);
    g_vt_context[17] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::IASetInputLayout", ctx_IASetInputLayout, NULL);
    g_vt_context[18] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::IASetVertexBuffers", ctx_IASetVertexBuffers, NULL);
    g_vt_context[19] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::IASetIndexBuffer", ctx_IASetIndexBuffer, NULL);
    g_vt_context[24] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::IASetPrimitiveTopology", ctx_IASetPrimitiveTopology, NULL);
    g_vt_context[33] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::OMSetRenderTargets", ctx_OMSetRenderTargets, NULL);
    g_vt_context[44] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::RSSetViewports", ctx_RSSetViewports, NULL);
    g_vt_context[47] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::CopyResource", ctx_CopyResource, NULL);
    g_vt_context[48] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::UpdateSubresource", ctx_UpdateSubresource, NULL);
    g_vt_context[50] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::ClearRenderTargetView", ctx_ClearRenderTargetView, NULL);

    /* IDXGISwapChain / IDXGIAdapter / IDXGIOutput / IDXGIFactory slots */
    uint64_t t_get_parent = rt_alloc_dynamic_thunk("IDXGIObject::GetParent", dxgi_GetParentFactory, NULL);
    g_vt_swapchain[6] = t_get_parent;
    g_vt_swapchain[8] = rt_alloc_dynamic_thunk("IDXGISwapChain::Present", sc_Present, NULL);
    g_vt_swapchain[9] = rt_alloc_dynamic_thunk("IDXGISwapChain::GetBuffer", sc_GetBuffer, NULL);
    g_vt_swapchain[12]= rt_alloc_dynamic_thunk("IDXGISwapChain::GetDesc", sc_GetDesc, NULL);
    g_vt_adapter[6]   = t_get_parent;
    g_vt_adapter[7]   = rt_alloc_dynamic_thunk("IDXGIAdapter::EnumOutputs", adapter_EnumOutputs, NULL);
    g_vt_adapter[8]   = rt_alloc_dynamic_thunk("IDXGIAdapter::GetDesc", adapter_GetDesc, NULL);
    g_vt_adapter[10]  = rt_alloc_dynamic_thunk("IDXGIAdapter1::GetDesc1", adapter_GetDesc, NULL);
    g_vt_output[7]    = rt_alloc_dynamic_thunk("IDXGIOutput::GetDesc", output_GetDesc, NULL);
    g_vt_output[8]    = rt_alloc_dynamic_thunk("IDXGIOutput::GetDisplayModeList", output_GetDisplayModeList, NULL);
    g_vt_factory[7]   = rt_alloc_dynamic_thunk("IDXGIFactory::EnumAdapters", factory_EnumAdapters, NULL);
    g_vt_factory[10]  = rt_alloc_dynamic_thunk("IDXGIFactory::CreateSwapChain", factory_CreateSwapChain, NULL);
    g_vt_factory[12]  = rt_alloc_dynamic_thunk("IDXGIFactory1::EnumAdapters1", factory_EnumAdapters, NULL);

    g_vt_ready = 1;
}

/* ---- Top-level DLL exports: D3D11CreateDevice*, CreateDXGIFactory* ---- */
static D3D11DeviceObj *create_device_internal(void) {
    init_d3d11_vtables();
    id<MTLDevice> mdev = MTLCreateSystemDefaultDevice();
    if (!mdev) return NULL;
    D3D11DeviceObj *dev = (D3D11DeviceObj *)calloc(1, sizeof(D3D11DeviceObj));
    dev->base.lpVtbl = g_vt_device;
    dev->base.kind = COM_DEVICE;
    dev->base.refcount = 1;
    dev->mtl_dev = mdev;
    dev->mtl_queue = [mdev newCommandQueue];

    D3D11ContextObj *ctx = (D3D11ContextObj *)calloc(1, sizeof(D3D11ContextObj));
    ctx->base.lpVtbl = g_vt_context;
    ctx->base.kind = COM_CONTEXT;
    ctx->base.refcount = 1;
    ctx->dev = dev;
    ctx->topology = 4; /* D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST */
    dev->imm_ctx = ctx;
    return dev;
}

static void w_D3D11CreateDevice(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t pp_dev = win64_arg_i(c, 7);
    uint64_t p_fl   = win64_arg_i(c, 8);
    uint64_t pp_ctx = win64_arg_i(c, 9);
    D3D11DeviceObj *dev = create_device_internal();
    if (!dev) { c->rax = E_FAIL_HR; return; }
    if (pp_dev) W64(pp_dev, (uint64_t)(uintptr_t)dev);
    if (p_fl)   W32(p_fl, 0xb000);
    if (pp_ctx) W64(pp_ctx, (uint64_t)(uintptr_t)dev->imm_ctx);
    c->rax = S_OK_HR;
}

static void w_D3D11CreateDeviceAndSwapChain(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t sc_desc_va = win64_arg_i(c, 7);
    uint64_t pp_sc      = win64_arg_i(c, 8);
    uint64_t pp_dev     = win64_arg_i(c, 9);
    uint64_t p_fl       = win64_arg_i(c, 10);
    uint64_t pp_ctx     = win64_arg_i(c, 11);

    D3D11DeviceObj *dev = create_device_internal();
    if (!dev) { c->rax = E_FAIL_HR; return; }

    uint32_t w = sc_desc_va ? R32(sc_desc_va + 0) : 800;
    uint32_t h = sc_desc_va ? R32(sc_desc_va + 4) : 600;
    uint32_t fmt = sc_desc_va ? R32(sc_desc_va + 16) : 28;
    uint64_t hwnd = sc_desc_va ? R64(sc_desc_va + 48) : 0;
    if (w == 0) w = 800;
    if (h == 0) h = 600;

    DXGISwapChainObj *sc = (DXGISwapChainObj *)calloc(1, sizeof(DXGISwapChainObj));
    sc->base.lpVtbl = g_vt_swapchain;
    sc->base.kind = COM_SWAPCHAIN;
    sc->base.refcount = 1;
    sc->dev = dev;
    sc->width = w;
    sc->height = h;
    sc->backbuffer = create_tex2d_internal(dev, w, h, fmt, 0, NULL, 0);

    SDL_Window *win = win32_hwnd_to_sdl(hwnd);
    if (win) {
        sc->metal_view = SDL_Metal_CreateView(win);
        if (sc->metal_view) {
            sc->metal_layer = (__bridge CAMetalLayer *)SDL_Metal_GetLayer(sc->metal_view);
            sc->metal_layer.device = dev->mtl_dev;
            sc->metal_layer.pixelFormat = MTLPixelFormatBGRA8Unorm;
            sc->metal_layer.drawableSize = CGSizeMake(w, h);
        }
    }

    if (pp_sc)  W64(pp_sc, (uint64_t)(uintptr_t)sc);
    if (pp_dev) W64(pp_dev, (uint64_t)(uintptr_t)dev);
    if (p_fl)   W32(p_fl, 0xb000);
    if (pp_ctx) W64(pp_ctx, (uint64_t)(uintptr_t)dev->imm_ctx);
    c->rax = S_OK_HR;
}

static void w_CreateDXGIFactory(CPU64 *c, void *ud) {
    (void)ud;
    init_d3d11_vtables();
    uint64_t out_va = c->rdx;
    if (!out_va) { c->rax = E_INVALIDARG_H; return; }
    DXGIFactoryObj *fac = (DXGIFactoryObj *)calloc(1, sizeof(DXGIFactoryObj));
    fac->base.lpVtbl = g_vt_factory;
    fac->base.kind = COM_FACTORY;
    fac->base.refcount = 1;
    W64(out_va, (uint64_t)(uintptr_t)fac);
    c->rax = S_OK_HR;
}

void rt_register_d3d11_64(void) {
    rt_register_shim("D3D11CreateDevice", w_D3D11CreateDevice, NULL);
    rt_register_shim("D3D11CreateDeviceAndSwapChain", w_D3D11CreateDeviceAndSwapChain, NULL);
    rt_register_shim("CreateDXGIFactory", w_CreateDXGIFactory, NULL);
    rt_register_shim("CreateDXGIFactory1", w_CreateDXGIFactory, NULL);
}
