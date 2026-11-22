#import <Cocoa/Cocoa.h>
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
#include <time.h>

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
    COM_SRV,
    COM_DSV,
    COM_SAMPLER,
    COM_BLEND_STATE,
    COM_DEPTH_STENCIL_STATE,
    COM_RASTERIZER_STATE,
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
    id<MTLBuffer>    ring[4];
    uint32_t         ring_idx;
    uint32_t         ring_used;
    uint32_t         byte_width;
    uint32_t         bind_flags;
    uint32_t         usage;
} D3D11BufferObj;

typedef struct {
    ComBase          base;
    id<MTLTexture>   mtl_tex;
    uint32_t         width;
    uint32_t         height;
    uint32_t         mip_levels;
    uint32_t         array_size;
    int              is_cube;
    uint32_t         dxgi_fmt;
    MTLPixelFormat   mtl_fmt;
    uint32_t         usage;
    uint8_t         *mapped_cpu;
    uint32_t         mapped_mip;
    uint32_t         mapped_pitch;
    uint32_t         mapped_maptype;
} D3D11Texture2DObj;

typedef struct {
    ComBase          base;
    int              blend_enable;
    uint32_t         src_blend;
    uint32_t         dst_blend;
    uint32_t         blend_op;
    uint32_t         src_blend_alpha;
    uint32_t         dst_blend_alpha;
    uint32_t         blend_op_alpha;
    uint8_t          write_mask;
} D3D11BlendStateObj;

typedef struct {
    ComBase                 base;
    id<MTLDepthStencilState> mtl_dss;
} D3D11DepthStencilStateObj;

typedef struct {
    ComBase  base;
    uint32_t cull_mode;
    int      front_ccw;
    int      scissor_enable;
    int32_t  depth_bias;
    float    depth_bias_clamp;
    float    slope_depth_bias;
} D3D11RasterizerStateObj;

typedef struct {
    ComBase            base;
    D3D11Texture2DObj *tex;
} D3D11RTVObj;

typedef struct {
    ComBase            base;
    D3D11Texture2DObj *tex;
} D3D11SRVObj;

typedef struct {
    ComBase            base;
    D3D11Texture2DObj *tex;
} D3D11DSVObj;

typedef struct {
    ComBase             base;
    id<MTLSamplerState> mtl_sampler;
} D3D11SamplerObj;

typedef struct {
    ComBase          base;
    id<MTLFunction>  mtl_fn;
    DxbcTranslated   info;
    uint8_t         *bc_copy;
    size_t           bc_len;
    int              is_pixel;
    int              compiled;
} D3D11ShaderObj;

typedef struct {
    char     semantic[32];
    uint32_t sem_idx;
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
    D3D11DSVObj         *dsv;
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
    D3D11SRVObj         *vs_srvs[16];
    D3D11SRVObj         *ps_srvs[16];
    D3D11SamplerObj     *vs_samplers[16];
    D3D11SamplerObj     *ps_samplers[16];
    D3D11BlendStateObj  *blend_state;
    float                blend_factor[4];
    int                  has_blend_factor;
    D3D11DepthStencilStateObj *ds_state;
    uint32_t             stencil_ref;
    D3D11RasterizerStateObj   *rs_state;
    uint32_t             topology;
    float                vp_x, vp_y, vp_w, vp_h, vp_minz, vp_maxz;
    int                  has_vp;
    int32_t              sc_l, sc_t, sc_r, sc_b;
    int                  has_scissor;
    id<MTLCommandBuffer>        pending_cb;
    id<MTLRenderCommandEncoder> active_enc;
    D3D11Texture2DObj          *enc_rt[4];
    int                         enc_nrt;
    D3D11Texture2DObj          *enc_dt;
};

typedef struct {
    D3D11ShaderObj      *vs;
    D3D11ShaderObj      *ps;
    D3D11InputLayoutObj *layout;
    D3D11BlendStateObj  *blend;
    MTLPixelFormat       color_fmts[4];
    int                  num_rts;
    MTLPixelFormat       depth_fmt;
    id<MTLRenderPipelineState> pso;
} PsoCacheEntry;

struct D3D11DeviceObj {
    ComBase            base;
    id<MTLDevice>      mtl_dev;
    id<MTLCommandQueue> mtl_queue;
    id<MTLSamplerState> default_sampler;
    id<MTLDepthStencilState> default_dss;
    id<MTLBuffer>      zero_vb;
    D3D11ContextObj   *imm_ctx;
    PsoCacheEntry      pso_cache[512];
    int                pso_count;
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

static int dxgi_is_bc(uint32_t fmt) {
    return ((fmt >= 70 && fmt <= 84) || (fmt >= 94 && fmt <= 99));
}

static uint32_t dxgi_block_bytes(uint32_t fmt) {
    switch (fmt) {
        case 70: case 71: case 72: /* BC1 */
        case 79: case 80: case 81: /* BC4 */
            return 8;
        case 73: case 74: case 75: /* BC2 */
        case 76: case 77: case 78: /* BC3 */
        case 82: case 83: case 84: /* BC5 */
        case 94: case 95: case 96: /* BC6H */
        case 97: case 98: case 99: /* BC7 */
            return 16;
        default: return 0;
    }
}

static uint32_t dxgi_bpp(uint32_t fmt) {
    switch (fmt) {
        case 60: case 61: case 62: case 63: case 64: case 65: return 1; /* R8 / A8 */
        case 48: case 49: case 50: case 51: case 52: case 53: case 54: case 56: case 57: case 58: case 59: return 2; /* RG8 / R16 */
        case 10: case 11: case 12: case 13: case 14: return 8;  /* RGBA16 */
        case 1:  case 2:  case 3:  case 4:  return 16;          /* RGBA32 */
        case 16: case 17: case 18: return 8;                    /* RG32 */
        default: return 4;                                      /* RGBA8 / BGRA8 / R32 / RG16 */
    }
}

static uint32_t dxgi_row_pitch(uint32_t fmt, uint32_t w) {
    uint32_t bb = dxgi_block_bytes(fmt);
    if (bb) return ((w + 3U) / 4U) * bb;
    return w * dxgi_bpp(fmt);
}

static uint32_t dxgi_num_rows(uint32_t fmt, uint32_t h) {
    return dxgi_is_bc(fmt) ? ((h + 3U) / 4U) : h;
}

static MTLPixelFormat dxgi_to_mtl_pixel(uint32_t fmt) {
    switch (fmt) {
        case 87: case 88: case 90: case 92: return MTLPixelFormatBGRA8Unorm;
        case 91: case 93:          return MTLPixelFormatBGRA8Unorm_sRGB;
        case 27: case 28:          return MTLPixelFormatRGBA8Unorm;
        case 29:                   return MTLPixelFormatRGBA8Unorm_sRGB;
        case 31:                   return MTLPixelFormatRGBA8Snorm;
        case 60: case 61:          return MTLPixelFormatR8Unorm;
        case 65:                   return MTLPixelFormatA8Unorm;
        case 48: case 49:          return MTLPixelFormatRG8Unorm;
        case 34:                   return MTLPixelFormatRG16Float;
        case 41:                   return MTLPixelFormatR32Float;
        case 10:                   return MTLPixelFormatRGBA16Float;
        case 11:                   return MTLPixelFormatRGBA16Unorm;
        case 2:                    return MTLPixelFormatRGBA32Float;
        case 70: case 71:          return MTLPixelFormatBC1_RGBA;
        case 72:                   return MTLPixelFormatBC1_RGBA_sRGB;
        case 73: case 74:          return MTLPixelFormatBC2_RGBA;
        case 75:                   return MTLPixelFormatBC2_RGBA_sRGB;
        case 76: case 77:          return MTLPixelFormatBC3_RGBA;
        case 78:                   return MTLPixelFormatBC3_RGBA_sRGB;
        case 79: case 80:          return MTLPixelFormatBC4_RUnorm;
        case 81:                   return MTLPixelFormatBC4_RSnorm;
        case 82: case 83:          return MTLPixelFormatBC5_RGUnorm;
        case 84:                   return MTLPixelFormatBC5_RGSnorm;
        case 94: case 95:          return MTLPixelFormatBC6H_RGBUfloat;
        case 96:                   return MTLPixelFormatBC6H_RGBFloat;
        case 97: case 98:          return MTLPixelFormatBC7_RGBAUnorm;
        case 99:                   return MTLPixelFormatBC7_RGBAUnorm_sRGB;
        case 20: case 44: case 45: return MTLPixelFormatDepth32Float_Stencil8;
        case 39: case 40: case 54: case 55: return MTLPixelFormatDepth32Float;
        default:                   return MTLPixelFormatRGBA8Unorm;
    }
}

static MTLBlendFactor d3d_to_mtl_blend(uint32_t b) {
    switch (b) {
        case 1:  return MTLBlendFactorZero;
        case 2:  return MTLBlendFactorOne;
        case 3:  return MTLBlendFactorSourceColor;
        case 4:  return MTLBlendFactorOneMinusSourceColor;
        case 5:  return MTLBlendFactorSourceAlpha;
        case 6:  return MTLBlendFactorOneMinusSourceAlpha;
        case 7:  return MTLBlendFactorDestinationAlpha;
        case 8:  return MTLBlendFactorOneMinusDestinationAlpha;
        case 9:  return MTLBlendFactorDestinationColor;
        case 10: return MTLBlendFactorOneMinusDestinationColor;
        case 11: return MTLBlendFactorSourceAlphaSaturated;
        case 14: return MTLBlendFactorBlendColor;
        case 15: return MTLBlendFactorOneMinusBlendColor;
        default: return MTLBlendFactorOne;
    }
}

static MTLBlendOperation d3d_to_mtl_blend_op(uint32_t op) {
    switch (op) {
        case 2: return MTLBlendOperationSubtract;
        case 3: return MTLBlendOperationReverseSubtract;
        case 4: return MTLBlendOperationMin;
        case 5: return MTLBlendOperationMax;
        case 1: default: return MTLBlendOperationAdd;
    }
}

static MTLCompareFunction d3d_to_mtl_cmp(uint32_t fn) {
    switch (fn) {
        case 1: return MTLCompareFunctionNever;
        case 2: return MTLCompareFunctionLess;
        case 3: return MTLCompareFunctionEqual;
        case 4: return MTLCompareFunctionLessEqual;
        case 5: return MTLCompareFunctionGreater;
        case 6: return MTLCompareFunctionNotEqual;
        case 7: return MTLCompareFunctionGreaterEqual;
        case 8: default: return MTLCompareFunctionAlways;
    }
}

static MTLVertexFormat dxgi_to_mtl_vertex(uint32_t fmt) {
    switch (fmt) {
        case 2:  return MTLVertexFormatFloat4;
        case 3:  return MTLVertexFormatUInt4;
        case 4:  return MTLVertexFormatInt4;
        case 6:  return MTLVertexFormatFloat3;
        case 10: return MTLVertexFormatHalf4;
        case 11: return MTLVertexFormatUShort4Normalized;
        case 13: return MTLVertexFormatShort4Normalized;
        case 16: return MTLVertexFormatFloat2;
        case 28: return MTLVertexFormatUChar4Normalized;
        case 30: return MTLVertexFormatUChar4;
        case 31: return MTLVertexFormatChar4Normalized;
        case 34: return MTLVertexFormatHalf2;
        case 35: return MTLVertexFormatUShort2Normalized;
        case 37: return MTLVertexFormatShort2Normalized;
        case 41: return MTLVertexFormatFloat;
        case 42: return MTLVertexFormatUInt;
        case 43: return MTLVertexFormatInt;
        case 87: return MTLVertexFormatUChar4Normalized_BGRA;
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

static D3D11Texture2DObj *create_tex2d_ex(D3D11DeviceObj *dev, uint32_t w, uint32_t h,
                                          uint32_t dxgi_fmt, uint32_t usage,
                                          uint32_t mip_levels, uint32_t array_size, int is_cube,
                                          uint64_t init_arr_va) {
    if (w == 0) w = 1;
    if (h == 0) h = 1;
    if (w > 16384) w = 16384;
    if (h > 16384) h = 16384;
    if (array_size == 0) array_size = 1;
    if (is_cube && (array_size != 6 || w != h)) is_cube = 0;
    int is_depth = dxgi_is_depth(dxgi_fmt);
    int is_bc = dxgi_is_bc(dxgi_fmt);
    uint32_t max_dim = w > h ? w : h;
    uint32_t max_mips = 1;
    while ((1U << max_mips) <= max_dim) max_mips++;
    if (mip_levels == 0 || mip_levels > max_mips) mip_levels = max_mips;
    if (is_depth) mip_levels = 1;

    MTLPixelFormat mfmt = dxgi_to_mtl_pixel(dxgi_fmt);
    MTLTextureDescriptor *td;
    if (is_cube) {
        td = [MTLTextureDescriptor textureCubeDescriptorWithPixelFormat:mfmt size:w mipmapped:(mip_levels > 1)];
    } else {
        td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:mfmt width:w height:h mipmapped:(mip_levels > 1)];
        if (array_size > 1) {
            td.textureType = MTLTextureType2DArray;
            td.arrayLength = array_size;
        }
    }
    td.mipmapLevelCount = mip_levels;
    td.storageMode = is_depth ? MTLStorageModePrivate : MTLStorageModeShared;
    td.usage = is_depth
        ? (MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead)
        : ((usage == 3 || is_bc)
            ? MTLTextureUsageShaderRead
            : (MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead));
    id<MTLTexture> tex = [dev->mtl_dev newTextureWithDescriptor:td];
    if (!tex) return NULL;
    if (init_arr_va && !is_depth) {
        uint32_t nslices = is_cube ? 6 : array_size;
        for (uint32_t sl = 0; sl < nslices; sl++) {
            for (uint32_t m = 0; m < mip_levels; m++) {
                uint32_t sub = sl * mip_levels + m;
                uint64_t src_va = R64(init_arr_va + (uint64_t)sub * 16ULL);
                uint32_t pitch  = R32(init_arr_va + (uint64_t)sub * 16ULL + 8ULL);
                if (!src_va) continue;
                uint32_t mw = w >> m; if (mw == 0) mw = 1;
                uint32_t mh = h >> m; if (mh == 0) mh = 1;
                uint32_t min_pitch = dxgi_row_pitch(dxgi_fmt, mw);
                if (pitch < min_pitch) pitch = min_pitch;
                [tex replaceRegion:MTLRegionMake2D(0, 0, mw, mh) mipmapLevel:m slice:sl
                         withBytes:(const void *)(uintptr_t)src_va bytesPerRow:pitch bytesPerImage:0];
            }
        }
    }
    D3D11Texture2DObj *obj = (D3D11Texture2DObj *)calloc(1, sizeof(D3D11Texture2DObj));
    obj->base.lpVtbl = g_vt_tex2d;
    obj->base.kind = COM_TEXTURE2D;
    obj->base.refcount = 1;
    obj->mtl_tex = tex;
    obj->width = w;
    obj->height = h;
    obj->mip_levels = mip_levels;
    obj->array_size = is_cube ? 6 : array_size;
    obj->is_cube = is_cube;
    obj->dxgi_fmt = dxgi_fmt;
    obj->mtl_fmt = mfmt;
    obj->usage = usage;
    return obj;
}

static D3D11Texture2DObj *create_tex2d_internal(D3D11DeviceObj *dev, uint32_t w, uint32_t h,
                                                uint32_t dxgi_fmt, uint32_t usage,
                                                uint32_t mip_levels, uint64_t init_arr_va) {
    return create_tex2d_ex(dev, w, h, dxgi_fmt, usage, mip_levels, 1, 0, init_arr_va);
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
    W32(d + 8, t->mip_levels ? t->mip_levels : 1);  /* MipLevels */
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
    uint32_t mips = R32(desc_va + 8);
    uint32_t arr = R32(desc_va + 12);
    uint32_t fmt = R32(desc_va + 16);
    uint32_t samples = R32(desc_va + 20);
    uint32_t usage = R32(desc_va + 28);
    uint32_t misc = R32(desc_va + 40);
    if (getenv("ELF64_D3D11_TRACE") && (arr > 1 || samples > 1 || (misc & 4))) {
        static int cnt = 0;
        if (cnt++ < 25) fprintf(stderr, "[d3d11] CreateTexture2D %ux%u fmt=%u arr=%u samples=%u misc=0x%x\n", w, h, fmt, arr, samples, misc);
    }

    D3D11Texture2DObj *obj = create_tex2d_ex(dev, w, h, fmt, usage, mips, arr, (misc & 4) != 0, init_va);
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
        const char *sname = (const char *)(uintptr_t)R64(e + 0);
        uint32_t sidx = R32(e + 8);
        uint32_t fmt  = R32(e + 12);
        uint32_t slot = R32(e + 16);
        uint32_t off  = R32(e + 20);
        if (off == 0xFFFFFFFFU) off = auto_off;
        snprintf(il->elems[i].semantic, sizeof(il->elems[i].semantic), "%s", sname ? sname : "");
        il->elems[i].sem_idx  = sidx;
        il->elems[i].slot     = slot;
        il->elems[i].dxgi_fmt = fmt;
        il->elems[i].offset   = off;
        il->elems[i].attr_idx = i;
        uint32_t sz = (fmt == 2 || fmt == 3 || fmt == 4) ? 16 : (fmt == 6 ? 12 : ((fmt == 16 || fmt == 10 || fmt == 11 || fmt == 13) ? 8 : 4));
        auto_off = off + sz;
    }
    W64(out_va, (uint64_t)(uintptr_t)il);
    c->rax = S_OK_HR;
}

static void ensure_shader_compiled(D3D11DeviceObj *dev, D3D11ShaderObj *sh) {
    if (!dev || !sh || sh->compiled) return;
    sh->compiled = 1;
    int expect_pixel = sh->is_pixel;
    if (!sh->bc_copy || dxbc_to_msl(sh->bc_copy, sh->bc_len, &sh->info) != 0) {
        if (getenv("ELF64_D3D11_TRACE") || getenv("ELF64_TRACE")) {
            fprintf(stderr, "d3d11_metal: DXBC -> MSL translation failed (pixel=%d)\n", expect_pixel);
        }
        return;
    }
    @autoreleasepool {
        NSString *src = [NSString stringWithUTF8String:sh->info.msl_source];
        NSError *err = nil;
        id<MTLLibrary> lib = [dev->mtl_dev newLibraryWithSource:src options:nil error:&err];
        if (!lib) {
            if (getenv("ELF64_D3D11_TRACE") || getenv("ELF64_TRACE")) {
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
}

static void create_shader_common(CPU64 *c, int expect_pixel) {
    D3D11DeviceObj *dev = (D3D11DeviceObj *)(uintptr_t)c->rcx;
    const void *bc = (const void *)(uintptr_t)c->rdx;
    size_t bclen = (size_t)c->r8;
    uint64_t out_va = win64_arg_i(c, 4);
    if (!dev || !bc || bclen < 32 || !out_va) { c->rax = E_INVALIDARG_H; return; }
    if (memcmp(bc, "DXBC", 4) != 0) { c->rax = E_FAIL_HR; return; }

    D3D11ShaderObj *sh = (D3D11ShaderObj *)calloc(1, sizeof(D3D11ShaderObj));
    sh->bc_copy = (uint8_t *)malloc(bclen);
    if (!sh->bc_copy) { free(sh); c->rax = E_FAIL_HR; return; }
    memcpy(sh->bc_copy, bc, bclen);
    sh->bc_len = bclen;
    sh->is_pixel = expect_pixel;
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
static void dev_CreateShaderResourceView(CPU64 *c, void *ud) {
    (void)ud;
    ComBase *res = (ComBase *)(uintptr_t)c->rdx;
    uint64_t out_va = c->r9;
    if (!out_va) { c->rax = E_INVALIDARG_H; return; }
    D3D11SRVObj *srv = (D3D11SRVObj *)calloc(1, sizeof(D3D11SRVObj));
    srv->base.lpVtbl = g_vt_generic;
    srv->base.kind = COM_SRV;
    srv->base.refcount = 1;
    if (res && res->kind == COM_TEXTURE2D) {
        srv->tex = (D3D11Texture2DObj *)res;
        res->refcount++;
    }
    W64(out_va, (uint64_t)(uintptr_t)srv);
    c->rax = S_OK_HR;
}

static void dev_CreateDepthStencilView(CPU64 *c, void *ud) {
    (void)ud;
    ComBase *res = (ComBase *)(uintptr_t)c->rdx;
    uint64_t out_va = c->r9;
    if (!out_va) { c->rax = E_INVALIDARG_H; return; }
    D3D11DSVObj *dsv = (D3D11DSVObj *)calloc(1, sizeof(D3D11DSVObj));
    dsv->base.lpVtbl = g_vt_generic;
    dsv->base.kind = COM_DSV;
    dsv->base.refcount = 1;
    if (res && res->kind == COM_TEXTURE2D) {
        dsv->tex = (D3D11Texture2DObj *)res;
        res->refcount++;
    }
    W64(out_va, (uint64_t)(uintptr_t)dsv);
    c->rax = S_OK_HR;
}

static MTLSamplerAddressMode d3d_to_mtl_addr(uint32_t a) {
    switch (a) {
        case 2: return MTLSamplerAddressModeMirrorRepeat;
        case 3: return MTLSamplerAddressModeClampToEdge;
        case 4: return MTLSamplerAddressModeClampToBorderColor;
        case 1: default: return MTLSamplerAddressModeRepeat;
    }
}

static void dev_CreateSamplerState(CPU64 *c, void *ud) {
    (void)ud;
    D3D11DeviceObj *dev = (D3D11DeviceObj *)(uintptr_t)c->rcx;
    uint64_t desc_va = c->rdx;
    uint64_t out_va  = c->r8;
    if (!dev || !out_va) { c->rax = E_INVALIDARG_H; return; }
    D3D11SamplerObj *smp = (D3D11SamplerObj *)calloc(1, sizeof(D3D11SamplerObj));
    smp->base.lpVtbl = g_vt_generic;
    smp->base.kind = COM_SAMPLER;
    smp->base.refcount = 1;
    @autoreleasepool {
        MTLSamplerDescriptor *sd = [[MTLSamplerDescriptor alloc] init];
        if (desc_va) {
            uint32_t filt = R32(desc_va + 0);
            uint32_t au = R32(desc_va + 4), av = R32(desc_va + 8), aw = R32(desc_va + 12);
            int point_min = ((filt & 0x10) == 0 && filt != 0x55 && filt != 0x15);
            int point_mag = ((filt & 0x04) == 0 && filt != 0x55 && filt != 0x15);
            sd.minFilter = point_min ? MTLSamplerMinMagFilterNearest : MTLSamplerMinMagFilterLinear;
            sd.magFilter = point_mag ? MTLSamplerMinMagFilterNearest : MTLSamplerMinMagFilterLinear;
            sd.mipFilter = MTLSamplerMipFilterNotMipmapped; /* shortcut: avoid sampling unpopulated mip levels; switch to linear once all subresource mips are tracked */
            sd.sAddressMode = d3d_to_mtl_addr(au);
            sd.tAddressMode = d3d_to_mtl_addr(av);
            sd.rAddressMode = d3d_to_mtl_addr(aw);
        } else {
            sd.minFilter = MTLSamplerMinMagFilterLinear;
            sd.magFilter = MTLSamplerMinMagFilterLinear;
            sd.sAddressMode = MTLSamplerAddressModeClampToEdge;
            sd.tAddressMode = MTLSamplerAddressModeClampToEdge;
        }
        smp->mtl_sampler = [dev->mtl_dev newSamplerStateWithDescriptor:sd];
    }
    W64(out_va, (uint64_t)(uintptr_t)smp);
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
static void ctx_PSSetShaderResources(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t start = (uint32_t)c->rdx, num = (uint32_t)c->r8;
    uint64_t arr = c->r9;
    for (uint32_t i = 0; i < num && start + i < 16; i++)
        ctx->ps_srvs[start + i] = arr ? (D3D11SRVObj *)(uintptr_t)R64(arr + i * 8ULL) : NULL;
}
static void ctx_PSSetSamplers(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t start = (uint32_t)c->rdx, num = (uint32_t)c->r8;
    uint64_t arr = c->r9;
    for (uint32_t i = 0; i < num && start + i < 16; i++)
        ctx->ps_samplers[start + i] = arr ? (D3D11SamplerObj *)(uintptr_t)R64(arr + i * 8ULL) : NULL;
}
static void ctx_VSSetShaderResources(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t start = (uint32_t)c->rdx, num = (uint32_t)c->r8;
    uint64_t arr = c->r9;
    for (uint32_t i = 0; i < num && start + i < 16; i++)
        ctx->vs_srvs[start + i] = arr ? (D3D11SRVObj *)(uintptr_t)R64(arr + i * 8ULL) : NULL;
}
static void ctx_VSSetSamplers(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t start = (uint32_t)c->rdx, num = (uint32_t)c->r8;
    uint64_t arr = c->r9;
    for (uint32_t i = 0; i < num && start + i < 16; i++)
        ctx->vs_samplers[start + i] = arr ? (D3D11SamplerObj *)(uintptr_t)R64(arr + i * 8ULL) : NULL;
}
static void dev_CreateBlendState(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t desc_va = c->rdx;
    uint64_t out_va  = c->r8;
    if (!out_va) { c->rax = E_INVALIDARG_H; return; }
    D3D11BlendStateObj *bs = (D3D11BlendStateObj *)calloc(1, sizeof(D3D11BlendStateObj));
    bs->base.lpVtbl = g_vt_generic; bs->base.kind = COM_BLEND_STATE; bs->base.refcount = 1;
    bs->write_mask = 0xF;
    if (desc_va) {
        /* D3D11_BLEND_DESC: RenderTarget[0] starts at +8 */
        bs->blend_enable    = R32(desc_va + 8) != 0;
        bs->src_blend       = R32(desc_va + 12);
        bs->dst_blend       = R32(desc_va + 16);
        bs->blend_op        = R32(desc_va + 20);
        bs->src_blend_alpha = R32(desc_va + 24);
        bs->dst_blend_alpha = R32(desc_va + 28);
        bs->blend_op_alpha  = R32(desc_va + 32);
        bs->write_mask      = R8(desc_va + 36);
    }
    W64(out_va, (uint64_t)(uintptr_t)bs);
    c->rax = S_OK_HR;
}

static MTLStencilOperation d3d_to_mtl_stencil_op(uint32_t op) {
    switch (op) {
        case 2: return MTLStencilOperationZero;
        case 3: return MTLStencilOperationReplace;
        case 4: return MTLStencilOperationIncrementClamp;
        case 5: return MTLStencilOperationDecrementClamp;
        case 6: return MTLStencilOperationInvert;
        case 7: return MTLStencilOperationIncrementWrap;
        case 8: return MTLStencilOperationDecrementWrap;
        case 1: default: return MTLStencilOperationKeep;
    }
}

static void dev_CreateDepthStencilState(CPU64 *c, void *ud) {
    (void)ud;
    D3D11DeviceObj *dev = (D3D11DeviceObj *)(uintptr_t)c->rcx;
    uint64_t desc_va = c->rdx;
    uint64_t out_va  = c->r8;
    if (!dev || !out_va) { c->rax = E_INVALIDARG_H; return; }
    D3D11DepthStencilStateObj *ds = (D3D11DepthStencilStateObj *)calloc(1, sizeof(D3D11DepthStencilStateObj));
    ds->base.lpVtbl = g_vt_generic; ds->base.kind = COM_DEPTH_STENCIL_STATE; ds->base.refcount = 1;
    @autoreleasepool {
        MTLDepthStencilDescriptor *d = [[MTLDepthStencilDescriptor alloc] init];
        int depth_en = desc_va ? (R32(desc_va + 0) != 0) : 1;
        uint32_t wmask = desc_va ? R32(desc_va + 4) : 1;
        uint32_t dfunc = desc_va ? R32(desc_va + 8) : 2; /* LESS */
        d.depthCompareFunction = depth_en ? d3d_to_mtl_cmp(dfunc) : MTLCompareFunctionAlways;
        d.depthWriteEnabled = (depth_en && wmask != 0) ? YES : NO;
        if (desc_va && R32(desc_va + 12) != 0 /* StencilEnable */) {
            uint8_t rmask = R8(desc_va + 16);
            uint8_t smask = R8(desc_va + 17);
            MTLStencilDescriptor *f = [[MTLStencilDescriptor alloc] init];
            f.stencilFailureOperation   = d3d_to_mtl_stencil_op(R32(desc_va + 20));
            f.depthFailureOperation     = d3d_to_mtl_stencil_op(R32(desc_va + 24));
            f.depthStencilPassOperation = d3d_to_mtl_stencil_op(R32(desc_va + 28));
            f.stencilCompareFunction    = d3d_to_mtl_cmp(R32(desc_va + 32));
            f.readMask  = rmask;
            f.writeMask = smask;
            MTLStencilDescriptor *b = [[MTLStencilDescriptor alloc] init];
            b.stencilFailureOperation   = d3d_to_mtl_stencil_op(R32(desc_va + 36));
            b.depthFailureOperation     = d3d_to_mtl_stencil_op(R32(desc_va + 40));
            b.depthStencilPassOperation = d3d_to_mtl_stencil_op(R32(desc_va + 44));
            b.stencilCompareFunction    = d3d_to_mtl_cmp(R32(desc_va + 48));
            b.readMask  = rmask;
            b.writeMask = smask;
            d.frontFaceStencil = f;
            d.backFaceStencil  = b;
        }
        ds->mtl_dss = [dev->mtl_dev newDepthStencilStateWithDescriptor:d];
    }
    W64(out_va, (uint64_t)(uintptr_t)ds);
    c->rax = S_OK_HR;
}

static void dev_CreateRasterizerState(CPU64 *c, void *ud) {
    (void)ud;
    uint64_t desc_va = c->rdx;
    uint64_t out_va  = c->r8;
    if (!out_va) { c->rax = E_INVALIDARG_H; return; }
    D3D11RasterizerStateObj *rs = (D3D11RasterizerStateObj *)calloc(1, sizeof(D3D11RasterizerStateObj));
    rs->base.lpVtbl = g_vt_generic; rs->base.kind = COM_RASTERIZER_STATE; rs->base.refcount = 1;
    rs->cull_mode      = desc_va ? R32(desc_va + 4) : 3; /* D3D11_CULL_BACK */
    rs->front_ccw      = desc_va ? (R32(desc_va + 8) != 0) : 0;
    if (desc_va) {
        rs->depth_bias = (int32_t)R32(desc_va + 12);
        uint32_t bc = R32(desc_va + 16), sb = R32(desc_va + 20);
        memcpy(&rs->depth_bias_clamp, &bc, 4);
        memcpy(&rs->slope_depth_bias, &sb, 4);
    }
    rs->scissor_enable = desc_va ? (R32(desc_va + 28) != 0) : 0;
    W64(out_va, (uint64_t)(uintptr_t)rs);
    c->rax = S_OK_HR;
}

static void ctx_OMSetBlendState(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *b = (ComBase *)(uintptr_t)c->rdx;
    ctx->blend_state = (b && b->kind == COM_BLEND_STATE) ? (D3D11BlendStateObj *)b : NULL;
    if (c->r8) {
        memcpy(ctx->blend_factor, (const void *)(uintptr_t)c->r8, 16);
        ctx->has_blend_factor = 1;
    } else {
        ctx->blend_factor[0] = ctx->blend_factor[1] = ctx->blend_factor[2] = ctx->blend_factor[3] = 1.0f;
        ctx->has_blend_factor = 0;
    }
}
static void ctx_OMSetDepthStencilState(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *b = (ComBase *)(uintptr_t)c->rdx;
    ctx->ds_state = (b && b->kind == COM_DEPTH_STENCIL_STATE) ? (D3D11DepthStencilStateObj *)b : NULL;
    ctx->stencil_ref = (uint32_t)c->r8;
}
static void ctx_RSSetState(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *b = (ComBase *)(uintptr_t)c->rdx;
    ctx->rs_state = (b && b->kind == COM_RASTERIZER_STATE) ? (D3D11RasterizerStateObj *)b : NULL;
}
static void ctx_RSSetScissorRects(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    uint32_t num = (uint32_t)c->rdx;
    uint64_t rva = c->r8;
    if (num > 0 && rva) {
        ctx->sc_l = (int32_t)R32(rva + 0); ctx->sc_t = (int32_t)R32(rva + 4);
        ctx->sc_r = (int32_t)R32(rva + 8); ctx->sc_b = (int32_t)R32(rva + 12);
        ctx->has_scissor = 1;
    } else {
        ctx->has_scissor = 0;
    }
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
    ComBase *dsv = (ComBase *)(uintptr_t)c->r9;
    ctx->dsv = (dsv && dsv->kind == COM_DSV) ? (D3D11DSVObj *)dsv : NULL;
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

static void ctx_end_pass(D3D11ContextObj *ctx) {
    if (!ctx || !ctx->active_enc) return;
    [ctx->active_enc endEncoding];
    ctx->active_enc = nil;
    ctx->enc_nrt = 0;
    ctx->enc_dt = NULL;
    for (int i = 0; i < 4; i++) ctx->enc_rt[i] = NULL;
}

static id<MTLCommandBuffer> ctx_ensure_cb(D3D11ContextObj *ctx) {
    if (!ctx->pending_cb) ctx->pending_cb = [ctx->dev->mtl_queue commandBuffer];
    return ctx->pending_cb;
}

static void ctx_flush_gpu(D3D11ContextObj *ctx, int wait) {
    if (!ctx) return;
    ctx_end_pass(ctx);
    if (ctx->pending_cb) {
        id<MTLCommandBuffer> cb = ctx->pending_cb;
        ctx->pending_cb = nil;
        [cb commit];
        if (wait) [cb waitUntilCompleted];
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
        ctx_end_pass(ctx);
        MTLRenderPassDescriptor *rpd = [MTLRenderPassDescriptor renderPassDescriptor];
        rpd.colorAttachments[0].texture = rtv->tex->mtl_tex;
        rpd.colorAttachments[0].loadAction = MTLLoadActionClear;
        rpd.colorAttachments[0].storeAction = MTLStoreActionStore;
        rpd.colorAttachments[0].clearColor = MTLClearColorMake(rgba[0], rgba[1], rgba[2], rgba[3]);
        id<MTLCommandBuffer> cb = ctx_ensure_cb(ctx);
        id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rpd];
        [enc endEncoding];
    }
}

static void ctx_ClearDepthStencilView(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *b = (ComBase *)(uintptr_t)c->rdx;
    if (!ctx || !b || b->kind != COM_DSV) return;
    D3D11DSVObj *dsv = (D3D11DSVObj *)b;
    if (!dsv->tex || !dsv->tex->mtl_tex) return;
    uint32_t flags = (uint32_t)c->r8;
    float depth = c->xmm[3].f[0];
    uint8_t stencil = (uint8_t)win64_arg_i(c, 4);
    if (depth < 0.0f || depth > 1.0f) depth = 1.0f;
    @autoreleasepool {
        ctx_end_pass(ctx);
        MTLRenderPassDescriptor *rpd = [MTLRenderPassDescriptor renderPassDescriptor];
        if (flags & 1) {
            rpd.depthAttachment.texture = dsv->tex->mtl_tex;
            rpd.depthAttachment.loadAction = MTLLoadActionClear;
            rpd.depthAttachment.storeAction = MTLStoreActionStore;
            rpd.depthAttachment.clearDepth = depth;
        }
        if ((flags & 2) && dsv->tex->mtl_fmt == MTLPixelFormatDepth32Float_Stencil8) {
            rpd.stencilAttachment.texture = dsv->tex->mtl_tex;
            rpd.stencilAttachment.loadAction = MTLLoadActionClear;
            rpd.stencilAttachment.storeAction = MTLStoreActionStore;
            rpd.stencilAttachment.clearStencil = stencil;
        }
        if (flags & 3) {
            id<MTLCommandBuffer> cb = ctx_ensure_cb(ctx);
            id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rpd];
            [enc endEncoding];
        }
    }
}

static void ctx_draw_common(D3D11ContextObj *ctx, int indexed, uint32_t count,
                            uint32_t start, int32_t base_vtx, uint32_t inst_cnt, uint32_t base_inst) {
    if (!ctx || !ctx->vs || count == 0 || inst_cnt == 0) return;
    D3D11Texture2DObj *rts[4] = {NULL, NULL, NULL, NULL};
    int nrt = 0;
    uint32_t ref_w = 0, ref_h = 0;
    int max_rt = ctx->num_rtvs < 4 ? ctx->num_rtvs : 4;
    for (int i = 0; i < max_rt; i++) {
        if (ctx->rtvs[i] && ctx->rtvs[i]->tex && ctx->rtvs[i]->tex->mtl_tex) {
            if (ref_w == 0) { ref_w = ctx->rtvs[i]->tex->width; ref_h = ctx->rtvs[i]->tex->height; }
            if (ctx->rtvs[i]->tex->width == ref_w && ctx->rtvs[i]->tex->height == ref_h) {
                rts[i] = ctx->rtvs[i]->tex;
                nrt = i + 1;
            }
        }
    }
    D3D11Texture2DObj *dt = (ctx->dsv && ctx->dsv->tex && ctx->dsv->tex->mtl_tex) ? ctx->dsv->tex : NULL;
    if (nrt > 0 && dt && (dt->width != ref_w || dt->height != ref_h)) dt = NULL;
    if (nrt == 0 && !dt) return;
    if (nrt == 0) { ref_w = dt->width; ref_h = dt->height; }
    if (nrt > 0 && !ctx->ps) return;

    ensure_shader_compiled(ctx->dev, ctx->vs);
    if (ctx->ps) ensure_shader_compiled(ctx->dev, ctx->ps);
    if (!ctx->vs->mtl_fn || (nrt > 0 && (!ctx->ps || !ctx->ps->mtl_fn))) return;

    @autoreleasepool {
        MTLPixelFormat dfmt = dt ? dt->mtl_fmt : MTLPixelFormatInvalid;
        MTLPixelFormat cfmts[4] = { MTLPixelFormatInvalid, MTLPixelFormatInvalid, MTLPixelFormatInvalid, MTLPixelFormatInvalid };
        for (int i = 0; i < nrt; i++) cfmts[i] = rts[i] ? rts[i]->mtl_fmt : MTLPixelFormatInvalid;

        id<MTLRenderPipelineState> pso = nil;
        for (int i = 0; i < ctx->dev->pso_count; i++) {
            PsoCacheEntry *e = &ctx->dev->pso_cache[i];
            if (e->vs == ctx->vs && e->ps == ctx->ps && e->layout == ctx->layout &&
                e->blend == ctx->blend_state && e->num_rts == nrt && e->depth_fmt == dfmt &&
                memcmp(e->color_fmts, cfmts, sizeof(cfmts)) == 0) {
                pso = e->pso;
                break;
            }
        }
        if (!pso) {
            MTLRenderPipelineDescriptor *ppd = [[MTLRenderPipelineDescriptor alloc] init];
            ppd.vertexFunction = ctx->vs->mtl_fn;
            ppd.fragmentFunction = (nrt > 0 && ctx->ps) ? ctx->ps->mtl_fn : nil;
            for (int i = 0; i < nrt; i++) {
                if (cfmts[i] == MTLPixelFormatInvalid) continue;
                MTLRenderPipelineColorAttachmentDescriptor *ca = ppd.colorAttachments[i];
                ca.pixelFormat = cfmts[i];
                if (ctx->blend_state) {
                    D3D11BlendStateObj *bs = ctx->blend_state;
                    ca.blendingEnabled = bs->blend_enable ? YES : NO;
                    if (bs->blend_enable) {
                        ca.sourceRGBBlendFactor        = d3d_to_mtl_blend(bs->src_blend);
                        ca.destinationRGBBlendFactor   = d3d_to_mtl_blend(bs->dst_blend);
                        ca.rgbBlendOperation           = d3d_to_mtl_blend_op(bs->blend_op);
                        ca.sourceAlphaBlendFactor      = d3d_to_mtl_blend(bs->src_blend_alpha);
                        ca.destinationAlphaBlendFactor = d3d_to_mtl_blend(bs->dst_blend_alpha);
                        ca.alphaBlendOperation         = d3d_to_mtl_blend_op(bs->blend_op_alpha);
                    }
                    MTLColorWriteMask wm = MTLColorWriteMaskNone;
                    if (bs->write_mask & 1) wm |= MTLColorWriteMaskRed;
                    if (bs->write_mask & 2) wm |= MTLColorWriteMaskGreen;
                    if (bs->write_mask & 4) wm |= MTLColorWriteMaskBlue;
                    if (bs->write_mask & 8) wm |= MTLColorWriteMaskAlpha;
                    ca.writeMask = wm;
                }
            }
            if (dfmt != MTLPixelFormatInvalid) {
                ppd.depthAttachmentPixelFormat = dfmt;
                if (dfmt == MTLPixelFormatDepth32Float_Stencil8) ppd.stencilAttachmentPixelFormat = dfmt;
            }
            if (ctx->layout && ctx->layout->num_elems > 0) {
                MTLVertexDescriptor *vd = [MTLVertexDescriptor vertexDescriptor];
                uint32_t max_end[16] = {0};
                for (int i = 0; i < ctx->layout->num_elems; i++) {
                    LayoutElem *e = &ctx->layout->elems[i];
                    if (e->slot >= 16) continue;
                    uint32_t aidx = e->attr_idx;
                    if (e->semantic[0] && ctx->vs && ctx->vs->info.num_inputs > 0) {
                        int matched = 0;
                        for (int k = 0; k < ctx->vs->info.num_inputs; k++) {
                            const DxbcSigElem *si = &ctx->vs->info.inputs[k];
                            if (strcasecmp(si->semantic, e->semantic) == 0 && si->semantic_index == e->sem_idx) {
                                aidx = si->reg & 31U;
                                matched = 1;
                                break;
                            }
                        }
                        if (!matched) continue;
                    }
                    if (aidx >= 31) continue;
                    vd.attributes[aidx].format = dxgi_to_mtl_vertex(e->dxgi_fmt);
                    vd.attributes[aidx].offset = e->offset;
                    vd.attributes[aidx].bufferIndex = e->slot;
                    uint32_t end_off = e->offset + 16;
                    if (end_off > max_end[e->slot]) max_end[e->slot] = end_off;
                }
                for (uint32_t sl = 0; sl < 16; sl++) {
                    if (max_end[sl] == 0) continue;
                    if (sl < 8 && ctx->vbs[sl] && ctx->vb_strides[sl] > 0) {
                        vd.layouts[sl].stride = ctx->vb_strides[sl];
                        vd.layouts[sl].stepFunction = MTLVertexStepFunctionPerVertex;
                    } else {
                        vd.layouts[sl].stride = max_end[sl];
                        vd.layouts[sl].stepFunction = MTLVertexStepFunctionConstant;
                        vd.layouts[sl].stepRate = 0;
                    }
                }
                ppd.vertexDescriptor = vd;
            }
            NSError *err = nil;
            pso = [ctx->dev->mtl_dev newRenderPipelineStateWithDescriptor:ppd error:&err];
            if (!pso) {
                if (getenv("ELF64_TRACE")) {
                    fprintf(stderr, "d3d11_metal: pipeline state error: %s\n",
                            err ? [[err localizedDescription] UTF8String] : "?");
                }
                return;
            }
            if (ctx->dev->pso_count < 512) {
                PsoCacheEntry *e = &ctx->dev->pso_cache[ctx->dev->pso_count++];
                e->vs = ctx->vs; e->ps = ctx->ps; e->layout = ctx->layout; e->blend = ctx->blend_state;
                e->num_rts = nrt; memcpy(e->color_fmts, cfmts, sizeof(cfmts)); e->depth_fmt = dfmt; e->pso = pso;
            }
        }

        int same_pass = (ctx->active_enc != nil && ctx->enc_nrt == nrt && ctx->enc_dt == dt);
        for (int i = 0; same_pass && i < 4; i++) {
            if (ctx->enc_rt[i] != rts[i]) same_pass = 0;
        }
        if (same_pass) {
            for (int i = 0; i < 16; i++) {
                D3D11Texture2DObj *st = (ctx->ps_srvs[i] && ctx->ps_srvs[i]->tex) ? ctx->ps_srvs[i]->tex : NULL;
                if (!st) continue;
                for (int j = 0; j < nrt; j++) if (st == rts[j]) { same_pass = 0; break; }
                if (st == dt) same_pass = 0;
            }
        }
        if (!same_pass) {
            ctx_end_pass(ctx);
            MTLRenderPassDescriptor *rpd = [MTLRenderPassDescriptor renderPassDescriptor];
            for (int i = 0; i < nrt; i++) {
                if (!rts[i]) continue;
                rpd.colorAttachments[i].texture = rts[i]->mtl_tex;
                rpd.colorAttachments[i].loadAction = MTLLoadActionLoad;
                rpd.colorAttachments[i].storeAction = MTLStoreActionStore;
            }
            if (dt) {
                rpd.depthAttachment.texture = dt->mtl_tex;
                rpd.depthAttachment.loadAction = MTLLoadActionLoad;
                rpd.depthAttachment.storeAction = MTLStoreActionStore;
                if (dfmt == MTLPixelFormatDepth32Float_Stencil8) {
                    rpd.stencilAttachment.texture = dt->mtl_tex;
                    rpd.stencilAttachment.loadAction = MTLLoadActionLoad;
                    rpd.stencilAttachment.storeAction = MTLStoreActionStore;
                }
            }
            id<MTLCommandBuffer> cb = ctx_ensure_cb(ctx);
            ctx->active_enc = [cb renderCommandEncoderWithDescriptor:rpd];
            ctx->enc_nrt = nrt;
            ctx->enc_dt = dt;
            for (int i = 0; i < 4; i++) ctx->enc_rt[i] = rts[i];
        }

        id<MTLRenderCommandEncoder> enc = ctx->active_enc;
        [enc setRenderPipelineState:pso];
        if (dt) {
            if (ctx->ds_state && ctx->ds_state->mtl_dss) {
                [enc setDepthStencilState:ctx->ds_state->mtl_dss];
                [enc setStencilReferenceValue:ctx->stencil_ref];
            } else if (ctx->dev->default_dss) {
                [enc setDepthStencilState:ctx->dev->default_dss];
                [enc setStencilReferenceValue:0];
            }
        }
        if (ctx->has_blend_factor) {
            [enc setBlendColorRed:ctx->blend_factor[0] green:ctx->blend_factor[1]
                             blue:ctx->blend_factor[2] alpha:ctx->blend_factor[3]];
        }
        if (ctx->rs_state) {
            MTLCullMode cm = (ctx->rs_state->cull_mode == 2) ? MTLCullModeFront
                           : (ctx->rs_state->cull_mode == 3) ? MTLCullModeBack : MTLCullModeNone;
            [enc setCullMode:cm];
            [enc setFrontFacingWinding:ctx->rs_state->front_ccw ? MTLWindingCounterClockwise : MTLWindingClockwise];
            [enc setDepthBias:(float)ctx->rs_state->depth_bias
                   slopeScale:ctx->rs_state->slope_depth_bias
                        clamp:ctx->rs_state->depth_bias_clamp];
            if (ctx->rs_state->scissor_enable && ctx->has_scissor) {
                int32_t l = ctx->sc_l < 0 ? 0 : ctx->sc_l;
                int32_t t = ctx->sc_t < 0 ? 0 : ctx->sc_t;
                int32_t r = ctx->sc_r > (int32_t)ref_w ? (int32_t)ref_w : ctx->sc_r;
                int32_t b = ctx->sc_b > (int32_t)ref_h ? (int32_t)ref_h : ctx->sc_b;
                if (r > l && b > t) {
                    [enc setScissorRect:(MTLScissorRect){(NSUInteger)l, (NSUInteger)t, (NSUInteger)(r - l), (NSUInteger)(b - t)}];
                } else {
                    [enc setScissorRect:(MTLScissorRect){0, 0, ref_w, ref_h}];
                }
            } else {
                [enc setScissorRect:(MTLScissorRect){0, 0, ref_w, ref_h}];
            }
        } else {
            [enc setCullMode:MTLCullModeNone];
            [enc setDepthBias:0.0f slopeScale:0.0f clamp:0.0f];
            [enc setScissorRect:(MTLScissorRect){0, 0, ref_w, ref_h}];
        }

        MTLViewport vp;
        if (ctx->has_vp && ctx->vp_w > 0 && ctx->vp_h > 0) {
            vp = (MTLViewport){ ctx->vp_x, ctx->vp_y, ctx->vp_w, ctx->vp_h, ctx->vp_minz, ctx->vp_maxz };
        } else {
            vp = (MTLViewport){ 0.0, 0.0, (double)ref_w, (double)ref_h, 0.0, 1.0 };
        }
        [enc setViewport:vp];

        for (int i = 0; i < 8; i++) {
            if (ctx->vbs[i] && ctx->vbs[i]->mtl_buf) {
                [enc setVertexBuffer:ctx->vbs[i]->mtl_buf offset:ctx->vb_offsets[i] atIndex:(NSUInteger)i];
            } else if (ctx->dev->zero_vb) {
                [enc setVertexBuffer:ctx->dev->zero_vb offset:0 atIndex:(NSUInteger)i];
            }
        }
        for (int i = 0; i < 14; i++) {
            if (ctx->vs_cbs[i] && ctx->vs_cbs[i]->mtl_buf) {
                if (ctx->vs_cbs[i]->byte_width <= 4096) {
                    [enc setVertexBytes:[ctx->vs_cbs[i]->mtl_buf contents] length:ctx->vs_cbs[i]->byte_width atIndex:(NSUInteger)(16 + i)];
                } else {
                    [enc setVertexBuffer:ctx->vs_cbs[i]->mtl_buf offset:0 atIndex:(NSUInteger)(16 + i)];
                }
            }
            if (ctx->ps_cbs[i] && ctx->ps_cbs[i]->mtl_buf) {
                if (ctx->ps_cbs[i]->byte_width <= 4096) {
                    [enc setFragmentBytes:[ctx->ps_cbs[i]->mtl_buf contents] length:ctx->ps_cbs[i]->byte_width atIndex:(NSUInteger)(16 + i)];
                } else {
                    [enc setFragmentBuffer:ctx->ps_cbs[i]->mtl_buf offset:0 atIndex:(NSUInteger)(16 + i)];
                }
            }
        }
        for (int i = 0; i < 16; i++) {
            if (ctx->ps_srvs[i] && ctx->ps_srvs[i]->tex && ctx->ps_srvs[i]->tex->mtl_tex) {
                [enc setFragmentTexture:ctx->ps_srvs[i]->tex->mtl_tex atIndex:(NSUInteger)i];
            }
            if (ctx->vs_srvs[i] && ctx->vs_srvs[i]->tex && ctx->vs_srvs[i]->tex->mtl_tex) {
                [enc setVertexTexture:ctx->vs_srvs[i]->tex->mtl_tex atIndex:(NSUInteger)i];
            }
            id<MTLSamplerState> psmp = (ctx->ps_samplers[i] && ctx->ps_samplers[i]->mtl_sampler)
                ? ctx->ps_samplers[i]->mtl_sampler : ctx->dev->default_sampler;
            if (psmp) [enc setFragmentSamplerState:psmp atIndex:(NSUInteger)i];
            id<MTLSamplerState> vsmp = (ctx->vs_samplers[i] && ctx->vs_samplers[i]->mtl_sampler)
                ? ctx->vs_samplers[i]->mtl_sampler : ctx->dev->default_sampler;
            if (vsmp) [enc setVertexSamplerState:vsmp atIndex:(NSUInteger)i];
        }

        MTLPrimitiveType prim = d3d_to_mtl_prim(ctx->topology);
        if (indexed && ctx->ib && ctx->ib->mtl_buf) {
            MTLIndexType itype = (ctx->ib_fmt == 57) ? MTLIndexTypeUInt16 : MTLIndexTypeUInt32;
            NSUInteger isz = (itype == MTLIndexTypeUInt16) ? 2 : 4;
            [enc drawIndexedPrimitives:prim indexCount:count indexType:itype
                           indexBuffer:ctx->ib->mtl_buf indexBufferOffset:(ctx->ib_offset + start * isz)
                         instanceCount:inst_cnt baseVertex:base_vtx baseInstance:base_inst];
        } else {
            [enc drawPrimitives:prim vertexStart:start vertexCount:count
                  instanceCount:inst_cnt baseInstance:base_inst];
        }
    }
}

static void ctx_Draw(CPU64 *c, void *ud) {
    (void)ud;
    ctx_draw_common((D3D11ContextObj *)(uintptr_t)c->rcx, 0, (uint32_t)c->rdx, (uint32_t)c->r8, 0, 1, 0);
}
static void ctx_DrawIndexed(CPU64 *c, void *ud) {
    (void)ud;
    ctx_draw_common((D3D11ContextObj *)(uintptr_t)c->rcx, 1, (uint32_t)c->rdx, (uint32_t)c->r8, (int32_t)c->r9, 1, 0);
}

static void ctx_DrawIndexedInstanced(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t idx_cnt = (uint32_t)c->rdx;
    uint32_t inst_cnt = (uint32_t)c->r8;
    uint32_t start_idx = (uint32_t)c->r9;
    int32_t  base_vtx = (int32_t)win64_arg_i(c, 4);
    uint32_t start_inst = (uint32_t)win64_arg_i(c, 5);
    if (inst_cnt > 0)
        ctx_draw_common((D3D11ContextObj *)(uintptr_t)c->rcx, 1, idx_cnt, start_idx, base_vtx, inst_cnt, start_inst);
}
static void ctx_DrawInstanced(CPU64 *c, void *ud) {
    (void)ud;
    uint32_t vtx_cnt = (uint32_t)c->rdx;
    uint32_t inst_cnt = (uint32_t)c->r8;
    uint32_t start_vtx = (uint32_t)c->r9;
    uint32_t start_inst = (uint32_t)win64_arg_i(c, 4);
    if (inst_cnt > 0)
        ctx_draw_common((D3D11ContextObj *)(uintptr_t)c->rcx, 0, vtx_cnt, start_vtx, 0, inst_cnt, start_inst);
}

static void ctx_GenerateMips(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *b = (ComBase *)(uintptr_t)c->rdx;
    if (!ctx || !b || b->kind != COM_SRV) return;
    D3D11SRVObj *srv = (D3D11SRVObj *)b;
    if (!srv->tex || !srv->tex->mtl_tex || srv->tex->mip_levels <= 1 ||
        dxgi_is_bc(srv->tex->dxgi_fmt) || dxgi_is_depth(srv->tex->dxgi_fmt)) return;
    @autoreleasepool {
        ctx_end_pass(ctx);
        id<MTLCommandBuffer> cb = ctx_ensure_cb(ctx);
        id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
        [blit generateMipmapsForTexture:srv->tex->mtl_tex];
        [blit endEncoding];
    }
}

static void ctx_Flush(CPU64 *c, void *ud) {
    (void)ud;
    ctx_flush_gpu((D3D11ContextObj *)(uintptr_t)c->rcx, 0);
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
            ctx_end_pass(ctx);
            id<MTLCommandBuffer> cb = ctx_ensure_cb(ctx);
            id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
            [blit copyFromTexture:st->mtl_tex sourceSlice:0 sourceLevel:0
                     sourceOrigin:MTLOriginMake(0, 0, 0)
                       sourceSize:MTLSizeMake(st->width, st->height, 1)
                        toTexture:dt->mtl_tex destinationSlice:0 destinationLevel:0
                destinationOrigin:MTLOriginMake(0, 0, 0)];
            [blit endEncoding];
        }
    } else if (dst->kind == COM_BUFFER && src->kind == COM_BUFFER) {
        ctx_flush_gpu(ctx, 1);
        D3D11BufferObj *db = (D3D11BufferObj *)dst;
        D3D11BufferObj *sb = (D3D11BufferObj *)src;
        uint32_t n = db->byte_width < sb->byte_width ? db->byte_width : sb->byte_width;
        memcpy([db->mtl_buf contents], [sb->mtl_buf contents], n);
    }
}

static void ctx_CopySubresourceRegion(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *dst = (ComBase *)(uintptr_t)c->rdx;
    uint32_t dst_sub = (uint32_t)c->r8;
    uint32_t dst_x = (uint32_t)c->r9;
    uint32_t dst_y = (uint32_t)win64_arg_i(c, 4);
    ComBase *src = (ComBase *)(uintptr_t)win64_arg_i(c, 6);
    uint32_t src_sub = (uint32_t)win64_arg_i(c, 7);
    uint64_t src_box = win64_arg_i(c, 8);
    if (!ctx || !dst || !src) return;
    if (dst->kind == COM_TEXTURE2D && src->kind == COM_TEXTURE2D) {
        D3D11Texture2DObj *dt = (D3D11Texture2DObj *)dst;
        D3D11Texture2DObj *st = (D3D11Texture2DObj *)src;
        if (!dt->mtl_tex || !st->mtl_tex) return;
        uint32_t smip = src_sub < st->mip_levels ? src_sub : 0;
        uint32_t dmip = dst_sub < dt->mip_levels ? dst_sub : 0;
        uint32_t sw = st->width >> smip; if (sw == 0) sw = 1;
        uint32_t sh = st->height >> smip; if (sh == 0) sh = 1;
        uint32_t dw = dt->width >> dmip; if (dw == 0) dw = 1;
        uint32_t dh = dt->height >> dmip; if (dh == 0) dh = 1;
        uint32_t sx = 0, sy = 0, cw = sw, ch = sh;
        if (src_box) {
            sx = R32(src_box + 0); sy = R32(src_box + 4);
            uint32_t sr = R32(src_box + 12), sb = R32(src_box + 16);
            cw = (sr > sx) ? (sr - sx) : 0;
            ch = (sb > sy) ? (sb - sy) : 0;
        }
        if (sx >= sw || sy >= sh || dst_x >= dw || dst_y >= dh || cw == 0 || ch == 0) return;
        if (sx + cw > sw) cw = sw - sx;
        if (sy + ch > sh) ch = sh - sy;
        if (dst_x + cw > dw) cw = dw - dst_x;
        if (dst_y + ch > dh) ch = dh - dst_y;
        @autoreleasepool {
            ctx_end_pass(ctx);
            id<MTLCommandBuffer> cb = ctx_ensure_cb(ctx);
            id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
            [blit copyFromTexture:st->mtl_tex sourceSlice:0 sourceLevel:smip
                     sourceOrigin:MTLOriginMake(sx, sy, 0)
                       sourceSize:MTLSizeMake(cw, ch, 1)
                        toTexture:dt->mtl_tex destinationSlice:0 destinationLevel:dmip
                destinationOrigin:MTLOriginMake(dst_x, dst_y, 0)];
            [blit endEncoding];
        }
    } else if (dst->kind == COM_BUFFER && src->kind == COM_BUFFER) {
        ctx_flush_gpu(ctx, 1);
        D3D11BufferObj *db = (D3D11BufferObj *)dst;
        D3D11BufferObj *sb = (D3D11BufferObj *)src;
        uint32_t sx = src_box ? R32(src_box + 0) : 0;
        uint32_t sr = src_box ? R32(src_box + 12) : sb->byte_width;
        if (sr > sx && dst_x < db->byte_width && sx < sb->byte_width) {
            uint32_t n = sr - sx;
            if (sx + n > sb->byte_width) n = sb->byte_width - sx;
            if (dst_x + n > db->byte_width) n = db->byte_width - dst_x;
            memcpy((uint8_t *)[db->mtl_buf contents] + dst_x, (const uint8_t *)[sb->mtl_buf contents] + sx, n);
        }
    }
}

static void ctx_Map(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *res = (ComBase *)(uintptr_t)c->rdx;
    uint32_t subres = (uint32_t)c->r8;
    uint32_t map_type = (uint32_t)c->r9;
    uint64_t mapped_va = win64_arg_i(c, 5);
    if (!res || !mapped_va) { c->rax = E_INVALIDARG_H; return; }
    if (res->kind == COM_BUFFER) {
        D3D11BufferObj *b = (D3D11BufferObj *)res;
        if (ctx && map_type == 4 && b->byte_width > 4096) {
            /* Rotate 4-slot ring on WRITE_DISCARD to avoid per-draw GPU stalls. */
            if (!b->ring[0]) b->ring[0] = b->mtl_buf;
            b->ring_idx = (b->ring_idx + 1U) & 3U;
            if (!b->ring[b->ring_idx]) {
                b->ring[b->ring_idx] = [ctx->dev->mtl_dev newBufferWithLength:b->byte_width
                                                                      options:MTLResourceStorageModeShared];
            }
            if (++b->ring_used >= 4U) {
                ctx_flush_gpu(ctx, 1);
                b->ring_used = 0;
            }
            if (b->ring[b->ring_idx]) b->mtl_buf = b->ring[b->ring_idx];
        } else if (ctx && (map_type == 1 || map_type == 3)) {
            ctx_flush_gpu(ctx, 1);
        }
        W64(mapped_va + 0, (uint64_t)(uintptr_t)[b->mtl_buf contents]);
        W32(mapped_va + 8, b->byte_width);
        W32(mapped_va + 12, b->byte_width);
        c->rax = S_OK_HR;
        return;
    }
    if (res->kind == COM_TEXTURE2D) {
        if (ctx && (map_type == 1 || map_type == 3)) ctx_flush_gpu(ctx, 1);
        D3D11Texture2DObj *t = (D3D11Texture2DObj *)res;
        uint32_t mip = subres < t->mip_levels ? subres : 0;
        uint32_t mw = t->width >> mip; if (mw == 0) mw = 1;
        uint32_t mh = t->height >> mip; if (mh == 0) mh = 1;
        uint32_t row_pitch = dxgi_row_pitch(t->dxgi_fmt, mw);
        uint32_t nrows = dxgi_num_rows(t->dxgi_fmt, mh);
        size_t total = (size_t)row_pitch * nrows;
        if (t->mapped_cpu) free(t->mapped_cpu);
        t->mapped_cpu = (uint8_t *)calloc(1, total ? total : 16);
        t->mapped_mip = mip;
        t->mapped_pitch = row_pitch;
        t->mapped_maptype = map_type;
        if ((map_type == 1 || map_type == 3) && !dxgi_is_depth(t->dxgi_fmt) && t->mtl_tex) {
            [t->mtl_tex getBytes:t->mapped_cpu bytesPerRow:row_pitch
                      fromRegion:MTLRegionMake2D(0, 0, mw, mh) mipmapLevel:mip];
        }
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
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *res = (ComBase *)(uintptr_t)c->rdx;
    if (res && res->kind == COM_TEXTURE2D) {
        D3D11Texture2DObj *t = (D3D11Texture2DObj *)res;
        if (t->mapped_cpu) {
            if (t->mapped_maptype != 1 && !dxgi_is_depth(t->dxgi_fmt) && t->mtl_tex) {
                if (ctx) ctx_flush_gpu(ctx, 1);
                uint32_t mip = t->mapped_mip < t->mip_levels ? t->mapped_mip : 0;
                uint32_t mw = t->width >> mip; if (mw == 0) mw = 1;
                uint32_t mh = t->height >> mip; if (mh == 0) mh = 1;
                [t->mtl_tex replaceRegion:MTLRegionMake2D(0, 0, mw, mh) mipmapLevel:mip
                                withBytes:t->mapped_cpu bytesPerRow:t->mapped_pitch];
            }
            free(t->mapped_cpu);
            t->mapped_cpu = NULL;
        }
    }
}

static void ctx_UpdateSubresource(CPU64 *c, void *ud) {
    (void)ud;
    D3D11ContextObj *ctx = (D3D11ContextObj *)(uintptr_t)c->rcx;
    ComBase *res = (ComBase *)(uintptr_t)c->rdx;
    uint32_t subres = (uint32_t)c->r8;
    uint64_t box_va = c->r9;
    uint64_t src_va = win64_arg_i(c, 4);
    uint32_t src_pitch = (uint32_t)win64_arg_i(c, 5);
    if (!res || !src_va) return;
    if (res->kind == COM_BUFFER) {
        D3D11BufferObj *b = (D3D11BufferObj *)res;
        if (ctx && b->byte_width > 4096) ctx_flush_gpu(ctx, 1);
        uint32_t off = box_va ? R32(box_va + 0) : 0;
        uint32_t end = box_va ? R32(box_va + 12) : b->byte_width;
        if (end > b->byte_width) end = b->byte_width;
        if (end > off) memcpy((uint8_t *)[b->mtl_buf contents] + off, (const void *)(uintptr_t)src_va, end - off);
    } else if (res->kind == COM_TEXTURE2D) {
        if (ctx) ctx_flush_gpu(ctx, 1);
        D3D11Texture2DObj *t = (D3D11Texture2DObj *)res;
        if (!t->mtl_tex || dxgi_is_depth(t->dxgi_fmt)) return;
        uint32_t mips = t->mip_levels ? t->mip_levels : 1;
        uint32_t arr  = t->array_size ? t->array_size : 1;
        uint32_t mip  = subres % mips;
        uint32_t sl   = subres / mips;
        if (sl >= arr) sl = 0;
        uint32_t mw = t->width >> mip; if (mw == 0) mw = 1;
        uint32_t mh = t->height >> mip; if (mh == 0) mh = 1;
        uint32_t x = 0, y = 0, rw = mw, rh = mh;
        if (box_va) {
            x = R32(box_va + 0); y = R32(box_va + 4);
            uint32_t r = R32(box_va + 12), b = R32(box_va + 16);
            rw = (r > x) ? (r - x) : 0;
            rh = (b > y) ? (b - y) : 0;
        }
        if (x >= mw || y >= mh || rw == 0 || rh == 0) return;
        if (x + rw > mw) rw = mw - x;
        if (y + rh > mh) rh = mh - y;
        uint32_t min_pitch = dxgi_row_pitch(t->dxgi_fmt, rw);
        uint32_t pitch = (src_pitch >= min_pitch) ? src_pitch : min_pitch;
        [t->mtl_tex replaceRegion:MTLRegionMake2D(x, y, rw, rh) mipmapLevel:mip slice:sl
                        withBytes:(const void *)(uintptr_t)src_va bytesPerRow:pitch bytesPerImage:0];
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

static void sc_ResizeBuffers(CPU64 *c, void *ud) {
    (void)ud;
    DXGISwapChainObj *sc = (DXGISwapChainObj *)(uintptr_t)c->rcx;
    uint32_t w = (uint32_t)c->r8;
    uint32_t h = (uint32_t)c->r9;
    uint32_t fmt = (uint32_t)win64_arg_i(c, 4);
    if (!sc) { c->rax = E_INVALIDARG_H; return; }
    if (w == 0) w = sc->width;
    if (h == 0) h = sc->height;
    if (fmt == 0 && sc->backbuffer) fmt = sc->backbuffer->dxgi_fmt;
    if (w != sc->width || h != sc->height) {
        sc->width = w; sc->height = h;
        sc->backbuffer = create_tex2d_internal(sc->dev, w, h, fmt ? fmt : 28, 0, 1, 0);
        if (sc->metal_layer) sc->metal_layer.drawableSize = CGSizeMake(w, h);
    }
    c->rax = S_OK_HR;
}

static FILE    *g_rec_fp = NULL;
static uint8_t *g_rec_buf = NULL;
static uint32_t g_rec_w = 0, g_rec_h = 0;

static void rec_close_atexit(void) {
    if (g_rec_fp) { pclose(g_rec_fp); g_rec_fp = NULL; }
    free(g_rec_buf); g_rec_buf = NULL;
}

static void rec_draw_cursor(uint8_t *px, uint32_t w, uint32_t h, int mx, int my) {
    static const char *arrow[14] = {
        "X           ",
        "XX          ",
        "X.X         ",
        "X..X        ",
        "X...X       ",
        "X....X      ",
        "X.....X     ",
        "X......X    ",
        "X.......X   ",
        "X....XXXX   ",
        "X..X..X     ",
        "X.X X..X    ",
        "XX   X..X   ",
        "     XXXX   ",
    };
    for (int dy = 0; dy < 14; dy++) {
        int y = my + dy;
        if (y < 0 || y >= (int)h) continue;
        for (int dx = 0; dx < 12; dx++) {
            char ch = arrow[dy][dx];
            if (ch == ' ') continue;
            int x = mx + dx;
            if (x < 0 || x >= (int)w) continue;
            uint8_t *p = px + ((size_t)y * w + (size_t)x) * 4;
            uint8_t v = (ch == '.') ? 255 : 15;
            p[0] = v; p[1] = v; p[2] = v; p[3] = 255;
        }
    }
}

static void rec_capture_frame(D3D11Texture2DObj *bb) {
    const char *rec_path = getenv("ELF64_RECORD_MP4");
    if (!rec_path || !*rec_path || !bb || !bb->mtl_tex) return;
    static uint64_t last_ns = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    if (last_ns && now_ns - last_ns < 33333333ULL) return;
    uint32_t w = bb->width, h = bb->height;
    if (!g_rec_fp) {
        const char *pix = (bb->mtl_fmt == MTLPixelFormatBGRA8Unorm) ? "bgra" : "rgba";
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "ffmpeg -y -loglevel error -f rawvideo -pix_fmt %s -s %ux%u -r 30 -i - "
                 "-c:v libx264 -preset ultrafast -crf 20 -pix_fmt yuv420p "
                 "-movflags +frag_keyframe+empty_moov+default_base_moof '%s'",
                 pix, w, h, rec_path);
        g_rec_fp = popen(cmd, "w");
        g_rec_buf = (uint8_t *)malloc((size_t)w * h * 4);
        g_rec_w = w; g_rec_h = h;
        atexit(rec_close_atexit);
        fprintf(stderr, "[d3d11_metal] recording %ux%u@30fps -> %s\n", w, h, rec_path);
    }
    if (!g_rec_fp || !g_rec_buf || w != g_rec_w || h != g_rec_h) return;
    [bb->mtl_tex getBytes:g_rec_buf bytesPerRow:w * 4 fromRegion:MTLRegionMake2D(0, 0, w, h) mipmapLevel:0];
    if (!SDL_GetRelativeMouseMode()) {
        int mx = 0, my = 0;
        win32_get_mouse_xy(&mx, &my);
        rec_draw_cursor(g_rec_buf, w, h, mx, my);
    }
    int reps = last_ns ? (int)((now_ns - last_ns) / 33333333ULL) : 1;
    if (reps < 1) reps = 1;
    if (reps > 3) reps = 3;
    last_ns = now_ns;
    for (int i = 0; i < reps; i++) fwrite(g_rec_buf, 1, (size_t)w * h * 4, g_rec_fp);
    fflush(g_rec_fp);
}

static void sc_Present(CPU64 *c, void *ud) {
    (void)ud;
    static uint32_t g_present_frames = 0;
    DXGISwapChainObj *sc = (DXGISwapChainObj *)(uintptr_t)c->rcx;
    if (sc && sc->dev && sc->dev->imm_ctx) {
        int need_cpu = (getenv("ELF64_DUMP_FRAME") != NULL || getenv("ELF64_RECORD_MP4") != NULL);
        if (need_cpu) {
            ctx_flush_gpu(sc->dev->imm_ctx, 1);
        } else {
            ctx_end_pass(sc->dev->imm_ctx);
        }
    }
    if (sc && sc->backbuffer) {
        g_present_frames++;
        if (g_present_frames == 1 && (getenv("ELF64_TRACE") || getenv("ELF64_DUMP_FRAME"))) {
            fprintf(stderr, "[d3d11_metal] FIRST FRAME PRESENTED (%ux%u)\n", sc->width, sc->height);
        }
        const char *dump_path = getenv("ELF64_DUMP_FRAME");
        const char *exit_env  = getenv("ELF64_EXIT_AFTER_FRAMES");
        uint32_t exit_frame   = exit_env ? (uint32_t)atoi(exit_env) : 0;
        if (dump_path && *dump_path &&
            (g_present_frames == 3 || g_present_frames == 15 || (exit_frame && g_present_frames == exit_frame)) &&
            sc->backbuffer->mtl_tex) {
            uint32_t w = sc->backbuffer->width, h = sc->backbuffer->height;
            uint8_t *px = (uint8_t *)malloc((size_t)w * h * 4);
            if (px) {
                [sc->backbuffer->mtl_tex getBytes:px bytesPerRow:w * 4 fromRegion:MTLRegionMake2D(0, 0, w, h) mipmapLevel:0];
                FILE *f = fopen(dump_path, "wb");
                if (f) {
                    fprintf(f, "P6\n%u %u\n255\n", w, h);
                    int is_bgra = (sc->backbuffer->mtl_fmt == MTLPixelFormatBGRA8Unorm);
                    for (size_t i = 0; i < (size_t)w * h; i++) {
                        uint8_t rgb[3] = { px[i*4 + (is_bgra?2:0)], px[i*4 + 1], px[i*4 + (is_bgra?0:2)] };
                        fwrite(rgb, 1, 3, f);
                    }
                    fclose(f);
                    fprintf(stderr, "[d3d11_metal] dumped frame %u -> %s\n", g_present_frames, dump_path);
                }
                free(px);
            }
        }
        rec_capture_frame(sc->backbuffer);
        if (exit_frame && g_present_frames >= exit_frame) {
            fprintf(stderr, "[d3d11_metal] exiting cleanly at frame %u\n", g_present_frames);
            _exit(0);
        }
    }
    if (sc && sc->metal_layer && sc->backbuffer) {
        SDL_PumpEvents();
        @autoreleasepool {
            id<CAMetalDrawable> drawable = [sc->metal_layer nextDrawable];
            if (drawable) {
                id<MTLCommandBuffer> cb = (sc->dev && sc->dev->imm_ctx && sc->dev->imm_ctx->pending_cb)
                    ? sc->dev->imm_ctx->pending_cb : [sc->dev->mtl_queue commandBuffer];
                if (sc->dev && sc->dev->imm_ctx) sc->dev->imm_ctx->pending_cb = nil;
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
            } else if (sc->dev && sc->dev->imm_ctx) {
                ctx_flush_gpu(sc->dev->imm_ctx, 0);
            }
        }
    } else if (sc && sc->dev && sc->dev->imm_ctx) {
        ctx_flush_gpu(sc->dev->imm_ctx, 0);
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
    sc->backbuffer = create_tex2d_internal(dev, w, h, fmt, 0, 1, 0);
    SDL_Window *win = win32_hwnd_to_sdl(hwnd);
    if (!win && !getenv("ELF64_HEADLESS")) {
        if (!SDL_WasInit(SDL_INIT_VIDEO)) SDL_Init(SDL_INIT_VIDEO);
        win = SDL_CreateWindow("elf64-recomp (Metal)", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                               (int)w, (int)h, SDL_WINDOW_METAL | SDL_WINDOW_SHOWN);
    }
    if (win) {
        SDL_SetWindowSize(win, (int)w, (int)h);
        if (!getenv("ELF64_HEADLESS")) {
            [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
            SDL_ShowWindow(win);
            SDL_RaiseWindow(win);
            [NSApp activateIgnoringOtherApps:YES];
        }
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
    g_vt_device[7]  = rt_alloc_dynamic_thunk("ID3D11Device::CreateShaderResourceView", dev_CreateShaderResourceView, NULL);
    g_vt_device[8]  = rt_alloc_dynamic_thunk("ID3D11Device::CreateUnorderedAccessView", dev_CreateGenericView, NULL);
    g_vt_device[9]  = rt_alloc_dynamic_thunk("ID3D11Device::CreateRenderTargetView", dev_CreateRenderTargetView, NULL);
    g_vt_device[10] = rt_alloc_dynamic_thunk("ID3D11Device::CreateDepthStencilView", dev_CreateDepthStencilView, NULL);
    g_vt_device[11] = rt_alloc_dynamic_thunk("ID3D11Device::CreateInputLayout", dev_CreateInputLayout, NULL);
    g_vt_device[12] = rt_alloc_dynamic_thunk("ID3D11Device::CreateVertexShader", dev_CreateVertexShader, NULL);
    g_vt_device[15] = rt_alloc_dynamic_thunk("ID3D11Device::CreatePixelShader", dev_CreatePixelShader, NULL);
    g_vt_device[20] = rt_alloc_dynamic_thunk("ID3D11Device::CreateBlendState", dev_CreateBlendState, NULL);
    g_vt_device[21] = rt_alloc_dynamic_thunk("ID3D11Device::CreateDepthStencilState", dev_CreateDepthStencilState, NULL);
    g_vt_device[22] = rt_alloc_dynamic_thunk("ID3D11Device::CreateRasterizerState", dev_CreateRasterizerState, NULL);
    g_vt_device[23] = rt_alloc_dynamic_thunk("ID3D11Device::CreateSamplerState", dev_CreateSamplerState, NULL);
    g_vt_device[24] = rt_alloc_dynamic_thunk("ID3D11Device::CreateQuery", dev_CreateGenericState, NULL);
    g_vt_device[29] = rt_alloc_dynamic_thunk("ID3D11Device::CheckFormatSupport", dev_CheckFormatSupport, NULL);
    g_vt_device[30] = rt_alloc_dynamic_thunk("ID3D11Device::CheckMultisampleQualityLevels", dev_CheckMultisampleQualityLevels, NULL);
    g_vt_device[37] = rt_alloc_dynamic_thunk("ID3D11Device::GetFeatureLevel", dev_GetFeatureLevel, NULL);
    g_vt_device[40] = rt_alloc_dynamic_thunk("ID3D11Device::GetImmediateContext", dev_GetImmediateContext, NULL);

    /* ID3D11DeviceContext slots */
    g_vt_context[7]  = rt_alloc_dynamic_thunk("ID3D11DeviceContext::VSSetConstantBuffers", ctx_VSSetConstantBuffers, NULL);
    g_vt_context[8]  = rt_alloc_dynamic_thunk("ID3D11DeviceContext::PSSetShaderResources", ctx_PSSetShaderResources, NULL);
    g_vt_context[9]  = rt_alloc_dynamic_thunk("ID3D11DeviceContext::PSSetShader", ctx_PSSetShader, NULL);
    g_vt_context[10] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::PSSetSamplers", ctx_PSSetSamplers, NULL);
    g_vt_context[11] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::VSSetShader", ctx_VSSetShader, NULL);
    g_vt_context[12] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::DrawIndexed", ctx_DrawIndexed, NULL);
    g_vt_context[13] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::Draw", ctx_Draw, NULL);
    g_vt_context[14] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::Map", ctx_Map, NULL);
    g_vt_context[15] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::Unmap", ctx_Unmap, NULL);
    g_vt_context[16] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::PSSetConstantBuffers", ctx_PSSetConstantBuffers, NULL);
    g_vt_context[17] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::IASetInputLayout", ctx_IASetInputLayout, NULL);
    g_vt_context[18] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::IASetVertexBuffers", ctx_IASetVertexBuffers, NULL);
    g_vt_context[19] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::IASetIndexBuffer", ctx_IASetIndexBuffer, NULL);
    g_vt_context[20] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::DrawIndexedInstanced", ctx_DrawIndexedInstanced, NULL);
    g_vt_context[21] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::DrawInstanced", ctx_DrawInstanced, NULL);
    g_vt_context[24] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::IASetPrimitiveTopology", ctx_IASetPrimitiveTopology, NULL);
    g_vt_context[25] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::VSSetShaderResources", ctx_VSSetShaderResources, NULL);
    g_vt_context[26] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::VSSetSamplers", ctx_VSSetSamplers, NULL);
    g_vt_context[33] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::OMSetRenderTargets", ctx_OMSetRenderTargets, NULL);
    g_vt_context[35] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::OMSetBlendState", ctx_OMSetBlendState, NULL);
    g_vt_context[36] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::OMSetDepthStencilState", ctx_OMSetDepthStencilState, NULL);
    g_vt_context[43] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::RSSetState", ctx_RSSetState, NULL);
    g_vt_context[44] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::RSSetViewports", ctx_RSSetViewports, NULL);
    g_vt_context[45] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::RSSetScissorRects", ctx_RSSetScissorRects, NULL);
    g_vt_context[46] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::CopySubresourceRegion", ctx_CopySubresourceRegion, NULL);
    g_vt_context[47] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::CopyResource", ctx_CopyResource, NULL);
    g_vt_context[48] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::UpdateSubresource", ctx_UpdateSubresource, NULL);
    g_vt_context[50] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::ClearRenderTargetView", ctx_ClearRenderTargetView, NULL);
    g_vt_context[53] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::ClearDepthStencilView", ctx_ClearDepthStencilView, NULL);
    g_vt_context[54] = rt_alloc_dynamic_thunk("ID3D11DeviceContext::GenerateMips", ctx_GenerateMips, NULL);
    g_vt_context[111]= rt_alloc_dynamic_thunk("ID3D11DeviceContext::Flush", ctx_Flush, NULL);

    /* IDXGISwapChain / IDXGIAdapter / IDXGIOutput / IDXGIFactory slots */
    uint64_t t_get_parent = rt_alloc_dynamic_thunk("IDXGIObject::GetParent", dxgi_GetParentFactory, NULL);
    g_vt_swapchain[6] = t_get_parent;
    g_vt_swapchain[8] = rt_alloc_dynamic_thunk("IDXGISwapChain::Present", sc_Present, NULL);
    g_vt_swapchain[9] = rt_alloc_dynamic_thunk("IDXGISwapChain::GetBuffer", sc_GetBuffer, NULL);
    g_vt_swapchain[12]= rt_alloc_dynamic_thunk("IDXGISwapChain::GetDesc", sc_GetDesc, NULL);
    g_vt_swapchain[13]= rt_alloc_dynamic_thunk("IDXGISwapChain::ResizeBuffers", sc_ResizeBuffers, NULL);
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
    MTLSamplerDescriptor *dsd = [[MTLSamplerDescriptor alloc] init];
    dsd.minFilter = MTLSamplerMinMagFilterLinear;
    dsd.magFilter = MTLSamplerMinMagFilterLinear;
    dsd.sAddressMode = MTLSamplerAddressModeRepeat;
    dsd.tAddressMode = MTLSamplerAddressModeRepeat;
    dev->default_sampler = [mdev newSamplerStateWithDescriptor:dsd];
    MTLDepthStencilDescriptor *ddss = [[MTLDepthStencilDescriptor alloc] init];
    ddss.depthCompareFunction = MTLCompareFunctionLess;
    ddss.depthWriteEnabled = YES;
    dev->default_dss = [mdev newDepthStencilStateWithDescriptor:ddss];
    dev->zero_vb = [mdev newBufferWithLength:4096 options:MTLResourceStorageModeShared];
    if (dev->zero_vb) memset([dev->zero_vb contents], 0, 4096);

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
    sc->backbuffer = create_tex2d_internal(dev, w, h, fmt, 0, 1, 0);

    SDL_Window *win = win32_hwnd_to_sdl(hwnd);
    if (!win && !getenv("ELF64_HEADLESS")) {
        if (!SDL_WasInit(SDL_INIT_VIDEO)) SDL_Init(SDL_INIT_VIDEO);
        win = SDL_CreateWindow("elf64-recomp (Metal)", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                               (int)w, (int)h, SDL_WINDOW_METAL | SDL_WINDOW_SHOWN);
    }
    if (win) {
        SDL_SetWindowSize(win, (int)w, (int)h);
        if (!getenv("ELF64_HEADLESS")) {
            [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
            SDL_ShowWindow(win);
            SDL_RaiseWindow(win);
            [NSApp activateIgnoringOtherApps:YES];
        }
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
