#include "win64_min.h"

int _fltused = 1;

/* Minimal Windows x64 D3D11 / DXGI COM definitions (exact SDK vtable slot layout). */
typedef struct { uint32_t Data1; uint16_t Data2, Data3; uint8_t Data4[8]; } GUID;

typedef struct {
    uint32_t Width, Height;
    uint32_t RefreshNum, RefreshDen;
    uint32_t Format, Scanline, Scaling;
    uint32_t SampleCount, SampleQuality;
    uint32_t BufferUsage, BufferCount;
    HWND     OutputWindow;
    BOOL     Windowed;
    uint32_t SwapEffect, Flags;
} DXGI_SWAP_CHAIN_DESC;

typedef struct {
    uint16_t Description[128];
    uint32_t VendorId, DeviceId, SubSysId, Revision;
    size_t   DedicatedVideoMemory, DedicatedSystemMemory, SharedSystemMemory;
    uint32_t LuidLo; int32_t LuidHi;
} DXGI_ADAPTER_DESC;

typedef struct {
    uint32_t ByteWidth, Usage, BindFlags, CPUAccessFlags, MiscFlags, StructureByteStride;
} D3D11_BUFFER_DESC;

typedef struct {
    const void *pSysMem;
    uint32_t    SysMemPitch, SysMemSlicePitch;
} D3D11_SUBRESOURCE_DATA;

typedef struct {
    uint32_t Width, Height, MipLevels, ArraySize, Format;
    uint32_t SampleCount, SampleQuality;
    uint32_t Usage, BindFlags, CPUAccessFlags, MiscFlags;
} D3D11_TEXTURE2D_DESC;

typedef struct {
    const char *SemanticName;
    uint32_t    SemanticIndex, Format, InputSlot, AlignedByteOffset, InputSlotClass, InstanceDataStepRate;
} D3D11_INPUT_ELEMENT_DESC;

typedef struct {
    float TopLeftX, TopLeftY, Width, Height, MinDepth, MaxDepth;
} D3D11_VIEWPORT;

typedef struct {
    void    *pData;
    uint32_t RowPitch, DepthPitch;
} D3D11_MAPPED_SUBRESOURCE;

typedef struct { void **vtbl; } ComObj;

__declspec(dllimport) HRESULT CreateDXGIFactory(const GUID *riid, void **ppFactory);
__declspec(dllimport) HRESULT D3D11CreateDeviceAndSwapChain(
    void *pAdapter, uint32_t DriverType, HMODULE Software, uint32_t Flags,
    const uint32_t *pFeatureLevels, uint32_t FeatureLevels, uint32_t SDKVersion,
    const DXGI_SWAP_CHAIN_DESC *pSwapChainDesc, void **ppSwapChain,
    void **ppDevice, uint32_t *pFeatureLevel, void **ppImmediateContext);

/* Build genuine DXBC container with ISGN + OSGN + SHDR (SM4.0) chunks. */
typedef struct { uint8_t buf[512]; uint32_t len; } DxbcBlob;

static void w32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t build_sig_chunk(uint8_t *dst, const char *fourcc,
                                const char *n0, uint32_t sv0, uint32_t r0,
                                const char *n1, uint32_t sv1, uint32_t r1) {
    uint32_t cnt = n1 ? 2u : 1u;
    uint32_t str_off = 8u + cnt * 24u;
    uint32_t pos = str_off;
    uint8_t *pay = dst + 8;
    memset(pay, 0, 128);
    w32(pay + 0, cnt); w32(pay + 4, 8);

    uint32_t off0 = pos;
    for (int i = 0; n0[i]; i++) pay[pos++] = (uint8_t)n0[i];
    pay[pos++] = 0;
    w32(pay + 8 + 0, off0); w32(pay + 8 + 8, sv0); w32(pay + 8 + 12, 3); w32(pay + 8 + 16, r0);
    pay[8 + 20] = 0xF; pay[8 + 21] = 0xF;

    if (n1) {
        uint32_t off1 = pos;
        for (int i = 0; n1[i]; i++) pay[pos++] = (uint8_t)n1[i];
        pay[pos++] = 0;
        w32(pay + 32 + 0, off1); w32(pay + 32 + 8, sv1); w32(pay + 32 + 12, 3); w32(pay + 32 + 16, r1);
        pay[32 + 20] = 0xF; pay[32 + 21] = 0xF;
    }
    while (pos & 3u) pay[pos++] = 0;
    dst[0] = (uint8_t)fourcc[0]; dst[1] = (uint8_t)fourcc[1];
    dst[2] = (uint8_t)fourcc[2]; dst[3] = (uint8_t)fourcc[3];
    w32(dst + 4, pos);
    return 8u + pos;
}

static void build_dxbc_shader(DxbcBlob *out, int is_pixel) {
    memset(out, 0, sizeof(*out));
    uint8_t *b = out->buf;
    uint32_t c0_off = 32 + 3 * 4; /* header + 3 chunk offsets */
    uint32_t c0_sz = is_pixel
        ? build_sig_chunk(b + c0_off, "ISGN", "SV_POSITION", 1, 0, "COLOR", 0, 1)
        : build_sig_chunk(b + c0_off, "ISGN", "POSITION", 0, 0, "COLOR", 0, 1);
    uint32_t c1_off = c0_off + c0_sz;
    uint32_t c1_sz = is_pixel
        ? build_sig_chunk(b + c1_off, "OSGN", "SV_TARGET", 0, 0, NULL, 0, 0)
        : build_sig_chunk(b + c1_off, "OSGN", "SV_POSITION", 1, 0, "COLOR", 0, 1);
    uint32_t c2_off = c1_off + c1_sz;

    /* SM4.0 tokens:
     *   dst operand: 4-comp(2) | mask(0<<2) | xyzw(0xF<<4) | OUTPUT(2<<12) | 1D(1<<20) = 0x001020F2
     *   src operand: 4-comp(2) | swiz(1<<2) | xyzw(0xE4<<4)| INPUT(1<<12)  | 1D(1<<20) = 0x00101E46
     *   MOV opcode:  54 | (5 << 24) = 0x05000036
     *   RET opcode:  62 | (1 << 24) = 0x0100003E
     */
    uint32_t toks[16];
    uint32_t nt = 0;
    toks[nt++] = is_pixel ? 0x00000040u : 0x00010040u; /* ps_4_0 / vs_4_0 */
    uint32_t len_idx = nt++;
    if (!is_pixel) {
        /* mov o0.xyzw, v0.xyzw */
        toks[nt++] = 0x05000036u; toks[nt++] = 0x001020F2u; toks[nt++] = 0; toks[nt++] = 0x00101E46u; toks[nt++] = 0;
        /* mov o1.xyzw, v1.xyzw */
        toks[nt++] = 0x05000036u; toks[nt++] = 0x001020F2u; toks[nt++] = 1; toks[nt++] = 0x00101E46u; toks[nt++] = 1;
    } else {
        /* mov o0.xyzw, v1.xyzw */
        toks[nt++] = 0x05000036u; toks[nt++] = 0x001020F2u; toks[nt++] = 0; toks[nt++] = 0x00101E46u; toks[nt++] = 1;
    }
    toks[nt++] = 0x0100003Eu; /* ret */
    toks[len_idx] = nt;

    b[c2_off + 0] = 'S'; b[c2_off + 1] = 'H'; b[c2_off + 2] = 'D'; b[c2_off + 3] = 'R';
    w32(b + c2_off + 4, nt * 4u);
    for (uint32_t i = 0; i < nt; i++) w32(b + c2_off + 8 + i * 4u, toks[i]);

    uint32_t total = c2_off + 8u + nt * 4u;
    b[0] = 'D'; b[1] = 'X'; b[2] = 'B'; b[3] = 'C';
    w32(b + 20, 1); w32(b + 24, total); w32(b + 28, 3);
    w32(b + 32, c0_off); w32(b + 36, c1_off); w32(b + 40, c2_off);
    out->len = total;
}

typedef struct { float x, y, z, w; float r, g, b, a; } Vertex;

int main(void) {
    /* 1. Query GPU name via DXGI */
    GUID iid; memset(&iid, 0, sizeof(iid));
    ComObj *factory = NULL, *adapter = NULL;
    if (CreateDXGIFactory(&iid, (void **)&factory) != 0 || !factory) {
        printf("FAIL: CreateDXGIFactory\n"); ExitProcess(1);
    }
    typedef HRESULT (*FnEnumAdapters)(void *, uint32_t, void **);
    typedef HRESULT (*FnGetDesc)(void *, DXGI_ADAPTER_DESC *);
    if (((FnEnumAdapters)factory->vtbl[7])(factory, 0, (void **)&adapter) != 0 || !adapter) {
        printf("FAIL: EnumAdapters\n"); ExitProcess(2);
    }
    DXGI_ADAPTER_DESC adesc;
    memset(&adesc, 0, sizeof(adesc));
    ((FnGetDesc)adapter->vtbl[8])(adapter, &adesc);
    char gpu[128];
    int gi = 0;
    while (adesc.Description[gi] && gi < 127) { gpu[gi] = (char)adesc.Description[gi]; gi++; }
    gpu[gi] = '\0';

    /* 2. Create D3D11 Device + SwapChain (64x64 RGBA8) */
    DXGI_SWAP_CHAIN_DESC scd;
    memset(&scd, 0, sizeof(scd));
    scd.Width = 64; scd.Height = 64; scd.Format = 28; /* DXGI_FORMAT_R8G8B8A8_UNORM */
    scd.SampleCount = 1; scd.BufferCount = 1; scd.Windowed = TRUE;

    ComObj *sc = NULL, *dev = NULL, *ctx = NULL;
    uint32_t fl = 0;
    if (D3D11CreateDeviceAndSwapChain(NULL, 1, 0, 0, NULL, 0, 7, &scd,
                                      (void **)&sc, (void **)&dev, &fl, (void **)&ctx) != 0) {
        printf("FAIL: D3D11CreateDeviceAndSwapChain\n"); ExitProcess(3);
    }

    /* 3. Backbuffer + RTV + Clear to cornflower blue (0.1, 0.2, 0.8, 1.0) */
    ComObj *bb = NULL, *rtv = NULL;
    typedef HRESULT (*FnGetBuffer)(void *, uint32_t, const GUID *, void **);
    typedef HRESULT (*FnCreateRTV)(void *, void *, void *, void **);
    typedef void    (*FnClearRTV)(void *, void *, const float *);
    if (((FnGetBuffer)sc->vtbl[9])(sc, 0, &iid, (void **)&bb) != 0 || !bb) {
        printf("FAIL: SwapChain::GetBuffer\n"); ExitProcess(4);
    }
    if (((FnCreateRTV)dev->vtbl[9])(dev, bb, NULL, (void **)&rtv) != 0 || !rtv) {
        printf("FAIL: CreateRenderTargetView\n"); ExitProcess(5);
    }
    float clear_col[4] = {0.1f, 0.2f, 0.8f, 1.0f};
    ((FnClearRTV)ctx->vtbl[50])(ctx, rtv, clear_col);

    /* 4. Compile DXBC SM4.0 VS & PS -> Metal shaders */
    DxbcBlob vs_bc, ps_bc;
    build_dxbc_shader(&vs_bc, 0);
    build_dxbc_shader(&ps_bc, 1);
    ComObj *vs = NULL, *ps = NULL, *il = NULL, *vb = NULL;
    typedef HRESULT (*FnCreateShader)(void *, const void *, size_t, void *, void **);
    typedef HRESULT (*FnCreateIL)(void *, const D3D11_INPUT_ELEMENT_DESC *, uint32_t, const void *, size_t, void **);
    typedef HRESULT (*FnCreateBuf)(void *, const D3D11_BUFFER_DESC *, const D3D11_SUBRESOURCE_DATA *, void **);

    if (((FnCreateShader)dev->vtbl[12])(dev, vs_bc.buf, vs_bc.len, NULL, (void **)&vs) != 0) {
        printf("FAIL: CreateVertexShader\n"); ExitProcess(6);
    }
    if (((FnCreateShader)dev->vtbl[15])(dev, ps_bc.buf, ps_bc.len, NULL, (void **)&ps) != 0) {
        printf("FAIL: CreatePixelShader\n"); ExitProcess(7);
    }

    D3D11_INPUT_ELEMENT_DESC ied[2];
    memset(ied, 0, sizeof(ied));
    ied[0].SemanticName = "POSITION"; ied[0].Format = 2; ied[0].AlignedByteOffset = 0;
    ied[1].SemanticName = "COLOR";    ied[1].Format = 2; ied[1].AlignedByteOffset = 16;
    if (((FnCreateIL)dev->vtbl[11])(dev, ied, 2, vs_bc.buf, vs_bc.len, (void **)&il) != 0) {
        printf("FAIL: CreateInputLayout\n"); ExitProcess(8);
    }

    /* Centered triangle covering (32, 32) but NOT corner (2, 2). */
    Vertex verts[3] = {
        {  0.0f,  0.5f, 0.0f, 1.0f,  0.9f, 0.8f, 0.1f, 1.0f },
        {  0.5f, -0.5f, 0.0f, 1.0f,  0.9f, 0.8f, 0.1f, 1.0f },
        { -0.5f, -0.5f, 0.0f, 1.0f,  0.9f, 0.8f, 0.1f, 1.0f },
    };
    D3D11_BUFFER_DESC bd;
    memset(&bd, 0, sizeof(bd));
    bd.ByteWidth = sizeof(verts); bd.BindFlags = 1; /* VERTEX_BUFFER */
    D3D11_SUBRESOURCE_DATA sd;
    memset(&sd, 0, sizeof(sd));
    sd.pSysMem = verts;
    if (((FnCreateBuf)dev->vtbl[3])(dev, &bd, &sd, (void **)&vb) != 0) {
        printf("FAIL: CreateBuffer\n"); ExitProcess(9);
    }

    /* 5. Bind pipeline & Draw(3, 0) on Apple Silicon Metal GPU */
    typedef void (*FnOMSetRT)(void *, uint32_t, void **, void *);
    typedef void (*FnRSSetVP)(void *, uint32_t, const D3D11_VIEWPORT *);
    typedef void (*FnIASetIL)(void *, void *);
    typedef void (*FnIASetVB)(void *, uint32_t, uint32_t, void **, const uint32_t *, const uint32_t *);
    typedef void (*FnIASetTopo)(void *, uint32_t);
    typedef void (*FnSetSh)(void *, void *, void *, uint32_t);
    typedef void (*FnDraw)(void *, uint32_t, uint32_t);

    void *rtv_arr[1] = { rtv };
    ((FnOMSetRT)ctx->vtbl[33])(ctx, 1, rtv_arr, NULL);
    D3D11_VIEWPORT vp = { 0.0f, 0.0f, 64.0f, 64.0f, 0.0f, 1.0f };
    ((FnRSSetVP)ctx->vtbl[44])(ctx, 1, &vp);
    ((FnIASetIL)ctx->vtbl[17])(ctx, il);
    void *vb_arr[1] = { vb };
    uint32_t stride = sizeof(Vertex), offset = 0;
    ((FnIASetVB)ctx->vtbl[18])(ctx, 0, 1, vb_arr, &stride, &offset);
    ((FnIASetTopo)ctx->vtbl[24])(ctx, 4); /* TRIANGLELIST */
    ((FnSetSh)ctx->vtbl[11])(ctx, vs, NULL, 0);
    ((FnSetSh)ctx->vtbl[9])(ctx, ps, NULL, 0);
    ((FnDraw)ctx->vtbl[13])(ctx, 3, 0);

    /* 6. Staging texture readback & pixel verification */
    D3D11_TEXTURE2D_DESC td;
    memset(&td, 0, sizeof(td));
    td.Width = 64; td.Height = 64; td.MipLevels = 1; td.ArraySize = 1;
    td.Format = 28; td.SampleCount = 1; td.Usage = 3; /* D3D11_USAGE_STAGING */
    ComObj *staging = NULL;
    typedef HRESULT (*FnCreateTex2D)(void *, const D3D11_TEXTURE2D_DESC *, void *, void **);
    typedef void    (*FnCopyRes)(void *, void *, void *);
    typedef HRESULT (*FnMap)(void *, void *, uint32_t, uint32_t, uint32_t, D3D11_MAPPED_SUBRESOURCE *);
    typedef void    (*FnUnmap)(void *, void *, uint32_t);
    typedef HRESULT (*FnPresent)(void *, uint32_t, uint32_t);

    if (((FnCreateTex2D)dev->vtbl[5])(dev, &td, NULL, (void **)&staging) != 0) {
        printf("FAIL: CreateTexture2D staging\n"); ExitProcess(10);
    }
    ((FnCopyRes)ctx->vtbl[47])(ctx, staging, bb);

    D3D11_MAPPED_SUBRESOURCE mapped;
    memset(&mapped, 0, sizeof(mapped));
    if (((FnMap)ctx->vtbl[14])(ctx, staging, 0, 1, 0, &mapped) != 0 || !mapped.pData) {
        printf("FAIL: Map staging\n"); ExitProcess(11);
    }

    const uint8_t *px = (const uint8_t *)mapped.pData;
    const uint8_t *corner = px + 2 * mapped.RowPitch + 2 * 4;
    const uint8_t *center = px + 32 * mapped.RowPitch + 32 * 4;
    int cr = corner[0], cg = corner[1], cb = corner[2];
    int tr = center[0], tg = center[1], tb = center[2];
    ((FnUnmap)ctx->vtbl[15])(ctx, staging, 0);
    ((FnPresent)sc->vtbl[8])(sc, 0, 0);

    /* Corner should be cornflower blue (~26, 51, 204); center should be gold (~230, 204, 26). */
    if (cr < 15 || cr > 38 || cg < 40 || cg > 64 || cb < 190 || cb > 218) {
        printf("FAIL: clear pixel=(%d,%d,%d)\n", cr, cg, cb);
        ExitProcess(12);
    }
    if (tr < 215 || tr > 245 || tg < 190 || tg > 218 || tb < 15 || tb > 38) {
        printf("FAIL: tri pixel=(%d,%d,%d)\n", tr, tg, tb);
        ExitProcess(13);
    }

    printf("D3D11_SMOKE64 PASS gpu='%s' fl=0x%x clear=(%d,%d,%d) tri=(%d,%d,%d)\n",
           gpu, fl, cr, cg, cb, tr, tg, tb);
    ExitProcess(0);
    return 0;
}
