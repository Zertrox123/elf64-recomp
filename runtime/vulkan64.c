#include "runtime64.h"
#include "win64_abi.h"
#include <SDL.h>

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>

#include "vulkan64_gen.inc"

extern SDL_Window *win32_hwnd_to_sdl(uint64_t hwnd);
extern uint64_t    win32_primary_hwnd(void);

typedef struct VkMetalSurfaceCreateInfoEXT_Local {
    VkStructureType sType;
    const void     *pNext;
    VkFlags         flags;
    const void     *pLayer;
} VkMetalSurfaceCreateInfoEXT_Local;

typedef VkResult (VKAPI_PTR *PFN_vkCreateMetalSurfaceEXT_Local)(
    VkInstance, const VkMetalSurfaceCreateInfoEXT_Local *, const VkAllocationCallbacks *, VkSurfaceKHR *);

static void *g_mvk_handle = NULL;
static PFN_vkGetInstanceProcAddr g_mvk_gipa = NULL;
static PFN_vkGetDeviceProcAddr   g_mvk_gdpa = NULL;
static PFN_vkCreateInstance      g_mvk_create_instance = NULL;
static PFN_vkCreateDevice        g_mvk_create_device = NULL;
static PFN_vkEnumerateInstanceExtensionProperties g_mvk_enum_inst_ext = NULL;
static PFN_vkEnumerateDeviceExtensionProperties   g_mvk_enum_dev_ext = NULL;
static PFN_vkGetPhysicalDeviceFeatures            g_mvk_get_phys_feat = NULL;
static PFN_vkGetPhysicalDeviceFeatures2           g_mvk_get_phys_feat2 = NULL;
static PFN_vkCreateMetalSurfaceEXT_Local          g_mvk_create_metal_surface = NULL;

static inline uint64_t vk_arg(const CPU64 *c, int idx) {
    return g_rt_is_win64 ? win64_arg_i(c, idx) : sysv_arg_i(c, idx);
}

static int ensure_moltenvk(void) {
    if (g_mvk_gipa) return 1;
    const char *ldir = getenv("ELF64_LIB_DIR");
    if (ldir && *ldir) {
        char p[512];
        snprintf(p, sizeof(p), "%s/libMoltenVK.dylib", ldir);
        g_mvk_handle = dlopen(p, RTLD_LAZY | RTLD_LOCAL);
    }
    const char *paths[] = {
        "/opt/homebrew/lib/libMoltenVK.dylib",
        "/usr/local/lib/libMoltenVK.dylib",
        "libMoltenVK.dylib",
        NULL
    };
    for (int i = 0; !g_mvk_handle && paths[i]; i++) {
        g_mvk_handle = dlopen(paths[i], RTLD_LAZY | RTLD_LOCAL);
    }
    if (!g_mvk_handle) {
        fprintf(stderr, "elf64-recomp: failed to dlopen libMoltenVK.dylib: %s\n", dlerror());
        return 0;
    }
    g_mvk_gipa = (PFN_vkGetInstanceProcAddr)dlsym(g_mvk_handle, "vkGetInstanceProcAddr");
    g_mvk_gdpa = (PFN_vkGetDeviceProcAddr)dlsym(g_mvk_handle, "vkGetDeviceProcAddr");
    g_mvk_create_instance = (PFN_vkCreateInstance)dlsym(g_mvk_handle, "vkCreateInstance");
    g_mvk_create_device = (PFN_vkCreateDevice)dlsym(g_mvk_handle, "vkCreateDevice");
    g_mvk_enum_inst_ext = (PFN_vkEnumerateInstanceExtensionProperties)dlsym(g_mvk_handle, "vkEnumerateInstanceExtensionProperties");
    g_mvk_enum_dev_ext = (PFN_vkEnumerateDeviceExtensionProperties)dlsym(g_mvk_handle, "vkEnumerateDeviceExtensionProperties");
    g_mvk_get_phys_feat = (PFN_vkGetPhysicalDeviceFeatures)dlsym(g_mvk_handle, "vkGetPhysicalDeviceFeatures");
    g_mvk_get_phys_feat2 = (PFN_vkGetPhysicalDeviceFeatures2)dlsym(g_mvk_handle, "vkGetPhysicalDeviceFeatures2");
    g_mvk_create_metal_surface = (PFN_vkCreateMetalSurfaceEXT_Local)dlsym(g_mvk_handle, "vkCreateMetalSurfaceEXT");
    return g_mvk_gipa != NULL;
}

static RTShimFn find_vk_tramp(const char *name) {
    size_t lo = 0, hi = g_vk_cmd_tramp_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strcmp(g_vk_cmd_tramps[mid].name, name);
        if (cmp == 0) return g_vk_cmd_tramps[mid].tramp;
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    return NULL;
}

/* Forward declarations for intercepted commands */
static void sh_vkGetInstanceProcAddr(CPU64 *c, void *ud);
static void sh_vkGetDeviceProcAddr(CPU64 *c, void *ud);
static void sh_vkCreateInstance(CPU64 *c, void *ud);
static void sh_vkCreateDevice(CPU64 *c, void *ud);
static void sh_vkEnumerateInstanceExtensionProperties(CPU64 *c, void *ud);
static void sh_vkCreateWin32SurfaceKHR(CPU64 *c, void *ud);
static void sh_vkGetPhysicalDeviceWin32PresentationSupportKHR(CPU64 *c, void *ud);

static void sh_vkEnumerateInstanceExtensionProperties(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk() || !g_mvk_enum_inst_ext) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED;
        return;
    }
    const char *layer = (const char *)(uintptr_t)vk_arg(c, 0);
    uint32_t *pCount = (uint32_t *)(uintptr_t)vk_arg(c, 1);
    VkExtensionProperties *pProps = (VkExtensionProperties *)(uintptr_t)vk_arg(c, 2);
    VkResult r = g_mvk_enum_inst_ext(layer, pCount, pProps);
    if (r == VK_SUCCESS && pProps && pCount && g_rt_is_win64) {
        for (uint32_t i = 0; i < *pCount; i++) {
            if (strcmp(pProps[i].extensionName, "VK_MVK_macos_surface") == 0) {
                snprintf(pProps[i].extensionName, VK_MAX_EXTENSION_NAME_SIZE, "VK_KHR_win32_surface");
            }
        }
    }
    c->rax = (uint64_t)(uint32_t)r;
}

static void sh_vkCreateInstance(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk() || !g_mvk_create_instance) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED;
        return;
    }
    const VkInstanceCreateInfo *ci = (const VkInstanceCreateInfo *)(uintptr_t)vk_arg(c, 0);
    VkInstance *out = (VkInstance *)(uintptr_t)vk_arg(c, 2);
    if (!ci) { c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED; return; }

    VkExtensionProperties supp[64];
    uint32_t supp_n = 64;
    if (g_mvk_enum_inst_ext) g_mvk_enum_inst_ext(NULL, &supp_n, supp);
    else supp_n = 0;

    VkInstanceCreateInfo local_ci = *ci;
    const char *exts[64];
    uint32_t ext_n = 0;
    for (uint32_t i = 0; i < ci->enabledExtensionCount && ext_n < 60; i++) {
        const char *en = ci->ppEnabledExtensionNames[i];
        if (!en) continue;
        if (strcmp(en, "VK_KHR_win32_surface") == 0 ||
            strcmp(en, "VK_KHR_xcb_surface") == 0 ||
            strcmp(en, "VK_KHR_xlib_surface") == 0) {
            en = "VK_EXT_metal_surface";
        }
        int ok = (supp_n == 0);
        for (uint32_t j = 0; j < supp_n; j++) {
            if (strcmp(supp[j].extensionName, en) == 0) { ok = 1; break; }
        }
        if (ok) exts[ext_n++] = en;
    }
    local_ci.enabledExtensionCount = ext_n;
    local_ci.ppEnabledExtensionNames = exts;
    local_ci.enabledLayerCount = 0;
    local_ci.ppEnabledLayerNames = NULL;

    /* shortcut: pass NULL for guest VkAllocationCallbacks because callback ptrs are guest x86_64 code; wrap via rt_invoke64 if a game requires custom allocators. */
    VkResult r = g_mvk_create_instance(&local_ci, NULL, out);
    c->rax = (uint64_t)(uint32_t)r;
}

static void mask_phys_features(VkPhysicalDevice phys, VkPhysicalDeviceFeatures *req) {
    if (!g_mvk_get_phys_feat || !req) return;
    VkPhysicalDeviceFeatures supp;
    memset(&supp, 0, sizeof(supp));
    g_mvk_get_phys_feat(phys, &supp);
    uint32_t *rq = (uint32_t *)req;
    const uint32_t *sp = (const uint32_t *)&supp;
    for (size_t i = 0; i < sizeof(VkPhysicalDeviceFeatures) / sizeof(uint32_t); i++) {
        rq[i] &= sp[i];
    }
}

static void sh_vkCreateDevice(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk() || !g_mvk_create_device) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED;
        return;
    }
    VkPhysicalDevice phys = (VkPhysicalDevice)(uintptr_t)vk_arg(c, 0);
    const VkDeviceCreateInfo *ci = (const VkDeviceCreateInfo *)(uintptr_t)vk_arg(c, 1);
    VkDevice *out = (VkDevice *)(uintptr_t)vk_arg(c, 3);
    if (!ci) { c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED; return; }

    VkExtensionProperties supp[256];
    uint32_t supp_n = 256;
    if (g_mvk_enum_dev_ext) g_mvk_enum_dev_ext(phys, NULL, &supp_n, supp);
    else supp_n = 0;

    VkDeviceCreateInfo local_ci = *ci;
    const char *exts[256];
    uint32_t ext_n = 0;
    for (uint32_t i = 0; i < ci->enabledExtensionCount && ext_n < 250; i++) {
        const char *en = ci->ppEnabledExtensionNames[i];
        if (!en) continue;
        int ok = (supp_n == 0);
        for (uint32_t j = 0; j < supp_n; j++) {
            if (strcmp(supp[j].extensionName, en) == 0) { ok = 1; break; }
        }
        if (ok) exts[ext_n++] = en;
    }
    local_ci.enabledExtensionCount = ext_n;
    local_ci.ppEnabledExtensionNames = exts;

    VkPhysicalDeviceFeatures local_feat;
    if (ci->pEnabledFeatures) {
        local_feat = *ci->pEnabledFeatures;
        mask_phys_features(phys, &local_feat);
        local_ci.pEnabledFeatures = &local_feat;
    }
    /* Also mask VkPhysicalDeviceFeatures2 and all extension feature structs in pNext chain */
    VkBaseOutStructure *pnext = (VkBaseOutStructure *)(uintptr_t)local_ci.pNext;
    while (pnext) {
        if (pnext->sType == VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2) {
            VkPhysicalDeviceFeatures2 *f2 = (VkPhysicalDeviceFeatures2 *)pnext;
            mask_phys_features(phys, &f2->features);
        } else if (g_mvk_get_phys_feat2) {
            uint32_t supp_buf[64];
            memset(supp_buf, 0xFF, sizeof(supp_buf));
            VkBaseOutStructure *shdr = (VkBaseOutStructure *)supp_buf;
            shdr->sType = pnext->sType;
            shdr->pNext = NULL;
            VkPhysicalDeviceFeatures2 qf2;
            memset(&qf2, 0, sizeof(qf2));
            qf2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2;
            qf2.pNext = shdr;
            g_mvk_get_phys_feat2(phys, &qf2);
            uint32_t *req_words = (uint32_t *)pnext;
            for (size_t k = 4; k < 64; k++) {
                if (supp_buf[k] == 0) req_words[k] = 0;
            }
        }
        pnext = pnext->pNext;
    }

    /* shortcut: ignore guest VkAllocationCallbacks ptr (see sh_vkCreateInstance). */
    VkResult r = g_mvk_create_device(phys, &local_ci, NULL, out);
    c->rax = (uint64_t)(uint32_t)r;
}

static void sh_vkCreateWin32SurfaceKHR(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk() || !g_mvk_create_metal_surface) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED;
        return;
    }
    VkInstance inst = (VkInstance)(uintptr_t)vk_arg(c, 0);
    uint64_t ci_va  = vk_arg(c, 1);
    VkSurfaceKHR *out = (VkSurfaceKHR *)(uintptr_t)vk_arg(c, 3);
    uint64_t hwnd = ci_va ? R64(ci_va + 32) : 0;
    SDL_Window *win = win32_hwnd_to_sdl(hwnd);
    if (!win) win = win32_hwnd_to_sdl(win32_primary_hwnd());
    if (!win || !out) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_SURFACE_LOST_KHR;
        return;
    }
    if (!getenv("ELF64_HEADLESS") && (SDL_GetWindowFlags(win) & SDL_WINDOW_HIDDEN)) {
        SDL_ShowWindow(win);
        SDL_RaiseWindow(win);
    }
    SDL_MetalView view = SDL_Metal_CreateView(win);
    void *layer = view ? SDL_Metal_GetLayer(view) : NULL;
    if (!layer) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_SURFACE_LOST_KHR;
        return;
    }
    VkMetalSurfaceCreateInfoEXT_Local mci;
    memset(&mci, 0, sizeof(mci));
    mci.sType  = (VkStructureType)1000217000; /* VK_STRUCTURE_TYPE_METAL_SURFACE_CREATE_INFO_EXT */
    mci.pLayer = layer;
    VkResult r = g_mvk_create_metal_surface(inst, &mci, NULL, out);
    c->rax = (uint64_t)(uint32_t)r;
}

static void sh_vkGetPhysicalDeviceWin32PresentationSupportKHR(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = 1; /* VK_TRUE */
}

/*
 * MoltenVK workaround (KhronosGroup/MoltenVK#2768):
 * DXVK D3D9 emits aliased combined image samplers (e.g. s0_2d and s0_2d_shadow,
 * Depth=0 vs Depth=1) on the same (DescriptorSet, Binding) and branches between
 * them using SpecId 1 (samplerDepthMode). SPIRV-Cross/MSL rejects aliased
 * bindings of different texture types. Specialize & prune the dead variant at
 * pipeline creation time so MoltenVK compiles cleanly.
 */
typedef struct {
    VkShaderModule mod;
    uint32_t      *words;
    size_t         nwords;
} SpvModEntry;

static pthread_mutex_t g_spv_mu = PTHREAD_MUTEX_INITIALIZER;
static SpvModEntry    *g_spv_mods = NULL;
static size_t          g_spv_mod_cnt = 0, g_spv_mod_cap = 0;

static PFN_vkCreateShaderModule      g_mvk_create_shader_module = NULL;
static PFN_vkDestroyShaderModule     g_mvk_destroy_shader_module = NULL;
static PFN_vkCreateGraphicsPipelines g_mvk_create_graphics_pipelines = NULL;

static int spv_has_aliased_uc_bindings(const uint32_t *w, size_t nw) {
    if (!w || nw < 5 || w[0] != 0x07230203U) return 0;
    uint32_t bound = w[3];
    if (bound == 0 || bound > 65536) return 0;
    uint32_t *set_arr  = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint32_t *bind_arr = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint8_t  *has_bind = (uint8_t  *)calloc(bound, 1);
    uint32_t  uc_vars[64];
    int       uc_cnt = 0;
    int       found = 0;
    if (!set_arr || !bind_arr || !has_bind) goto done;

    for (size_t i = 5; i < nw; ) {
        uint32_t wc = w[i] >> 16, op = w[i] & 0xFFFFU;
        if (wc == 0 || i + wc > nw) break;
        if (op == 71 && wc >= 4) { /* OpDecorate */
            uint32_t tid = w[i + 1], dec = w[i + 2];
            if (tid < bound) {
                if (dec == 34) set_arr[tid] = w[i + 3];
                else if (dec == 33) { bind_arr[tid] = w[i + 3]; has_bind[tid] = 1; }
            }
        } else if (op == 59 && wc >= 4 && w[i + 3] == 0) { /* OpVariable UniformConstant */
            if (uc_cnt < 64 && w[i + 2] < bound) uc_vars[uc_cnt++] = w[i + 2];
        } else if (op == 54) { /* OpFunction: declarations finished */
            break;
        }
        i += wc;
    }
    for (int a = 0; a < uc_cnt && !found; a++) {
        uint32_t va = uc_vars[a];
        if (!has_bind[va]) continue;
        for (int b = a + 1; b < uc_cnt; b++) {
            uint32_t vb = uc_vars[b];
            if (has_bind[vb] && set_arr[va] == set_arr[vb] && bind_arr[va] == bind_arr[vb]) {
                found = 1;
                break;
            }
        }
    }
done:
    free(set_arr);
    free(bind_arr);
    free(has_bind);
    return found;
}

typedef struct {
    uint32_t reg_var;
    uint32_t shd_var;
    int      bit_idx;
    uint32_t dead_var;
} SpvAliasPair;

static int spv_dealias_samplers(const uint32_t *w, size_t nw, uint32_t spec1_val,
                                uint32_t **out_w, size_t *out_nw) {
    *out_w = NULL;
    *out_nw = 0;
    if (!w || nw < 5 || w[0] != 0x07230203U) return 0;
    uint32_t bound = w[3];
    if (bound == 0 || bound > 65536) return 0;

    /* Count instructions */
    size_t ninst = 0;
    for (size_t i = 5; i < nw; ) {
        uint32_t wc = w[i] >> 16;
        if (wc == 0 || i + wc > nw) return 0;
        ninst++;
        i += wc;
    }
    if (ninst == 0) return 0;

    size_t   *inst_off  = (size_t   *)malloc(ninst * sizeof(size_t));
    uint32_t *set_arr   = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint32_t *bind_arr  = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint8_t  *has_bind  = (uint8_t  *)calloc(bound, 1);
    uint32_t *ptr_ty    = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint32_t *simg_ty   = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint8_t  *img_depth = (uint8_t  *)calloc(bound, 1);
    uint32_t *var_ty    = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint32_t *const_val = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint8_t  *is_const  = (uint8_t  *)calloc(bound, 1);
    uint32_t *ineq_lhs  = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint32_t *bfe_off   = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint32_t *blk_start = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint32_t *blk_end   = (uint32_t *)calloc(bound, sizeof(uint32_t));
    uint8_t  *is_dead_v = (uint8_t  *)calloc(bound, 1);
    uint8_t  *is_dead_b = (uint8_t  *)calloc(bound, 1);
    uint8_t  *del_inst  = (uint8_t  *)calloc(ninst, 1);
    uint32_t *rw_branch = (uint32_t *)calloc(ninst, sizeof(uint32_t));
    uint32_t  uc_vars[64];
    int       uc_cnt = 0;
    SpvAliasPair pairs[32];
    int       pair_cnt = 0;
    int       ret = 0;

    if (!inst_off || !set_arr || !bind_arr || !has_bind || !ptr_ty || !simg_ty ||
        !img_depth || !var_ty || !const_val || !is_const || !ineq_lhs || !bfe_off ||
        !blk_start || !blk_end || !is_dead_v || !is_dead_b || !del_inst || !rw_branch)
        goto cleanup;

    /* Pass 1: index instructions, types, decorations, constants, blocks */
    uint32_t cur_lbl = 0;
    for (size_t idx = 0, i = 5; idx < ninst; idx++) {
        inst_off[idx] = i;
        uint32_t wc = w[i] >> 16, op = w[i] & 0xFFFFU;
        if (op == 25 && wc >= 5 && w[i + 1] < bound) { /* OpTypeImage: result, sampled, dim, depth */
            img_depth[w[i + 1]] = (uint8_t)(w[i + 4] + 1); /* 1=non-depth, 2=depth */
        } else if (op == 27 && wc >= 3 && w[i + 1] < bound) { /* OpTypeSampledImage */
            simg_ty[w[i + 1]] = w[i + 2];
        } else if (op == 32 && wc >= 4 && w[i + 1] < bound) { /* OpTypePointer */
            ptr_ty[w[i + 1]] = w[i + 3];
        } else if (op == 43 && wc >= 4 && w[i + 2] < bound) { /* OpConstant */
            const_val[w[i + 2]] = w[i + 3];
            is_const[w[i + 2]] = 1;
        } else if (op == 71 && wc >= 4 && w[i + 1] < bound) { /* OpDecorate */
            if (w[i + 2] == 34) set_arr[w[i + 1]] = w[i + 3];
            else if (w[i + 2] == 33) { bind_arr[w[i + 1]] = w[i + 3]; has_bind[w[i + 1]] = 1; }
        } else if (op == 59 && wc >= 4 && w[i + 3] == 0 && w[i + 2] < bound) { /* OpVariable UC */
            var_ty[w[i + 2]] = w[i + 1];
            if (uc_cnt < 64) uc_vars[uc_cnt++] = w[i + 2];
        } else if (op == 171 && wc >= 5 && w[i + 2] < bound) { /* OpINotEqual */
            ineq_lhs[w[i + 2]] = w[i + 3];
        } else if (op == 203 && wc >= 6 && w[i + 2] < bound) { /* OpBitFieldUExtract */
            bfe_off[w[i + 2]] = w[i + 4];
        } else if (op == 248 && wc >= 2 && w[i + 1] < bound) { /* OpLabel */
            if (cur_lbl) blk_end[cur_lbl] = (uint32_t)idx;
            cur_lbl = w[i + 1];
            blk_start[cur_lbl] = (uint32_t)idx;
        } else if (op == 56) { /* OpFunctionEnd */
            if (cur_lbl) blk_end[cur_lbl] = (uint32_t)idx;
            cur_lbl = 0;
        }
        i += wc;
    }

    /* Group aliased UniformConstant pairs (Depth=0 vs Depth=1) */
    for (int a = 0; a < uc_cnt; a++) {
        uint32_t va = uc_vars[a];
        if (!has_bind[va]) continue;
        for (int b = a + 1; b < uc_cnt && pair_cnt < 32; b++) {
            uint32_t vb = uc_vars[b];
            if (!has_bind[vb] || set_arr[va] != set_arr[vb] || bind_arr[va] != bind_arr[vb]) continue;
            uint32_t ta = ptr_ty[var_ty[va]], tb = ptr_ty[var_ty[vb]];
            uint32_t ia = (ta < bound && simg_ty[ta] < bound) ? simg_ty[ta] : ta;
            uint32_t ib = (tb < bound && simg_ty[tb] < bound) ? simg_ty[tb] : tb;
            uint8_t da = (ia < bound) ? img_depth[ia] : 0;
            uint8_t db = (ib < bound) ? img_depth[ib] : 0;
            if (da == 1 && db == 2) {
                pairs[pair_cnt++] = (SpvAliasPair){ va, vb, -1, vb };
            } else if (da == 2 && db == 1) {
                pairs[pair_cnt++] = (SpvAliasPair){ vb, va, -1, va };
            }
        }
    }
    if (pair_cnt == 0) goto cleanup;

    /* Pass 2: determine each pair's bit index in SpecId 1 from OpBranchConditional */
    for (size_t idx = 0; idx < ninst; idx++) {
        size_t i = inst_off[idx];
        uint32_t op = w[i] & 0xFFFFU;
        if (op != 250) continue; /* OpBranchConditional */
        uint32_t cond = w[i + 1], t_lbl = w[i + 2], f_lbl = w[i + 3];
        if (t_lbl >= bound || f_lbl >= bound || !blk_end[t_lbl] || !blk_end[f_lbl]) continue;
        for (int p = 0; p < pair_cnt; p++) {
            int t_shd = 0, f_reg = 0, t_reg = 0, f_shd = 0;
            for (uint32_t k = blk_start[t_lbl]; k < blk_end[t_lbl]; k++) {
                size_t ko = inst_off[k];
                if ((w[ko] & 0xFFFFU) == 61) { /* OpLoad */
                    if (w[ko + 3] == pairs[p].shd_var) t_shd = 1;
                    if (w[ko + 3] == pairs[p].reg_var) t_reg = 1;
                }
            }
            for (uint32_t k = blk_start[f_lbl]; k < blk_end[f_lbl]; k++) {
                size_t ko = inst_off[k];
                if ((w[ko] & 0xFFFFU) == 61) {
                    if (w[ko + 3] == pairs[p].reg_var) f_reg = 1;
                    if (w[ko + 3] == pairs[p].shd_var) f_shd = 1;
                }
            }
            if ((t_shd && f_reg) || (t_reg && f_shd)) {
                uint32_t lhs = (cond < bound) ? ineq_lhs[cond] : 0;
                uint32_t off_id = (lhs < bound) ? bfe_off[lhs] : 0;
                if (off_id < bound && is_const[off_id] && const_val[off_id] < 32) {
                    pairs[p].bit_idx = (int)const_val[off_id];
                }
            }
        }
    }

    for (int p = 0; p < pair_cnt; p++) {
        int use_shadow = (pairs[p].bit_idx >= 0) ? (int)((spec1_val >> pairs[p].bit_idx) & 1U) : 0;
        pairs[p].dead_var = use_shadow ? pairs[p].reg_var : pairs[p].shd_var;
        is_dead_v[pairs[p].dead_var] = 1;
    }

    /* Pass 3: mark dead branch blocks and dead variable declarations */
    for (size_t idx = 0; idx < ninst; idx++) {
        size_t i = inst_off[idx];
        uint32_t op = w[i] & 0xFFFFU;
        if (op == 5 && w[i + 1] < bound && is_dead_v[w[i + 1]]) { /* OpName */
            del_inst[idx] = 1;
        } else if (op == 71 && w[i + 1] < bound && is_dead_v[w[i + 1]]) { /* OpDecorate */
            del_inst[idx] = 1;
        } else if (op == 59 && w[i + 2] < bound && is_dead_v[w[i + 2]]) { /* OpVariable */
            del_inst[idx] = 1;
        } else if (op == 250) { /* OpBranchConditional */
            uint32_t t_lbl = w[i + 2], f_lbl = w[i + 3];
            if (t_lbl >= bound || f_lbl >= bound || !blk_end[t_lbl] || !blk_end[f_lbl]) continue;
            int t_dead = 0, f_dead = 0;
            for (uint32_t k = blk_start[t_lbl]; k < blk_end[t_lbl]; k++) {
                size_t ko = inst_off[k];
                if ((w[ko] & 0xFFFFU) == 61 && w[ko + 3] < bound && is_dead_v[w[ko + 3]]) t_dead = 1;
            }
            for (uint32_t k = blk_start[f_lbl]; k < blk_end[f_lbl]; k++) {
                size_t ko = inst_off[k];
                if ((w[ko] & 0xFFFFU) == 61 && w[ko + 3] < bound && is_dead_v[w[ko + 3]]) f_dead = 1;
            }
            if (t_dead && !f_dead) {
                if (idx > 0 && (w[inst_off[idx - 1]] & 0xFFFFU) == 247) del_inst[idx - 1] = 1;
                rw_branch[idx] = f_lbl;
                is_dead_b[t_lbl] = 1;
                for (uint32_t k = blk_start[t_lbl]; k < blk_end[t_lbl]; k++) del_inst[k] = 1;
            } else if (f_dead && !t_dead) {
                if (idx > 0 && (w[inst_off[idx - 1]] & 0xFFFFU) == 247) del_inst[idx - 1] = 1;
                rw_branch[idx] = t_lbl;
                is_dead_b[f_lbl] = 1;
                for (uint32_t k = blk_start[f_lbl]; k < blk_end[f_lbl]; k++) del_inst[k] = 1;
            }
        }
    }

    /* Pass 4: emit patched SPIR-V */
    uint32_t *out = (uint32_t *)malloc(nw * sizeof(uint32_t));
    if (!out) goto cleanup;
    size_t on = 0;
    for (size_t k = 0; k < 5; k++) out[on++] = w[k];
    for (size_t idx = 0; idx < ninst; idx++) {
        if (del_inst[idx]) continue;
        size_t i = inst_off[idx];
        uint32_t wc = w[i] >> 16, op = w[i] & 0xFFFFU;
        if (rw_branch[idx]) {
            out[on++] = (2U << 16) | 249U; /* OpBranch */
            out[on++] = rw_branch[idx];
        } else if (op == 15) { /* OpEntryPoint: strip dead interface vars if listed */
            size_t start_on = on;
            size_t j = 3;
            while (j < wc) {
                uint32_t wd = w[i + j++];
                if ((wd & 0xFF) == 0 || ((wd >> 8) & 0xFF) == 0 ||
                    ((wd >> 16) & 0xFF) == 0 || ((wd >> 24) & 0xFF) == 0) break;
            }
            for (size_t k = 0; k < j; k++) out[on++] = w[i + k];
            for (size_t k = j; k < wc; k++) {
                uint32_t id = w[i + k];
                if (id < bound && is_dead_v[id]) continue;
                out[on++] = id;
            }
            out[start_on] = ((uint32_t)(on - start_on) << 16) | 15U;
        } else if (op == 245 && wc >= 5) { /* OpPhi: drop incoming edges from deleted blocks */
            size_t start_on = on;
            out[on++] = w[i];
            out[on++] = w[i + 1];
            out[on++] = w[i + 2];
            for (size_t k = 3; k + 1 < wc; k += 2) {
                uint32_t parent = w[i + k + 1];
                if (parent < bound && is_dead_b[parent]) continue;
                out[on++] = w[i + k];
                out[on++] = parent;
            }
            out[start_on] = ((uint32_t)(on - start_on) << 16) | 245U;
        } else {
            memcpy(&out[on], &w[i], wc * sizeof(uint32_t));
            on += wc;
        }
    }
    *out_w = out;
    *out_nw = on;
    ret = 1;

cleanup:
    free(inst_off); free(set_arr); free(bind_arr); free(has_bind);
    free(ptr_ty); free(simg_ty); free(img_depth); free(var_ty);
    free(const_val); free(is_const); free(ineq_lhs); free(bfe_off);
    free(blk_start); free(blk_end); free(is_dead_v); free(is_dead_b);
    free(del_inst); free(rw_branch);
    return ret;
}

static uint32_t read_spec_u32(const VkSpecializationInfo *si, uint32_t id) {
    if (!si || !si->pMapEntries || !si->pData) return 0;
    for (uint32_t i = 0; i < si->mapEntryCount; i++) {
        if (si->pMapEntries[i].constantID == id &&
            si->pMapEntries[i].size >= 4 &&
            si->pMapEntries[i].offset + 4 <= si->dataSize) {
            uint32_t v = 0;
            memcpy(&v, (const uint8_t *)si->pData + si->pMapEntries[i].offset, 4);
            return v;
        }
    }
    return 0;
}

static void sh_vkCreateShaderModule(CPU64 *c, void *ud) {
    PFN_vkCreateShaderModule fn = (PFN_vkCreateShaderModule)ud;
    if (!fn) fn = g_mvk_create_shader_module;
    VkDevice dev = (VkDevice)(uintptr_t)vk_arg(c, 0);
    const VkShaderModuleCreateInfo *ci = (const VkShaderModuleCreateInfo *)(uintptr_t)vk_arg(c, 1);
    VkShaderModule *out = (VkShaderModule *)(uintptr_t)vk_arg(c, 3);
    VkResult r = fn ? fn(dev, ci, NULL, out) : VK_ERROR_INITIALIZATION_FAILED;
    if (r == VK_SUCCESS && ci && out && *out && ci->pCode && ci->codeSize >= 20 &&
        spv_has_aliased_uc_bindings(ci->pCode, ci->codeSize / 4)) {
        size_t nw = ci->codeSize / 4;
        uint32_t *copy = (uint32_t *)malloc(nw * sizeof(uint32_t));
        if (copy) {
            memcpy(copy, ci->pCode, nw * sizeof(uint32_t));
            pthread_mutex_lock(&g_spv_mu);
            if (g_spv_mod_cnt == g_spv_mod_cap) {
                size_t nc = g_spv_mod_cap ? g_spv_mod_cap * 2 : 64;
                SpvModEntry *na = (SpvModEntry *)realloc(g_spv_mods, nc * sizeof(SpvModEntry));
                if (na) { g_spv_mods = na; g_spv_mod_cap = nc; }
            }
            if (g_spv_mod_cnt < g_spv_mod_cap) {
                g_spv_mods[g_spv_mod_cnt++] = (SpvModEntry){ *out, copy, nw };
            } else {
                free(copy);
            }
            pthread_mutex_unlock(&g_spv_mu);
        }
    }
    c->rax = (uint64_t)(uint32_t)r;
}

static void sh_vkDestroyShaderModule(CPU64 *c, void *ud) {
    PFN_vkDestroyShaderModule fn = (PFN_vkDestroyShaderModule)ud;
    if (!fn) fn = g_mvk_destroy_shader_module;
    VkDevice dev = (VkDevice)(uintptr_t)vk_arg(c, 0);
    VkShaderModule mod = (VkShaderModule)(uintptr_t)vk_arg(c, 1);
    if (mod) {
        pthread_mutex_lock(&g_spv_mu);
        for (size_t i = 0; i < g_spv_mod_cnt; i++) {
            if (g_spv_mods[i].mod == mod) {
                free(g_spv_mods[i].words);
                g_spv_mods[i] = g_spv_mods[--g_spv_mod_cnt];
                break;
            }
        }
        pthread_mutex_unlock(&g_spv_mu);
    }
    if (fn) fn(dev, mod, NULL);
}

static int lookup_spv_copy(VkShaderModule mod, uint32_t **out_w, size_t *out_nw) {
    if (!mod) return 0;
    pthread_mutex_lock(&g_spv_mu);
    for (size_t i = 0; i < g_spv_mod_cnt; i++) {
        if (g_spv_mods[i].mod == mod) {
            size_t nw = g_spv_mods[i].nwords;
            uint32_t *cp = (uint32_t *)malloc(nw * sizeof(uint32_t));
            if (cp) {
                memcpy(cp, g_spv_mods[i].words, nw * sizeof(uint32_t));
                *out_w = cp;
                *out_nw = nw;
            }
            pthread_mutex_unlock(&g_spv_mu);
            return cp != NULL;
        }
    }
    pthread_mutex_unlock(&g_spv_mu);
    return 0;
}

static void sh_vkCreateGraphicsPipelines(CPU64 *c, void *ud) {
    PFN_vkCreateGraphicsPipelines fn = (PFN_vkCreateGraphicsPipelines)ud;
    if (!fn) fn = g_mvk_create_graphics_pipelines;
    VkDevice dev = (VkDevice)(uintptr_t)vk_arg(c, 0);
    VkPipelineCache cache = (VkPipelineCache)(uintptr_t)vk_arg(c, 1);
    uint32_t count = (uint32_t)vk_arg(c, 2);
    const VkGraphicsPipelineCreateInfo *cis = (const VkGraphicsPipelineCreateInfo *)(uintptr_t)vk_arg(c, 3);
    VkPipeline *out = (VkPipeline *)(uintptr_t)vk_arg(c, 5);
    if (!fn || !cis || count == 0) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED;
        return;
    }

    VkGraphicsPipelineCreateInfo *mod_cis = NULL;
    VkPipelineShaderStageCreateInfo **stage_copies = NULL;
    VkShaderModule *tmp_mods = NULL;
    size_t tmp_cnt = 0, tmp_cap = 0;
    uint32_t **tmp_spvs = NULL;
    size_t spv_cnt = 0, spv_cap = 0;
    VkShaderModuleCreateInfo **tmp_smcis = NULL;
    size_t smci_cnt = 0, smci_cap = 0;

    for (uint32_t p = 0; p < count; p++) {
        for (uint32_t s = 0; s < cis[p].stageCount; s++) {
            const VkPipelineShaderStageCreateInfo *st = &cis[p].pStages[s];
            uint32_t *orig_w = NULL;
            size_t orig_nw = 0;
            const VkShaderModuleCreateInfo *inline_smci = NULL;

            if (st->module != VK_NULL_HANDLE) {
                lookup_spv_copy(st->module, &orig_w, &orig_nw);
            } else {
                const VkBaseInStructure *pn = (const VkBaseInStructure *)st->pNext;
                while (pn) {
                    if (pn->sType == VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO) {
                        const VkShaderModuleCreateInfo *sm = (const VkShaderModuleCreateInfo *)pn;
                        if (sm->pCode && sm->codeSize >= 20 &&
                            spv_has_aliased_uc_bindings(sm->pCode, sm->codeSize / 4)) {
                            inline_smci = sm;
                        }
                        break;
                    }
                    pn = pn->pNext;
                }
            }
            if (!orig_w && !inline_smci) continue;

            uint32_t spec1 = read_spec_u32(st->pSpecializationInfo, 1);
            uint32_t *patched = NULL;
            size_t patched_nw = 0;
            int ok = spv_dealias_samplers(orig_w ? orig_w : inline_smci->pCode,
                                          orig_w ? orig_nw : (inline_smci->codeSize / 4),
                                          spec1, &patched, &patched_nw);
            free(orig_w);
            if (!ok || !patched) continue;

            if (!mod_cis) {
                mod_cis = (VkGraphicsPipelineCreateInfo *)malloc(count * sizeof(*mod_cis));
                stage_copies = (VkPipelineShaderStageCreateInfo **)calloc(count, sizeof(*stage_copies));
                memcpy(mod_cis, cis, count * sizeof(*mod_cis));
            }
            if (!stage_copies[p]) {
                stage_copies[p] = (VkPipelineShaderStageCreateInfo *)malloc(cis[p].stageCount * sizeof(*stage_copies[p]));
                memcpy(stage_copies[p], cis[p].pStages, cis[p].stageCount * sizeof(*stage_copies[p]));
                mod_cis[p].pStages = stage_copies[p];
            }

            if (inline_smci) {
                if (spv_cnt == spv_cap) {
                    spv_cap = spv_cap ? spv_cap * 2 : 16;
                    tmp_spvs = (uint32_t **)realloc(tmp_spvs, spv_cap * sizeof(*tmp_spvs));
                }
                tmp_spvs[spv_cnt++] = patched;
                /* If inline_smci is head of pNext (always true for DXVK maintenance5), replace directly; else create temp module. */
                if (st->pNext == (const void *)inline_smci) {
                    VkShaderModuleCreateInfo *sm_copy = (VkShaderModuleCreateInfo *)malloc(sizeof(*sm_copy));
                    if (sm_copy) {
                        *sm_copy = *inline_smci;
                        sm_copy->pCode = patched;
                        sm_copy->codeSize = patched_nw * sizeof(uint32_t);
                        stage_copies[p][s].pNext = sm_copy;
                        if (smci_cnt == smci_cap) {
                            smci_cap = smci_cap ? smci_cap * 2 : 16;
                            tmp_smcis = (VkShaderModuleCreateInfo **)realloc(tmp_smcis, smci_cap * sizeof(*tmp_smcis));
                        }
                        tmp_smcis[smci_cnt++] = sm_copy;
                    }
                } else if (g_mvk_create_shader_module) {
                    VkShaderModuleCreateInfo smci = *inline_smci;
                    smci.pNext = NULL;
                    smci.pCode = patched;
                    smci.codeSize = patched_nw * sizeof(uint32_t);
                    VkShaderModule tm = VK_NULL_HANDLE;
                    if (g_mvk_create_shader_module(dev, &smci, NULL, &tm) == VK_SUCCESS && tm) {
                        stage_copies[p][s].module = tm;
                        stage_copies[p][s].pNext = NULL;
                        if (tmp_cnt == tmp_cap) {
                            tmp_cap = tmp_cap ? tmp_cap * 2 : 16;
                            tmp_mods = (VkShaderModule *)realloc(tmp_mods, tmp_cap * sizeof(*tmp_mods));
                        }
                        tmp_mods[tmp_cnt++] = tm;
                    }
                }
            } else if (g_mvk_create_shader_module) {
                VkShaderModuleCreateInfo smci;
                memset(&smci, 0, sizeof(smci));
                smci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
                smci.codeSize = patched_nw * sizeof(uint32_t);
                smci.pCode = patched;
                VkShaderModule tm = VK_NULL_HANDLE;
                if (g_mvk_create_shader_module(dev, &smci, NULL, &tm) == VK_SUCCESS && tm) {
                    stage_copies[p][s].module = tm;
                    if (tmp_cnt == tmp_cap) {
                        tmp_cap = tmp_cap ? tmp_cap * 2 : 16;
                        tmp_mods = (VkShaderModule *)realloc(tmp_mods, tmp_cap * sizeof(*tmp_mods));
                    }
                    tmp_mods[tmp_cnt++] = tm;
                }
                free(patched);
            } else {
                free(patched);
            }
        }
    }

    /* Fixup pointers in case tmp_smcis was reallocated (only needed if >16 inline shaders in one batch). */
    VkResult r = fn(dev, cache, count, mod_cis ? mod_cis : cis, NULL, out);

    if (g_mvk_destroy_shader_module) {
        for (size_t i = 0; i < tmp_cnt; i++) g_mvk_destroy_shader_module(dev, tmp_mods[i], NULL);
    }
    for (size_t i = 0; i < spv_cnt; i++) free(tmp_spvs[i]);
    free(tmp_spvs);
    for (size_t i = 0; i < smci_cnt; i++) free(tmp_smcis[i]);
    free(tmp_smcis);
    free(tmp_mods);
    if (stage_copies) {
        for (uint32_t p = 0; p < count; p++) free(stage_copies[p]);
        free(stage_copies);
    }
    free(mod_cis);
    c->rax = (uint64_t)(uint32_t)r;
}

static uint64_t wrap_vk_proc(const char *name, PFN_vkVoidFunction pfn) {
    if (strcmp(name, "vkGetInstanceProcAddr") == 0)
        return rt_alloc_dynamic_thunk("vkGetInstanceProcAddr", sh_vkGetInstanceProcAddr, NULL);
    if (strcmp(name, "vkGetDeviceProcAddr") == 0)
        return rt_alloc_dynamic_thunk("vkGetDeviceProcAddr", sh_vkGetDeviceProcAddr, NULL);
    if (strcmp(name, "vkCreateInstance") == 0)
        return rt_alloc_dynamic_thunk("vkCreateInstance", sh_vkCreateInstance, NULL);
    if (strcmp(name, "vkCreateDevice") == 0)
        return rt_alloc_dynamic_thunk("vkCreateDevice", sh_vkCreateDevice, NULL);
    if (strcmp(name, "vkEnumerateInstanceExtensionProperties") == 0)
        return rt_alloc_dynamic_thunk("vkEnumerateInstanceExtensionProperties", sh_vkEnumerateInstanceExtensionProperties, NULL);
    if (strcmp(name, "vkCreateWin32SurfaceKHR") == 0)
        return rt_alloc_dynamic_thunk("vkCreateWin32SurfaceKHR", sh_vkCreateWin32SurfaceKHR, NULL);
    if (strcmp(name, "vkGetPhysicalDeviceWin32PresentationSupportKHR") == 0)
        return rt_alloc_dynamic_thunk("vkGetPhysicalDeviceWin32PresentationSupportKHR", sh_vkGetPhysicalDeviceWin32PresentationSupportKHR, NULL);
    if (strcmp(name, "vkCreateShaderModule") == 0 && pfn) {
        g_mvk_create_shader_module = (PFN_vkCreateShaderModule)pfn;
        return rt_alloc_dynamic_thunk("vkCreateShaderModule", sh_vkCreateShaderModule, (void *)pfn);
    }
    if (strcmp(name, "vkDestroyShaderModule") == 0 && pfn) {
        g_mvk_destroy_shader_module = (PFN_vkDestroyShaderModule)pfn;
        return rt_alloc_dynamic_thunk("vkDestroyShaderModule", sh_vkDestroyShaderModule, (void *)pfn);
    }
    if (strcmp(name, "vkCreateGraphicsPipelines") == 0 && pfn) {
        g_mvk_create_graphics_pipelines = (PFN_vkCreateGraphicsPipelines)pfn;
        return rt_alloc_dynamic_thunk("vkCreateGraphicsPipelines", sh_vkCreateGraphicsPipelines, (void *)pfn);
    }
    if (!pfn) return 0;

    RTShimFn tramp = find_vk_tramp(name);
    if (!tramp) {
        fprintf(stderr, "elf64-recomp: WARNING no Vulkan trampoline for '%s'\n", name);
        return 0;
    }
    return rt_alloc_dynamic_thunk(strdup(name), tramp, (void *)pfn);
}

static void sh_vkGetInstanceProcAddr(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk()) { c->rax = 0; return; }
    VkInstance inst = (VkInstance)(uintptr_t)vk_arg(c, 0);
    const char *name = (const char *)(uintptr_t)vk_arg(c, 1);
    if (!name) { c->rax = 0; return; }
    PFN_vkVoidFunction pfn = g_mvk_gipa(inst, name);
    c->rax = wrap_vk_proc(name, pfn);
}

static void sh_vkGetDeviceProcAddr(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk()) { c->rax = 0; return; }
    VkDevice dev = (VkDevice)(uintptr_t)vk_arg(c, 0);
    const char *name = (const char *)(uintptr_t)vk_arg(c, 1);
    if (!name) { c->rax = 0; return; }
    PFN_vkVoidFunction pfn = g_mvk_gdpa(dev, name);
    c->rax = wrap_vk_proc(name, pfn);
}

void rt_register_vulkan64(void) {
    rt_register_shim("vkGetInstanceProcAddr", sh_vkGetInstanceProcAddr, NULL);
    rt_register_shim("vkGetDeviceProcAddr", sh_vkGetDeviceProcAddr, NULL);
    rt_register_shim("vkCreateInstance", sh_vkCreateInstance, NULL);
    rt_register_shim("vkCreateDevice", sh_vkCreateDevice, NULL);
    rt_register_shim("vkEnumerateInstanceExtensionProperties", sh_vkEnumerateInstanceExtensionProperties, NULL);
    rt_register_shim("vkCreateWin32SurfaceKHR", sh_vkCreateWin32SurfaceKHR, NULL);
    rt_register_shim("vkGetPhysicalDeviceWin32PresentationSupportKHR", sh_vkGetPhysicalDeviceWin32PresentationSupportKHR, NULL);

    /* Also register direct MoltenVK exports for binaries linked against libvulkan.so.1. */
    if (ensure_moltenvk()) {
        for (size_t i = 0; i < g_vk_cmd_tramp_count; i++) {
            const char *name = g_vk_cmd_tramps[i].name;
            if (strcmp(name, "vkGetInstanceProcAddr") == 0 ||
                strcmp(name, "vkGetDeviceProcAddr") == 0 ||
                strcmp(name, "vkCreateInstance") == 0 ||
                strcmp(name, "vkCreateDevice") == 0) {
                continue;
            }
            void *sym = dlsym(g_mvk_handle, name);
            if (sym) {
                rt_register_shim(name, g_vk_cmd_tramps[i].tramp, sym);
            }
        }
    }
}
