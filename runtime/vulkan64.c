#include "runtime64.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>

#include "vulkan64_gen.inc"

static void *g_mvk_handle = NULL;
static PFN_vkGetInstanceProcAddr g_mvk_gipa = NULL;
static PFN_vkGetDeviceProcAddr   g_mvk_gdpa = NULL;
static PFN_vkCreateInstance      g_mvk_create_instance = NULL;
static PFN_vkCreateDevice        g_mvk_create_device = NULL;

static int ensure_moltenvk(void) {
    if (g_mvk_gipa) return 1;
    const char *paths[] = {
        "/opt/homebrew/lib/libMoltenVK.dylib",
        "/usr/local/lib/libMoltenVK.dylib",
        "libMoltenVK.dylib",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        g_mvk_handle = dlopen(paths[i], RTLD_LAZY | RTLD_LOCAL);
        if (g_mvk_handle) break;
    }
    if (!g_mvk_handle) {
        fprintf(stderr, "elf64-recomp: failed to dlopen libMoltenVK.dylib: %s\n", dlerror());
        return 0;
    }
    g_mvk_gipa = (PFN_vkGetInstanceProcAddr)dlsym(g_mvk_handle, "vkGetInstanceProcAddr");
    g_mvk_gdpa = (PFN_vkGetDeviceProcAddr)dlsym(g_mvk_handle, "vkGetDeviceProcAddr");
    g_mvk_create_instance = (PFN_vkCreateInstance)dlsym(g_mvk_handle, "vkCreateInstance");
    g_mvk_create_device = (PFN_vkCreateDevice)dlsym(g_mvk_handle, "vkCreateDevice");
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

static void sh_vkCreateInstance(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk() || !g_mvk_create_instance) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED;
        return;
    }
    const VkInstanceCreateInfo *ci = (const VkInstanceCreateInfo *)(uintptr_t)c->rdi;
    /* shortcut: pass NULL for guest VkAllocationCallbacks because callback ptrs are guest x86_64 code; wrap via rt_invoke64 if a game requires custom allocators. */
    VkInstance *out = (VkInstance *)(uintptr_t)c->rdx;
    VkResult r = g_mvk_create_instance(ci, NULL, out);
    c->rax = (uint64_t)(uint32_t)r;
}

static void sh_vkCreateDevice(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk() || !g_mvk_create_device) {
        c->rax = (uint64_t)(uint32_t)VK_ERROR_INITIALIZATION_FAILED;
        return;
    }
    VkPhysicalDevice phys = (VkPhysicalDevice)(uintptr_t)c->rdi;
    const VkDeviceCreateInfo *ci = (const VkDeviceCreateInfo *)(uintptr_t)c->rsi;
    VkDevice *out = (VkDevice *)(uintptr_t)c->rcx;
    /* shortcut: ignore guest VkAllocationCallbacks ptr (see sh_vkCreateInstance). */
    VkResult r = g_mvk_create_device(phys, ci, NULL, out);
    c->rax = (uint64_t)(uint32_t)r;
}

static uint64_t wrap_vk_proc(const char *name, PFN_vkVoidFunction pfn) {
    if (!pfn) return 0;
    if (strcmp(name, "vkGetInstanceProcAddr") == 0)
        return rt_alloc_dynamic_thunk("vkGetInstanceProcAddr", sh_vkGetInstanceProcAddr, NULL);
    if (strcmp(name, "vkGetDeviceProcAddr") == 0)
        return rt_alloc_dynamic_thunk("vkGetDeviceProcAddr", sh_vkGetDeviceProcAddr, NULL);
    if (strcmp(name, "vkCreateInstance") == 0)
        return rt_alloc_dynamic_thunk("vkCreateInstance", sh_vkCreateInstance, NULL);
    if (strcmp(name, "vkCreateDevice") == 0)
        return rt_alloc_dynamic_thunk("vkCreateDevice", sh_vkCreateDevice, NULL);

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
    VkInstance inst = (VkInstance)(uintptr_t)c->rdi;
    const char *name = (const char *)(uintptr_t)c->rsi;
    if (!name) { c->rax = 0; return; }
    PFN_vkVoidFunction pfn = g_mvk_gipa(inst, name);
    c->rax = wrap_vk_proc(name, pfn);
}

static void sh_vkGetDeviceProcAddr(CPU64 *c, void *ud) {
    (void)ud;
    if (!ensure_moltenvk()) { c->rax = 0; return; }
    VkDevice dev = (VkDevice)(uintptr_t)c->rdi;
    const char *name = (const char *)(uintptr_t)c->rsi;
    if (!name) { c->rax = 0; return; }
    PFN_vkVoidFunction pfn = g_mvk_gdpa(dev, name);
    c->rax = wrap_vk_proc(name, pfn);
}

void rt_register_vulkan64(void) {
    rt_register_shim("vkGetInstanceProcAddr", sh_vkGetInstanceProcAddr, NULL);
    rt_register_shim("vkGetDeviceProcAddr", sh_vkGetDeviceProcAddr, NULL);
    rt_register_shim("vkCreateInstance", sh_vkCreateInstance, NULL);
    rt_register_shim("vkCreateDevice", sh_vkCreateDevice, NULL);

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
