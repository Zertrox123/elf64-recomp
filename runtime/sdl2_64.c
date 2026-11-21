#include "runtime64.h"

#include <SDL.h>
#include <SDL_vulkan.h>

static void sh_SDL_Init(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(int64_t)SDL_Init((Uint32)c->rdi);
}
static void sh_SDL_InitSubSystem(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(int64_t)SDL_InitSubSystem((Uint32)c->rdi);
}
static void sh_SDL_Quit(CPU64 *c, void *ud) {
    (void)c; (void)ud;
    SDL_Quit();
}
static void sh_SDL_GetError(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(uintptr_t)SDL_GetError();
}
static void sh_SDL_CreateWindow(CPU64 *c, void *ud) {
    (void)ud;
    SDL_Window *w = SDL_CreateWindow(
        (const char *)(uintptr_t)c->rdi,
        (int)c->rsi, (int)c->rdx, (int)c->rcx, (int)c->r8, (Uint32)c->r9);
    c->rax = (uint64_t)(uintptr_t)w;
}
static void sh_SDL_DestroyWindow(CPU64 *c, void *ud) {
    (void)ud;
    SDL_DestroyWindow((SDL_Window *)(uintptr_t)c->rdi);
}
static void sh_SDL_PollEvent(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)(int64_t)SDL_PollEvent((SDL_Event *)(uintptr_t)c->rdi);
}
static void sh_SDL_GetTicks(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)SDL_GetTicks();
}
static void sh_SDL_GetTicks64(CPU64 *c, void *ud) {
    (void)ud;
    c->rax = (uint64_t)SDL_GetTicks64();
}
static void sh_SDL_Delay(CPU64 *c, void *ud) {
    (void)ud;
    SDL_Delay((Uint32)c->rdi);
}
static void sh_SDL_Vulkan_LoadLibrary(CPU64 *c, void *ud) {
    (void)ud;
    const char *path = (const char *)(uintptr_t)c->rdi;
    /* Override Linux libvulkan.so.1 path with Homebrew MoltenVK on macOS. */
    if (!path || strstr(path, ".so")) path = "/opt/homebrew/lib/libMoltenVK.dylib";
    c->rax = (uint64_t)(int64_t)SDL_Vulkan_LoadLibrary(path);
}
static void sh_SDL_Vulkan_UnloadLibrary(CPU64 *c, void *ud) {
    (void)c; (void)ud;
    SDL_Vulkan_UnloadLibrary();
}
static void sh_SDL_Vulkan_GetVkGetInstanceProcAddr(CPU64 *c, void *ud) {
    (void)ud;
    void *sud = NULL;
    RTShimFn fn = rt_find_shim("vkGetInstanceProcAddr", &sud);
    c->rax = fn ? rt_alloc_dynamic_thunk("vkGetInstanceProcAddr", fn, sud) : 0;
}
static void sh_SDL_Vulkan_GetInstanceExtensions(CPU64 *c, void *ud) {
    (void)ud;
    SDL_bool ok = SDL_Vulkan_GetInstanceExtensions(
        (SDL_Window *)(uintptr_t)c->rdi,
        (unsigned int *)(uintptr_t)c->rsi,
        (const char **)(uintptr_t)c->rdx);
    c->rax = (uint64_t)ok;
}
static void sh_SDL_Vulkan_CreateSurface(CPU64 *c, void *ud) {
    (void)ud;
    SDL_bool ok = SDL_Vulkan_CreateSurface(
        (SDL_Window *)(uintptr_t)c->rdi,
        (VkInstance)(uintptr_t)c->rsi,
        (VkSurfaceKHR *)(uintptr_t)c->rdx);
    c->rax = (uint64_t)ok;
}
static void sh_SDL_Vulkan_GetDrawableSize(CPU64 *c, void *ud) {
    (void)ud;
    SDL_Vulkan_GetDrawableSize(
        (SDL_Window *)(uintptr_t)c->rdi,
        (int *)(uintptr_t)c->rsi,
        (int *)(uintptr_t)c->rdx);
}

void rt_register_sdl2_64(void) {
    #define REG(name, fn) rt_register_shim(name, fn, NULL)
    REG("SDL_Init", sh_SDL_Init);
    REG("SDL_InitSubSystem", sh_SDL_InitSubSystem);
    REG("SDL_Quit", sh_SDL_Quit);
    REG("SDL_GetError", sh_SDL_GetError);
    REG("SDL_CreateWindow", sh_SDL_CreateWindow);
    REG("SDL_DestroyWindow", sh_SDL_DestroyWindow);
    REG("SDL_PollEvent", sh_SDL_PollEvent);
    REG("SDL_GetTicks", sh_SDL_GetTicks);
    REG("SDL_GetTicks64", sh_SDL_GetTicks64);
    REG("SDL_Delay", sh_SDL_Delay);
    REG("SDL_Vulkan_LoadLibrary", sh_SDL_Vulkan_LoadLibrary);
    REG("SDL_Vulkan_UnloadLibrary", sh_SDL_Vulkan_UnloadLibrary);
    REG("SDL_Vulkan_GetVkGetInstanceProcAddr", sh_SDL_Vulkan_GetVkGetInstanceProcAddr);
    REG("SDL_Vulkan_GetInstanceExtensions", sh_SDL_Vulkan_GetInstanceExtensions);
    REG("SDL_Vulkan_CreateSurface", sh_SDL_Vulkan_CreateSurface);
    REG("SDL_Vulkan_GetDrawableSize", sh_SDL_Vulkan_GetDrawableSize);
    #undef REG
}
