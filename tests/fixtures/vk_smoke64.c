#include "linux64_min.h"

#define VK_NO_PROTOTYPES
#include <vulkan/vulkan_core.h>

/* Minimal SDL2 Vulkan declarations matching Linux x86_64 SDL2 ABI. */
#define SDL_INIT_VIDEO 0x00000020u
extern int         SDL_Init(uint32_t flags);
extern void        SDL_Quit(void);
extern const char *SDL_GetError(void);
extern int         SDL_Vulkan_LoadLibrary(const char *path);
extern void       *SDL_Vulkan_GetVkGetInstanceProcAddr(void);
extern void        SDL_Vulkan_UnloadLibrary(void);

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        printf("FAIL: SDL_Init: %s\n", SDL_GetError());
        return 1;
    }

    if (SDL_Vulkan_LoadLibrary("libvulkan.so.1") != 0) {
        printf("FAIL: SDL_Vulkan_LoadLibrary: %s\n", SDL_GetError());
        return 1;
    }

    PFN_vkGetInstanceProcAddr gipa =
        (PFN_vkGetInstanceProcAddr)SDL_Vulkan_GetVkGetInstanceProcAddr();
    if (!gipa) {
        printf("FAIL: SDL_Vulkan_GetVkGetInstanceProcAddr returned NULL\n");
        return 2;
    }

    PFN_vkCreateInstance pCreateInstance =
        (PFN_vkCreateInstance)gipa(VK_NULL_HANDLE, "vkCreateInstance");
    if (!pCreateInstance) {
        printf("FAIL: vkCreateInstance lookup\n");
        return 3;
    }

    VkApplicationInfo app;
    memset(&app, 0, sizeof(app));
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "elf64-recomp-vk-smoke";
    app.apiVersion = VK_MAKE_API_VERSION(0, 1, 2, 0);

    VkInstanceCreateInfo ici;
    memset(&ici, 0, sizeof(ici));
    ici.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ici.pApplicationInfo = &app;

    VkInstance inst = VK_NULL_HANDLE;
    VkResult res = pCreateInstance(&ici, NULL, &inst);
    if (res != VK_SUCCESS || !inst) {
        printf("FAIL: vkCreateInstance res=%d\n", (int)res);
        return 4;
    }

    PFN_vkEnumeratePhysicalDevices pEnumPhys =
        (PFN_vkEnumeratePhysicalDevices)gipa(inst, "vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceProperties pGetProps =
        (PFN_vkGetPhysicalDeviceProperties)gipa(inst, "vkGetPhysicalDeviceProperties");
    PFN_vkGetPhysicalDeviceMemoryProperties pGetMemProps =
        (PFN_vkGetPhysicalDeviceMemoryProperties)gipa(inst, "vkGetPhysicalDeviceMemoryProperties");
    PFN_vkCreateDevice pCreateDevice =
        (PFN_vkCreateDevice)gipa(inst, "vkCreateDevice");
    PFN_vkGetDeviceProcAddr pGdpa =
        (PFN_vkGetDeviceProcAddr)gipa(inst, "vkGetDeviceProcAddr");
    PFN_vkDestroyInstance pDestroyInstance =
        (PFN_vkDestroyInstance)gipa(inst, "vkDestroyInstance");

    uint32_t count = 0;
    res = pEnumPhys(inst, &count, NULL);
    if (res != VK_SUCCESS || count == 0) {
        printf("FAIL: vkEnumeratePhysicalDevices res=%d count=%u\n", (int)res, count);
        return 5;
    }

    VkPhysicalDevice phys[8];
    if (count > 8) count = 8;
    res = pEnumPhys(inst, &count, phys);
    if (res != VK_SUCCESS) {
        printf("FAIL: vkEnumeratePhysicalDevices(fill) res=%d\n", (int)res);
        return 6;
    }

    VkPhysicalDeviceProperties props;
    memset(&props, 0, sizeof(props));
    pGetProps(phys[0], &props);

    /* Create VkDevice on queue family 0 */
    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci;
    memset(&qci, 0, sizeof(qci));
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = 0;
    qci.queueCount = 1;
    qci.pQueuePriorities = &prio;

    VkDeviceCreateInfo dci;
    memset(&dci, 0, sizeof(dci));
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;

    VkDevice dev = VK_NULL_HANDLE;
    res = pCreateDevice(phys[0], &dci, NULL, &dev);
    if (res != VK_SUCCESS || !dev) {
        printf("FAIL: vkCreateDevice res=%d\n", (int)res);
        return 7;
    }

    PFN_vkCreateBuffer pCreateBuf = (PFN_vkCreateBuffer)pGdpa(dev, "vkCreateBuffer");
    PFN_vkGetBufferMemoryRequirements pGetBufReq = (PFN_vkGetBufferMemoryRequirements)pGdpa(dev, "vkGetBufferMemoryRequirements");
    PFN_vkAllocateMemory pAllocMem = (PFN_vkAllocateMemory)pGdpa(dev, "vkAllocateMemory");
    PFN_vkBindBufferMemory pBindBuf = (PFN_vkBindBufferMemory)pGdpa(dev, "vkBindBufferMemory");
    PFN_vkMapMemory pMapMem = (PFN_vkMapMemory)pGdpa(dev, "vkMapMemory");
    PFN_vkUnmapMemory pUnmapMem = (PFN_vkUnmapMemory)pGdpa(dev, "vkUnmapMemory");
    PFN_vkDestroyBuffer pDestroyBuf = (PFN_vkDestroyBuffer)pGdpa(dev, "vkDestroyBuffer");
    PFN_vkFreeMemory pFreeMem = (PFN_vkFreeMemory)pGdpa(dev, "vkFreeMemory");
    PFN_vkDestroyDevice pDestroyDev = (PFN_vkDestroyDevice)pGdpa(dev, "vkDestroyDevice");

    VkBufferCreateInfo bci;
    memset(&bci, 0, sizeof(bci));
    bci.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bci.size = 4096;
    bci.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer buf = VK_NULL_HANDLE;
    res = pCreateBuf(dev, &bci, NULL, &buf);
    if (res != VK_SUCCESS || !buf) {
        printf("FAIL: vkCreateBuffer res=%d\n", (int)res);
        return 8;
    }

    VkMemoryRequirements req;
    memset(&req, 0, sizeof(req));
    pGetBufReq(dev, buf, &req);

    VkPhysicalDeviceMemoryProperties mprops;
    memset(&mprops, 0, sizeof(mprops));
    pGetMemProps(phys[0], &mprops);

    uint32_t mem_idx = 0xFFFFFFFFu;
    uint32_t want = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    for (uint32_t i = 0; i < mprops.memoryTypeCount; i++) {
        if ((req.memoryTypeBits & (1u << i)) &&
            (mprops.memoryTypes[i].propertyFlags & want) == want) {
            mem_idx = i;
            break;
        }
    }
    if (mem_idx == 0xFFFFFFFFu) {
        printf("FAIL: no host-visible memory type\n");
        return 9;
    }

    VkMemoryAllocateInfo mai;
    memset(&mai, 0, sizeof(mai));
    mai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    mai.allocationSize = req.size;
    mai.memoryTypeIndex = mem_idx;

    VkDeviceMemory mem = VK_NULL_HANDLE;
    res = pAllocMem(dev, &mai, NULL, &mem);
    if (res != VK_SUCCESS || !mem) {
        printf("FAIL: vkAllocateMemory res=%d\n", (int)res);
        return 10;
    }

    res = pBindBuf(dev, buf, mem, 0);
    if (res != VK_SUCCESS) {
        printf("FAIL: vkBindBufferMemory res=%d\n", (int)res);
        return 11;
    }

    void *mapped = NULL;
    res = pMapMem(dev, mem, 0, 4096, 0, &mapped);
    if (res != VK_SUCCESS || !mapped) {
        printf("FAIL: vkMapMemory res=%d\n", (int)res);
        return 12;
    }
    uint32_t *u32 = (uint32_t *)mapped;
    u32[0] = 0xCAFEBABEu;
    u32[1] = 0x12345678u;
    uint32_t readback = u32[0] ^ u32[1];
    pUnmapMem(dev, mem);

    pDestroyBuf(dev, buf, NULL);
    pFreeMem(dev, mem, NULL);
    pDestroyDev(dev, NULL);
    pDestroyInstance(inst, NULL);
    SDL_Vulkan_UnloadLibrary();
    SDL_Quit();

    if (readback != (0xCAFEBABEu ^ 0x12345678u)) {
        printf("FAIL: readback=0x%x\n", readback);
        return 13;
    }

    printf("VK_SMOKE64 PASS gpu='%s' api=%u.%u.%u readback=0x%x\n",
           props.deviceName,
           VK_API_VERSION_MAJOR(props.apiVersion),
           VK_API_VERSION_MINOR(props.apiVersion),
           VK_API_VERSION_PATCH(props.apiVersion),
           readback);
    return 0;
}
