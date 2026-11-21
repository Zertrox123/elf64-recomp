# elf64-recomp

Static **x86_64 -> C -> ARM64 macOS** recompiler supporting both:
- **Linux ELF64 (System V AMD64)** + **SDL2** + **Vulkan -> MoltenVK**
- **Windows PE32+ (Win64 ABI)** + **Win32/UCRT/User32** + **Direct3D 11 & DXGI -> Apple Metal** (with live DXBC SM4/SM5 -> MSL shader translation)

## Architecture

1. **Frontends (`tools/elfprep64.py`, `tools/peprep64.py`)**
   - Unified 64-bit virtual address space above macOS ARM64's GPU carveout (`0x7000000000+`, 16 KiB aligned, 16 MiB module stride) so guest pointers equal native ARM64 pointers.
   - `elfprep64.py`: `ET_DYN`/`ET_EXEC`, `DT_RELA`/`DT_JMPREL`, Variant II TLS (`TPOFF64`/`DTPMOD64`/`DTPOFF64`), `COPY`, `IRELATIVE`, multi-`.so` `ld.so` lookup, `init_array`/`fini_array`.
   - `peprep64.py`: PE32+ `.exe`/`.dll`, `.reloc` (`DIR64`/`HIGHLOW`), cross-DLL imports/exports (including ordinals, forwarders, delay-load IATs), `.pdata` `RUNTIME_FUNCTION` roots, PE TLS callbacks, `DllMain`.
2. **Shared x86_64 -> C Static Lifter (`tools/lift64.py`, `tools/build64.py`)**
   - Disassembles via `objdump -d -M intel`, discovers `call` + RIP-relative `lea` leaf callbacks + `.pdata`/symbol/`data_ptrs` roots, shards across N C files compiled in parallel with SHA-256 object caching.
   - Lifts 8/16/32/64-bit GPRs (with mandatory 32->64 zero-extension), `[rip + disp]`, `fs:`/`gs:` TLS/canary/TEB, PIC switch tables, `lock` atomics, `rep` string ops, 128-bit `imul`/`idiv`, and SSE/SSE2/SSE4.1.
3. **Runtime & Graphics Bridges (`runtime/`)**
   - Core: `cpu64.h`, `runtime64.c` (exact-VA `mmap`, O(1) dispatch, `rt_invoke64` + `rt_invoke_win64`, TLS + `%fs:0x28` canary + `%gs:0x30` Windows TEB/PEB).
   - Linux/Vulkan: `libc64.c`, `sdl2_64.c`, `tools/gen_vulkan64.py` + `vulkan64.c` (865+ Vulkan commands from Khronos `vk.xml` -> `libMoltenVK.dylib`).
   - Windows/Direct3D 11: `win64_abi.h`, `win32_64.c` (`kernel32`/`ucrtbase`/`user32` -> SDL2), `dxbc_msl.c` (DXBC SM4/SM5 -> MSL translator), `d3d11_metal.m` (Windows x64 COM vtables for `IDXGIFactory`/`IDXGIAdapter`/`IDXGISwapChain`/`ID3D11Device`/`ID3D11DeviceContext` -> native Apple Metal).

## Requirements (macOS Apple Silicon)

```sh
brew install sdl2 molten-vk vulkan-headers lld
```

## Verification

```sh
make check
# Or with UndefinedBehaviorSanitizer:
CFLAGS="-fsanitize=undefined -fno-sanitize-recover=all" LDFLAGS="-fsanitize=undefined" make check
```

`make check` compiles and executes four real x86_64 end-to-end test suites (plus 9 unit tests):
- `test-smoke`: Linux ELF64 PIE + `libcalc.so` (128-bit math, switch table, SSE2, stack canary, `qsort` callback, Linux 144-byte `stat`, 4 pthreads + `lock inc`).
- `test-vulkan`: Linux ELF64 -> SDL2 -> MoltenVK on Apple Silicon GPU.
- `test-win64`: Windows PE32+ `.exe` + `.dll` (`DllMain`, 6-arg Win64 shadow space, `gs:[0x30]` TEB, `HeapAlloc`, `VirtualAlloc`, `QPC`, `GetProcAddress`, `qsort`, 4 Win32 `CreateThread` + `CRITICAL_SECTION` + `TlsAlloc`).
- `test-d3d11`: Windows PE32+ Direct3D 11 + DXGI -> Apple Metal GPU (DXBC SM4.0 shaders -> MSL, clear + triangle `Draw` + staging `CopyResource`/`Map` pixel readback).
