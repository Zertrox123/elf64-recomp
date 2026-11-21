# elf64-recomp

Static x86_64 ELF64 (Linux System V AMD64) -> C -> ARM64 macOS recompiler with a native Vulkan (MoltenVK) + SDL2 bridge.

## Architecture

1. **`tools/elfprep64.py`** — Loads one or more ELF64 x86_64 modules (`ET_DYN` PIE executables & `.so` libraries) into a unified 64-bit virtual address space above macOS ARM64's GPU carveout (`0x7000000000+`), aligns images to 16 KiB ARM64 pages, applies `DT_RELA` / `DT_JMPREL` / Variant II TLS (`TPOFF64`, `DTPMOD64`, `DTPOFF64`) / `COPY` / `IRELATIVE` relocations, resolves multi-module `ld.so` exports, allocates external import thunks (`0x7070000000+`), and writes relocated `.img` files + `layout.json`.
2. **`tools/lift64.py`** — Disassembles prepared ELF64 binaries via `objdump -d -M intel --adjust-vma=...`, splits functions into sharded C units, and lifts x86_64 instructions (8/16/32/64-bit GPRs with mandatory 32->64 zero-extension, RIP-relative addressing, `fs:` TLS & stack canary, intra-function switch tables, `lock` atomics, `rep` string ops, 128-bit `imul`/`idiv`, and SSE/SSE2/SSE4.1) into portable C.
3. **`tools/gen_vulkan64.py` + `runtime/vulkan64.c`** — Parses Khronos `vk.xml` to generate System V AMD64 -> Darwin ARM64 trampolines for 865+ Vulkan commands (exact for Darwin ARM64's packed stack-argument ABI). Because both Linux x86_64 and macOS ARM64 are LP64 little-endian and `elf64-recomp` uses a unified 64-bit address space, Vulkan structs and handles pass directly to `libMoltenVK.dylib`.
4. **`runtime/`** — `cpu64.h`, `runtime64.c` (exact-VA `mmap` loader, O(1) dispatch table, `rt_invoke64` host->guest callbacks, Variant II TLS + `%fs:0x28` stack canary), `libc64.c` (System V variadic `printf`, Linux 144-byte `struct stat`, Linux-sized `pthread_mutex_t`/`pthread_cond_t` side-table, `qsort`, `dlopen`/`dlsym`, `libgcc` 128-bit helpers), and `sdl2_64.c` (native SDL2 + `SDL_Vulkan_*`).
5. **`tools/build64.py`** — Orchestrates `elfprep64` -> `lift64` -> content-hash cached parallel `clang` -> native ARM64 Mach-O binary.

## Requirements (macOS Apple Silicon)

```sh
brew install sdl2 molten-vk vulkan-headers lld
```

## Quick Verification

```sh
make check
# Or with UndefinedBehaviorSanitizer:
CFLAGS="-fsanitize=undefined -fno-sanitize-recover=all" LDFLAGS="-fsanitize=undefined" make check
```

## Roadmap toward Portal: Revolution & 64-bit Source Games

- **Phase 1 (done):** Core ELF64 loader/relocator, x86_64 -> C static lifter, System V AMD64 runtime, SDL2 + full MoltenVK bridge (verified end-to-end on compiled `x86_64-linux-gnu` multi-module + Vulkan binaries).
- **Phase 2 (next):** Bring up a real 64-bit Linux Source/Strata module graph (`launcher.so`, `tier0.so`, `vstdlib.so`, `engine.so`, `shaderapivk.so` / DXVK-native): expand glibc/C++ ABI shims (`libstdc++` / `cxa_throw` / `futex` / `epoll` / sockets / FreeType / OpenAL / 64-bit Steamworks), add AVX/FMA lifting if present, and add DXVK/MoltenVK swapchain + presentation shims.
- **Note on Portal: Revolution (`601360`):** Since August 2025, Portal: Revolution's public Steam branch ships Windows x64 (`bin\win64\revolution.exe`, DX11) and dropped the native Linux depot (`601362`) from active `appinfo.vdf`. Two paths forward share the same `lift64.py` core:
  1. Target a Linux x86_64 64-bit Source game first (e.g., Team Fortress 2 64-bit, CS:S 64-bit, or historical Portal: Revolution Linux depot `601362` if available via Steam console `download_depot`).
  2. Add a PE64/Win64 frontend (`peprep64.py` + Win64 ABI + DX11 -> DXMT/Metal bridge) reusing `lift64.py` for the current Windows 64-bit Portal: Revolution build.
