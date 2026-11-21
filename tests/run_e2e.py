#!/usr/bin/env python3
"""End-to-end verification: compile real x86_64-linux-gnu ELF64 binaries,
recompile them statically to native ARM64 macOS via build64.py, and run them.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX_DIR = os.path.join(REPO_ROOT, "tests", "fixtures")
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

sys.path.insert(0, TOOLS_DIR)
import build64  # noqa: E402


def find_lld() -> str:
    for cand in ("/opt/homebrew/bin/ld.lld", "ld.lld"):
        if os.path.exists(cand):
            return cand
    return "ld.lld"


def find_lld_link() -> str:
    for cand in ("/opt/homebrew/bin/lld-link", "lld-link"):
        if os.path.exists(cand):
            return cand
    return "lld-link"


def find_dlltool() -> str:
    for cand in ("/opt/homebrew/opt/llvm/bin/llvm-dlltool", "llvm-dlltool"):
        if os.path.exists(cand):
            return cand
    return "llvm-dlltool"


def make_import_lib(tmp: str, dll_name: str, syms: list[str]) -> str:
    def_path = os.path.join(tmp, f"{dll_name}.def")
    lib_path = os.path.join(tmp, f"{dll_name}.lib")
    with open(def_path, "w") as f:
        f.write(f"LIBRARY {dll_name}\nEXPORTS\n")
        for s in syms:
            f.write(f"  {s}\n")
    subprocess.check_call([find_dlltool(), "-m", "i386:x86-64", "-d", def_path, "-l", lib_path])
    return lib_path


def compile_win64_obj(src: str, obj: str) -> None:
    cmd = [
        "clang", "-target", "x86_64-pc-windows-msvc",
        "-O2", "-mno-avx", "-mno-avx2",
        f"-I{FIX_DIR}",
        "-c", src, "-o", obj,
    ]
    subprocess.check_call(cmd)


def compile_x86_64_obj(src: str, obj: str, extra_flags=None) -> None:
    cmd = [
        "clang", "-target", "x86_64-linux-gnu",
        "-O2", "-fPIC", "-fstack-protector-strong",
        "-fno-asynchronous-unwind-tables",
        "-mno-avx", "-mno-avx2",
        f"-I{FIX_DIR}",
        "-c", src, "-o", obj,
    ] + (extra_flags or [])
    subprocess.check_call(cmd)


def test_smoke64(tmp: str) -> None:
    lld = find_lld()
    lib_o = os.path.join(tmp, "libcalc.o")
    lib_so = os.path.join(tmp, "libcalc.so")
    main_o = os.path.join(tmp, "smoke64.o")
    main_elf = os.path.join(tmp, "smoke64")

    compile_x86_64_obj(os.path.join(FIX_DIR, "libcalc.c"), lib_o)
    subprocess.check_call([lld, "-shared", "--allow-shlib-undefined", lib_o, "-o", lib_so])

    compile_x86_64_obj(os.path.join(FIX_DIR, "smoke64.c"), main_o)
    subprocess.check_call([
        lld, "-pie", "--export-dynamic", "--unresolved-symbols=ignore-all",
        "-e", "main", main_o, lib_so, "-o", main_elf,
    ])

    work = os.path.join(tmp, "build_smoke64")
    out_bin = os.path.join(tmp, "smoke64_arm64")
    build64.build_elf64([main_elf, lib_so], work, out_bin, shards=4, strict=True)

    res = subprocess.run([out_bin], capture_output=True, text=True, check=False)
    print(res.stdout, end="")
    if res.stderr:
        print(res.stderr, end="", file=sys.stderr)
    assert res.returncode == 0, f"smoke64 exited with {res.returncode}"
    assert "SMOKE64 PASS" in res.stdout, f"unexpected stdout: {res.stdout!r}"
    assert "dot=6.00 hyp=5.00" in res.stdout, f"FP printf mismatch: {res.stdout!r}"
    assert "threads=6000/2000" in res.stdout, f"thread mismatch: {res.stdout!r}"


def test_vk_smoke64(tmp: str) -> None:
    lld = find_lld()
    vk_o = os.path.join(tmp, "vk_smoke64.o")
    vk_elf = os.path.join(tmp, "vk_smoke64")

    compile_x86_64_obj(
        os.path.join(FIX_DIR, "vk_smoke64.c"),
        vk_o,
        extra_flags=["-I/opt/homebrew/include"],
    )
    subprocess.check_call([
        lld, "-shared", "--allow-shlib-undefined",
        "-e", "main", vk_o, "-o", vk_elf,
    ])

    work = os.path.join(tmp, "build_vk_smoke64")
    out_bin = os.path.join(tmp, "vk_smoke64_arm64")
    build64.build_elf64([vk_elf], work, out_bin, shards=4, strict=True)

    res = subprocess.run([out_bin], capture_output=True, text=True, check=False)
    print(res.stdout, end="")
    if res.stderr:
        print(res.stderr, end="", file=sys.stderr)
    assert res.returncode == 0, f"vk_smoke64 exited with {res.returncode}"
    assert "VK_SMOKE64 PASS" in res.stdout, f"unexpected stdout: {res.stdout!r}"


def test_win_smoke64(tmp: str) -> None:
    lld_link = find_lld_link()
    k32_lib = make_import_lib(tmp, "kernel32.dll", [
        "GetProcessHeap", "HeapAlloc", "HeapFree", "VirtualAlloc", "VirtualFree",
        "QueryPerformanceFrequency", "QueryPerformanceCounter",
        "TlsAlloc", "TlsSetValue", "TlsGetValue", "TlsFree",
        "InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection",
        "CreateThread", "WaitForSingleObject", "CloseHandle",
        "GetModuleHandleA", "GetProcAddress", "ExitProcess",
    ])
    ucrt_lib = make_import_lib(tmp, "ucrtbase.dll", ["printf", "puts", "qsort", "memset"])

    dll_o = os.path.join(tmp, "win_calc.obj")
    dll_p = os.path.join(tmp, "win_calc.dll")
    dll_lib = os.path.join(tmp, "win_calc.lib")
    exe_o = os.path.join(tmp, "win_smoke64.obj")
    exe_p = os.path.join(tmp, "win_smoke64.exe")

    compile_win64_obj(os.path.join(FIX_DIR, "win_calc.c"), dll_o)
    subprocess.check_call([
        lld_link, "/dll", "/entry:DllMain", f"/implib:{dll_lib}", dll_o, f"/out:{dll_p}",
    ])

    compile_win64_obj(os.path.join(FIX_DIR, "win_smoke64.c"), exe_o)
    subprocess.check_call([
        lld_link, "/entry:main", "/subsystem:console",
        exe_o, dll_lib, k32_lib, ucrt_lib, f"/out:{exe_p}",
    ])

    work = os.path.join(tmp, "build_win_smoke64")
    out_bin = os.path.join(tmp, "win_smoke64_arm64")
    build64.build_elf64([exe_p, dll_p], work, out_bin, shards=4, strict=True)

    res = subprocess.run([out_bin], capture_output=True, text=True, check=False)
    print(res.stdout, end="")
    if res.stderr:
        print(res.stderr, end="", file=sys.stderr)
    assert res.returncode == 0, f"win_smoke64 exited with {res.returncode}"
    assert "WIN_SMOKE64 PASS" in res.stdout, f"unexpected stdout: {res.stdout!r}"
    assert "dll=9001 sum6=910 lerp=12.50" in res.stdout, f"mismatch: {res.stdout!r}"
    assert "threads=8000/1600" in res.stdout, f"thread mismatch: {res.stdout!r}"


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    with tempfile.TemporaryDirectory(prefix="elf64_recomp_e2e_") as tmp:
        if which in ("all", "smoke64"):
            test_smoke64(tmp)
        if which in ("all", "vulkan"):
            test_vk_smoke64(tmp)
        if which in ("all", "win64"):
            test_win_smoke64(tmp)
    print("E2E OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
