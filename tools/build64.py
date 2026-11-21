#!/usr/bin/env python3
"""End-to-end build pipeline: ELF64 x86_64 binaries -> native ARM64 macOS executable.

Steps:
1. Run elfprep64.py to relocate modules and generate layout.json + .img files.
2. Run lift64.py to disassemble and lift all modules into sharded C files + manifest.
3. Ensure runtime/vulkan64_gen.inc is generated from Khronos vk.xml.
4. Compile lifted shards + runtime sources in parallel with clang (content-hash cached).
5. Link into a native Apple Silicon ARM64 Mach-O binary.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shlex
import subprocess
import sys
from typing import List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME_DIR = os.path.join(REPO_ROOT, "runtime")
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

sys.path.insert(0, TOOLS_DIR)
import elfprep64  # noqa: E402
import gen_vulkan64  # noqa: E402
import lift64  # noqa: E402
import peprep64  # noqa: E402


def is_pe_file(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(2) == b"MZ"


def pkg_config_flags(pkg: str, mode: str) -> List[str]:
    try:
        out = subprocess.check_output(["pkg-config", mode, pkg], text=True).strip()
        return shlex.split(out)
    except Exception:
        return []


def compile_one(src: str, obj_dir: str, cflags: List[str]) -> str:
    h = hashlib.sha256()
    h.update(" ".join(cflags).encode())
    h.update(open(src, "rb").read())
    # Hash runtime headers so header edits invalidate cached objects.
    for hdr in ("cpu64.h", "runtime64.h", "win64_abi.h", "dxbc_msl.h", "vulkan64_gen.inc"):
        hp = os.path.join(RUNTIME_DIR, hdr)
        if os.path.exists(hp):
            h.update(open(hp, "rb").read())
    digest = h.hexdigest()[:16]
    base = os.path.splitext(os.path.basename(src))[0]
    obj = os.path.join(obj_dir, f"{base}_{digest}.o")
    if os.path.exists(obj):
        return obj
    per_file = ["-fobjc-arc"] if src.endswith(".m") else []
    cmd = ["clang", "-c", src, "-o", obj] + cflags + per_file
    subprocess.check_call(cmd)
    return obj


def build_elf64(
    elf_paths: List[str],
    work_dir: str,
    out_bin: str,
    shards: int = 8,
    jobs: int = 0,
    opt: str = "-O2",
    strict: bool = False,
    relink: bool = False,
) -> str:
    os.makedirs(work_dir, exist_ok=True)
    prep_dir = os.path.join(work_dir, "prep")
    lift_dir = os.path.join(work_dir, "lifted")
    obj_dir = os.path.join(work_dir, "obj")
    os.makedirs(obj_dir, exist_ok=True)

    vk_inc = os.path.join(RUNTIME_DIR, "vulkan64_gen.inc")
    if not os.path.exists(vk_inc):
        gen_vulkan64.generate(gen_vulkan64.DEFAULT_VK_XML, vk_inc)

    shards_meta = os.path.join(lift_dir, "shards.json")
    if relink and os.path.exists(shards_meta):
        with open(shards_meta) as f:
            lifted = json.load(f)
    else:
        if is_pe_file(elf_paths[0]):
            peprep64.prepare_pe_modules(elf_paths, prep_dir)
        else:
            elfprep64.prepare_modules(elf_paths, prep_dir)
        layout_path = os.path.join(prep_dir, "layout.json")
        lifted = lift64.lift_layout(layout_path, lift_dir, shards=shards, strict=strict)
        with open(shards_meta, "w") as f:
            json.dump({"manifest": lifted["manifest"], "shards": lifted["shards"]}, f)

    sdl_cflags = pkg_config_flags("sdl2", "--cflags")
    sdl_libs = pkg_config_flags("sdl2", "--libs")
    if not sdl_cflags:
        sdl_cflags = ["-I/opt/homebrew/include", "-I/opt/homebrew/include/SDL2"]
    if not sdl_libs:
        sdl_libs = ["-L/opt/homebrew/lib", "-lSDL2", "-Wl,-framework,Cocoa"]

    extra_cflags = shlex.split(os.environ.get("CFLAGS", ""))
    extra_ldflags = shlex.split(os.environ.get("LDFLAGS", ""))

    cflags = [
        opt, "-std=gnu11", "-Wall", "-Wextra",
        "-Wno-unused-label", "-Wno-unused-parameter", "-Wno-unused-variable", "-Wno-parentheses-equality",
        f"-I{RUNTIME_DIR}",
        "-I/opt/homebrew/include",
    ] + sdl_cflags + extra_cflags

    rt_sources = [
        os.path.join(RUNTIME_DIR, name)
        for name in (
            "runtime64.c", "libc64.c", "sdl2_64.c", "vulkan64.c",
            "win32_64.c", "win32_crt_extra.c", "dxbc_msl.c", "d3d11_metal.m", "main64.c",
        )
    ]
    all_sources = rt_sources + [lifted["manifest"]] + lifted["shards"]

    workers = jobs or max(1, os.cpu_count() or 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(compile_one, src, obj_dir, cflags) for src in all_sources]
        objs = [f.result() for f in futs]

    os.makedirs(os.path.dirname(os.path.abspath(out_bin)), exist_ok=True)
    link_cmd = (
        ["clang", "-o", out_bin] + objs + sdl_libs + [
            "-framework", "Metal", "-framework", "QuartzCore", "-framework", "Foundation",
            "-lm", "-lpthread", "-ldl",
        ] + extra_ldflags
    )
    subprocess.check_call(link_cmd)
    return os.path.abspath(out_bin)


def main() -> int:
    ap = argparse.ArgumentParser(description="Static recompiler: ELF64 x86_64 -> native ARM64 macOS.")
    ap.add_argument("-w", "--work-dir", required=True, help="Build working directory")
    ap.add_argument("-o", "--output", required=True, help="Output native ARM64 executable")
    ap.add_argument("-j", "--jobs", type=int, default=0, help="Parallel clang jobs")
    ap.add_argument("--shards", type=int, default=8, help="Lifted C shard count")
    ap.add_argument("--opt", default="-O2", help="Clang optimization level (default: -O2)")
    ap.add_argument("--strict", action="store_true", help="Fail on any unimplemented x86_64 instruction")
    ap.add_argument("--relink", action="store_true", help="Skip prep/lift and recompile/relink runtime only")
    ap.add_argument("elfs", nargs="*", help="Main ELF64/PE64 binary followed by shared libraries")
    args = ap.parse_args()
    if not args.relink and not args.elfs:
        ap.error("elfs required unless --relink is set")

    out = build_elf64(
        args.elfs, args.work_dir, args.output,
        shards=args.shards, jobs=args.jobs, opt=args.opt, strict=args.strict,
        relink=args.relink,
    )
    print(f"build64: built native ARM64 binary -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
