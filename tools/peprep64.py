#!/usr/bin/env python3
"""PE32+ (Windows x86_64) static loader and relocator.

Loads one or more PE64 binaries (.exe + .dll) into the same unified 64-bit VA
space used by elfprep64.py (0x7000000000+, 16 KiB page aligned), applies
.reloc base relocations, resolves cross-DLL imports/exports (including
ordinals and forwarders), extracts .pdata RUNTIME_FUNCTION roots and TLS
callbacks, patches IATs with host thunks, and emits layout.json + .img files.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

MODULE_BASE_START = 0x7000000000
MODULE_STRIDE = 0x01000000
THUNK_BASE = 0x7070000000
THUNK_STRIDE = 8
DATA_IMPORT_BASE = 0x7080000000

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_DLL = 0x2000
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_EXCEPTION = 3
DIR_BASERELOC = 5
DIR_TLS = 9
DIR_DELAY_IMPORT = 13

REL_BASED_ABSOLUTE = 0
REL_BASED_HIGHLOW = 3
REL_BASED_DIR64 = 10


def align_up(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def read_cstr(buf: bytes | bytearray, off: int) -> str:
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end == -1:
        end = len(buf)
    return bytes(buf[off:end]).decode("utf-8", errors="replace")


@dataclass
class PeSection:
    name: str
    vsize: int
    vaddr: int
    raw_size: int
    raw_ptr: int
    chars: int


@dataclass
class PeModule:
    name: str
    dll_key: str
    path: str
    is_main: bool
    is_dll: bool
    orig_image_base: int
    base: int
    size_of_image: int
    entry_rva: int
    mem: bytearray
    reloc_raw: bytearray
    sections: List[PeSection] = field(default_factory=list)
    data_dirs: List[Tuple[int, int]] = field(default_factory=list)
    exec_ranges: List[Tuple[int, int]] = field(default_factory=list)
    data_ranges: List[Tuple[int, int]] = field(default_factory=list)
    exports: Dict[str, int] = field(default_factory=dict)
    ordinal_exports: Dict[int, int] = field(default_factory=dict)
    forwarders: Dict[str, str] = field(default_factory=dict)
    pdata_funcs: List[int] = field(default_factory=list)
    tls_callbacks: List[int] = field(default_factory=list)
    tls_vaddr: int = 0
    tls_size: int = 0
    tls_index_va: int = 0

    @property
    def entry(self) -> int:
        return (self.base + self.entry_rva) if self.entry_rva else 0

    @property
    def vma_delta(self) -> int:
        return self.base - self.orig_image_base

    def rva_to_raw(self, rva: int) -> Optional[int]:
        for s in self.sections:
            span = max(s.vsize, s.raw_size)
            if s.vaddr <= rva < s.vaddr + span:
                off = rva - s.vaddr
                if off < s.raw_size:
                    return s.raw_ptr + off
                return None
        return None

    def r32(self, rva: int) -> int:
        return struct.unpack_from("<I", self.mem, rva)[0]

    def r64(self, rva: int) -> int:
        return struct.unpack_from("<Q", self.mem, rva)[0]

    def w32(self, rva: int, val: int) -> None:
        struct.pack_into("<I", self.mem, rva, val & 0xFFFFFFFF)

    def w64(self, rva: int, val: int) -> None:
        struct.pack_into("<Q", self.mem, rva, val & 0xFFFFFFFFFFFFFFFF)


def parse_pe64(path: str, base_cursor: int, is_main: bool) -> Tuple[PeModule, int]:
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < 0x100 or raw[:2] != b"MZ":
        raise ValueError(f"{path}: not a PE file (missing MZ)")

    pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise ValueError(f"{path}: missing PE signature")

    machine, num_secs, _ts, _sym, _nsym, opt_sz, chars = struct.unpack_from(
        "<HHIIIHH", raw, pe_off + 4
    )
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ValueError(f"{path}: expected AMD64 (0x8664), got 0x{machine:x}")

    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", raw, opt_off)[0]
    if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        raise ValueError(f"{path}: expected PE32+ (0x20b), got 0x{magic:x}")

    entry_rva = struct.unpack_from("<I", raw, opt_off + 16)[0]
    orig_image_base = struct.unpack_from("<Q", raw, opt_off + 24)[0]
    size_of_image = struct.unpack_from("<I", raw, opt_off + 56)[0]
    size_of_headers = struct.unpack_from("<I", raw, opt_off + 60)[0]
    num_rva = struct.unpack_from("<I", raw, opt_off + 108)[0]

    data_dirs = []
    for i in range(min(num_rva, 16)):
        rva, sz = struct.unpack_from("<II", raw, opt_off + 112 + i * 8)
        data_dirs.append((rva, sz))
    while len(data_dirs) < 16:
        data_dirs.append((0, 0))

    sec_off = opt_off + opt_sz
    sections: List[PeSection] = []
    for i in range(num_secs):
        name_b, vsize, vaddr, raw_sz, raw_ptr, _rp, _lp, _nr, _nl, schars = (
            struct.unpack_from("<8sIIIIIIHHI", raw, sec_off + i * 40)
        )
        sname = name_b.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        sections.append(PeSection(sname, vsize, vaddr, raw_sz, raw_ptr, schars))

    mem_size = align_up(size_of_image, 0x4000)
    base = base_cursor
    next_cursor = align_up(base + mem_size, MODULE_STRIDE)

    mem = bytearray(mem_size)
    hdr_copy = min(size_of_headers, len(raw), mem_size)
    mem[:hdr_copy] = raw[:hdr_copy]
    for s in sections:
        if s.raw_size > 0 and s.vaddr < mem_size:
            n = min(s.raw_size, len(raw) - s.raw_ptr, mem_size - s.vaddr)
            if n > 0:
                mem[s.vaddr : s.vaddr + n] = raw[s.raw_ptr : s.raw_ptr + n]

    mod = PeModule(
        name=os.path.basename(path),
        dll_key=os.path.basename(path).lower(),
        path=os.path.abspath(path),
        is_main=is_main,
        is_dll=bool(chars & IMAGE_FILE_DLL),
        orig_image_base=orig_image_base,
        base=base,
        size_of_image=mem_size,
        entry_rva=entry_rva,
        mem=mem,
        reloc_raw=bytearray(raw),
        sections=sections,
        data_dirs=data_dirs,
    )

    for s in sections:
        span = align_up(max(s.vsize, s.raw_size), 1)
        if span == 0:
            continue
        if s.chars & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE):
            mod.exec_ranges.append((base + s.vaddr, base + s.vaddr + span))
        elif s.name in (".rdata", ".data", ".CRT", ".idata"):
            mod.data_ranges.append((base + s.vaddr, base + s.vaddr + span))

    # Apply base relocations (.reloc) to both mem and reloc_raw (so objdump sees patched immediates).
    reloc_rva, reloc_sz = data_dirs[DIR_BASERELOC]
    delta = mod.vma_delta
    if reloc_rva and reloc_sz and delta != 0:
        pos = reloc_rva
        end = reloc_rva + reloc_sz
        while pos + 8 <= end:
            page_rva, blk_sz = struct.unpack_from("<II", mod.mem, pos)
            if blk_sz < 8:
                break
            count = (blk_sz - 8) // 2
            for i in range(count):
                entry = struct.unpack_from("<H", mod.mem, pos + 8 + i * 2)[0]
                rtype = entry >> 12
                off = entry & 0xFFF
                rva = page_rva + off
                if rtype == REL_BASED_ABSOLUTE:
                    continue
                elif rtype == REL_BASED_DIR64:
                    nv = (mod.r64(rva) + delta) & 0xFFFFFFFFFFFFFFFF
                    mod.w64(rva, nv)
                    if any(lo <= nv < hi for lo, hi in mod.exec_ranges):
                        mod.pdata_funcs.append(nv)
                    raw_off = mod.rva_to_raw(rva)
                    if raw_off is not None and raw_off + 8 <= len(mod.reloc_raw):
                        struct.pack_into("<Q", mod.reloc_raw, raw_off, nv)
                elif rtype == REL_BASED_HIGHLOW:
                    nv = (mod.r32(rva) + delta) & 0xFFFFFFFF
                    mod.w32(rva, nv)
                    raw_off = mod.rva_to_raw(rva)
                    if raw_off is not None and raw_off + 4 <= len(mod.reloc_raw):
                        struct.pack_into("<I", mod.reloc_raw, raw_off, nv)
                else:
                    raise ValueError(f"{mod.name}: unsupported PE reloc type {rtype} at RVA 0x{rva:x}")
            pos += blk_sz

    # Parse .pdata RUNTIME_FUNCTION table (primary function starts; skip UNW_FLAG_CHAININFO
    # continuations so shrink-wrapped MSVC functions & switch tables stay contiguous).
    exc_rva, exc_sz = data_dirs[DIR_EXCEPTION]
    if exc_rva and exc_sz:
        for off in range(exc_rva, exc_rva + exc_sz - 11, 12):
            begin_rva, end_rva, unwind_rva = struct.unpack_from("<III", mod.mem, off)
            if begin_rva and end_rva > begin_rva:
                is_chained = unwind_rva < len(mod.mem) and bool((mod.mem[unwind_rva] >> 3) & 4)
                if not is_chained:
                    mod.pdata_funcs.append(base + begin_rva)

    # Parse Export Directory
    exp_rva, exp_sz = data_dirs[DIR_EXPORT]
    if exp_rva and exp_sz:
        (
            _flags, _ts, _maj, _min, _name_rva, ord_base,
            num_funcs, num_names, addr_funcs_rva, addr_names_rva, addr_ords_rva,
        ) = struct.unpack_from("<IIHHIIIIIII", mod.mem, exp_rva)

        for ord_idx in range(num_funcs):
            fn_rva = mod.r32(addr_funcs_rva + ord_idx * 4)
            if fn_rva == 0:
                continue
            if not (exp_rva <= fn_rva < exp_rva + exp_sz):
                mod.ordinal_exports[ord_base + ord_idx] = base + fn_rva

        for i in range(num_names):
            name_rva = mod.r32(addr_names_rva + i * 4)
            ord_idx = struct.unpack_from("<H", mod.mem, addr_ords_rva + i * 2)[0]
            sname = read_cstr(mod.mem, name_rva)
            if not sname or ord_idx >= num_funcs:
                continue
            fn_rva = mod.r32(addr_funcs_rva + ord_idx * 4)
            if exp_rva <= fn_rva < exp_rva + exp_sz:
                mod.forwarders[sname] = read_cstr(mod.mem, fn_rva)
            else:
                mod.exports[sname] = base + fn_rva

    # Parse TLS Directory (addresses already relocated via .reloc!)
    tls_rva, tls_sz = data_dirs[DIR_TLS]
    if tls_rva and tls_sz >= 32:
        start_va, end_va, idx_va, cb_va = struct.unpack_from("<QQQQ", mod.mem, tls_rva)
        if end_va > start_va:
            mod.tls_vaddr = start_va
            mod.tls_size = end_va - start_va
        mod.tls_index_va = idx_va
        if cb_va and base <= cb_va < base + mem_size:
            cb_rva = cb_va - base
            while cb_rva + 8 <= mem_size:
                fn = mod.r64(cb_rva)
                if fn == 0:
                    break
                mod.tls_callbacks.append(fn)
                cb_rva += 8

    return mod, next_cursor


def prepare_pe_modules(pe_paths: List[str], out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    modules: List[PeModule] = []
    cursor = MODULE_BASE_START
    for i, path in enumerate(pe_paths):
        mod, cursor = parse_pe64(path, cursor, is_main=(i == 0))
        modules.append(mod)

    # Index loaded guest DLLs by lowercase filename (with and without .dll suffix).
    mod_by_dll: Dict[str, PeModule] = {}
    for mod in modules:
        mod_by_dll[mod.dll_key] = mod
        if mod.dll_key.endswith(".dll"):
            mod_by_dll[mod.dll_key[:-4]] = mod

    imports: Dict[str, Tuple[str, str, int]] = {}  # key -> (dll, sym, thunk_addr)
    next_thunk = THUNK_BASE

    def resolve_pe_import(dll_name: str, sym_name: Optional[str], ordinal: Optional[int], depth: int = 0) -> int:
        nonlocal next_thunk
        if depth > 6:
            raise ValueError(f"cyclic PE forwarder for {dll_name}!{sym_name}")
        dll_key = dll_name.lower()
        target_mod = mod_by_dll.get(dll_key) or (mod_by_dll.get(dll_key[:-4]) if dll_key.endswith(".dll") else None)
        if target_mod is not None:
            if sym_name is not None:
                if sym_name in target_mod.exports:
                    return target_mod.exports[sym_name]
                if sym_name in target_mod.forwarders:
                    fwd = target_mod.forwarders[sym_name]
                    if "." in fwd:
                        fdll, fsym = fwd.split(".", 1)
                        if not fdll.lower().endswith(".dll"):
                            fdll += ".dll"
                        if fsym.startswith("#"):
                            return resolve_pe_import(fdll, None, int(fsym[1:]), depth + 1)
                        return resolve_pe_import(fdll, fsym, None, depth + 1)
            elif ordinal is not None and ordinal in target_mod.ordinal_exports:
                return target_mod.ordinal_exports[ordinal]

        name_str = sym_name if sym_name is not None else f"#{ordinal}"
        key = f"{dll_key}!{name_str}"
        if key not in imports:
            imports[key] = (dll_key, name_str, next_thunk)
            next_thunk += THUNK_STRIDE
        return imports[key][2]

    # Patch standard and delay-load IATs, recording guest DLL import dependencies.
    guest_deps: Dict[str, List[str]] = {m.dll_key: [] for m in modules}
    for mod in modules:
        imp_rva, imp_sz = mod.data_dirs[DIR_IMPORT]
        if imp_rva and imp_sz:
            pos = imp_rva
            while pos + 20 <= len(mod.mem):
                ilt_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", mod.mem, pos)
                if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                    break
                dll_name = read_cstr(mod.mem, name_rva)
                dep_key = dll_name.lower()
                if dep_key in mod_by_dll and dep_key not in guest_deps[mod.dll_key]:
                    guest_deps[mod.dll_key].append(mod_by_dll[dep_key].dll_key)
                src_rva = ilt_rva or iat_rva
                idx = 0
                while True:
                    thunk = mod.r64(src_rva + idx * 8)
                    if thunk == 0:
                        break
                    if thunk & (1 << 63):
                        addr = resolve_pe_import(dll_name, None, thunk & 0xFFFF)
                    else:
                        sym_name = read_cstr(mod.mem, (thunk & 0x7FFFFFFF) + 2)
                        addr = resolve_pe_import(dll_name, sym_name, None)
                    mod.w64(iat_rva + idx * 8, addr)
                    idx += 1
                pos += 20

        # Delay-load imports (IMAGE_DELAYLOAD_DESCRIPTOR = 32 bytes)
        dimp_rva, dimp_sz = mod.data_dirs[DIR_DELAY_IMPORT]
        if dimp_rva and dimp_sz:
            pos = dimp_rva
            while pos + 32 <= len(mod.mem):
                attrs, name_rva, _mod_h, iat_rva, int_rva, _biat, _uiat, _ts = (
                    struct.unpack_from("<IIIIIIII", mod.mem, pos)
                )
                if name_rva == 0 and iat_rva == 0:
                    break
                if attrs & 1:  # RVA-based (standard on x64)
                    dll_name = read_cstr(mod.mem, name_rva)
                    idx = 0
                    while True:
                        thunk = mod.r64(int_rva + idx * 8)
                        if thunk == 0:
                            break
                        if thunk & (1 << 63):
                            addr = resolve_pe_import(dll_name, None, thunk & 0xFFFF)
                        else:
                            sym_name = read_cstr(mod.mem, (thunk & 0x7FFFFFFF) + 2)
                            addr = resolve_pe_import(dll_name, sym_name, None)
                        mod.w64(iat_rva + idx * 8, addr)
                        idx += 1
                pos += 32

    all_exec_ranges = [r for m in modules for r in m.exec_ranges]

    def in_exec(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in all_exec_ranges)

    mod_layouts = []
    dll_inits = []
    tls_callbacks_all: List[int] = []
    pe_tls_idx = 0
    for mod in modules:
        # Assign Windows implicit TLS index (_tls_index) and patch AddressOfIndex.
        tls_mod_id = 0
        if mod.tls_size > 0 or mod.tls_index_va:
            tls_mod_id = pe_tls_idx
            if mod.tls_index_va and mod.base <= mod.tls_index_va < mod.base + mod.size_of_image:
                mod.w32(mod.tls_index_va - mod.base, tls_mod_id)
            pe_tls_idx += 1

        img_path = os.path.join(out_dir, f"{mod.name}.img")
        with open(img_path, "wb") as f:
            f.write(mod.mem)
        reloc_pe_path = os.path.join(out_dir, f"{mod.name}.reloc.pe")
        with open(reloc_pe_path, "wb") as f:
            f.write(mod.reloc_raw)

        code_roots: Set[int] = set()
        if mod.entry and in_exec(mod.entry):
            code_roots.add(mod.entry)
        for fn in mod.pdata_funcs:
            if in_exec(fn):
                code_roots.add(fn)
        for fn in mod.exports.values():
            if in_exec(fn):
                code_roots.add(fn)
        for fn in mod.ordinal_exports.values():
            if in_exec(fn):
                code_roots.add(fn)
        for fn in mod.tls_callbacks:
            if in_exec(fn):
                code_roots.add(fn)
                tls_callbacks_all.append(fn)

        # Scan relocated data sections for 8-byte pointers targeting executable sections.
        for lo, hi in mod.data_ranges:
            start_rva = lo - mod.base
            end_rva = hi - mod.base
            for rva in range(start_rva, min(end_rva, len(mod.mem)) - 7, 8):
                ptr = mod.r64(rva)
                if in_exec(ptr):
                    code_roots.add(ptr)

        if mod.is_dll and mod.entry:
            dll_inits.append({"name": mod.name, "entry": mod.entry, "hmodule": mod.base})

        mod_layouts.append({
            "name": mod.name,
            "soname": mod.dll_key,
            "elf_path": os.path.abspath(reloc_pe_path),
            "image_path": os.path.abspath(img_path),
            "is_main": mod.is_main,
            "is_dll": mod.is_dll,
            "base": mod.base,
            "vma_delta": mod.vma_delta,
            "vaddr_min": 0,
            "map_addr": mod.base,
            "mem_size": mod.size_of_image,
            "entry": mod.entry,
            "exec_ranges": [[lo, hi] for lo, hi in mod.exec_ranges],
            "init_array": [],
            "fini_array": [],
            "needed": [],
            "tls": {
                "mod_id": tls_mod_id,
                "vaddr": mod.tls_vaddr,
                "filesz": mod.tls_size,
                "memsz": mod.tls_size,
                "align": 16,
                "tpoff": tls_mod_id,
            },
            "exports": mod.exports,
            "code_roots": sorted(code_roots),
        })

    # Order DLL initializers topologically (imported guest DLLs run DllMain first).
    dll_by_key = {d["name"].lower(): d for d in dll_inits}
    ordered_dll_inits: List[dict] = []
    visited: Set[str] = set()

    def visit_dll(key: str) -> None:
        if key in visited:
            return
        visited.add(key)
        for dep in guest_deps.get(key, []):
            visit_dll(dep)
        if key in dll_by_key:
            ordered_dll_inits.append(dll_by_key[key])

    for m in modules:
        visit_dll(m.dll_key)

    main_mod = mod_layouts[0]
    layout = {
        "arch": "x86_64",
        "format": "pe64",
        "abi": "win64",
        "thunk_base": THUNK_BASE,
        "data_import_base": DATA_IMPORT_BASE,
        "total_tls_size": 0,
        "entry": main_mod["entry"],
        "main_symbol": main_mod["exports"].get("main", 0),
        "init_order": tls_callbacks_all,
        "dll_inits": ordered_dll_inits,
        "modules": mod_layouts,
        "imports": [
            {"name": sym, "dll": dll, "addr": addr}
            for (_k, (dll, sym, addr)) in sorted(imports.items(), key=lambda kv: kv[1][2])
        ],
        "data_imports": [],
        "copy_relocs": [],
        "irelatives": [],
    }

    layout_path = os.path.join(out_dir, "layout.json")
    with open(layout_path, "w") as f:
        json.dump(layout, f, indent=2)
    return layout


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare PE32+ x86_64 binaries for static recompilation.")
    ap.add_argument("-o", "--out-dir", required=True, help="Output directory for images and layout.json")
    ap.add_argument("pes", nargs="+", help="Main PE64 .exe followed by guest .dll modules")
    args = ap.parse_args()

    layout = prepare_pe_modules(args.pes, args.out_dir)
    print(
        f"peprep64: {len(layout['modules'])} module(s), "
        f"{len(layout['imports'])} host import(s), "
        f"entry=0x{layout['entry']:x}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
