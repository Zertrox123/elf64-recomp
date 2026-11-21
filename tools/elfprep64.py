#!/usr/bin/env python3
"""ELF64 (x86_64 / System V AMD64) static loader and relocator.

Loads one or more ELF64 binaries (ET_DYN PIE executable + shared libraries) into
a unified 64-bit virtual address space above macOS ARM64's GPU carveout
(0x7000000000+), applies DT_RELA / DT_JMPREL / TLS relocations, allocates thunk
addresses for external host imports, and emits per-module relocated memory
images + layout.json for lift64.py and runtime64.c.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# macOS ARM64 reserves 0x1000000000..0x6fffffffff for the GPU carveout.
# 0x7000000000+ is clean, unmapped, and exact-hint mappable without MAP_FIXED.
MODULE_BASE_START = 0x7000000000
MODULE_STRIDE = 0x01000000      # 16 MiB alignment between modules
THUNK_BASE = 0x7070000000       # Within +2 GiB of MODULE_BASE_START (PC32 safe)
THUNK_STRIDE = 8
DATA_IMPORT_BASE = 0x7080000000 # Synthetic slots for stdin/stdout/stderr/environ

# ELF64 constants
EI_CLASS, ELFCLASS64 = 4, 2
EI_DATA, ELFDATA2LSB = 5, 1
EM_X86_64 = 62
ET_EXEC, ET_DYN = 2, 3

PT_LOAD = 1
PT_DYNAMIC = 2
PT_TLS = 7

PF_X = 1

SHT_SYMTAB = 2
SHT_RELA = 4
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15

SHF_EXECINSTR = 0x4

STB_LOCAL, STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE = 0, 1, 2, 10
STT_OBJECT, STT_FUNC, STT_TLS, STT_GNU_IFUNC = 1, 2, 6, 10
SHN_UNDEF = 0

DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_PLTREL = 20
DT_JMPREL = 23
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28

# x86_64 relocation types
R_X86_64_NONE = 0
R_X86_64_64 = 1
R_X86_64_PC32 = 2
R_X86_64_PLT32 = 4
R_X86_64_COPY = 5
R_X86_64_GLOB_DAT = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE = 8
R_X86_64_DTPMOD64 = 16
R_X86_64_DTPOFF64 = 17
R_X86_64_TPOFF64 = 18
R_X86_64_IRELATIVE = 37

KNOWN_DATA_IMPORTS = {
    "stdin", "stdout", "stderr", "environ", "__environ", "_environ",
    "optarg", "optind", "opterr", "optopt", "__progname", "__progname_full",
}


def align_up(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def align_down(v: int, a: int) -> int:
    return v & ~(a - 1)


def read_cstr(blob: bytes, off: int) -> str:
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end == -1:
        end = len(blob)
    return blob[off:end].decode("utf-8", errors="replace")


@dataclass
class ElfSym:
    name: str
    bind: int
    stype: int
    shndx: int
    value: int
    size: int


@dataclass
class ElfModule:
    name: str
    path: str
    is_main: bool
    e_type: int
    e_entry: int
    base: int
    vaddr_min: int
    vaddr_max: int
    mem: bytearray
    raw: bytes
    load_segs: List[Tuple[int, int, int, int, int]] = field(default_factory=list)
    exec_ranges: List[Tuple[int, int]] = field(default_factory=list)
    data_ranges: List[Tuple[int, int]] = field(default_factory=list)
    dynsyms: List[ElfSym] = field(default_factory=list)
    symtabsyms: List[ElfSym] = field(default_factory=list)
    dyn: Dict[int, int] = field(default_factory=dict)
    needed: List[str] = field(default_factory=list)
    soname: str = ""
    tls_mod_id: int = 0
    tls_vaddr: int = 0
    tls_filesz: int = 0
    tls_memsz: int = 0
    tls_align: int = 1
    tls_tpoff: int = 0  # Negative offset from %fs:0 (Variant II static TLS)
    init_array: List[int] = field(default_factory=list)
    fini_array: List[int] = field(default_factory=list)

    def vaddr_to_off(self, vaddr: int) -> int:
        off = vaddr - self.base - self.vaddr_min
        if off < 0 or off >= len(self.mem):
            raise ValueError(
                f"{self.name}: vaddr 0x{vaddr:x} outside [0x{self.base + self.vaddr_min:x}, "
                f"0x{self.base + self.vaddr_max:x})"
            )
        return off

    def r64(self, vaddr: int) -> int:
        off = self.vaddr_to_off(vaddr)
        return struct.unpack_from("<Q", self.mem, off)[0]

    def w64(self, vaddr: int, val: int) -> None:
        off = self.vaddr_to_off(vaddr)
        struct.pack_into("<Q", self.mem, off, val & 0xFFFFFFFFFFFFFFFF)

    def w32(self, vaddr: int, val: int) -> None:
        off = self.vaddr_to_off(vaddr)
        struct.pack_into("<I", self.mem, off, val & 0xFFFFFFFF)


def parse_elf64(path: str, base_cursor: int, is_main: bool) -> Tuple[ElfModule, int]:
    raw = open(path, "rb").read()
    if len(raw) < 64 or raw[:4] != b"\x7fELF":
        raise ValueError(f"{path}: not an ELF file")
    if raw[EI_CLASS] != ELFCLASS64 or raw[EI_DATA] != ELFDATA2LSB:
        raise ValueError(f"{path}: expected 64-bit little-endian ELF")

    (
        e_type, e_machine, _e_ver, e_entry, e_phoff, e_shoff,
        _e_flags, _e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)

    if e_machine != EM_X86_64:
        raise ValueError(f"{path}: expected EM_X86_64 (62), got {e_machine}")
    if e_type not in (ET_EXEC, ET_DYN):
        raise ValueError(f"{path}: unsupported e_type {e_type}")

    load_segs = []
    dyn_ph = None
    tls_ph = None
    for i in range(e_phnum):
        p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = (
            struct.unpack_from("<IIQQQQQQ", raw, e_phoff + i * e_phentsize)
        )
        if p_type == PT_LOAD and p_memsz > 0:
            load_segs.append((p_vaddr, p_memsz, p_offset, p_filesz, p_flags))
        elif p_type == PT_DYNAMIC:
            dyn_ph = (p_offset, p_filesz)
        elif p_type == PT_TLS:
            tls_ph = (p_vaddr, p_filesz, p_memsz, max(p_align, 1))

    if not load_segs:
        raise ValueError(f"{path}: no PT_LOAD segments")

    # Align image boundaries to macOS ARM64 16 KiB page size.
    vaddr_min = align_down(min(s[0] for s in load_segs), 0x4000)
    vaddr_max = align_up(max(s[0] + s[1] for s in load_segs), 0x4000)
    mem_size = vaddr_max - vaddr_min

    if e_type == ET_DYN:
        base = base_cursor
        next_cursor = align_up(base + vaddr_max, MODULE_STRIDE)
    else:
        # ET_EXEC uses fixed virtual addresses; reject low addresses below macOS __PAGEZERO.
        if vaddr_min < 0x100000000:
            raise ValueError(
                f"{path}: non-PIE ET_EXEC at 0x{vaddr_min:x} sits inside macOS 4 GiB __PAGEZERO; "
                "compile/link as PIE (-fPIE -pie) or shared library (-shared)"
            )
        base = 0
        next_cursor = base_cursor

    mem = bytearray(mem_size)
    for p_vaddr, _p_memsz, p_offset, p_filesz, _p_flags in load_segs:
        dst = p_vaddr - vaddr_min
        if p_filesz > 0:
            mem[dst : dst + p_filesz] = raw[p_offset : p_offset + p_filesz]

    mod = ElfModule(
        name=os.path.basename(path),
        path=os.path.abspath(path),
        is_main=is_main,
        e_type=e_type,
        e_entry=(base + e_entry) if e_entry else 0,
        base=base,
        vaddr_min=vaddr_min,
        vaddr_max=vaddr_max,
        mem=mem,
        raw=raw,
        load_segs=load_segs,
    )

    if tls_ph:
        mod.tls_vaddr, mod.tls_filesz, mod.tls_memsz, mod.tls_align = tls_ph

    # Parse sections (for symbols, executable ranges, data ranges)
    shdrs = []
    for i in range(e_shnum):
        sh = struct.unpack_from("<IIQQQQIIQQ", raw, e_shoff + i * e_shentsize)
        shdrs.append(sh)

    shstr = b""
    if e_shstrndx < len(shdrs):
        s = shdrs[e_shstrndx]
        shstr = raw[s[4] : s[4] + s[5]]

    def parse_symtab(sh_idx: int) -> List[ElfSym]:
        sh = shdrs[sh_idx]
        sh_off, sh_size, sh_link, sh_entsize = sh[4], sh[5], sh[6], sh[9]
        if sh_entsize == 0:
            sh_entsize = 24
        str_sh = shdrs[sh_link]
        strtab = raw[str_sh[4] : str_sh[4] + str_sh[5]]
        syms = []
        for off in range(sh_off, sh_off + sh_size, sh_entsize):
            st_name, st_info, _st_other, st_shndx, st_value, st_size = (
                struct.unpack_from("<IBBHQQ", raw, off)
            )
            syms.append(ElfSym(
                name=read_cstr(strtab, st_name),
                bind=st_info >> 4,
                stype=st_info & 0xF,
                shndx=st_shndx,
                value=st_value,
                size=st_size,
            ))
        return syms

    for idx, sh in enumerate(shdrs):
        sh_name_off, sh_type, sh_flags, sh_addr, sh_off, sh_size = sh[:6]
        sname = read_cstr(shstr, sh_name_off)
        if sh_type == SHT_DYNSYM:
            mod.dynsyms = parse_symtab(idx)
        elif sh_type == SHT_SYMTAB:
            mod.symtabsyms = parse_symtab(idx)
        if sh_addr and sh_size:
            if sh_flags & SHF_EXECINSTR:
                mod.exec_ranges.append((base + sh_addr, base + sh_addr + sh_size))
            elif sname in (".rodata", ".data", ".data.rel.ro", ".init_array", ".fini_array"):
                mod.data_ranges.append((base + sh_addr, base + sh_addr + sh_size))

    # Fallback if stripped of section headers: use PT_LOAD flags
    if not mod.exec_ranges:
        for p_vaddr, p_memsz, _off, _fsz, p_flags in load_segs:
            if p_flags & PF_X:
                mod.exec_ranges.append((base + p_vaddr, base + p_vaddr + p_memsz))

    # Parse PT_DYNAMIC
    if dyn_ph:
        d_off, d_sz = dyn_ph
        needed_offs = []
        soname_off = None
        for off in range(d_off, d_off + d_sz, 16):
            d_tag, d_val = struct.unpack_from("<qQ", raw, off)
            if d_tag == DT_NULL:
                break
            if d_tag == DT_NEEDED:
                needed_offs.append(d_val)
            elif d_tag == DT_SONAME:
                soname_off = d_val
            else:
                mod.dyn[d_tag] = d_val

        dynstr_va = mod.dyn.get(DT_STRTAB)
        if dynstr_va is not None:
            dynstr_off = mod.vaddr_to_off(base + dynstr_va)
            dynstr_blob = bytes(mod.mem[dynstr_off:])
            mod.needed = [read_cstr(dynstr_blob, o) for o in needed_offs]
            if soname_off is not None:
                mod.soname = read_cstr(dynstr_blob, soname_off)

    return mod, next_cursor


def parse_rela_table(mod: ElfModule, table_va: int, table_sz: int, ent_sz: int = 24) -> List[Tuple[int, int, int, int]]:
    out = []
    if not table_va or not table_sz:
        return out
    off = mod.vaddr_to_off(mod.base + table_va)
    for pos in range(off, off + table_sz, ent_sz):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", mod.mem, pos)
        r_sym = r_info >> 32
        r_type = r_info & 0xFFFFFFFF
        out.append((r_offset, r_sym, r_type, r_addend))
    return out


def prepare_modules(elf_paths: List[str], out_dir: str) -> dict:
    """Prepare one or more ELF64 binaries into out_dir and return layout dict."""
    os.makedirs(out_dir, exist_ok=True)
    modules: List[ElfModule] = []
    cursor = MODULE_BASE_START
    for i, path in enumerate(elf_paths):
        mod, cursor = parse_elf64(path, cursor, is_main=(i == 0))
        modules.append(mod)

    # Assign static TLS layout (Variant II: modules packed below %fs:0).
    tls_cursor = 0
    tls_mod_id = 1
    for mod in modules:
        if mod.tls_memsz > 0:
            mod.tls_mod_id = tls_mod_id
            tls_mod_id += 1
            tls_cursor = align_up(tls_cursor + mod.tls_memsz, max(mod.tls_align, 16))
            mod.tls_tpoff = -tls_cursor
    total_tls_size = align_up(tls_cursor, 16)

    # Build global export table following ELF ld.so rules (load order; strong beats weak).
    # Maps symbol name -> (addr, bind, stype, size, mod_name)
    global_exports: Dict[str, Tuple[int, int, int, int, str]] = {}
    for mod in modules:
        for sym in mod.dynsyms:
            if not sym.name or sym.shndx == SHN_UNDEF:
                continue
            if sym.bind not in (STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE):
                continue
            addr = (mod.base + sym.value) if sym.stype != STT_TLS else sym.value
            prev = global_exports.get(sym.name)
            if prev is None or (prev[1] == STB_WEAK and sym.bind != STB_WEAK):
                global_exports[sym.name] = (addr, sym.bind, sym.stype, sym.size, mod.name)

    # Pre-scan R_X86_64_COPY in main executable: COPY binds the symbol globally to main's BSS slot.
    copy_relocs: List[dict] = []
    for mod in modules:
        relas = parse_rela_table(
            mod,
            mod.dyn.get(DT_RELA, 0),
            mod.dyn.get(DT_RELASZ, 0),
            mod.dyn.get(DT_RELAENT, 24),
        )
        for r_offset, r_sym, r_type, _r_addend in relas:
            if r_type != R_X86_64_COPY or r_sym >= len(mod.dynsyms):
                continue
            sym = mod.dynsyms[r_sym]
            dst = mod.base + r_offset
            src_info = global_exports.get(sym.name)
            if src_info is not None and src_info[0] != dst:
                copy_relocs.append({
                    "name": sym.name,
                    "dst": dst,
                    "src": src_info[0],
                    "size": sym.size or src_info[3],
                })
                global_exports[sym.name] = (dst, STB_GLOBAL, sym.stype, sym.size, mod.name)

    # Allocate external thunks and data imports on demand.
    imports: Dict[str, int] = {}
    data_imports: Dict[str, int] = {}
    next_thunk = THUNK_BASE
    next_data_import = DATA_IMPORT_BASE
    irelatives: List[dict] = []

    def resolve_symbol(mod: ElfModule, sym_idx: int) -> Tuple[int, Optional[ElfSym]]:
        nonlocal next_thunk, next_data_import
        if sym_idx == 0 or sym_idx >= len(mod.dynsyms):
            return 0, None
        sym = mod.dynsyms[sym_idx]
        if not sym.name:
            return (mod.base + sym.value) if sym.shndx != SHN_UNDEF else 0, sym

        if sym.name in global_exports:
            return global_exports[sym.name][0], sym

        if sym.shndx != SHN_UNDEF:
            return mod.base + sym.value, sym

        # Unresolved weak undefined symbol -> 0 (NULL) unless it's a known shim/hook
        if sym.bind == STB_WEAK and sym.name not in KNOWN_DATA_IMPORTS:
            # Weak symbols like __gmon_start__, _ITM_registerTMCloneTable resolve to 0.
            return 0, sym

        if sym.name in KNOWN_DATA_IMPORTS or sym.stype == STT_OBJECT:
            if sym.name not in data_imports:
                data_imports[sym.name] = next_data_import
                next_data_import += 8
            return data_imports[sym.name], sym

        if sym.name not in imports:
            imports[sym.name] = next_thunk
            next_thunk += THUNK_STRIDE
        return imports[sym.name], sym

    # Apply DT_RELA and DT_JMPREL for every module
    for mod in modules:
        all_relas = parse_rela_table(
            mod,
            mod.dyn.get(DT_RELA, 0),
            mod.dyn.get(DT_RELASZ, 0),
            mod.dyn.get(DT_RELAENT, 24),
        )
        if mod.dyn.get(DT_PLTREL, DT_RELA) == DT_RELA:
            all_relas += parse_rela_table(
                mod,
                mod.dyn.get(DT_JMPREL, 0),
                mod.dyn.get(DT_PLTRELSZ, 0),
                24,
            )

        for r_offset, r_sym, r_type, r_addend in all_relas:
            place = mod.base + r_offset
            if r_type == R_X86_64_NONE or r_type == R_X86_64_COPY:
                continue
            elif r_type == R_X86_64_RELATIVE:
                mod.w64(place, mod.base + r_addend)
            elif r_type == R_X86_64_64:
                s_val, _ = resolve_symbol(mod, r_sym)
                mod.w64(place, s_val + r_addend)
            elif r_type in (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT):
                s_val, _ = resolve_symbol(mod, r_sym)
                mod.w64(place, s_val)
            elif r_type in (R_X86_64_PC32, R_X86_64_PLT32):
                s_val, _ = resolve_symbol(mod, r_sym)
                disp = s_val + r_addend - place
                if disp < -(1 << 31) or disp >= (1 << 31):
                    raise ValueError(f"{mod.name}: PC32 overflow at 0x{place:x}: disp=0x{disp:x}")
                mod.w32(place, disp)
            elif r_type == R_X86_64_DTPMOD64:
                mod.w64(place, mod.tls_mod_id or 1)
            elif r_type == R_X86_64_DTPOFF64:
                sym = mod.dynsyms[r_sym] if r_sym < len(mod.dynsyms) else None
                mod.w64(place, (sym.value if sym else 0) + r_addend)
            elif r_type == R_X86_64_TPOFF64:
                sym = mod.dynsyms[r_sym] if r_sym < len(mod.dynsyms) else None
                mod.w64(place, (mod.tls_tpoff + (sym.value if sym else 0) + r_addend) & 0xFFFFFFFFFFFFFFFF)
            elif r_type == R_X86_64_IRELATIVE:
                resolver = mod.base + r_addend
                mod.w64(place, resolver)
                irelatives.append({"got": place, "resolver": resolver, "module": mod.name})
            else:
                raise ValueError(f"{mod.name}: unsupported relocation type {r_type} at 0x{place:x}")

    # Extract init_array / fini_array (after relocations are applied!)
    for mod in modules:
        if DT_INIT in mod.dyn and mod.dyn[DT_INIT]:
            mod.init_array.append(mod.base + mod.dyn[DT_INIT])
        ia_va = mod.dyn.get(DT_INIT_ARRAY, 0)
        ia_sz = mod.dyn.get(DT_INIT_ARRAYSZ, 0)
        for off in range(0, ia_sz, 8):
            fn = mod.r64(mod.base + ia_va + off)
            if fn and fn != 0xFFFFFFFFFFFFFFFF:
                mod.init_array.append(fn)

        fa_va = mod.dyn.get(DT_FINI_ARRAY, 0)
        fa_sz = mod.dyn.get(DT_FINI_ARRAYSZ, 0)
        for off in range(0, fa_sz, 8):
            fn = mod.r64(mod.base + fa_va + off)
            if fn and fn != 0xFFFFFFFFFFFFFFFF:
                mod.fini_array.append(fn)
        if DT_FINI in mod.dyn and mod.dyn[DT_FINI]:
            mod.fini_array.append(mod.base + mod.dyn[DT_FINI])

    # Collect all code roots (functions, entry, init/fini, irelative resolvers, and data pointers into exec sections).
    all_exec_ranges = [r for m in modules for r in m.exec_ranges]

    def in_exec(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in all_exec_ranges)

    mod_layouts = []
    for mod in modules:
        img_name = f"{mod.name}.img"
        img_path = os.path.join(out_dir, img_name)
        with open(img_path, "wb") as f:
            f.write(mod.mem)

        code_roots = set()
        if mod.e_entry and in_exec(mod.e_entry):
            code_roots.add(mod.e_entry)
        for fn in mod.init_array + mod.fini_array:
            if in_exec(fn):
                code_roots.add(fn)
        for ir in irelatives:
            if in_exec(ir["resolver"]):
                code_roots.add(ir["resolver"])
        for sym in mod.dynsyms + mod.symtabsyms:
            if sym.shndx != SHN_UNDEF and sym.stype in (STT_FUNC, STT_GNU_IFUNC) and sym.value:
                addr = mod.base + sym.value
                if in_exec(addr):
                    code_roots.add(addr)

        # Scan relocated data sections for 8-byte pointers targeting any executable section.
        for lo, hi in mod.data_ranges:
            start_off = mod.vaddr_to_off(lo)
            end_off = start_off + (hi - lo)
            for off in range(start_off, end_off - 7, 8):
                ptr = struct.unpack_from("<Q", mod.mem, off)[0]
                if in_exec(ptr):
                    code_roots.add(ptr)

        mod_exports = {}
        for sym in mod.dynsyms:
            if sym.name and sym.shndx != SHN_UNDEF and sym.bind in (STB_GLOBAL, STB_WEAK, STB_GNU_UNIQUE):
                mod_exports[sym.name] = mod.base + sym.value

        mod_layouts.append({
            "name": mod.name,
            "soname": mod.soname or mod.name,
            "elf_path": mod.path,
            "image_path": os.path.abspath(img_path),
            "is_main": mod.is_main,
            "base": mod.base,
            "vaddr_min": mod.vaddr_min,
            "map_addr": mod.base + mod.vaddr_min,
            "mem_size": len(mod.mem),
            "entry": mod.e_entry,
            "exec_ranges": [[lo, hi] for lo, hi in mod.exec_ranges],
            "init_array": mod.init_array,
            "fini_array": mod.fini_array,
            "needed": mod.needed,
            "tls": {
                "mod_id": mod.tls_mod_id,
                "vaddr": (mod.base + mod.tls_vaddr) if mod.tls_memsz else 0,
                "filesz": mod.tls_filesz,
                "memsz": mod.tls_memsz,
                "align": mod.tls_align,
                "tpoff": mod.tls_tpoff,
            },
            "exports": mod_exports,
            "code_roots": sorted(code_roots),
        })

    # Init order: shared libraries first, then main executable (reverse for fini).
    ordered_inits = []
    for ml in reversed(mod_layouts):
        ordered_inits.extend(ml["init_array"])

    main_mod = mod_layouts[0]
    layout = {
        "arch": "x86_64",
        "thunk_base": THUNK_BASE,
        "data_import_base": DATA_IMPORT_BASE,
        "total_tls_size": total_tls_size,
        "entry": main_mod["entry"],
        "main_symbol": main_mod["exports"].get("main", 0),
        "init_order": ordered_inits,
        "modules": mod_layouts,
        "imports": [{"name": k, "addr": v} for k, v in sorted(imports.items(), key=lambda kv: kv[1])],
        "data_imports": [{"name": k, "addr": v} for k, v in sorted(data_imports.items(), key=lambda kv: kv[1])],
        "copy_relocs": copy_relocs,
        "irelatives": irelatives,
    }

    layout_path = os.path.join(out_dir, "layout.json")
    with open(layout_path, "w") as f:
        json.dump(layout, f, indent=2)
    return layout


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare ELF64 x86_64 binaries for static recompilation.")
    ap.add_argument("-o", "--out-dir", required=True, help="Output directory for images and layout.json")
    ap.add_argument("elfs", nargs="+", help="Main ELF64 binary followed by shared libraries (.so)")
    args = ap.parse_args()

    layout = prepare_modules(args.elfs, args.out_dir)
    print(
        f"elfprep64: {len(layout['modules'])} module(s), "
        f"{len(layout['imports'])} import(s), "
        f"{len(layout['data_imports'])} data import(s), "
        f"entry=0x{layout['entry']:x}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
