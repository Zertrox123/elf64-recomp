#!/usr/bin/env python3
"""x86_64 (System V AMD64) -> portable C static lifter.

Disassembles prepared ELF64 binaries via Apple/LLVM objdump (-M intel), splits
code into per-function C units (sharded across N C files for parallel clang
builds), and lifts x86_64 GPR, memory/RIP-relative/FS-TLS, control flow,
switch tables, atomics, string ops, and SSE/SSE2/SSE4.1 instructions to C.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# Register tables: name -> (field_name, width_bits, kind)
# kind: '64', '32', '16', '8l', '8h', 'xmm'
GPR64 = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]
GPR32 = [
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
]
GPR16 = [
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
]
GPR8L = [
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
]
GPR8H = {"ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx"}

REG_INFO: Dict[str, Tuple[str, int, str]] = {}
for i, r64 in enumerate(GPR64):
    REG_INFO[r64] = (r64, 64, "64")
    REG_INFO[GPR32[i]] = (r64, 32, "32")
    REG_INFO[GPR16[i]] = (r64, 16, "16")
    REG_INFO[GPR8L[i]] = (r64, 8, "8l")
for r8h, r64 in GPR8H.items():
    REG_INFO[r8h] = (r64, 8, "8h")
for i in range(16):
    REG_INFO[f"xmm{i}"] = (f"xmm[{i}]", 128, "xmm")

SIZE_KW = {
    "byte ptr": 8,
    "word ptr": 16,
    "dword ptr": 32,
    "qword ptr": 64,
    "xmmword ptr": 128,
    "oword ptr": 128,
    "tbyte ptr": 80,
}

CC_EXPR = {
    "e": "c->zf", "z": "c->zf",
    "ne": "!c->zf", "nz": "!c->zf",
    "b": "c->cf", "c": "c->cf", "nae": "c->cf",
    "ae": "!c->cf", "nb": "!c->cf", "nc": "!c->cf",
    "be": "(c->cf || c->zf)", "na": "(c->cf || c->zf)",
    "a": "(!c->cf && !c->zf)", "nbe": "(!c->cf && !c->zf)",
    "l": "(c->sf != c->of)", "nge": "(c->sf != c->of)",
    "ge": "(c->sf == c->of)", "nl": "(c->sf == c->of)",
    "le": "(c->zf || (c->sf != c->of))", "ng": "(c->zf || (c->sf != c->of))",
    "g": "(!c->zf && (c->sf == c->of))", "nle": "(!c->zf && (c->sf == c->of))",
    "s": "c->sf", "ns": "!c->sf",
    "o": "c->of", "no": "!c->of",
    "p": "c->pf", "pe": "c->pf",
    "np": "!c->pf", "po": "!c->pf",
}

SYM_HDR_RE = re.compile(r"^([0-9a-fA-F]+)\s+<([^>]+)>:$")
INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s)+)\s*(.*)$")


@dataclass
class Insn:
    addr: int
    size: int
    text: str
    prefix: str
    mnemonic: str
    ops: List[str]

    @property
    def next_addr(self) -> int:
        return self.addr + self.size


@dataclass
class LiftedFunc:
    addr: int
    name: str
    insns: List[Insn] = field(default_factory=list)


def split_operands(op_str: str) -> List[str]:
    op_str = op_str.strip()
    if not op_str:
        return []
    out, cur, depth = [], [], 0
    for ch in op_str:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return out


def parse_insn_text(raw_text: str) -> Tuple[str, str, List[str]]:
    # Strip objdump trailing comments (# ... or <sym+0x...>)
    text = raw_text.split("#", 1)[0].strip()
    # Strip trailing <symbol> target annotation on call/jmp
    text = re.sub(r"\s+<[^>]+>$", "", text).strip()
    if not text:
        return "", "nop", []

    parts = text.split(None, 1)
    prefix = ""
    while parts[0] in ("lock", "rep", "repe", "repz", "repne", "repnz", "data16", "rex64", "bnd", "notrack"):
        p = parts[0]
        if p in ("lock", "rep", "repe", "repz", "repne", "repnz"):
            prefix = p
        if len(parts) == 1:
            return prefix, "nop", []
        parts = parts[1].split(None, 1)

    mnem = parts[0].lower()
    ops = split_operands(parts[1]) if len(parts) > 1 else []
    return prefix, mnem, ops


def find_objdump() -> str:
    for cand in ("/usr/bin/objdump", "/opt/homebrew/opt/llvm/bin/llvm-objdump"):
        if os.path.exists(cand):
            return cand
    return "objdump"


def disassemble_module(
    elf_path: str,
    base: int,
    code_roots: List[int],
    is_pe: bool = False,
    vma_delta: int = 0,
) -> List[LiftedFunc]:
    objdump = find_objdump()
    if is_pe:
        # Apple llvm-objdump ignores --adjust-vma on COFF/PE64; apply vma_delta in Python.
        cmd = [objdump, "-d", "-M", "intel", elf_path]
        shift = vma_delta
    else:
        cmd = [objdump, "-d", "-M", "intel", f"--adjust-vma=0x{base:x}", elf_path]
        shift = 0
    out = subprocess.check_output(cmd, text=True)

    # Parse all instructions in address order + symbol header starts.
    sym_starts: Dict[int, str] = {}
    all_insns: List[Insn] = []
    addr_to_idx: Dict[int, int] = {}
    pending_prefix = ""

    for line in out.splitlines():
        m = SYM_HDR_RE.match(line)
        if m:
            addr = int(m.group(1), 16) + shift
            sym_starts[addr] = m.group(2)
            pending_prefix = ""
            continue
        m = INSN_RE.match(line)
        if m:
            addr = int(m.group(1), 16) + shift
            raw_hex = m.group(2).strip().split()
            text = m.group(3).strip()
            if not text:
                # Continuation line of long instruction raw bytes in objdump
                if all_insns:
                    all_insns[-1].size += len(raw_hex)
                continue
            prefix, mnem, ops = parse_insn_text(text)
            # Shift direct PC-relative branch/call immediates when rebasing PE64.
            if shift and ops and (
                mnem in ("call", "jmp", "jecxz", "jrcxz")
                or (mnem.startswith("j") and mnem[1:] in CC_EXPR)
            ):
                t = parse_imm(ops[0])
                if t is not None:
                    ops[0] = f"0x{t + shift:x}"
            # llvm-objdump emits standalone 'f0: lock' / 'f3: rep' prefix lines before the insn.
            if prefix and mnem == "nop" and not ops:
                pending_prefix = prefix
                prefix = ""
            elif pending_prefix:
                prefix = pending_prefix
                pending_prefix = ""
            if addr not in addr_to_idx:
                addr_to_idx[addr] = len(all_insns)
                all_insns.append(Insn(addr, len(raw_hex), text, prefix, mnem, ops))

    if not all_insns:
        return []

    # Resync disassembly for any known code_root or direct call target whose entry byte
    # was swallowed by inline jump-table data in .text.
    lo_code = all_insns[0].addr
    hi_code = all_insns[-1].next_addr
    want_roots = {r for r in code_roots if lo_code <= r < hi_code}
    for insn in all_insns:
        if insn.mnemonic == "call" and len(insn.ops) == 1:
            t = parse_imm(insn.ops[0])
            if t is not None and lo_code <= t < hi_code:
                want_roots.add(t)
        elif insn.mnemonic == "jmp" and insn.size == 5 and len(insn.ops) == 1:
            t = parse_imm(insn.ops[0])
            if t is not None and lo_code <= t < hi_code and (t & 0xF) == 0:
                want_roots.add(t)
        elif insn.mnemonic == "lea" and len(insn.ops) == 2 and "[rip" in insn.ops[1]:
            m_rip = re.search(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]", insn.ops[1])
            if m_rip:
                disp = int(m_rip.group(2), 0)
                if m_rip.group(1) == "-":
                    disp = -disp
                t = insn.next_addr + disp
                if lo_code <= t < hi_code and (t & 0xF) == 0:
                    want_roots.add(t)
    missing_roots = sorted(r for r in want_roots if r not in addr_to_idx)
    if missing_roots:
        resynced_ranges: List[Tuple[int, int]] = []
        resynced_insns: List[Insn] = []
        for mr in missing_roots:
            if mr in addr_to_idx:
                continue
            stop_addr = mr + 0x2000
            raw_start = mr - shift
            raw_stop = stop_addr - shift
            rcmd = [
                objdump, "-d", "-M", "intel",
                f"--start-address=0x{raw_start:x}",
                f"--stop-address=0x{raw_stop:x}",
            ]
            if not is_pe:
                rcmd.append(f"--adjust-vma=0x{base:x}")
            rcmd.append(elf_path)
            rout = subprocess.check_output(rcmd, text=True)
            r_pending = ""
            added_any = False
            for line in rout.splitlines():
                m = INSN_RE.match(line)
                if not m:
                    continue
                addr = int(m.group(1), 16) + shift
                raw_hex = m.group(2).strip().split()
                text = m.group(3).strip()
                if not text:
                    if added_any and resynced_insns:
                        resynced_insns[-1].size += len(raw_hex)
                    continue
                # Stop once we resynchronize with the primary disassembly stream.
                if added_any and addr in addr_to_idx:
                    break
                prefix, mnem, ops = parse_insn_text(text)
                if shift and ops and (
                    mnem in ("call", "jmp", "jecxz", "jrcxz")
                    or (mnem.startswith("j") and mnem[1:] in CC_EXPR)
                ):
                    t = parse_imm(ops[0])
                    if t is not None:
                        ops[0] = f"0x{t + shift:x}"
                if prefix and mnem == "nop" and not ops:
                    r_pending = prefix
                    prefix = ""
                elif r_pending:
                    prefix = r_pending
                    r_pending = ""
                if addr not in addr_to_idx:
                    ins_obj = Insn(addr, len(raw_hex), text, prefix, mnem, ops)
                    resynced_insns.append(ins_obj)
                    addr_to_idx[addr] = -1
                    added_any = True
            if added_any:
                resynced_ranges.append((mr, resynced_insns[-1].next_addr))
        if resynced_insns:
            # Drop stale desynchronized instructions overlapped by resynced spans.
            all_insns = [
                ins for ins in all_insns
                if not any(lo <= ins.addr < hi for lo, hi in resynced_ranges)
            ] + resynced_insns
            all_insns.sort(key=lambda ins: ins.addr)
            addr_to_idx = {ins.addr: i for i, ins in enumerate(all_insns)}

    # Function starts = objdump symbol headers U layout code_roots (that exist in disassembly).
    root_set: Set[int] = set(sym_starts.keys())
    for r in code_roots:
        if r in addr_to_idx:
            root_set.add(r)

    def build_funcs(roots: Set[int]) -> List[LiftedFunc]:
        sorted_roots = sorted(r for r in roots if r in addr_to_idx)
        out_funcs: List[LiftedFunc] = []
        for i, start_addr in enumerate(sorted_roots):
            start_idx = addr_to_idx[start_addr]
            end_idx = addr_to_idx[sorted_roots[i + 1]] if i + 1 < len(sorted_roots) else len(all_insns)
            jt_cutoff = all_insns[end_idx].addr if end_idx < len(all_insns) else hi_code
            insns = []
            for idx in range(start_idx, end_idx):
                ins = all_insns[idx]
                if ins.addr >= jt_cutoff:
                    break
                if insns and ins.addr > insns[-1].next_addr + 0x100:
                    break
                if is_pe and ins.mnemonic in ("mov", "movsxd", "movzx") and len(ins.ops) == 2 and "rip" not in ins.ops[1]:
                    m_jt = re.search(r"\[[^\]]*\+[^\]]*\+\s*(0x[0-9a-fA-F]+)\s*\]", ins.ops[1])
                    if m_jt:
                        jt_va = base + int(m_jt.group(1), 16)
                        if ins.next_addr <= jt_va < jt_cutoff:
                            jt_cutoff = jt_va
                insns.append(ins)
            if insns:
                name = sym_starts.get(start_addr, f"sub_{start_addr:x}")
                out_funcs.append(LiftedFunc(start_addr, name, insns))
        return out_funcs

    # Also add direct `call <imm>` and RIP-relative `lea reg, [rip + disp]` code targets
    # (discovers static leaf callbacks such as qsort comparators that lack .pdata entries).
    for insn in all_insns:
        if insn.mnemonic == "call" and len(insn.ops) == 1:
            t = parse_imm(insn.ops[0])
            if t is not None and t in addr_to_idx:
                root_set.add(t)
        elif insn.mnemonic == "lea" and len(insn.ops) == 2 and "[rip" in insn.ops[1]:
            m_rip = re.search(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]", insn.ops[1])
            if m_rip:
                disp = int(m_rip.group(2), 0)
                if m_rip.group(1) == "-":
                    disp = -disp
                t = insn.next_addr + disp
                if t in addr_to_idx:
                    prev_idx = addr_to_idx[t] - 1
                    if (
                        prev_idx < 0
                        or all_insns[prev_idx].mnemonic in ("ret", "jmp", "int3", "nop", "ud2")
                        or ((t & 0xF) == 0 and all_insns[prev_idx].mnemonic == "add" and "al" in all_insns[prev_idx].text)
                    ):
                        root_set.add(t)

    # Close over cross-chunk direct jmp/jcc targets so split .pdata / .text.unlikely blocks never miss a root.
    funcs = build_funcs(root_set)
    while True:
        added = False
        for fn in funcs:
            local = {ins.addr for ins in fn.insns}
            for ins in fn.insns:
                if ins.ops and (
                    ins.mnemonic in ("jmp", "jecxz", "jrcxz")
                    or (ins.mnemonic.startswith("j") and ins.mnemonic[1:] in CC_EXPR)
                ):
                    t = parse_imm(ins.ops[0])
                    if t is not None and t in addr_to_idx and t not in local and t not in root_set:
                        root_set.add(t)
                        added = True
        if not added:
            break
        funcs = build_funcs(root_set)
    return funcs


def parse_imm(s: str) -> Optional[int]:
    s = s.strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None


def parse_mem(op: str, next_rip: int) -> Optional[Tuple[Optional[int], str]]:
    """Parse '[size ptr] [seg:][expr]' into (width_bits_or_None, C_addr_expr)."""
    s = op.strip()
    width = None
    for kw, bits in SIZE_KW.items():
        if s.startswith(kw + " "):
            width = bits
            s = s[len(kw) :].strip()
            break

    seg_prefix = ""
    if s.startswith("fs:"):
        seg_prefix = "c->fs_base + "
        s = s[3:].strip()
    elif s.startswith("gs:"):
        seg_prefix = "c->gs_base + "
        s = s[3:].strip()
    elif len(s) > 3 and s[2] == ":" and s[:2] in ("cs", "ds", "es", "ss"):
        s = s[3:].strip()

    if not (s.startswith("[") and s.endswith("]")):
        return None
    inner = s[1:-1].strip()
    if not inner:
        return width, "0ULL"

    # Tokenize by + and - keeping sign
    tokens = re.findall(r"[+-]?[^+-]+", inner.replace(" ", ""))
    terms = []
    for tok in tokens:
        sign = ""
        if tok[0] in "+-":
            sign = tok[0]
            tok = tok[1:]
        if not tok:
            continue
        if "*" in tok:
            lhs, rhs = tok.split("*", 1)
            if lhs in ("riz", "eiz") or rhs in ("riz", "eiz"):
                term = "0ULL"
            elif lhs in REG_INFO:
                r = reg_read_expr(lhs)
                scale = int(rhs, 0)
                term = f"((uint64_t)({r}) * {scale}ULL)"
            else:
                r = reg_read_expr(rhs)
                scale = int(lhs, 0)
                term = f"((uint64_t)({r}) * {scale}ULL)"
        elif tok in ("riz", "eiz"):
            term = "0ULL"
        elif tok == "rip":
            term = f"0x{next_rip:x}ULL"
        elif tok == "eip":
            term = f"0x{next_rip & 0xFFFFFFFF:x}ULL"
        elif tok in REG_INFO:
            term = f"(uint64_t)({reg_read_expr(tok)})"
        else:
            val = int(tok, 0)
            term = f"0x{val:x}ULL"

        if not terms:
            terms.append(f"(-{term})" if sign == "-" else term)
        else:
            terms.append(f" {'-' if sign == '-' else '+'} {term}")

    expr = "".join(terms) if terms else "0ULL"
    return width, f"({seg_prefix}({expr}))"


def reg_read_expr(reg: str) -> str:
    field_name, _bits, kind = REG_INFO[reg]
    if kind == "64":
        return f"c->{field_name}"
    if kind == "32":
        return f"GET32(c->{field_name})"
    if kind == "16":
        return f"GET16(c->{field_name})"
    if kind == "8l":
        return f"GET8L(c->{field_name})"
    if kind == "8h":
        return f"GET8H(c->{field_name})"
    return f"c->{field_name}"


def reg_write_stmt(reg: str, val_expr: str) -> str:
    field_name, _bits, kind = REG_INFO[reg]
    if kind == "64":
        return f"SET64(c->{field_name}, {val_expr})"
    if kind == "32":
        return f"SET32(c->{field_name}, {val_expr})"
    if kind == "16":
        return f"SET16(c->{field_name}, {val_expr})"
    if kind == "8l":
        return f"SET8L(c->{field_name}, {val_expr})"
    if kind == "8h":
        return f"SET8H(c->{field_name}, {val_expr})"
    return f"c->{field_name} = ({val_expr})"


def op_width(op: str, next_rip: int) -> Optional[int]:
    if op in REG_INFO:
        return REG_INFO[op][1]
    m = parse_mem(op, next_rip)
    if m is not None:
        return m[0]
    return None


def infer_width(ops: List[str], next_rip: int, default: int = 64) -> int:
    for op in ops:
        w = op_width(op, next_rip)
        if w is not None and w != 128:
            return w
    return default


SEG_REGS = {"cs": "0x33ULL", "ds": "0x2bULL", "es": "0x2bULL", "ss": "0x2bULL", "fs": "0x53ULL", "gs": "0x2bULL"}


def read_op(op: str, width: int, next_rip: int) -> str:
    if op in REG_INFO:
        return reg_read_expr(op)
    if op in SEG_REGS:
        return SEG_REGS[op]
    m = parse_mem(op, next_rip)
    if m is not None:
        w = m[0] or width
        return f"R{w}({m[1]})"
    imm = parse_imm(op)
    if imm is not None:
        if imm < 0:
            # Sign-extend negative immediate to width
            mask = (1 << width) - 1
            return f"0x{imm & mask:x}ULL"
        return f"0x{imm & 0xFFFFFFFFFFFFFFFF:x}ULL"
    raise ValueError(f"cannot read operand: {op!r}")


def write_op(op: str, width: int, val_expr: str, next_rip: int) -> str:
    if op in REG_INFO:
        return reg_write_stmt(op, val_expr)
    if op in SEG_REGS:
        return f"(void)({val_expr})"
    m = parse_mem(op, next_rip)
    if m is not None:
        w = m[0] or width
        return f"W{w}({m[1]}, {val_expr})"
    raise ValueError(f"cannot write operand: {op!r}")


def sign_ext_expr(expr: str, from_bits: int) -> str:
    if from_bits == 8:
        return f"(uint64_t)(int64_t)(int8_t)({expr})"
    if from_bits == 16:
        return f"(uint64_t)(int64_t)(int16_t)({expr})"
    if from_bits == 32:
        return f"(uint64_t)(int64_t)(int32_t)({expr})"
    return f"(uint64_t)({expr})"


def read_xmm_float(op: str, next_rip: int) -> str:
    if op in REG_INFO and REG_INFO[op][2] == "xmm":
        return f"c->{REG_INFO[op][0]}.f[0]"
    m = parse_mem(op, next_rip)
    if m is not None:
        return f"({{ uint32_t _u = R32({m[1]}); float _f; memcpy(&_f, &_u, 4); _f; }})"
    raise ValueError(f"bad xmm float op: {op}")


def read_xmm_double(op: str, next_rip: int) -> str:
    if op in REG_INFO and REG_INFO[op][2] == "xmm":
        return f"c->{REG_INFO[op][0]}.df[0]"
    m = parse_mem(op, next_rip)
    if m is not None:
        return f"({{ uint64_t _u = R64({m[1]}); double _d; memcpy(&_d, &_u, 8); _d; }})"
    raise ValueError(f"bad xmm double op: {op}")


def read_xmm128(op: str, next_rip: int) -> str:
    if op in REG_INFO and REG_INFO[op][2] == "xmm":
        return f"c->{REG_INFO[op][0]}"
    m = parse_mem(op, next_rip)
    if m is not None:
        return f"R128({m[1]})"
    raise ValueError(f"bad xmm128 op: {op}")


def lift_sse(insn: Insn) -> Optional[str]:
    m, ops, nr = insn.mnemonic, insn.ops, insn.next_addr
    if m in ("movaps", "movups", "movapd", "movupd", "movdqa", "movdqu", "lddqu", "movntdq", "movntdqa", "movntps", "movntpd"):
        dst, src = ops
        if dst in REG_INFO and REG_INFO[dst][2] == "xmm":
            return f"c->{REG_INFO[dst][0]} = {read_xmm128(src, nr)};"
        mm = parse_mem(dst, nr)
        return f"W128({mm[1]}, {read_xmm128(src, nr)});"

    if m == "movss":
        dst, src = ops
        if dst in REG_INFO and REG_INFO[dst][2] == "xmm":
            dr = f"c->{REG_INFO[dst][0]}"
            if src in REG_INFO and REG_INFO[src][2] == "xmm":
                return f"{dr}.f[0] = c->{REG_INFO[src][0]}.f[0];"
            mm = parse_mem(src, nr)
            return f"memset(&{dr}, 0, 16); {dr}.d[0] = R32({mm[1]});"
        mm = parse_mem(dst, nr)
        return f"W32({mm[1]}, c->{REG_INFO[src][0]}.d[0]);"

    if m == "movsd" and len(ops) == 2:
        dst, src = ops
        if dst in REG_INFO and REG_INFO[dst][2] == "xmm":
            dr = f"c->{REG_INFO[dst][0]}"
            if src in REG_INFO and REG_INFO[src][2] == "xmm":
                return f"{dr}.df[0] = c->{REG_INFO[src][0]}.df[0];"
            mm = parse_mem(src, nr)
            return f"memset(&{dr}, 0, 16); {dr}.q[0] = R64({mm[1]});"
        mm = parse_mem(dst, nr)
        return f"W64({mm[1]}, c->{REG_INFO[src][0]}.q[0]);"

    if m == "movd":
        dst, src = ops
        if dst in REG_INFO and REG_INFO[dst][2] == "xmm":
            dr = f"c->{REG_INFO[dst][0]}"
            if src.startswith("mm") and src[2:].isdigit():
                return f"memset(&{dr}, 0, 16);"
            return f"memset(&{dr}, 0, 16); {dr}.d[0] = (uint32_t)({read_op(src, 32, nr)});"
        if src.startswith("mm") and src[2:].isdigit():
            return f"{write_op(dst, 32, '0U', nr)};"
        if dst.startswith("mm") and dst[2:].isdigit():
            return "/* movd mm, src nop */"
        return f"{write_op(dst, 32, f'c->{REG_INFO[src][0]}.d[0]', nr)};"

    if m == "movq":
        dst, src = ops
        if dst in REG_INFO and REG_INFO[dst][2] == "xmm":
            dr = f"c->{REG_INFO[dst][0]}"
            if src in REG_INFO and REG_INFO[src][2] == "xmm":
                return f"{{ uint64_t _v = c->{REG_INFO[src][0]}.q[0]; memset(&{dr}, 0, 16); {dr}.q[0] = _v; }}"
            return f"memset(&{dr}, 0, 16); {dr}.q[0] = {read_op(src, 64, nr)};"
        return f"{write_op(dst, 64, f'c->{REG_INFO[src][0]}.q[0]', nr)};"

    if m in ("movlps", "movlpd"):
        dst, src = ops
        if dst in REG_INFO and REG_INFO[dst][2] == "xmm":
            mm = parse_mem(src, nr)
            return f"c->{REG_INFO[dst][0]}.q[0] = R64({mm[1]});"
        mm = parse_mem(dst, nr)
        return f"W64({mm[1]}, c->{REG_INFO[src][0]}.q[0]);"

    if m in ("movhps", "movhpd"):
        dst, src = ops
        if dst in REG_INFO and REG_INFO[dst][2] == "xmm":
            mm = parse_mem(src, nr)
            return f"c->{REG_INFO[dst][0]}.q[1] = R64({mm[1]});"
        mm = parse_mem(dst, nr)
        return f"W64({mm[1]}, c->{REG_INFO[src][0]}.q[1]);"

    if m == "movlhps":
        d, s = REG_INFO[ops[0]][0], REG_INFO[ops[1]][0]
        return f"c->{d}.q[1] = c->{s}.q[0];"
    if m == "movhlps":
        d, s = REG_INFO[ops[0]][0], REG_INFO[ops[1]][0]
        return f"c->{d}.q[0] = c->{s}.q[1];"
    if m == "movddup":
        d = f"c->{REG_INFO[ops[0]][0]}"
        if ops[1] in REG_INFO:
            return f"{{ uint64_t _v = c->{REG_INFO[ops[1]][0]}.q[0]; {d}.q[0] = _v; {d}.q[1] = _v; }}"
        mm = parse_mem(ops[1], nr)
        return f"{{ uint64_t _v = R64({mm[1]}); {d}.q[0] = _v; {d}.q[1] = _v; }}"

    # Scalar FP arithmetic
    scalar_f = {"addss": "+", "subss": "-", "mulss": "*", "divss": "/"}
    if m in scalar_f:
        d = f"c->{REG_INFO[ops[0]][0]}.f[0]"
        return f"{d} = {d} {scalar_f[m]} ({read_xmm_float(ops[1], nr)});"
    scalar_d = {"addsd": "+", "subsd": "-", "mulsd": "*", "divsd": "/"}
    if m in scalar_d:
        d = f"c->{REG_INFO[ops[0]][0]}.df[0]"
        return f"{d} = {d} {scalar_d[m]} ({read_xmm_double(ops[1], nr)});"

    if m == "sqrtss":
        return f"c->{REG_INFO[ops[0]][0]}.f[0] = sqrtf({read_xmm_float(ops[1], nr)});"
    if m == "sqrtsd":
        return f"c->{REG_INFO[ops[0]][0]}.df[0] = sqrt({read_xmm_double(ops[1], nr)});"
    if m == "rcpss":
        return f"c->{REG_INFO[ops[0]][0]}.f[0] = 1.0f / ({read_xmm_float(ops[1], nr)});"
    if m == "rsqrtss":
        return f"c->{REG_INFO[ops[0]][0]}.f[0] = 1.0f / sqrtf({read_xmm_float(ops[1], nr)});"
    if m == "minss":
        d = f"c->{REG_INFO[ops[0]][0]}.f[0]"
        return f"{{ float _b = {read_xmm_float(ops[1], nr)}; {d} = ({d} < _b) ? {d} : _b; }}"
    if m == "maxss":
        d = f"c->{REG_INFO[ops[0]][0]}.f[0]"
        return f"{{ float _b = {read_xmm_float(ops[1], nr)}; {d} = ({d} > _b) ? {d} : _b; }}"
    if m == "minsd":
        d = f"c->{REG_INFO[ops[0]][0]}.df[0]"
        return f"{{ double _b = {read_xmm_double(ops[1], nr)}; {d} = ({d} < _b) ? {d} : _b; }}"
    if m == "maxsd":
        d = f"c->{REG_INFO[ops[0]][0]}.df[0]"
        return f"{{ double _b = {read_xmm_double(ops[1], nr)}; {d} = ({d} > _b) ? {d} : _b; }}"
    if m in ("ucomiss", "comiss"):
        return f"f_ucomi_f(c, c->{REG_INFO[ops[0]][0]}.f[0], {read_xmm_float(ops[1], nr)});"
    if m in ("ucomisd", "comisd"):
        return f"f_ucomi_d(c, c->{REG_INFO[ops[0]][0]}.df[0], {read_xmm_double(ops[1], nr)});"

    # Packed FP arithmetic
    packed_f = {"addps": "+", "subps": "-", "mulps": "*", "divps": "/"}
    if m in packed_f:
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {d}.f[_i] {packed_f[m]}= _s.f[_i]; }}"
    packed_d = {"addpd": "+", "subpd": "-", "mulpd": "*", "divpd": "/"}
    if m in packed_d:
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<2; _i++) {d}.df[_i] {packed_d[m]}= _s.df[_i]; }}"
    if m == "sqrtps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {d}.f[_i] = sqrtf(_s.f[_i]); }}"
    if m == "sqrtpd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<2; _i++) {d}.df[_i] = sqrt(_s.df[_i]); }}"
    if m == "rcpps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {d}.f[_i] = 1.0f / _s.f[_i]; }}"
    if m == "rsqrtps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {d}.f[_i] = 1.0f / sqrtf(_s.f[_i]); }}"
    if m in ("minps", "maxps"):
        cmp = "<" if m == "minps" else ">"
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {d}.f[_i] = ({d}.f[_i] {cmp} _s.f[_i]) ? {d}.f[_i] : _s.f[_i]; }}"
    if m in ("minpd", "maxpd"):
        cmp = "<" if m == "minpd" else ">"
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<2; _i++) {d}.df[_i] = ({d}.df[_i] {cmp} _s.df[_i]) ? {d}.df[_i] : _s.df[_i]; }}"

    # Bitwise 128-bit
    if m in ("xorps", "xorpd", "pxor"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        if ops[0] == ops[1]:
            return f"{d}.q[0] = 0; {d}.q[1] = 0;"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; {d}.q[0] ^= _s.q[0]; {d}.q[1] ^= _s.q[1]; }}"
    if m in ("orps", "orpd", "por"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; {d}.q[0] |= _s.q[0]; {d}.q[1] |= _s.q[1]; }}"
    if m in ("andps", "andpd", "pand"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; {d}.q[0] &= _s.q[0]; {d}.q[1] &= _s.q[1]; }}"
    if m in ("andnps", "andnpd", "pandn"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; {d}.q[0] = (~{d}.q[0]) & _s.q[0]; {d}.q[1] = (~{d}.q[1]) & _s.q[1]; }}"

    # Conversions
    if m == "cvtsi2ss":
        w = op_width(ops[1], nr) or 32
        sv = f"(int{w}_t)({read_op(ops[1], w, nr)})"
        return f"c->{REG_INFO[ops[0]][0]}.f[0] = (float)({sv});"
    if m == "cvtsi2sd":
        w = op_width(ops[1], nr) or 32
        sv = f"(int{w}_t)({read_op(ops[1], w, nr)})"
        return f"c->{REG_INFO[ops[0]][0]}.df[0] = (double)({sv});"
    if m in ("cvttss2si", "cvtss2si"):
        w = op_width(ops[0], nr) or 32
        fn = "(int64_t)" if m == "cvttss2si" else "(int64_t)llrintf"
        return f"{write_op(ops[0], w, f'(uint64_t){fn}({read_xmm_float(ops[1], nr)})', nr)};"
    if m in ("cvttsd2si", "cvtsd2si"):
        w = op_width(ops[0], nr) or 32
        fn = "(int64_t)" if m == "cvttsd2si" else "(int64_t)llrint"
        return f"{write_op(ops[0], w, f'(uint64_t){fn}({read_xmm_double(ops[1], nr)})', nr)};"
    if m == "cvtss2sd":
        return f"c->{REG_INFO[ops[0]][0]}.df[0] = (double)({read_xmm_float(ops[1], nr)});"
    if m == "cvtsd2ss":
        return f"c->{REG_INFO[ops[0]][0]}.f[0] = (float)({read_xmm_double(ops[1], nr)});"
    if m == "cvtdq2ps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {d}.f[_i] = (float)_s.sd[_i]; }}"
    if m in ("cvttps2dq", "cvtps2dq"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        fn = "(int32_t)" if m == "cvttps2dq" else "(int32_t)lrintf"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {d}.sd[_i] = {fn}(_s.f[_i]); }}"
    if m == "cvtps2pd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; {d}.df[0] = (double)_s.f[0]; {d}.df[1] = (double)_s.f[1]; }}"
    if m == "cvtdq2pd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; {d}.df[0] = (double)_s.sd[0]; {d}.df[1] = (double)_s.sd[1]; }}"
    if m == "cvtpd2ps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; {d}.f[0] = (float)_s.df[0]; {d}.f[1] = (float)_s.df[1]; {d}.q[1] = 0; }}"
    if m in ("cvttpd2dq", "cvtpd2dq"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        fn = "(int32_t)" if m == "cvttpd2dq" else "(int32_t)lrint"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; {d}.sd[0] = {fn}(_s.df[0]); {d}.sd[1] = {fn}(_s.df[1]); {d}.q[1] = 0; }}"

    # Packed integer ALU + shuffles + masks
    padd_map = {"paddb": ("b", 16, "+"), "paddw": ("w", 8, "+"), "paddd": ("d", 4, "+"), "paddq": ("q", 2, "+"),
                "psubb": ("b", 16, "-"), "psubw": ("w", 8, "-"), "psubd": ("d", 4, "-"), "psubq": ("q", 2, "-"),
                "pmullw": ("w", 8, "*"), "pmulld": ("d", 4, "*")}
    if m in padd_map:
        fld, cnt, op_c = padd_map[m]
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<{cnt}; _i++) {d}.{fld}[_i] {op_c}= _s.{fld}[_i]; }}"

    pcmpeq_map = {"pcmpeqb": ("b", 16, "0xFF"), "pcmpeqw": ("w", 8, "0xFFFF"),
                  "pcmpeqd": ("d", 4, "0xFFFFFFFFU"), "pcmpeqq": ("q", 2, "~0ULL")}
    if m in pcmpeq_map:
        fld, cnt, ones = pcmpeq_map[m]
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<{cnt}; _i++) {d}.{fld}[_i] = ({d}.{fld}[_i] == _s.{fld}[_i]) ? {ones} : 0; }}"

    pcmpgt_map = {"pcmpgtb": ("sb", "b", 16, "0xFF"), "pcmpgtw": ("sw", "w", 8, "0xFFFF"),
                  "pcmpgtd": ("sd", "d", 4, "0xFFFFFFFFU"), "pcmpgtq": ("sq", "q", 2, "~0ULL")}
    if m in pcmpgt_map:
        sfld, ufld, cnt, ones = pcmpgt_map[m]
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<{cnt}; _i++) {d}.{ufld}[_i] = ({d}.{sfld}[_i] > _s.{sfld}[_i]) ? {ones} : 0; }}"

    if m == "pmovmskb":
        s = f"c->{REG_INFO[ops[1]][0]}"
        w = op_width(ops[0], nr) or 32
        return (
            f"{{ uint32_t _m = 0; for (int _i=0; _i<16; _i++) _m |= (uint32_t)(({s}.b[_i] >> 7) & 1) << _i; "
            f"{write_op(ops[0], w, '_m', nr)}; }}"
        )
    if m == "movmskps":
        s = f"c->{REG_INFO[ops[1]][0]}"
        w = op_width(ops[0], nr) or 32
        return (
            f"{{ uint32_t _m = 0; for (int _i=0; _i<4; _i++) _m |= (uint32_t)(({s}.d[_i] >> 31) & 1) << _i; "
            f"{write_op(ops[0], w, '_m', nr)}; }}"
        )
    if m == "movmskpd":
        s = f"c->{REG_INFO[ops[1]][0]}"
        w = op_width(ops[0], nr) or 32
        return (
            f"{{ uint32_t _m = (uint32_t)((({s}.q[0] >> 63) & 1) | ((({s}.q[1] >> 63) & 1) << 1)); "
            f"{write_op(ops[0], w, '_m', nr)}; }}"
        )

    if m == "pshufd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        return (
            f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; Xmm128 _r; "
            f"_r.d[0]=_s.d[{(imm>>0)&3}]; _r.d[1]=_s.d[{(imm>>2)&3}]; "
            f"_r.d[2]=_s.d[{(imm>>4)&3}]; _r.d[3]=_s.d[{(imm>>6)&3}]; {d}=_r; }}"
        )
    if m == "pshuflw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        return (
            f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; Xmm128 _r = _s; "
            f"_r.w[0]=_s.w[{(imm>>0)&3}]; _r.w[1]=_s.w[{(imm>>2)&3}]; "
            f"_r.w[2]=_s.w[{(imm>>4)&3}]; _r.w[3]=_s.w[{(imm>>6)&3}]; {d}=_r; }}"
        )
    if m == "pshufhw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        return (
            f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; Xmm128 _r = _s; "
            f"_r.w[4]=_s.w[{4+((imm>>0)&3)}]; _r.w[5]=_s.w[{4+((imm>>2)&3)}]; "
            f"_r.w[6]=_s.w[{4+((imm>>4)&3)}]; _r.w[7]=_s.w[{4+((imm>>6)&3)}]; {d}=_r; }}"
        )
    if m == "shufps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        return (
            f"{{ Xmm128 _a = {d}; Xmm128 _b = {read_xmm128(ops[1], nr)}; Xmm128 _r; "
            f"_r.d[0]=_a.d[{(imm>>0)&3}]; _r.d[1]=_a.d[{(imm>>2)&3}]; "
            f"_r.d[2]=_b.d[{(imm>>4)&3}]; _r.d[3]=_b.d[{(imm>>6)&3}]; {d}=_r; }}"
        )
    if m == "shufpd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        return (
            f"{{ Xmm128 _a = {d}; Xmm128 _b = {read_xmm128(ops[1], nr)}; Xmm128 _r; "
            f"_r.q[0]=_a.q[{(imm>>0)&1}]; _r.q[1]=_b.q[{(imm>>1)&1}]; {d}=_r; }}"
        )
    if m == "unpcklps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (
            f"{{ Xmm128 _a = {d}; Xmm128 _b = {read_xmm128(ops[1], nr)}; "
            f"{d}.d[0]=_a.d[0]; {d}.d[1]=_b.d[0]; {d}.d[2]=_a.d[1]; {d}.d[3]=_b.d[1]; }}"
        )
    if m == "unpckhps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (
            f"{{ Xmm128 _a = {d}; Xmm128 _b = {read_xmm128(ops[1], nr)}; "
            f"{d}.d[0]=_a.d[2]; {d}.d[1]=_b.d[2]; {d}.d[2]=_a.d[3]; {d}.d[3]=_b.d[3]; }}"
        )
    if m in ("unpcklpd", "punpcklqdq"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _b = {read_xmm128(ops[1], nr)}; {d}.q[1] = _b.q[0]; }}"
    if m in ("unpckhpd", "punpckhqdq"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a = {d}; Xmm128 _b = {read_xmm128(ops[1], nr)}; {d}.q[0] = _a.q[1]; {d}.q[1] = _b.q[1]; }}"
    if m == "punpcklbw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; for (int _i=0;_i<8;_i++){{ {d}.b[_i*2]=_a.b[_i]; {d}.b[_i*2+1]=_b.b[_i]; }} }}"
    if m == "punpckhbw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; for (int _i=0;_i<8;_i++){{ {d}.b[_i*2]=_a.b[8+_i]; {d}.b[_i*2+1]=_b.b[8+_i]; }} }}"
    if m == "punpcklwd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; for (int _i=0;_i<4;_i++){{ {d}.w[_i*2]=_a.w[_i]; {d}.w[_i*2+1]=_b.w[_i]; }} }}"
    if m == "punpckhwd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; for (int _i=0;_i<4;_i++){{ {d}.w[_i*2]=_a.w[4+_i]; {d}.w[_i*2+1]=_b.w[4+_i]; }} }}"
    if m == "punpckldq":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; {d}.d[0]=_a.d[0]; {d}.d[1]=_b.d[0]; {d}.d[2]=_a.d[1]; {d}.d[3]=_b.d[1]; }}"
    if m == "punpckhdq":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; {d}.d[0]=_a.d[2]; {d}.d[1]=_b.d[2]; {d}.d[2]=_a.d[3]; {d}.d[3]=_b.d[3]; }}"
    if m == "packuswb":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}, _r; "
                f"for (int _i=0;_i<8;_i++){{ int _v=_a.sw[_i]; _r.b[_i]=(uint8_t)(_v<0?0:(_v>255?255:_v)); "
                f"_v=_b.sw[_i]; _r.b[8+_i]=(uint8_t)(_v<0?0:(_v>255?255:_v)); }} {d}=_r; }}")
    if m == "packsswb":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}, _r; "
                f"for (int _i=0;_i<8;_i++){{ int _v=_a.sw[_i]; _r.sb[_i]=(int8_t)(_v<-128?-128:(_v>127?127:_v)); "
                f"_v=_b.sw[_i]; _r.sb[8+_i]=(int8_t)(_v<-128?-128:(_v>127?127:_v)); }} {d}=_r; }}")
    if m == "packssdw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}, _r; "
                f"for (int _i=0;_i<4;_i++){{ int32_t _v=_a.sd[_i]; _r.sw[_i]=(int16_t)(_v<-32768?-32768:(_v>32767?32767:_v)); "
                f"_v=_b.sd[_i]; _r.sw[4+_i]=(int16_t)(_v<-32768?-32768:(_v>32767?32767:_v)); }} {d}=_r; }}")
    if m == "packusdw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}, _r; "
                f"for (int _i=0;_i<4;_i++){{ int32_t _v=_a.sd[_i]; _r.w[_i]=(uint16_t)(_v<0?0:(_v>65535?65535:_v)); "
                f"_v=_b.sd[_i]; _r.w[4+_i]=(uint16_t)(_v<0?0:(_v>65535?65535:_v)); }} {d}=_r; }}")
    if m == "pmaddwd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}, _r; "
                f"for (int _i=0;_i<4;_i++) _r.sd[_i]=(int32_t)_a.sw[_i*2]*_b.sw[_i*2]+(int32_t)_a.sw[_i*2+1]*_b.sw[_i*2+1]; {d}=_r; }}")
    if m == "pmuludq":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; {d}.q[0]=(uint64_t)_a.d[0]*_b.d[0]; {d}.q[1]=(uint64_t)_a.d[2]*_b.d[2]; }}"
    if m == "pmulhw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; for (int _i=0;_i<8;_i++) {d}.sw[_i]=(int16_t)(((int32_t)_a.sw[_i]*_b.sw[_i])>>16); }}"
    if m == "pmulhuw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _a={d}, _b={read_xmm128(ops[1], nr)}; for (int _i=0;_i<8;_i++) {d}.w[_i]=(uint16_t)(((uint32_t)_a.w[_i]*_b.w[_i])>>16); }}"
    pminmax = {
        "pminub": ("b", 16, "<"), "pmaxub": ("b", 16, ">"),
        "pminsb": ("sb", 16, "<"), "pmaxsb": ("sb", 16, ">"),
        "pminuw": ("w", 8, "<"), "pmaxuw": ("w", 8, ">"),
        "pminsw": ("sw", 8, "<"), "pmaxsw": ("sw", 8, ">"),
        "pminud": ("d", 4, "<"), "pmaxud": ("d", 4, ">"),
        "pminsd": ("sd", 4, "<"), "pmaxsd": ("sd", 4, ">"),
    }
    if m in pminmax:
        fld, cnt, cmp = pminmax[m]
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s={read_xmm128(ops[1], nr)}; for (int _i=0;_i<{cnt};_i++) {d}.{fld}[_i]=({d}.{fld}[_i] {cmp} _s.{fld}[_i])?{d}.{fld}[_i]:_s.{fld}[_i]; }}"
    if m in ("pabsb", "pabsw", "pabsd"):
        sf, uf, cnt = {"pabsb": ("sb", "b", 16), "pabsw": ("sw", "w", 8), "pabsd": ("sd", "d", 4)}[m]
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s={read_xmm128(ops[1], nr)}; for (int _i=0;_i<{cnt};_i++){{ int64_t _v=_s.{sf}[_i]; {d}.{uf}[_i]=(_v<0)?-_v:_v; }} }}"
    psat = {
        "paddusb": ("b", 16, 1, 0, 255), "psubusb": ("b", 16, -1, 0, 255),
        "paddusw": ("w", 8, 1, 0, 65535), "psubusw": ("w", 8, -1, 0, 65535),
        "paddsb": ("sb", 16, 1, -128, 127), "psubsb": ("sb", 16, -1, -128, 127),
        "paddsw": ("sw", 8, 1, -32768, 32767), "psubsw": ("sw", 8, -1, -32768, 32767),
    }
    if m in psat:
        fld, cnt, sgn, lo, hi = psat[m]
        d = f"c->{REG_INFO[ops[0]][0]}"
        op_c = "+" if sgn > 0 else "-"
        return f"{{ Xmm128 _s={read_xmm128(ops[1], nr)}; for (int _i=0;_i<{cnt};_i++){{ int32_t _v=(int32_t){d}.{fld}[_i] {op_c} (int32_t)_s.{fld}[_i]; {d}.{fld}[_i]=_v<{lo}?{lo}:(_v>{hi}?{hi}:_v); }} }}"
    if m in ("pslldq", "psrldq"):
        d = f"c->{REG_INFO[ops[0]][0]}"
        cnt = parse_imm(ops[1])
        if m == "pslldq":
            return f"{{ Xmm128 _a={d}; memset(&{d},0,16); for (int _i={cnt};_i<16;_i++) {d}.b[_i]=_a.b[_i-{cnt}]; }}"
        return f"{{ Xmm128 _a={d}; memset(&{d},0,16); for (int _i=0;_i<16-{cnt};_i++) {d}.b[_i]=_a.b[_i+{cnt}]; }}"
    if m in ("psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq"):
        is_l = m.startswith("psll")
        sz = m[-1]
        cnt_map = {"w": (8, 16), "d": (4, 32), "q": (2, 64)}
        lanes, bits = cnt_map[sz]
        d = f"c->{REG_INFO[ops[0]][0]}"
        sh = f"{parse_imm(ops[1])}U" if parse_imm(ops[1]) is not None else f"(unsigned)({read_xmm128(ops[1], nr)}.q[0])"
        op_s = "<<" if is_l else ">>"
        return f"{{ unsigned _sh = {sh}; for (int _i=0; _i<{lanes}; _i++) {d}.{sz}[_i] = (_sh >= {bits}) ? 0 : ({d}.{sz}[_i] {op_s} _sh); }}"
    if m in ("psraw", "psrad"):
        sz = m[-1]
        lanes, bits, sf = (8, 16, "sw") if sz == "w" else (4, 32, "sd")
        d = f"c->{REG_INFO[ops[0]][0]}"
        sh = f"{parse_imm(ops[1])}U" if parse_imm(ops[1]) is not None else f"(unsigned)({read_xmm128(ops[1], nr)}.q[0])"
        return f"{{ unsigned _sh = {sh}; if (_sh >= {bits}) _sh = {bits - 1}; for (int _i=0; _i<{lanes}; _i++) {d}.{sf}[_i] >>= _sh; }}"
    if m == "pshufb":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (
            f"{{ Xmm128 _a = {d}, _m = {read_xmm128(ops[1], nr)}, _r; "
            f"for (int _i=0; _i<16; _i++) _r.b[_i] = (_m.b[_i] & 0x80) ? 0 : _a.b[_m.b[_i] & 0xF]; {d} = _r; }}"
        )
    if m == "palignr":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        return (
            f"{{ Xmm128 _a = {d}, _b = {read_xmm128(ops[1], nr)}, _r; uint8_t _cat[32]; "
            f"memcpy(_cat, _b.b, 16); memcpy(_cat + 16, _a.b, 16); "
            f"for (int _i=0; _i<16; _i++) _r.b[_i] = (_i + {imm} < 32) ? _cat[_i + {imm}] : 0; {d} = _r; }}"
        )
    if m == "ptest":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (
            f"{{ Xmm128 _a = {d}, _b = {read_xmm128(ops[1], nr)}; "
            f"c->zf = (((_a.q[0] & _b.q[0]) | (_a.q[1] & _b.q[1])) == 0); "
            f"c->cf = ((((~_a.q[0]) & _b.q[0]) | ((~_a.q[1]) & _b.q[1])) == 0); c->of = c->sf = c->pf = c->af = 0; }}"
        )
    if m in ("roundss", "roundsd"):
        is_d = (m == "roundsd")
        imm = parse_imm(ops[2]) & 3
        fn = {0: "rint", 1: "floor", 2: "ceil", 3: "trunc"}[imm]
        if is_d:
            return f"c->{REG_INFO[ops[0]][0]}.df[0] = {fn}({read_xmm_double(ops[1], nr)});"
        return f"c->{REG_INFO[ops[0]][0]}.f[0] = {fn}f({read_xmm_float(ops[1], nr)});"
    if m == "blendvps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        msk = f"c->{REG_INFO[ops[2]][0]}" if len(ops) > 2 else "c->xmm[0]"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) if ({msk}.d[_i] >> 31) {d}.d[_i] = _s.d[_i]; }}"
    if m == "pblendw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<8; _i++) if (({imm} >> _i) & 1) {d}.w[_i] = _s.w[_i]; }}"
    if m in ("pextrb", "pextrw", "pextrd", "pextrq"):
        fld, bits, mask = {"pextrb": ("b", 8, 15), "pextrw": ("w", 16, 7), "pextrd": ("d", 32, 3), "pextrq": ("q", 64, 1)}[m]
        s = f"c->{REG_INFO[ops[1]][0]}"
        idx = parse_imm(ops[2]) & mask
        dw = op_width(ops[0], nr) or (64 if bits == 64 else 32)
        return f"{write_op(ops[0], dw, f'{s}.{fld}[{idx}]', nr)};"
    if m in ("pinsrb", "pinsrw", "pinsrd", "pinsrq"):
        fld, bits, mask = {"pinsrb": ("b", 8, 15), "pinsrw": ("w", 16, 7), "pinsrd": ("d", 32, 3), "pinsrq": ("q", 64, 1)}[m]
        d = f"c->{REG_INFO[ops[0]][0]}"
        idx = parse_imm(ops[2]) & mask
        return f"{d}.{fld}[{idx}] = (uint{bits}_t)({read_op(ops[1], bits, nr)});"
    if m in ("pmovzxbw", "pmovzxbd", "pmovzxwd", "pmovzxbq", "pmovzxwq", "pmovzxdq",
             "pmovsxbw", "pmovsxbd", "pmovsxwd", "pmovsxbq", "pmovsxwq", "pmovsxdq"):
        is_sx = m.startswith("pmovsx")
        kind = m[6:]
        spec = {
            "bw": ("sb" if is_sx else "b", "w", "int16_t" if is_sx else "uint16_t", 8, 8),
            "bd": ("sb" if is_sx else "b", "d", "int32_t" if is_sx else "uint32_t", 4, 4),
            "wd": ("sw" if is_sx else "w", "d", "int32_t" if is_sx else "uint32_t", 4, 8),
            "bq": ("sb" if is_sx else "b", "q", "int64_t" if is_sx else "uint64_t", 2, 2),
            "wq": ("sw" if is_sx else "w", "q", "int64_t" if is_sx else "uint64_t", 2, 4),
            "dq": ("sd" if is_sx else "d", "q", "int64_t" if is_sx else "uint64_t", 2, 8),
        }[kind]
        sf, df, cast_t, cnt, nbytes = spec
        d = f"c->{REG_INFO[ops[0]][0]}"
        mm = parse_mem(ops[1], nr)
        if mm is not None:
            return f"{{ Xmm128 _s; memset(&_s, 0, 16); memcpy(&_s, (const void *)(uintptr_t)({mm[1]}), {nbytes}); Xmm128 _r; memset(&_r, 0, 16); for (int _i=0; _i<{cnt}; _i++) _r.{df}[_i] = (uint64_t)({cast_t})_s.{sf}[_i]; {d} = _r; }}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; Xmm128 _r; memset(&_r, 0, 16); for (int _i=0; _i<{cnt}; _i++) _r.{df}[_i] = (uint64_t)({cast_t})_s.{sf}[_i]; {d} = _r; }}"
    cmp_preds = {
        "eq": "(_a == _b)", "lt": "(_a < _b)", "le": "(_a <= _b)",
        "unord": "(isnan(_a) || isnan(_b))", "neq": "!(_a == _b)",
        "nlt": "!(_a < _b)", "nle": "!(_a <= _b)", "ord": "(!isnan(_a) && !isnan(_b))",
    }
    if m.startswith("cmp") and len(m) >= 7 and m[-2:] in ("ps", "pd", "ss", "sd") and m[3:-2] in cmp_preds:
        pred = cmp_preds[m[3:-2]]
        suf = m[-2:]
        d = f"c->{REG_INFO[ops[0]][0]}"
        if suf == "ps":
            return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {{ float _a = {d}.f[_i], _b = _s.f[_i]; {d}.d[_i] = {pred} ? 0xFFFFFFFFU : 0U; }} }}"
        if suf == "pd":
            return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<2; _i++) {{ double _a = {d}.df[_i], _b = _s.df[_i]; {d}.q[_i] = {pred} ? ~0ULL : 0ULL; }} }}"
        if suf == "ss":
            return f"{{ float _a = {d}.f[0], _b = {read_xmm_float(ops[1], nr)}; {d}.d[0] = {pred} ? 0xFFFFFFFFU : 0U; }}"
        return f"{{ double _a = {d}.df[0], _b = {read_xmm_double(ops[1], nr)}; {d}.q[0] = {pred} ? ~0ULL : 0ULL; }}"
    if m == "pblendvb":
        d = f"c->{REG_INFO[ops[0]][0]}"
        msk = f"c->{REG_INFO[ops[2]][0]}" if len(ops) > 2 else "c->xmm[0]"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<16; _i++) if ({msk}.b[_i] & 0x80) {d}.b[_i] = _s.b[_i]; }}"
    if m == "blendvpd":
        d = f"c->{REG_INFO[ops[0]][0]}"
        msk = f"c->{REG_INFO[ops[2]][0]}" if len(ops) > 2 else "c->xmm[0]"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<2; _i++) if ({msk}.q[_i] >> 63) {d}.q[_i] = _s.q[_i]; }}"
    if m in ("roundps", "roundpd"):
        imm = parse_imm(ops[2]) & 3
        fn = {0: "rint", 1: "floor", 2: "ceil", 3: "trunc"}[imm]
        d = f"c->{REG_INFO[ops[0]][0]}"
        if m == "roundps":
            return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<4; _i++) {d}.f[_i] = {fn}f(_s.f[_i]); }}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<2; _i++) {d}.df[_i] = {fn}(_s.df[_i]); }}"
    if m == "dpps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; float _sum = 0.0f; for (int _i=0; _i<4; _i++) if (({imm} >> (4 + _i)) & 1) _sum += {d}.f[_i] * _s.f[_i]; for (int _i=0; _i<4; _i++) {d}.f[_i] = (({imm} >> _i) & 1) ? _sum : 0.0f; }}"
    if m == "insertps":
        d = f"c->{REG_INFO[ops[0]][0]}"
        imm = parse_imm(ops[2])
        src_lane = (imm >> 6) & 3
        dst_lane = (imm >> 4) & 3
        zmask = imm & 0xF
        mm = parse_mem(ops[1], nr)
        src_e = f"({read_xmm_float(ops[1], nr)})" if mm is not None else f"c->{REG_INFO[ops[1]][0]}.f[{src_lane}]"
        return f"{{ float _v = {src_e}; {d}.f[{dst_lane}] = _v; for (int _i=0; _i<4; _i++) if (({zmask} >> _i) & 1) {d}.f[_i] = 0.0f; }}"
    if m == "extractps":
        s = f"c->{REG_INFO[ops[1]][0]}"
        idx = parse_imm(ops[2]) & 3
        return f"{write_op(ops[0], 32, f'{s}.d[{idx}]', nr)};"
    if m in ("pavgb", "pavgw"):
        fld, cnt, ct = ("b", 16, "uint8_t") if m == "pavgb" else ("w", 8, "uint16_t")
        d = f"c->{REG_INFO[ops[0]][0]}"
        return f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; for (int _i=0; _i<{cnt}; _i++) {d}.{fld}[_i] = ({ct})(((uint32_t){d}.{fld}[_i] + (uint32_t)_s.{fld}[_i] + 1U) >> 1); }}"
    if m == "psadbw":
        d = f"c->{REG_INFO[ops[0]][0]}"
        return (
            f"{{ Xmm128 _s = {read_xmm128(ops[1], nr)}; uint16_t _s0 = 0, _s1 = 0; "
            f"for (int _i=0; _i<8; _i++) {{ int _d0 = (int){d}.b[_i] - (int)_s.b[_i]; _s0 += (uint16_t)(_d0 < 0 ? -_d0 : _d0); "
            f"int _d1 = (int){d}.b[_i+8] - (int)_s.b[_i+8]; _s1 += (uint16_t)(_d1 < 0 ? -_d1 : _d1); }} "
            f"{d}.q[0] = _s0; {d}.q[1] = _s1; }}"
        )
    if m == "pcmpistri":
        imm = parse_imm(ops[2])
        return f"f_pcmpistri(c, c->{REG_INFO[ops[0]][0]}, {read_xmm128(ops[1], nr)}, 0x{imm & 0xFF:x}U);"
    if m == "stmxcsr":
        mm = parse_mem(ops[0], nr)
        return f"W32({mm[1]}, c->mxcsr);"
    if m == "ldmxcsr":
        mm = parse_mem(ops[0], nr)
        return f"c->mxcsr = R32({mm[1]});"
    return None


def _parse_fpu_st(op: str) -> Optional[int]:
    op = op.strip().lower()
    if op == "st":
        return 0
    if op.startswith("st(") and op.endswith(")") and op[3:-1].isdigit():
        return int(op[3:-1])
    return None


def _read_fpu_mem(op: str, nr: int) -> Optional[str]:
    mm = parse_mem(op, nr)
    if mm is None:
        return None
    w, addr = mm
    if w == 80 or "tbyte" in op:
        return f"fpu_read80({addr})"
    if w == 64 or "qword" in op:
        return f"({{ uint64_t _u = R64({addr}); double _d; memcpy(&_d, &_u, 8); _d; }})"
    return f"({{ uint32_t _u = R32({addr}); float _f; memcpy(&_f, &_u, 4); (double)_f; }})"


def lift_x87(insn: Insn) -> Optional[str]:
    m, ops, nr = insn.mnemonic, insn.ops, insn.next_addr

    if m == "fldz":
        return "fpu_push(c, 0.0);"
    if m == "fld1":
        return "fpu_push(c, 1.0);"
    if m == "fldpi":
        return "fpu_push(c, 3.14159265358979323846);"
    if m == "fldl2e":
        return "fpu_push(c, 1.44269504088896340736);"
    if m == "fldl2t":
        return "fpu_push(c, 3.32192809488736234787);"
    if m == "fldlg2":
        return "fpu_push(c, 0.30102999566398119521);"
    if m == "fldln2":
        return "fpu_push(c, 0.69314718055994530942);"

    if m == "fild":
        mm = parse_mem(ops[0], nr)
        if mm is not None:
            w, addr = mm
            w = w or 32
            return f"fpu_push(c, (double)(int{w}_t)R{w}({addr}));"
        return None

    if m in ("fist", "fistp", "fisttp"):
        mm = parse_mem(ops[0], nr)
        if mm is not None:
            w, addr = mm
            w = w or 32
            pop_s = " fpu_pop(c);" if m != "fist" else ""
            conv = "(int64_t)trunc(*fpu_st(c, 0))" if m == "fisttp" else "(int64_t)llrint(*fpu_st(c, 0))"
            return f"{{ int{w}_t _iv = (int{w}_t)({conv}); W{w}({addr}, (uint{w}_t)_iv);{pop_s} }}"
        return None

    if m == "fld":
        st = _parse_fpu_st(ops[0])
        if st is not None:
            return f"fpu_push(c, *fpu_st(c, {st}));"
        me = _read_fpu_mem(ops[0], nr)
        if me is not None:
            return f"fpu_push(c, {me});"
        return None

    if m in ("fst", "fstp"):
        pop_s = " fpu_pop(c);" if m == "fstp" else ""
        st = _parse_fpu_st(ops[0])
        if st is not None:
            if st == 0 and m == "fstp":
                return "fpu_pop(c);"
            return f"*fpu_st(c, {st}) = *fpu_st(c, 0);{pop_s}"
        mm = parse_mem(ops[0], nr)
        if mm is not None:
            w, addr = mm
            if w == 80 or "tbyte" in ops[0]:
                return f"fpu_write80({addr}, *fpu_st(c, 0));{pop_s}"
            if w == 64 or "qword" in ops[0]:
                return f"{{ double _d = *fpu_st(c, 0); uint64_t _u; memcpy(&_u, &_d, 8); W64({addr}, _u);{pop_s} }}"
            return f"{{ float _f = (float)*fpu_st(c, 0); uint32_t _u; memcpy(&_u, &_f, 4); W32({addr}, _u);{pop_s} }}"
        return None

    if m == "fxch":
        idx = _parse_fpu_st(ops[0]) if ops else 1
        if idx is None:
            idx = 1
        return f"{{ double _t = *fpu_st(c, 0); *fpu_st(c, 0) = *fpu_st(c, {idx}); *fpu_st(c, {idx}) = _t; }}"

    if m == "fabs":
        return "*fpu_st(c, 0) = fabs(*fpu_st(c, 0));"
    if m == "fchs":
        return "*fpu_st(c, 0) = -(*fpu_st(c, 0));"
    if m == "fsqrt":
        return "*fpu_st(c, 0) = sqrt(*fpu_st(c, 0));"
    if m == "fcos":
        return "*fpu_st(c, 0) = cos(*fpu_st(c, 0)); c->fpu_sw &= ~0x0400U;"
    if m == "fsin":
        return "*fpu_st(c, 0) = sin(*fpu_st(c, 0)); c->fpu_sw &= ~0x0400U;"
    if m == "frndint":
        return "*fpu_st(c, 0) = rint(*fpu_st(c, 0));"
    if m == "fscale":
        return "*fpu_st(c, 0) = ldexp(*fpu_st(c, 0), (int)trunc(*fpu_st(c, 1)));"
    if m == "f2xm1":
        return "*fpu_st(c, 0) = exp2(*fpu_st(c, 0)) - 1.0;"
    if m == "fyl2x":
        return "{ double _x = fpu_pop(c); *fpu_st(c, 0) *= log2(_x); }"
    if m == "fyl2xp1":
        return "{ double _x = fpu_pop(c); *fpu_st(c, 0) *= log2(_x + 1.0); }"
    if m == "fprem1":
        return "{ double _d = *fpu_st(c, 1); *fpu_st(c, 0) = remainder(*fpu_st(c, 0), _d); c->fpu_sw &= ~0x4700U; }"
    if m == "fprem":
        return "{ double _d = *fpu_st(c, 1); *fpu_st(c, 0) = fmod(*fpu_st(c, 0), _d); c->fpu_sw &= ~0x4700U; }"
    if m == "fxam":
        return "fpu_fxam(c, *fpu_st(c, 0));"

    if m in ("fadd", "faddp", "fsub", "fsubp", "fsubr", "fsubrp", "fmul", "fmulp", "fdiv", "fdivp", "fdivr", "fdivrp"):
        is_pop = m.endswith("p")
        base_m = m[:-1] if is_pop else m
        op_c = {"fadd": "+", "fsub": "-", "fsubr": "r-", "fmul": "*", "fdiv": "/", "fdivr": "r/"}[base_m]
        if not ops:
            dst_i, src_e = 1, "*fpu_st(c, 0)"
        elif len(ops) == 1:
            st = _parse_fpu_st(ops[0])
            if st is not None:
                dst_i, src_e = (st, "*fpu_st(c, 0)") if is_pop else (0, f"*fpu_st(c, {st})")
            else:
                me = _read_fpu_mem(ops[0], nr)
                if me is None:
                    return None
                dst_i, src_e = 0, me
        else:
            d_st = _parse_fpu_st(ops[0])
            s_st = _parse_fpu_st(ops[1])
            if d_st is None or s_st is None:
                return None
            dst_i, src_e = d_st, f"*fpu_st(c, {s_st})"
        pop_s = " fpu_pop(c);" if is_pop else ""
        if op_c == "r-":
            return f"{{ double _a = *fpu_st(c, {dst_i}), _b = {src_e}; *fpu_st(c, {dst_i}) = _b - _a;{pop_s} }}"
        if op_c == "r/":
            return f"{{ double _a = *fpu_st(c, {dst_i}), _b = {src_e}; *fpu_st(c, {dst_i}) = _b / _a;{pop_s} }}"
        return f"{{ double _a = *fpu_st(c, {dst_i}), _b = {src_e}; *fpu_st(c, {dst_i}) = _a {op_c} _b;{pop_s} }}"

    if m in ("fcom", "fcomp", "fucom", "fucomp"):
        is_pop = m.endswith("p")
        pop_s = " fpu_pop(c);" if is_pop else ""
        if not ops:
            rhs = "*fpu_st(c, 1)"
        else:
            st = _parse_fpu_st(ops[0])
            rhs = f"*fpu_st(c, {st})" if st is not None else _read_fpu_mem(ops[0], nr)
            if rhs is None:
                return None
        return f"fpu_com(c, *fpu_st(c, 0), {rhs});{pop_s}"

    if m in ("fcomi", "fcomip", "fucomi", "fucompi"):
        is_pop = m.endswith("pi") or m.endswith("ip")
        pop_s = " fpu_pop(c);" if is_pop else ""
        st = _parse_fpu_st(ops[-1]) if ops else 1
        if st is None:
            st = 1
        return f"f_ucomi_d(c, *fpu_st(c, 0), *fpu_st(c, {st}));{pop_s}"

    if m == "fldenv":
        mm = parse_mem(ops[0], nr)
        if mm is not None:
            return f"c->fpu_cw = R16({mm[1]}); c->fpu_sw = R16(({mm[1]}) + 4);"
    if m in ("fnstenv", "fstenv"):
        mm = parse_mem(ops[0], nr)
        if mm is not None:
            return f"memset((void *)(uintptr_t)({mm[1]}), 0, 28); W16({mm[1]}, c->fpu_cw ? c->fpu_cw : 0x037FU); W16(({mm[1]}) + 4, c->fpu_sw);"
    return None


def lift_insn(insn: Insn, local_addrs: Set[int], has_ind_jmp: bool, unimpl: List[str]) -> str:
    m, ops, pfx, nr = insn.mnemonic, insn.ops, insn.prefix, insn.next_addr

    if m in ("nop", "endbr64", "endbr32", "rdsspq", "rdsspd", "incsspq", "incsspd",
             "pause", "mfence", "lfence", "sfence",
             "prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta", "prefetchw",
             "prefetchit0", "prefetchit1", "vzeroupper", "<unknown>",
             "fldcw", "fnclex", "fclex", "fninit", "finit", "fwait", "wait", "emms"):
        return "/* nop */"
    if m in ("fnstcw", "fstcw"):
        return f"{write_op(ops[0], 16, 'c->fpu_cw ? c->fpu_cw : 0x037FU', nr)};"
    if m in ("fnstsw", "fstsw"):
        return f"{write_op(ops[0], 16, 'c->fpu_sw', nr)};"
    if m in ("rdrand", "rdseed"):
        w = op_width(ops[0], nr) or 32
        return (
            f"{{ uint64_t _rn = 0; arc4random_buf(&_rn, sizeof(_rn)); "
            f"{write_op(ops[0], w, '_rn', nr)}; c->cf = 1; c->of = c->sf = c->zf = c->af = c->pf = 0; }}"
        )
    if m == "xgetbv":
        return "SET32(c->rax, 0x3U); SET32(c->rdx, 0U);"
    if m == "int":
        return f'fprintf(stderr, "elf64-recomp: guest int {ops[0] if ops else 0} (__fastfail rcx=%llu) at 0x{insn.addr:x}\\n", (unsigned long long)c->rcx); abort();'
    if m == "cld":
        return "c->df = 0;"
    if m == "std":
        return "c->df = 1;"
    if m == "clc":
        return "c->cf = 0;"
    if m == "stc":
        return "c->cf = 1;"
    if m == "cmc":
        return "c->cf ^= 1;"
    if m in ("ud2", "int3", "hlt"):
        return f'fprintf(stderr, "elf64-recomp: trap {m} at 0x{insn.addr:x}\\n"); abort();'

    # Stack
    if m == "push":
        w = op_width(ops[0], nr) or 64
        v = sign_ext_expr(read_op(ops[0], w, nr), w) if w < 64 else read_op(ops[0], 64, nr)
        return f"push64(c, {v});"
    if m == "pop":
        return f"{write_op(ops[0], 64, 'pop64(c)', nr)};"
    if m == "leave":
        return "c->rsp = c->rbp; c->rbp = pop64(c);"

    # Control flow
    if m == "ret":
        imm = parse_imm(ops[0]) if ops else 0
        if imm:
            return f"c->rip = pop64(c); c->rsp += 0x{imm & 0xFFFF:x}ULL; return;"
        return "c->rip = pop64(c); return;"

    if m == "call":
        t = parse_imm(ops[0])
        if t is not None:
            return f"push64(c, 0x{nr:x}ULL); rt_call(c, 0x{t:x}ULL); if (c->halted) return;"
        target_expr = read_op(ops[0], 64, nr)
        return f"{{ uint64_t _t = {target_expr}; push64(c, 0x{nr:x}ULL); rt_call(c, _t); if (c->halted) return; }}"

    if m == "jmp":
        t = parse_imm(ops[0])
        if t is not None:
            if t in local_addrs:
                return f"goto L_{t:x};"
            return f"rt_tailcall(c, 0x{t:x}ULL); return;"
        target_expr = read_op(ops[0], 64, nr)
        if has_ind_jmp:
            return f"{{ _ind_target = {target_expr}; goto L_ind_dispatch; }}"
        return f"rt_tailcall(c, {target_expr}); return;"

    if m.startswith("j") and m[1:] in CC_EXPR:
        cc = CC_EXPR[m[1:]]
        t = parse_imm(ops[0])
        if t in local_addrs:
            return f"if ({cc}) goto L_{t:x};"
        return f"if ({cc}) {{ rt_tailcall(c, 0x{t:x}ULL); return; }}"

    if m in ("jecxz", "jrcxz"):
        cond = "(GET32(c->rcx) == 0)" if m == "jecxz" else "(c->rcx == 0)"
        t = parse_imm(ops[0])
        if t in local_addrs:
            return f"if ({cond}) goto L_{t:x};"
        return f"if ({cond}) {{ rt_tailcall(c, 0x{t:x}ULL); return; }}"

    if m.startswith("set") and m[3:] in CC_EXPR:
        return f"{write_op(ops[0], 8, f'({CC_EXPR[m[3:]]}) ? 1ULL : 0ULL', nr)};"

    if m.startswith("cmov") and m[4:] in CC_EXPR:
        w = infer_width(ops, nr, 64)
        src = read_op(ops[1], w, nr)
        # Note: in x86_64, 32-bit cmovcc ALWAYS zeroes upper 32 bits of dst reg even if condition is false!
        if w == 32 and ops[0] in REG_INFO:
            return f"if ({CC_EXPR[m[4:]]}) {{ {write_op(ops[0], 32, src, nr)}; }} else {{ {write_op(ops[0], 32, read_op(ops[0], 32, nr), nr)}; }}"
        return f"if ({CC_EXPR[m[4:]]}) {{ {write_op(ops[0], w, src, nr)}; }}"

    # Data movement
    if m in ("mov", "movabs", "movnti"):
        w = infer_width(ops, nr, 64)
        return f"{write_op(ops[0], w, read_op(ops[1], w, nr), nr)};"
    if m == "movzx":
        dw = op_width(ops[0], nr) or 32
        sw = op_width(ops[1], nr) or 8
        return f"{write_op(ops[0], dw, read_op(ops[1], sw, nr), nr)};"
    if m in ("movsx", "movsxd"):
        dw = op_width(ops[0], nr) or 64
        sw = op_width(ops[1], nr) or (32 if m == "movsxd" else 8)
        return f"{write_op(ops[0], dw, sign_ext_expr(read_op(ops[1], sw, nr), sw), nr)};"
    if m == "lea":
        dw = op_width(ops[0], nr) or 64
        mm = parse_mem(ops[1], nr)
        return f"{write_op(ops[0], dw, mm[1], nr)};"
    if m == "xchg":
        w = infer_width(ops, nr, 64)
        if ops[0] == ops[1]:
            return f"{write_op(ops[0], w, read_op(ops[0], w, nr), nr)};"
        return (
            f"{{ uint64_t _a = {read_op(ops[0], w, nr)}, _b = {read_op(ops[1], w, nr)}; "
            f"{write_op(ops[0], w, '_b', nr)}; {write_op(ops[1], w, '_a', nr)}; }}"
        )
    if m == "bswap":
        w = op_width(ops[0], nr) or 32
        v = read_op(ops[0], w, nr)
        fn = "__builtin_bswap64" if w == 64 else "__builtin_bswap32"
        return f"{write_op(ops[0], w, f'{fn}({v})', nr)};"
    if m in ("cbw", "cbtw"):
        return "SET16(c->rax, (int16_t)(int8_t)GET8L(c->rax));"
    if m == "cwde":
        return "SET32(c->rax, (int32_t)(int16_t)GET16(c->rax));"
    if m in ("cdqe", "cltq"):
        return "c->rax = (uint64_t)(int64_t)(int32_t)GET32(c->rax);"
    if m == "cwd":
        return "SET16(c->rdx, ((int16_t)GET16(c->rax) < 0) ? 0xFFFF : 0);"
    if m == "cdq":
        return "SET32(c->rdx, ((int32_t)GET32(c->rax) < 0) ? 0xFFFFFFFFU : 0U);"
    if m in ("cqo", "cqto"):
        return "c->rdx = ((int64_t)c->rax < 0) ? ~0ULL : 0ULL;"

    # Atomics (lock prefix or cmpxchg/xadd)
    if m == "cmpxchg16b":
        mm = parse_mem(ops[0], nr)
        return (
            f"{{ __uint128_t _exp = ((__uint128_t)c->rdx << 64) | c->rax; "
            f"__uint128_t _des = ((__uint128_t)c->rcx << 64) | c->rbx; "
            f"int _ok = __atomic_compare_exchange_n((__uint128_t *)(uintptr_t)({mm[1]}), &_exp, _des, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); "
            f"c->zf = (uint8_t)_ok; if (!_ok) {{ c->rax = (uint64_t)_exp; c->rdx = (uint64_t)(_exp >> 64); }} }}"
        )
    if m == "cmpxchg8b":
        mm = parse_mem(ops[0], nr)
        return (
            f"{{ uint64_t _exp = ((uint64_t)GET32(c->rdx) << 32) | GET32(c->rax); "
            f"uint64_t _des = ((uint64_t)GET32(c->rcx) << 32) | GET32(c->rbx); "
            f"int _ok = __atomic_compare_exchange_n((uint64_t *)(uintptr_t)({mm[1]}), &_exp, _des, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); "
            f"c->zf = (uint8_t)_ok; if (!_ok) {{ SET32(c->rax, _exp); SET32(c->rdx, _exp >> 32); }} }}"
        )
    if m == "cmpxchg":
        w = infer_width(ops, nr, 64)
        mm = parse_mem(ops[0], nr)
        acc = {8: "GET8L(c->rax)", 16: "GET16(c->rax)", 32: "GET32(c->rax)", 64: "c->rax"}[w]
        acc_set = {8: "SET8L(c->rax, _old)", 16: "SET16(c->rax, _old)", 32: "SET32(c->rax, _old)", 64: "c->rax = _old"}[w]
        src = read_op(ops[1], w, nr)
        if mm is not None and pfx == "lock":
            ct = f"uint{w}_t"
            return (
                f"{{ {ct} _exp = ({ct})({acc}), _des = ({ct})({src}); "
                f"int _ok = __atomic_compare_exchange_n(({ct} *)(uintptr_t)({mm[1]}), &_exp, _des, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); "
                f"f_sub(c, {acc}, _exp, {w}); if (!_ok) {{ uint64_t _old = _exp; {acc_set}; }} }}"
            )
        return (
            f"{{ uint64_t _old = {read_op(ops[0], w, nr)}; f_sub(c, {acc}, _old, {w}); "
            f"if (c->zf) {{ {write_op(ops[0], w, src, nr)}; }} else {{ {acc_set}; }} }}"
        )
    if m == "xadd":
        w = infer_width(ops, nr, 64)
        mm = parse_mem(ops[0], nr)
        src = read_op(ops[1], w, nr)
        if mm is not None and pfx == "lock":
            ct = f"uint{w}_t"
            return (
                f"{{ {ct} _s = ({ct})({src}); {ct} _old = __atomic_fetch_add(({ct} *)(uintptr_t)({mm[1]}), _s, __ATOMIC_SEQ_CST); "
                f"f_add(c, _old, _s, {w}); {write_op(ops[1], w, '_old', nr)}; }}"
            )
        return (
            f"{{ uint64_t _a = {read_op(ops[0], w, nr)}, _b = {src}; "
            f"uint64_t _r = f_add(c, _a, _b, {w}); {write_op(ops[0], w, '_r', nr)}; {write_op(ops[1], w, '_a', nr)}; }}"
        )

    # Integer ALU (with lock atomic support for add/sub/and/or/xor/inc/dec on memory)
    if m in ("add", "adc", "sub", "sbb", "and", "or", "xor"):
        w = infer_width(ops, nr, 64)
        if m == "xor" and ops[0] == ops[1] and ops[0] in REG_INFO:
            return f"{write_op(ops[0], w, '0ULL', nr)}; c->cf=0; c->of=0; c->zf=1; c->sf=0; c->pf=1;"
        mm = parse_mem(ops[0], nr)
        src = read_op(ops[1], w, nr)
        if pfx == "lock" and mm is not None and m in ("add", "sub", "and", "or", "xor"):
            ct = f"uint{w}_t"
            atomic_fn = {"add": "__atomic_fetch_add", "sub": "__atomic_fetch_sub",
                         "and": "__atomic_fetch_and", "or": "__atomic_fetch_or", "xor": "__atomic_fetch_xor"}[m]
            flag_stmt = {
                "add": f"f_add(c, _old, _s, {w});",
                "sub": f"f_sub(c, _old, _s, {w});",
                "and": f"f_logic(c, _old & _s, {w});",
                "or":  f"f_logic(c, _old | _s, {w});",
                "xor": f"f_logic(c, _old ^ _s, {w});",
            }[m]
            return f"{{ {ct} _s = ({ct})({src}); {ct} _old = {atomic_fn}(({ct} *)(uintptr_t)({mm[1]}), _s, __ATOMIC_SEQ_CST); {flag_stmt} }}"
        a = read_op(ops[0], w, nr)
        if m in ("add", "adc", "sub", "sbb"):
            return f"{{ uint64_t _r = f_{m}(c, {a}, {src}, {w}); {write_op(ops[0], w, '_r', nr)}; }}"
        op_c = {"and": "&", "or": "|", "xor": "^"}[m]
        return f"{{ uint64_t _r = f_logic(c, ({a}) {op_c} ({src}), {w}); {write_op(ops[0], w, '_r', nr)}; }}"

    if m in ("inc", "dec"):
        w = infer_width(ops, nr, 64)
        mm = parse_mem(ops[0], nr)
        if pfx == "lock" and mm is not None:
            ct = f"uint{w}_t"
            afn = "__atomic_fetch_add" if m == "inc" else "__atomic_fetch_sub"
            return f"{{ {ct} _old = {afn}(({ct} *)(uintptr_t)({mm[1]}), 1, __ATOMIC_SEQ_CST); f_{m}(c, _old, {w}); }}"
        return f"{{ uint64_t _r = f_{m}(c, {read_op(ops[0], w, nr)}, {w}); {write_op(ops[0], w, '_r', nr)}; }}"

    if m == "neg":
        w = infer_width(ops, nr, 64)
        return f"{{ uint64_t _r = f_sub(c, 0, {read_op(ops[0], w, nr)}, {w}); {write_op(ops[0], w, '_r', nr)}; }}"
    if m == "not":
        w = infer_width(ops, nr, 64)
        return f"{write_op(ops[0], w, f'~({read_op(ops[0], w, nr)})', nr)};"
    if m == "cmp":
        w = infer_width(ops, nr, 64)
        return f"f_sub(c, {read_op(ops[0], w, nr)}, {read_op(ops[1], w, nr)}, {w});"
    if m == "test":
        w = infer_width(ops, nr, 64)
        return f"f_logic(c, ({read_op(ops[0], w, nr)}) & ({read_op(ops[1], w, nr)}), {w});"

    # Multiply / divide
    if m == "imul":
        if len(ops) == 1:
            w = infer_width(ops, nr, 64)
            s = read_op(ops[0], w, nr)
            if w == 64:
                return f"{{ __int128 _p = (__int128)(int64_t)c->rax * (__int128)(int64_t)({s}); c->rax = (uint64_t)_p; c->rdx = (uint64_t)(_p >> 64); c->cf = c->of = (_p != (__int128)(int64_t)c->rax); }}"
            if w == 32:
                return f"{{ int64_t _p = (int64_t)(int32_t)GET32(c->rax) * (int64_t)(int32_t)({s}); SET32(c->rax, _p); SET32(c->rdx, (uint64_t)_p >> 32); c->cf = c->of = (_p != (int64_t)(int32_t)_p); }}"
            if w == 16:
                return f"{{ int32_t _p = (int32_t)(int16_t)GET16(c->rax) * (int32_t)(int16_t)({s}); SET16(c->rax, _p); SET16(c->rdx, (uint32_t)_p >> 16); c->cf = c->of = (_p != (int32_t)(int16_t)_p); }}"
            return f"{{ int16_t _p = (int16_t)(int8_t)GET8L(c->rax) * (int16_t)(int8_t)({s}); SET16(c->rax, _p); c->cf = c->of = (_p != (int16_t)(int8_t)_p); }}"
        w = op_width(ops[0], nr) or 64
        if len(ops) == 2:
            a, b = read_op(ops[0], w, nr), read_op(ops[1], w, nr)
        else:
            a, b = read_op(ops[1], w, nr), read_op(ops[2], w, nr)
        if w == 64:
            return f"{{ __int128 _p = (__int128)(int64_t)({a}) * (__int128)(int64_t)({b}); {write_op(ops[0], 64, '(uint64_t)_p', nr)}; c->cf = c->of = (_p != (__int128)(int64_t)(uint64_t)_p); }}"
        if w == 32:
            return f"{{ int64_t _p = (int64_t)(int32_t)({a}) * (int64_t)(int32_t)({b}); {write_op(ops[0], 32, '(uint32_t)_p', nr)}; c->cf = c->of = (_p != (int64_t)(int32_t)_p); }}"
        return f"{{ int32_t _p = (int32_t)(int16_t)({a}) * (int32_t)(int16_t)({b}); {write_op(ops[0], 16, '(uint16_t)_p', nr)}; c->cf = c->of = (_p != (int32_t)(int16_t)_p); }}"

    if m == "mul":
        w = infer_width(ops, nr, 64)
        s = read_op(ops[0], w, nr)
        if w == 64:
            return f"{{ __uint128_t _p = (__uint128_t)c->rax * (__uint128_t)({s}); c->rax = (uint64_t)_p; c->rdx = (uint64_t)(_p >> 64); c->cf = c->of = (c->rdx != 0); }}"
        if w == 32:
            return f"{{ uint64_t _p = (uint64_t)GET32(c->rax) * (uint64_t)(uint32_t)({s}); SET32(c->rax, _p); SET32(c->rdx, _p >> 32); c->cf = c->of = (c->rdx != 0); }}"
        if w == 16:
            return f"{{ uint32_t _p = (uint32_t)GET16(c->rax) * (uint32_t)(uint16_t)({s}); SET16(c->rax, _p); SET16(c->rdx, _p >> 16); c->cf = c->of = (GET16(c->rdx) != 0); }}"
        return f"{{ uint16_t _p = (uint16_t)GET8L(c->rax) * (uint16_t)(uint8_t)({s}); SET16(c->rax, _p); c->cf = c->of = ((_p >> 8) != 0); }}"

    if m == "idiv":
        w = infer_width(ops, nr, 64)
        s = read_op(ops[0], w, nr)
        if w == 64:
            return f"{{ __int128 _num = ((__int128)(int64_t)c->rdx << 64) | (__uint128_t)c->rax; int64_t _d = (int64_t)({s}); c->rax = (uint64_t)(int64_t)(_num / _d); c->rdx = (uint64_t)(int64_t)(_num % _d); }}"
        if w == 32:
            return f"{{ int64_t _num = ((int64_t)(int32_t)GET32(c->rdx) << 32) | (uint64_t)GET32(c->rax); int32_t _d = (int32_t)({s}); SET32(c->rax, (int32_t)(_num / _d)); SET32(c->rdx, (int32_t)(_num % _d)); }}"
        if w == 16:
            return f"{{ int32_t _num = ((int32_t)(int16_t)GET16(c->rdx) << 16) | (uint32_t)GET16(c->rax); int16_t _d = (int16_t)({s}); SET16(c->rax, (int16_t)(_num / _d)); SET16(c->rdx, (int16_t)(_num % _d)); }}"
        return f"{{ int16_t _num = (int16_t)GET16(c->rax); int8_t _d = (int8_t)({s}); SET8L(c->rax, (int8_t)(_num / _d)); SET8H(c->rax, (int8_t)(_num % _d)); }}"

    if m == "div":
        w = infer_width(ops, nr, 64)
        s = read_op(ops[0], w, nr)
        if w == 64:
            return f"{{ __uint128_t _num = ((__uint128_t)c->rdx << 64) | (__uint128_t)c->rax; uint64_t _d = ({s}); c->rax = (uint64_t)(_num / _d); c->rdx = (uint64_t)(_num % _d); }}"
        if w == 32:
            return f"{{ uint64_t _num = ((uint64_t)GET32(c->rdx) << 32) | (uint64_t)GET32(c->rax); uint32_t _d = (uint32_t)({s}); SET32(c->rax, (uint32_t)(_num / _d)); SET32(c->rdx, (uint32_t)(_num % _d)); }}"
        if w == 16:
            return f"{{ uint32_t _num = ((uint32_t)GET16(c->rdx) << 16) | (uint32_t)GET16(c->rax); uint16_t _d = (uint16_t)({s}); SET16(c->rax, (uint16_t)(_num / _d)); SET16(c->rdx, (uint16_t)(_num % _d)); }}"
        return f"{{ uint16_t _num = GET16(c->rax); uint8_t _d = (uint8_t)({s}); SET8L(c->rax, (uint8_t)(_num / _d)); SET8H(c->rax, (uint8_t)(_num % _d)); }}"

    # Shifts / rotates
    if m in ("shl", "sal", "shr", "sar", "rol", "ror"):
        w = op_width(ops[0], nr) or 64
        fn = "f_shl" if m in ("shl", "sal") else f"f_{m}"
        cnt = read_op(ops[1], 8, nr) if len(ops) > 1 else "1ULL"
        return f"{{ uint64_t _r = {fn}(c, {read_op(ops[0], w, nr)}, {cnt}, {w}); {write_op(ops[0], w, '_r', nr)}; }}"

    if m in ("rcl", "rcr"):
        w = op_width(ops[0], nr) or 64
        cnt = read_op(ops[1], 8, nr) if len(ops) > 1 else "1ULL"
        cmask = 63 if w == 64 else 31
        wmask = "~0ULL" if w == 64 else f"((1ULL << {w}) - 1ULL)"
        if m == "rcr":
            return (
                f"{{ uint64_t _v = ({read_op(ops[0], w, nr)}) & {wmask}; "
                f"unsigned _c = (unsigned)(({cnt}) & {cmask}U) % {w + 1}U; uint8_t _cf = c->cf & 1; "
                f"for (unsigned _i = 0; _i < _c; _i++) {{ uint8_t _nc = (uint8_t)(_v & 1); _v = (_v >> 1) | ((uint64_t)_cf << {w - 1}); _cf = _nc; }} "
                f"c->cf = _cf; if ((({cnt}) & {cmask}U) == 1) c->of = (uint8_t)(((_v >> {w - 1}) ^ (_v >> {w - 2})) & 1); "
                f"{write_op(ops[0], w, '_v', nr)}; }}"
            )
        return (
            f"{{ uint64_t _v = ({read_op(ops[0], w, nr)}) & {wmask}; "
            f"unsigned _c = (unsigned)(({cnt}) & {cmask}U) % {w + 1}U; uint8_t _cf = c->cf & 1; "
            f"for (unsigned _i = 0; _i < _c; _i++) {{ uint8_t _nc = (uint8_t)((_v >> {w - 1}) & 1); _v = ((_v << 1) | _cf) & {wmask}; _cf = _nc; }} "
            f"c->cf = _cf; if ((({cnt}) & {cmask}U) == 1) c->of = (uint8_t)(((_v >> {w - 1}) ^ _cf) & 1); "
            f"{write_op(ops[0], w, '_v', nr)}; }}"
        )

    if m == "lahf":
        return "SET8H(c->rax, (uint8_t)((c->cf&1) | 2 | ((c->pf&1)<<2) | ((c->af&1)<<4) | ((c->zf&1)<<6) | ((c->sf&1)<<7)));"
    if m == "sahf":
        return "{ uint8_t _f = GET8H(c->rax); c->cf=_f&1; c->pf=(_f>>2)&1; c->af=(_f>>4)&1; c->zf=(_f>>6)&1; c->sf=(_f>>7)&1; }"
    if m in ("pushfq", "pushf"):
        return "push64(c, (uint64_t)((c->cf&1) | 2 | ((c->pf&1)<<2) | ((c->af&1)<<4) | ((c->zf&1)<<6) | ((c->sf&1)<<7) | ((c->df&1)<<10) | ((c->of&1)<<11)));"
    if m in ("popfq", "popf"):
        return "{ uint64_t _f = pop64(c); c->cf=_f&1; c->pf=(_f>>2)&1; c->af=(_f>>4)&1; c->zf=(_f>>6)&1; c->sf=(_f>>7)&1; c->df=(_f>>10)&1; c->of=(_f>>11)&1; }"

    if m in ("shld", "shrd"):
        w = op_width(ops[0], nr) or 64
        d = read_op(ops[0], w, nr)
        s = read_op(ops[1], w, nr)
        cnt = read_op(ops[2], 8, nr)
        cmask = 63 if w == 64 else 31
        if m == "shld":
            return (
                f"{{ uint64_t _cnt = ({cnt}) & {cmask}U; if (_cnt) {{ "
                f"uint64_t _a = {d}, _b = {s}; "
                f"uint64_t _r = (_cnt >= {w}) ? 0 : ((_a << _cnt) | (_b >> ({w} - _cnt))); "
                f"c->cf = (uint8_t)((_a >> ({w} - _cnt)) & 1); f_logic(c, _r, {w}); {write_op(ops[0], w, '_r', nr)}; }} }}"
            )
        return (
            f"{{ uint64_t _cnt = ({cnt}) & {cmask}U; if (_cnt) {{ "
            f"uint64_t _a = {d}, _b = {s}; "
            f"uint64_t _r = (_cnt >= {w}) ? 0 : ((_a >> _cnt) | (_b << ({w} - _cnt))); "
            f"c->cf = (uint8_t)((_a >> (_cnt - 1)) & 1); f_logic(c, _r, {w}); {write_op(ops[0], w, '_r', nr)}; }} }}"
        )

    # Bit ops
    if m in ("bt", "bts", "btr", "btc"):
        w = op_width(ops[0], nr) or 64
        b = read_op(ops[1], w, nr)
        a = read_op(ops[0], w, nr)
        if m == "bt":
            return f"c->cf = (uint8_t)((({a}) >> (({b}) & {w - 1}U)) & 1ULL);"
        bit_op = {"bts": "|", "btr": "& ~", "btc": "^"}[m]
        return (
            f"{{ uint64_t _v = {a}, _bit = 1ULL << (({b}) & {w - 1}U); "
            f"c->cf = ((_v & _bit) != 0); _v = _v {bit_op}(_bit); {write_op(ops[0], w, '_v', nr)}; }}"
        )
    if m in ("bsf", "tzcnt"):
        w = op_width(ops[0], nr) or 64
        s = read_op(ops[1], w, nr)
        zero_stmt = f"{write_op(ops[0], w, str(w) + 'ULL', nr)};" if m == "tzcnt" else ""
        return (
            f"{{ uint64_t _s = {s}; if (_s == 0) {{ c->zf = 1; c->cf = 1; {zero_stmt} }} "
            f"else {{ c->zf = 0; c->cf = 0; {write_op(ops[0], w, '__builtin_ctzll(_s)', nr)}; }} }}"
        )
    if m in ("bsr", "lzcnt"):
        w = op_width(ops[0], nr) or 64
        s = read_op(ops[1], w, nr)
        if m == "bsr":
            return f"{{ uint64_t _s = {s}; if (_s == 0) {{ c->zf = 1; }} else {{ c->zf = 0; {write_op(ops[0], w, '63 - __builtin_clzll(_s)', nr)}; }} }}"
        return f"{{ uint64_t _s = {s}; if (_s == 0) {{ c->cf = 1; c->zf = 0; {write_op(ops[0], w, f'{w}ULL', nr)}; }} else {{ c->cf = 0; uint64_t _r = (uint64_t)(__builtin_clzll(_s) - {64 - w}); c->zf = (_r == 0); {write_op(ops[0], w, '_r', nr)}; }} }}"
    if m == "popcnt":
        w = op_width(ops[0], nr) or 64
        s = read_op(ops[1], w, nr)
        return f"{{ uint64_t _r = (uint64_t)__builtin_popcountll({s}); c->zf = (_r == 0); c->cf = c->of = c->sf = c->pf = 0; {write_op(ops[0], w, '_r', nr)}; }}"

    # String ops (movs*, stos*, cmps*, scas*) — never match SSE2 movsd/cmpsd with xmm operands!
    has_xmm_op = any(op in REG_INFO and REG_INFO[op][2] == "xmm" for op in ops)
    if not has_xmm_op and m in ("movsb", "movsw", "movsd", "movsq") and (len(ops) == 0 or "ptr" in ops[0]):
        sz = {"b": 1, "w": 2, "d": 4, "q": 8}[m[-1]]
        bits = sz * 8
        step = f"{{ W{bits}(c->rdi, R{bits}(c->rsi)); int64_t _d = c->df ? -{sz} : {sz}; c->rsi += _d; c->rdi += _d; }}"
        return f"while (c->rcx) {{ {step} c->rcx--; }}" if pfx == "rep" else step
    if m in ("stosb", "stosw", "stosd", "stosq"):
        sz = {"b": 1, "w": 2, "d": 4, "q": 8}[m[-1]]
        bits = sz * 8
        val = {8: "GET8L(c->rax)", 16: "GET16(c->rax)", 32: "GET32(c->rax)", 64: "c->rax"}[bits]
        step = f"{{ W{bits}(c->rdi, {val}); c->rdi += c->df ? -{sz} : {sz}; }}"
        return f"while (c->rcx) {{ {step} c->rcx--; }}" if pfx == "rep" else step
    if m in ("scasb", "scasw", "scasd", "scasq"):
        sz = {"b": 1, "w": 2, "d": 4, "q": 8}[m[-1]]
        bits = sz * 8
        val = {8: "GET8L(c->rax)", 16: "GET16(c->rax)", 32: "GET32(c->rax)", 64: "c->rax"}[bits]
        step = f"f_sub(c, {val}, R{bits}(c->rdi), {bits}); c->rdi += c->df ? -{sz} : {sz};"
        if pfx in ("rep", "repe", "repz"):
            return f"while (c->rcx) {{ {step} c->rcx--; if (!c->zf) break; }}"
        if pfx in ("repne", "repnz"):
            return f"while (c->rcx) {{ {step} c->rcx--; if (c->zf) break; }}"
        return f"{{ {step} }}"
    if not has_xmm_op and m in ("cmpsb", "cmpsw", "cmpsd", "cmpsq") and (len(ops) == 0 or "ptr" in ops[0]):
        sz = {"b": 1, "w": 2, "d": 4, "q": 8}[m[-1]]
        bits = sz * 8
        step = f"f_sub(c, R{bits}(c->rsi), R{bits}(c->rdi), {bits}); int64_t _d = c->df ? -{sz} : {sz}; c->rsi += _d; c->rdi += _d;"
        if pfx in ("rep", "repe", "repz"):
            return f"while (c->rcx) {{ {step} c->rcx--; if (!c->zf) break; }}"
        if pfx in ("repne", "repnz"):
            return f"while (c->rcx) {{ {step} c->rcx--; if (c->zf) break; }}"
        return f"{{ {step} }}"

    # CPUID / RDTSC
    if m == "cpuid":
        return (
            "{ uint32_t _leaf = GET32(c->rax); "
            "if (_leaf == 0) { SET32(c->rax, 1); SET32(c->rbx, 0x756e6547); SET32(c->rdx, 0x49656e69); SET32(c->rcx, 0x6c65746e); } "
            "else if (_leaf == 1) { SET32(c->rax, 0x000306c3); SET32(c->rbx, 0); SET32(c->rcx, 0x00180201); SET32(c->rdx, 0x078bfbff); } "
            "else { SET32(c->rax, 0); SET32(c->rbx, 0); SET32(c->rcx, 0); SET32(c->rdx, 0); } }"
        )
    if m in ("rdtsc", "rdtscp"):
        return "{ uint64_t _t = 0; __asm__ volatile(\"mrs %0, cntvct_el0\" : \"=r\"(_t)); SET32(c->rax, _t); SET32(c->rdx, _t >> 32); }"

    # SSE/SSE2/SSE4.1
    sse_code = lift_sse(insn)
    if sse_code is not None:
        return sse_code

    # x87 FPU
    fpu_code = lift_x87(insn)
    if fpu_code is not None:
        return fpu_code

    unimpl.append(f"0x{insn.addr:x}: {insn.text}")
    return f'fprintf(stderr, "elf64-recomp: UNIMPLEMENTED x86_64 insn at 0x{insn.addr:x}: {insn.text.replace(chr(34), chr(39))}\\n"); abort();'


def _is_msvc_setjmp(func: LiftedFunc) -> bool:
    if len(func.insns) < 12:
        return False
    t0, t1, t2 = func.insns[0].text, func.insns[1].text, func.insns[2].text
    return ("[rcx]" in t0 and "rdx" in t0 and
            "[rcx + 8]" in t1 and "rbx" in t1 and
            "[rcx + 0x18]" in t2 and "rbp" in t2)


def emit_function_c(func: LiftedFunc, unimpl: List[str], setjmp_addrs: Optional[Set[int]] = None) -> str:
    local_addrs = {ins.addr for ins in func.insns}
    # Determine whether this function has an intra-function indirect jump (switch table).
    has_ind_jmp = any(
        ins.mnemonic == "jmp" and parse_imm(ins.ops[0]) is None and not ins.ops[0].startswith("qword ptr [rip")
        for ins in func.insns
    )
    # Collect needed jump labels: targets of local branches, or all insns if switch table present.
    labels: Set[int] = set()
    if has_ind_jmp:
        labels = set(local_addrs)
    else:
        for ins in func.insns:
            if (ins.mnemonic == "jmp" or (ins.mnemonic.startswith("j") and ins.mnemonic[1:] in CC_EXPR)
                    or ins.mnemonic in ("jecxz", "jrcxz")) and ins.ops:
                t = parse_imm(ins.ops[0])
                if t is not None and t in local_addrs:
                    labels.add(t)

    # Identify calls to statically linked MSVC _setjmp so sigsetjmp lives in this host frame.
    sj_sites: Dict[int, int] = {}
    if setjmp_addrs:
        for ins in func.insns:
            if ins.mnemonic == "call" and ins.ops:
                t = parse_imm(ins.ops[0])
                if t is not None and t in setjmp_addrs:
                    sj_sites[ins.addr] = len(sj_sites)

    # Avoid O(N^2) LLVM optimizer blowup on huge intra-function switch tables.
    opt_attr = "__attribute__((optnone)) " if (has_ind_jmp and len(labels) > 250) else ""
    lines = [f"/* {func.name} @ 0x{func.addr:x} */", f"{opt_attr}void fn_{func.addr:x}(CPU64 *c) {{"]
    if has_ind_jmp:
        lines.append("    uint64_t _ind_target = 0;")
    for idx in range(len(sj_sites)):
        lines.append(f"    sigjmp_buf _sjb_{idx};")
    for ins in func.insns:
        if ins.addr in labels:
            lines.append(f"L_{ins.addr:x}:;")
        if ins.addr in sj_sites:
            idx = sj_sites[ins.addr]
            lines.append(
                f"    {{ int _jr = sigsetjmp(_sjb_{idx}, 0); "
                f"if (_jr == 0) {{ rt_setjmp_save(c->rcx, &_sjb_{idx}, c); "
                f"W64(c->rcx, c->rdx ? c->rdx : 1ULL); c->rax = 0; }} "
                f"else {{ c->rax = (uint64_t)_jr; }} }}"
            )
            continue
        try:
            stmt = lift_insn(ins, local_addrs, has_ind_jmp, unimpl)
        except (KeyError, ValueError):
            unimpl.append(f"0x{ins.addr:x}: {ins.text}")
            stmt = f'fprintf(stderr, "elf64-recomp: UNIMPLEMENTED x86_64 insn at 0x{ins.addr:x}: {ins.text.replace(chr(34), chr(39))}\\n"); abort();'
        lines.append(f"    {stmt}")

    # Fall-through out of function (e.g. tail block aligned into next function).
    if func.insns:
        last = func.insns[-1]
        if last.mnemonic not in ("ret", "jmp", "ud2", "hlt", "int3"):
            lines.append(f"    rt_tailcall(c, 0x{last.next_addr:x}ULL); return;")

    if has_ind_jmp:
        lines.append("L_ind_dispatch:")
        lines.append("    switch (_ind_target) {")
        for a in sorted(labels):
            lines.append(f"        case 0x{a:x}ULL: goto L_{a:x};")
        lines.append("        default: rt_tailcall(c, _ind_target); return;")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


def lift_layout(layout_path: str, out_dir: str, shards: int = 8, strict: bool = False) -> dict:
    with open(layout_path) as f:
        layout = json.load(f)

    is_pe = layout.get("format") == "pe64"
    is_win64 = layout.get("abi") == "win64"

    os.makedirs(out_dir, exist_ok=True)
    all_funcs: List[LiftedFunc] = []
    seen_addrs: Set[int] = set()
    unimpl: List[str] = []
    shard_files: List[str] = []
    header = '#include "runtime64.h"\n#include <stdio.h>\n#include <stdlib.h>\n#include <math.h>\n\n'

    def _dis_mod(mod: dict) -> List[LiftedFunc]:
        return disassemble_module(
            mod["elf_path"],
            mod["base"],
            mod["code_roots"],
            is_pe=is_pe,
            vma_delta=mod.get("vma_delta", 0),
        )

    mods = layout["modules"]
    if len(mods) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(mods), os.cpu_count() or 4)) as pool:
            per_mod_funcs = list(pool.map(_dis_mod, mods))
    else:
        per_mod_funcs = [_dis_mod(m) for m in mods]

    for mi, (mod, raw_funcs) in enumerate(zip(mods, per_mod_funcs)):
        mfuncs: List[LiftedFunc] = []
        for fn in raw_funcs:
            if fn.addr not in seen_addrs:
                seen_addrs.add(fn.addr)
                mfuncs.append(fn)
                all_funcs.append(fn)
        mfuncs.sort(key=lambda fn: fn.addr)
        if not mfuncs:
            continue
        mod_setjmps = {fn.addr for fn in mfuncs if _is_msvc_setjmp(fn)}
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", mod["name"])
        mshards = max(1, min(shards, (len(mfuncs) + 1999) // 2000))
        buckets: List[List[LiftedFunc]] = [[] for _ in range(mshards)]
        for i, fn in enumerate(mfuncs):
            buckets[i % mshards].append(fn)
        for si, bucket in enumerate(buckets):
            cpath = os.path.join(out_dir, f"m{mi:02d}_{safe}_{si:02d}.c")
            with open(cpath, "w") as f:
                f.write(header)
                for fn in bucket:
                    f.write(emit_function_c(fn, unimpl, mod_setjmps))
                    f.write("\n\n")
            shard_files.append(os.path.abspath(cpath))

    all_funcs.sort(key=lambda fn: fn.addr)

    if unimpl:
        print(f"lift64: WARNING {len(unimpl)} unimplemented instruction(s):", file=sys.stderr)
        for u in unimpl[:20]:
            print(f"  {u}", file=sys.stderr)
        if strict:
            raise RuntimeError(f"{len(unimpl)} unimplemented x86_64 instructions")

    # Emit recomp_manifest.c binding all modules, imports, exports, and lifted functions.
    manifest_path = os.path.join(out_dir, "recomp_manifest.c")
    with open(manifest_path, "w") as f:
        f.write('#include "runtime64.h"\n\n')
        for fn in all_funcs:
            f.write(f"void fn_{fn.addr:x}(CPU64 *c);\n")
        f.write("\nconst RTModuleSpec g_rt_modules[] = {\n")
        for m in layout["modules"]:
            t = m["tls"]
            f.write(
                f'    {{ "{m["name"]}", "{m["image_path"]}", '
                f'0x{m["map_addr"]:x}ULL, 0x{m["mem_size"]:x}ULL, '
                f'0x{t["vaddr"]:x}ULL, 0x{t["filesz"]:x}ULL, 0x{t["memsz"]:x}ULL, {t["tpoff"]}LL }},\n'
            )
        f.write(f"}};\nconst size_t g_rt_module_count = {len(layout['modules'])};\n\n")

        f.write("const RTImportSpec g_rt_imports[] = {\n")
        for imp in layout["imports"]:
            dll = f'"{imp["dll"]}"' if imp.get("dll") else "NULL"
            f.write(f'    {{ "{imp["name"]}", {dll}, 0x{imp["addr"]:x}ULL }},\n')
        f.write(f"    {{ NULL, NULL, 0 }}\n}};\nconst size_t g_rt_import_count = {len(layout['imports'])};\n\n")

        f.write("const RTImportSpec g_rt_data_imports[] = {\n")
        for imp in layout["data_imports"]:
            f.write(f'    {{ "{imp["name"]}", NULL, 0x{imp["addr"]:x}ULL }},\n')
        f.write(f"    {{ NULL, NULL, 0 }}\n}};\nconst size_t g_rt_data_import_count = {len(layout['data_imports'])};\n\n")

        f.write("const RTCopyReloc g_rt_copy_relocs[] = {\n")
        for cr in layout["copy_relocs"]:
            f.write(f'    {{ 0x{cr["dst"]:x}ULL, 0x{cr["src"]:x}ULL, 0x{cr["size"]:x}ULL }},\n')
        f.write(f"    {{ 0, 0, 0 }}\n}};\nconst size_t g_rt_copy_reloc_count = {len(layout['copy_relocs'])};\n\n")

        f.write("const RTIrelative g_rt_irelatives[] = {\n")
        for ir in layout["irelatives"]:
            f.write(f'    {{ 0x{ir["got"]:x}ULL, 0x{ir["resolver"]:x}ULL }},\n')
        f.write(f"    {{ 0, 0 }}\n}};\nconst size_t g_rt_irelative_count = {len(layout['irelatives'])};\n\n")

        f.write("const uint64_t g_rt_init_array[] = {\n")
        for addr in layout["init_order"]:
            f.write(f"    0x{addr:x}ULL,\n")
        f.write(f"    0ULL\n}};\nconst size_t g_rt_init_array_count = {len(layout['init_order'])};\n\n")

        exports = []
        for m in layout["modules"]:
            mbase = m["map_addr"]
            for name, addr in m["exports"].items():
                exports.append((name, mbase, addr))
        f.write("const RTExportSpec g_rt_exports[] = {\n")
        for name, mbase, addr in exports:
            f.write(f'    {{ "{name}", 0x{mbase:x}ULL, 0x{addr:x}ULL }},\n')
        f.write(f"    {{ NULL, 0, 0 }}\n}};\nconst size_t g_rt_export_count = {len(exports)};\n\n")

        f.write("const RTFuncEntry g_rt_funcs[] = {\n")
        for fn in all_funcs:
            f.write(f"    {{ 0x{fn.addr:x}ULL, fn_{fn.addr:x} }},\n")
        f.write(f"    {{ 0, NULL }}\n}};\nconst size_t g_rt_func_count = {len(all_funcs)};\n\n")

        dll_inits = layout.get("dll_inits", [])
        f.write("const RTDllInit g_rt_dll_inits[] = {\n")
        for di in dll_inits:
            f.write(f'    {{ "{di["name"]}", 0x{di["entry"]:x}ULL, 0x{di["hmodule"]:x}ULL }},\n')
        f.write(f"    {{ NULL, 0, 0 }}\n}};\nconst size_t g_rt_dll_init_count = {len(dll_inits)};\n\n")

        f.write(f"const uint64_t g_rt_entry_addr = 0x{layout['entry']:x}ULL;\n")
        f.write(f"const uint64_t g_rt_main_addr = 0x{layout['main_symbol']:x}ULL;\n")
        f.write(f"const uint64_t g_rt_total_tls_size = 0x{layout['total_tls_size']:x}ULL;\n")
        f.write(f"const uint64_t g_rt_data_import_base = 0x{layout['data_import_base']:x}ULL;\n")
        f.write(f"const int g_rt_is_win64 = {1 if is_win64 else 0};\n")

    return {
        "funcs": len(all_funcs),
        "shards": shard_files,
        "manifest": os.path.abspath(manifest_path),
        "unimpl": unimpl,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Lift prepared ELF64 x86_64 layout.json to C.")
    ap.add_argument("layout", help="Path to layout.json from elfprep64.py")
    ap.add_argument("-o", "--out-dir", required=True, help="Output directory for lifted C shards")
    ap.add_argument("-j", "--shards", type=int, default=8, help="Number of C shards")
    ap.add_argument("--strict", action="store_true", help="Fail if any instruction is unimplemented")
    args = ap.parse_args()

    res = lift_layout(args.layout, args.out_dir, shards=args.shards, strict=args.strict)
    print(f"lift64: lifted {res['funcs']} function(s) across {len(res['shards'])} shard(s), unimpl={len(res['unimpl'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
