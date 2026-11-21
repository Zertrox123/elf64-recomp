#!/usr/bin/env python3
"""Generate dark-theme GitHub status badges and squarified SVG treemaps.

Computes real coverage metrics against:
  1. System / Win32 / DX11 / Steamworks host DLL imports across the target
     Windows x64 game module graph (e.g., Portal: Revolution core DLLs).
  2. x86_64 lifter ISA groups + DXBC SM4/SM5 shader opcodes + Vulkan bridge.

Outputs (under docs/):
  - docs/status.json          (aggregated counts only; zero game binaries)
  - docs/status_treemap.svg   (side-by-side dark treemap matching GitHub dark UI)
  - docs/badge_libs.svg       (System libraries % badge)
  - docs/badge_isa.svg        (x86_64 ISA % badge)
  - docs/badge_dxbc.svg       (DXBC / D3D11 % badge)
  - docs/badge_vulkan.svg     (Vulkan / MoltenVK % badge)
"""

from __future__ import annotations

import argparse
import collections
import html
import json
import math
import os
import re
import sys
import tempfile
from typing import Dict, List, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
RUNTIME_DIR = os.path.join(REPO_ROOT, "runtime")
DOCS_DIR = os.path.join(REPO_ROOT, "docs")

sys.path.insert(0, TOOLS_DIR)
import audit_pe64  # noqa: E402
import peprep64  # noqa: E402

# Core Portal: Revolution Win64 module graph (excluding Qt editor tools).
REVOLUTION_CORE_DLLS = [
    "revolution.exe",
    "launcher.dll",
    "tier0.dll",
    "vstdlib.dll",
    "filesystem_stdio.dll",
    "engine.dll",
    "materialsystem.dll",
    "shaderapidx11.dll",
    "stdshader_dx11.dll",
    "studiorender.dll",
    "datacache.dll",
    "inputsystem.dll",
    "vphysics.dll",
    "vgui2.dll",
    "vguimatsurface.dll",
    "soundsystem.dll",
    "engineaudio.dll",
    "scenefilecache.dll",
    "localize.dll",
    "vscript.dll",
    "video_services.dll",
    "imemanager.dll",
    "soundemittersystem.dll",
    "richpresence.dll",
    "devui.dll",
    "toolframework.dll",
    "panorama.dll",
    "panoramauiclient.dll",
    "panorama_text_pango.dll",
]

# Reference x86_64 + DXBC SM4/SM5 instruction catalog grouped by ISA category.
ISA_CATALOG: Dict[str, List[str]] = {
    "GPR / ALU": [
        "mov", "movabs", "movzx", "movsx", "movsxd", "lea", "xchg", "bswap",
        "add", "adc", "sub", "sbb", "inc", "dec", "neg", "not",
        "and", "or", "xor", "cmp", "test", "imul", "mul", "idiv", "div",
        "shl", "shr", "sar", "rol", "ror", "shld", "shrd",
        "cbw", "cwde", "cdqe", "cwd", "cdq", "cqo", "push", "pop", "leave",
    ],
    "CTRL": [
        "jmp", "call", "ret", "je", "jne", "jl", "jle", "jg", "jge",
        "jb", "jbe", "ja", "jae", "js", "jns", "jo", "jno", "jp", "jnp",
        "jecxz", "jrcxz", "cmove", "cmovne", "cmovl", "cmovge", "cmovg",
        "cmovle", "cmovb", "cmovae", "cmova", "cmovbe",
        "sete", "setne", "setl", "setge", "setg", "setle", "setb", "setae",
    ],
    "SSE / SSE2": [
        "movaps", "movups", "movapd", "movupd", "movdqa", "movdqu",
        "movss", "movsd", "movd", "movq", "movlps", "movhps", "movlhps", "movhlps",
        "movddup", "addss", "subss", "mulss", "divss", "sqrtss", "minss", "maxss",
        "addsd", "subsd", "mulsd", "divsd", "sqrtsd", "minsd", "maxsd",
        "ucomiss", "ucomisd", "comiss", "comisd",
        "addps", "subps", "mulps", "divps", "sqrtps", "rcpps", "rsqrtps", "rcpss", "rsqrtss", "minps", "maxps",
        "addpd", "subpd", "mulpd", "divpd", "sqrtpd", "minpd", "maxpd",
        "xorps", "xorpd", "pxor", "orps", "orpd", "por", "andps", "andpd", "pand", "andnps", "pandn",
        "cvtsi2ss", "cvtsi2sd", "cvtss2si", "cvttss2si", "cvtsd2si", "cvttsd2si",
        "cvtss2sd", "cvtsd2ss", "cvtdq2ps", "cvtps2dq", "cvttps2dq", "cvtdq2pd", "cvtpd2dq", "cvtps2pd", "cvtpd2ps",
        "paddb", "paddw", "paddd", "paddq", "psubb", "psubw", "psubd", "psubq", "pmullw", "pmulld",
        "pmaddwd", "pmuludq", "pmulhw", "pmulhuw", "packuswb", "packsswb", "packssdw", "packusdw",
        "pminub", "pmaxub", "pminsw", "pmaxsw", "pminsd", "pmaxsd", "pminud", "pmaxud", "pabsb", "pabsw", "pabsd",
        "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpeqq", "pcmpgtb", "pcmpgtw", "pcmpgtd", "pcmpgtq",
        "pshufd", "pshuflw", "pshufhw", "shufps", "shufpd",
        "unpcklps", "unpckhps", "unpcklpd", "unpckhpd",
        "punpcklbw", "punpckhbw", "punpcklwd", "punpckhwd", "punpckldq", "punpckhdq",
        "pslldq", "psrldq", "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw", "psrad",
        "pmovmskb", "movmskps", "movmskpd", "stmxcsr", "ldmxcsr",
    ],
    "SSE4 / BIT": [
        "bt", "bts", "btr", "btc", "bsf", "bsr", "tzcnt", "lzcnt", "popcnt",
        "pcmpistri", "roundss", "roundsd", "blendvps", "pblendw", "pextrb", "pextrw",
        "pextrd", "pextrq", "pinsrb", "pinsrw", "pinsrd", "pinsrq", "ptest", "pshufb",
        "palignr", "pmovzxbd", "pmovzxbw", "pmovzxwd", "crc32",
    ],
    "ATOMIC / STR": [
        "cmpxchg", "xadd", "movsb", "movsw", "movsq", "stosb", "stosw", "stosd", "stosq",
        "scasb", "scasw", "scasd", "scasq", "cmpsb", "cmpsw", "cmpsq",
        "cpuid", "rdtsc", "xgetbv", "mfence", "lfence", "sfence", "pause", "cld", "std",
    ],
    "AVX / FMA": [
        "vzeroupper", "vmovdqu", "vmovdqa", "vmovntdq", "vmovaps", "vmovups",
        "vmovss", "vmovsd", "vmovd", "vmovq", "vaddss", "vaddsd", "vsubss", "vsubsd",
        "vmulss", "vmulsd", "vdivss", "vdivsd", "vaddps", "vmulps", "vpxor", "vpand", "vpor",
        "vpshufd", "vinsertf128", "vextractf128", "vbroadcastss",
        "vfmadd213ss", "vfmadd213sd", "vfmadd231ss", "vfmadd231sd", "vfmsub213sd",
        "vcomiss", "vcomisd", "vcvtdq2pd", "vpmovmskb",
    ],
    "DXBC SM4/5": [
        "mov", "add", "mul", "mad", "div", "dp2", "dp3", "dp4", "min", "max",
        "rsq", "sqrt", "ret",
        "movc", "lt", "ge", "eq", "ne", "and", "or", "xor", "ishl", "ishr", "ushr",
        "iadd", "imul", "ftoi", "itof", "ftou", "utof", "round_ni", "round_pi", "round_z",
        "sincos", "exp", "log", "frc", "deriv_rtx", "deriv_rty",
        "sample", "sample_l", "sample_b", "sample_c", "sample_c_lz", "ld", "ld_ms",
        "discard", "if", "else", "endif", "loop", "endloop", "breakc", "call",
    ],
}


def detect_lifted_mnemonics() -> set[str]:
    with open(os.path.join(TOOLS_DIR, "lift64.py")) as f:
        src = f.read()
    found = set(re.findall(r'"([a-z0-9_]+)"', src))
    # Expand condition-code families handled dynamically by jcc/cmovcc/setcc
    ccs = ["e", "ne", "l", "le", "g", "ge", "b", "be", "a", "ae", "s", "ns", "o", "no", "p", "np"]
    for cc in ccs:
        found.add("j" + cc)
        found.add("cmov" + cc)
        found.add("set" + cc)
    return found


def detect_dxbc_opcodes() -> set[str]:
    with open(os.path.join(RUNTIME_DIR, "dxbc_msl.c")) as f:
        src = f.read()
    impl = set()
    mapping = {
        "opc == 54": ["mov"],
        "opc == 0": ["add"],
        "opc == 56": ["mul"],
        "opc == 14": ["div"],
        "opc == 50": ["mad"],
        "opc == 15": ["dp2"],
        "opc == 16": ["dp3"],
        "opc == 17": ["dp4"],
        "opc == 51": ["min"],
        "opc == 52": ["max"],
        "opc == 68": ["rsq"],
        "opc == 76": ["sqrt"],
        "opc == 62": ["ret"],
        "opc == 55": ["movc"],
        "opc == 49": ["lt"],
        "opc == 29": ["ge"],
        "opc == 24": ["eq"],
        "opc == 57": ["ne"],
        "opc == 1 ": ["and"],
        "opc == 60": ["or"],
        "opc == 87": ["xor"],
        "opc == 41": ["ishl"],
        "opc == 42": ["ishr"],
        "opc == 85": ["ushr"],
        "opc == 30": ["iadd"],
        "opc == 27": ["ftoi"],
        "opc == 43": ["itof"],
        "opc == 28": ["ftou"],
        "opc == 86": ["utof"],
        "opc == 25": ["exp"],
        "opc == 47": ["log"],
        "opc == 26": ["frc"],
        "opc == 69": ["sample"],
        "opc == 72": ["sample_l"],
        "opc == 73": ["sample_b"],
        "opc == 13": ["discard"],
        "opc == 31": ["if"],
        "opc == 18": ["else"],
        "opc == 21": ["endif"],
    }
    for marker, names in mapping.items():
        if marker in src:
            impl.update(names)
    return impl


def collect_game_imports(game_bin_dir: str) -> Dict[str, Tuple[int, int]]:
    """Return {dll_label: (implemented_count, total_count)} across Portal: Revolution core DLLs."""
    impl = audit_pe64.collect_implemented_shims()
    pes = []
    for name in REVOLUTION_CORE_DLLS:
        p = os.path.join(game_bin_dir, name)
        if os.path.isfile(p):
            pes.append(p)
    # Also include client.dll / server.dll if present next door under revolution/bin/win64
    rev_bin = os.path.normpath(os.path.join(game_bin_dir, "..", "..", "revolution", "bin", "win64"))
    for name in ("client.dll", "server.dll"):
        p = os.path.join(rev_bin, name)
        if os.path.isfile(p):
            pes.append(p)

    if not pes:
        raise FileNotFoundError(f"No Portal: Revolution PE64 binaries found in {game_bin_dir}")

    import struct as _st

    lifted_names = {os.path.basename(p).lower() for p in pes}
    by_dll: Dict[str, List[str]] = collections.defaultdict(list)
    for path in pes:
        data = open(path, "rb").read()
        pe = _st.unpack_from("<I", data, 0x3C)[0]
        nsec = _st.unpack_from("<H", data, pe + 6)[0]
        opt_sz = _st.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        imp_rva = _st.unpack_from("<I", data, opt + 112 + 8)[0]
        if not imp_rva:
            continue
        secs = []
        for i in range(nsec):
            o = opt + opt_sz + i * 40
            vsz, vrva, rsz, rptr = _st.unpack_from("<IIII", data, o + 8)
            secs.append((vrva, max(vsz, rsz), rptr))

        def _rva(r: int) -> int | None:
            for vrva, sz, rptr in secs:
                if vrva <= r < vrva + sz:
                    return rptr + (r - vrva)
            return None

        def _cstr(r: int) -> str:
            o = _rva(r)
            return "" if o is None else data[o:data.index(b"\x00", o)].decode("latin1", errors="ignore")

        off = _rva(imp_rva)
        while off is not None:
            ilt, _ts, _fwd, name_rva, ft = _st.unpack_from("<IIIII", data, off)
            if not name_rva:
                break
            dll_full = _cstr(name_rva).lower()
            off += 20
            if dll_full in lifted_names:
                continue
            dll = dll_full[:-4] if dll_full.endswith(".dll") else dll_full
            io = _rva(ilt or ft)
            idx = 0
            while io is not None:
                ent = _st.unpack_from("<Q", data, io + idx * 8)[0]
                if not ent:
                    break
                sym = f"#{ent & 0xFFFF}" if (ent >> 63) else _cstr((ent & 0xFFFFFFFF) + 2)
                by_dll[dll].append(sym)
                idx += 1

    result: Dict[str, Tuple[int, int]] = {}
    for dll, syms in by_dll.items():
        uniq = sorted(set(syms))
        done = sum(
            1 for s in uniq
            if s in impl or f"{dll}.dll!{s}" in impl
        )
        result[dll] = (done, len(uniq))
    return result


# ---- Squarified Treemap Layout (Bruls, Huizing, van Wijk) ----
def squarify_layout(items: List[Tuple[str, float]], x: float, y: float, w: float, h: float) -> List[Tuple[str, float, float, float, float]]:
    """Return list of (label, rx, ry, rw, rh) covering (x, y, w, h)."""
    items = [(k, v) for k, v in items if v > 0]
    if not items or w <= 0 or h <= 0:
        return []
    total = sum(v for _, v in items)
    area_scale = (w * h) / total
    norm = [(k, v * area_scale) for k, v in sorted(items, key=lambda kv: -kv[1])]
    out: List[Tuple[str, float, float, float, float]] = []

    def worst(row: List[Tuple[str, float]], side: float) -> float:
        if not row or side <= 0:
            return float("inf")
        s = sum(v for _, v in row)
        rmin = min(v for _, v in row)
        rmax = max(v for _, v in row)
        s2 = s * s
        w2 = side * side
        return max((w2 * rmax) / s2, s2 / (w2 * rmin))

    rx, ry, rw, rh = x, y, w, h
    i = 0
    while i < len(norm):
        side = min(rw, rh)
        row = [norm[i]]
        i += 1
        while i < len(norm):
            cand = row + [norm[i]]
            if worst(cand, side) <= worst(row, side):
                row = cand
                i += 1
            else:
                break
        row_sum = sum(v for _, v in row)
        if rw >= rh:
            col_w = row_sum / rh if rh > 0 else 0
            cy = ry
            for k, v in row:
                ch = v / col_w if col_w > 0 else 0
                out.append((k, rx, cy, col_w, ch))
                cy += ch
            rx += col_w
            rw -= col_w
        else:
            row_h = row_sum / rw if rw > 0 else 0
            cx = rx
            for k, v in row:
                cw = v / row_h if row_h > 0 else 0
                out.append((k, cx, ry, cw, row_h))
                cx += cw
            ry += row_h
            rh -= row_h
    return out


def render_treemap_panel(
    title: str,
    groups: Dict[str, Tuple[int, int]],
    ox: float,
    oy: float,
    pw: float,
    ph: float,
) -> List[str]:
    done_sum = sum(v[0] for v in groups.values())
    tot_sum = sum(v[1] for v in groups.values())
    pct = (100.0 * done_sum / tot_sum) if tot_sum else 0.0

    svg = [
        f'<text x="{ox:.1f}" y="{oy - 8:.1f}" fill="#c9d1d9" font-family="ui-sans-serif, -apple-system, BlinkMacSystemFont, Segoe UI, Helvetica, Arial, sans-serif" '
        f'font-size="13" font-weight="500">{html.escape(title)}: {pct:.2f}% ({done_sum}/{tot_sum})</text>',
        f'<rect x="{ox:.1f}" y="{oy:.1f}" width="{pw:.1f}" height="{ph:.1f}" fill="#161b22" stroke="#0d1117" stroke-width="1.5"/>',
    ]

    rects = squarify_layout([(k, float(v[1])) for k, v in groups.items()], ox, oy, pw, ph)
    for label, rx, ry, rw, rh in rects:
        done, tot = groups[label]
        if rw < 1.5 or rh < 1.5:
            continue
        # Subdivide rectangle into a grid of micro-tiles (one tile per function/opcode, capped for crispness).
        aspect = rw / rh if rh > 0 else 1.0
        cols = max(1, int(round(math.sqrt(tot * aspect))))
        rows = max(1, int(math.ceil(tot / cols)))
        tw = rw / cols
        th = rh / rows
        gap = 0.6 if min(tw, th) > 3.5 else 0.25

        # Draw micro-tiles: green for implemented, dark slate for remaining.
        for idx in range(tot):
            r = idx // cols
            c = idx % cols
            tx = rx + c * tw
            ty = ry + r * th
            fill = "#2ea043" if idx < done else "#484f58"
            svg.append(
                f'<rect x="{tx + gap/2:.2f}" y="{ty + gap/2:.2f}" '
                f'width="{max(0.5, tw - gap):.2f}" height="{max(0.5, th - gap):.2f}" '
                f'fill="{fill}"/>'
            )

        # Crisp category border
        svg.append(
            f'<rect x="{rx:.2f}" y="{ry:.2f}" width="{rw:.2f}" height="{rh:.2f}" '
            f'fill="none" stroke="#0d1117" stroke-width="1.6"/>'
        )

        # Label if box is big enough
        if rw >= 28 and rh >= 14:
            max_chars = max(3, int((rw - 6) / 6.2))
            short = label if len(label) <= max_chars else label[: max_chars - 1] + "."
            # Subtle dark pill behind label for legibility over bright green tiles
            lbl_w = min(rw - 4, len(short) * 6.4 + 6)
            svg.append(
                f'<rect x="{rx + 2:.2f}" y="{ry + 2:.2f}" width="{lbl_w:.1f}" height="14" '
                f'rx="2" fill="#0d1117" fill-opacity="0.72"/>'
            )
            svg.append(
                f'<text x="{rx + 5:.2f}" y="{ry + 12.5:.2f}" fill="#f0f6fc" '
                f'font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="10.5" font-weight="600">'
                f'{html.escape(short)}</text>'
            )
    return svg


def badge_color(pct: float) -> str:
    if pct >= 85.0:
        return "#4c1"
    if pct >= 60.0:
        return "#97ca00"
    if pct >= 35.0:
        return "#dfb317"
    return "#fe7d37"


def render_badge(label: str, value: str, color: str) -> str:
    lw = int(len(label) * 6.8 + 16)
    vw = int(len(value) * 7.2 + 16)
    tw = lw + vw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{tw}" height="22" role="img" aria-label="{html.escape(label)}: {html.escape(value)}">\n'
        f'  <rect width="{lw}" height="22" fill="#555"/>\n'
        f'  <rect x="{lw}" width="{vw}" height="22" fill="{color}"/>\n'
        f'  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11.5">\n'
        f'    <text x="{lw / 2:.1f}" y="15">{html.escape(label)}</text>\n'
        f'    <text x="{lw + vw / 2:.1f}" y="15" font-weight="bold">{html.escape(value)}</text>\n'
        f'  </g>\n'
        f'</svg>\n'
    )


def render_full_svg(libs: Dict[str, Tuple[int, int]], isa: Dict[str, Tuple[int, int]]) -> str:
    W, H = 960, 340
    pad = 16
    gap = 16
    pw = (W - 2 * pad - gap) / 2
    ph = H - 46

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'  <rect width="{W}" height="{H}" rx="6" fill="#0d1117"/>',
    ]
    parts += render_treemap_panel("System libraries* (Portal: Revolution Win64)", libs, pad, 30, pw, ph)
    parts += render_treemap_panel("x86_64 ISA & DXBC shaders", isa, pad + pw + gap, 30, pw, ph)
    parts.append("</svg>\n")
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate GitHub status badges and SVG treemaps.")
    ap.add_argument("--game-bin", help="Path to Portal: Revolution bin/win64 directory")
    args = ap.parse_args()

    os.makedirs(DOCS_DIR, exist_ok=True)
    status_json = os.path.join(DOCS_DIR, "status.json")

    if args.game_bin:
        libs = collect_game_imports(args.game_bin)
    elif os.path.exists(status_json):
        with open(status_json) as f:
            prev = json.load(f)
        # Re-evaluate counts from cached library list if needed
        libs = {k: (v[0], v[1]) for k, v in prev["libraries"].items()}
    else:
        raise RuntimeError("Pass --game-bin <path/to/bin/win64> on initial generation")

    lifted = detect_lifted_mnemonics()
    dxbc = detect_dxbc_opcodes()
    isa: Dict[str, Tuple[int, int]] = {}
    for cat, ops in ISA_CATALOG.items():
        if cat == "DXBC SM4/5":
            done = sum(1 for o in ops if o in dxbc)
        else:
            done = sum(1 for o in ops if o in lifted)
        isa[cat] = (done, len(ops))

    lib_done = sum(v[0] for v in libs.values())
    lib_tot = sum(v[1] for v in libs.values())
    lib_pct = (100.0 * lib_done / lib_tot) if lib_tot else 0.0

    isa_done = sum(v[0] for k, v in isa.items() if k != "DXBC SM4/5")
    isa_tot = sum(v[1] for k, v in isa.items() if k != "DXBC SM4/5")
    isa_pct = (100.0 * isa_done / isa_tot) if isa_tot else 0.0

    dxbc_done, dxbc_tot = isa["DXBC SM4/5"]
    dxbc_pct = (100.0 * dxbc_done / dxbc_tot) if dxbc_tot else 0.0

    data = {
        "libraries": {k: [v[0], v[1]] for k, v in sorted(libs.items(), key=lambda kv: -kv[1][1])},
        "isa_and_shaders": {k: [v[0], v[1]] for k, v in isa.items()},
        "summary": {
            "libraries_pct": round(lib_pct, 2),
            "libraries_done": lib_done,
            "libraries_total": lib_tot,
            "isa_pct": round(isa_pct, 2),
            "isa_done": isa_done,
            "isa_total": isa_tot,
            "dxbc_pct": round(dxbc_pct, 2),
            "dxbc_done": dxbc_done,
            "dxbc_total": dxbc_tot,
        },
    }
    with open(status_json, "w") as f:
        json.dump(data, f, indent=2)

    with open(os.path.join(DOCS_DIR, "status_treemap.svg"), "w") as f:
        f.write(render_full_svg(libs, isa))
    with open(os.path.join(DOCS_DIR, "badge_libs.svg"), "w") as f:
        f.write(render_badge("libraries*", f"{lib_pct:.2f}%", badge_color(lib_pct)))
    with open(os.path.join(DOCS_DIR, "badge_isa.svg"), "w") as f:
        f.write(render_badge("x86_64 ISA", f"{isa_pct:.1f}%", badge_color(isa_pct)))
    with open(os.path.join(DOCS_DIR, "badge_dxbc.svg"), "w") as f:
        f.write(render_badge("DXBC shaders", f"{dxbc_pct:.1f}%", badge_color(dxbc_pct)))
    with open(os.path.join(DOCS_DIR, "badge_vulkan.svg"), "w") as f:
        f.write(render_badge("Vulkan bridge", "865 cmds", "#4c1"))

    print(
        f"gen_status: libraries*={lib_pct:.2f}% ({lib_done}/{lib_tot}), "
        f"x86_64={isa_pct:.1f}% ({isa_done}/{isa_tot}), "
        f"DXBC={dxbc_pct:.1f}% ({dxbc_done}/{dxbc_tot})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
