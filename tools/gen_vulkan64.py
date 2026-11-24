#!/usr/bin/env python3
"""Generate System V AMD64 -> Darwin ARM64 MoltenVK trampolines from vk.xml.

Because both Linux x86_64 and macOS ARM64 are LP64 little-endian and elf64-recomp
uses a unified 64-bit address space, all Vulkan structs and pointers pass
directly without marshalling. Only register/stack calling-convention adaptation
(distinguishing 64-bit ptr/handle/u64, 32-bit u32/enum/flags, float, double)
is needed — exact for Darwin ARM64's packed stack-argument ABI.
"""

from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Tuple

DEFAULT_VK_XML = "/opt/homebrew/share/vulkan/registry/vk.xml"

TYPES_64 = {
    "uint64_t", "int64_t", "size_t", "uintptr_t", "intptr_t",
    "VkDeviceSize", "VkDeviceAddress", "VkFlags64",
    "VkRemoteAddressNV", "PFN_vkVoidFunction",
}
TYPES_32 = {
    "uint32_t", "int32_t", "int", "unsigned int",
    "uint16_t", "int16_t", "uint8_t", "int8_t", "char",
    "VkBool32", "VkFlags", "VkResult", "VkSampleMask",
}


def parse_vk_xml(xml_path: str) -> Tuple[Dict[str, Tuple[str, List[str]]], Dict[str, str]]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Classify Vulkan types from <types>
    handles: Set[str] = set()
    bitmasks64: Set[str] = set()
    enums_and_bitmasks32: Set[str] = set()
    structs: Set[str] = set()

    for t in root.findall("./types/type"):
        cat = t.attrib.get("category", "")
        name = t.attrib.get("name") or (t.findtext("name") or "").strip()
        if not name:
            continue
        if cat == "handle":
            handles.add(name)
        elif cat == "bitmask":
            base = (t.findtext("type") or "").strip()
            if base == "VkFlags64":
                bitmasks64.add(name)
            else:
                enums_and_bitmasks32.add(name)
        elif cat == "enum":
            enums_and_bitmasks32.add(name)
        elif cat == "struct" or cat == "union":
            structs.add(name)

    def classify_param(elem: ET.Element) -> str:
        full = "".join(elem.itertext())
        tname = (elem.findtext("type") or "").strip()
        if "*" in full or "[" in full:
            return "p"
        if tname == "float":
            return "f"
        if tname == "double":
            return "d"
        if tname == "void":
            return "v"
        if tname in TYPES_64 or tname in handles or tname in bitmasks64 or tname.endswith("Flags2") or tname.endswith("Flags2KHR"):
            return "p"
        if tname in TYPES_32 or tname in enums_and_bitmasks32 or tname.startswith("Vk"):
            if tname in structs:
                return "STRUCT_BY_VAL"
            return "u"
        return "p"

    # Parse commands (only Vulkan API, exclude vulkansc-only)
    cmds: Dict[str, Tuple[str, List[str]]] = {}
    aliases: Dict[str, str] = {}

    for c in root.findall("./commands/command"):
        api = c.attrib.get("api", "")
        if api == "vulkansc":
            continue
        if "alias" in c.attrib:
            name = c.attrib["name"]
            if name not in cmds and name not in aliases:
                aliases[name] = c.attrib["alias"]
            continue
        proto = c.find("proto")
        if proto is None:
            continue
        name = (proto.findtext("name") or "").strip()
        if not name or name in cmds:
            continue
        ret = classify_param(proto)
        params = []
        skip = False
        for p in c.findall("param"):
            papi = p.attrib.get("api", "")
            if papi == "vulkansc":
                continue
            k = classify_param(p)
            if k == "STRUCT_BY_VAL":
                skip = True
                break
            params.append(k)
        if not skip and ret != "STRUCT_BY_VAL":
            cmds[name] = (ret, params)

    # Resolve aliases
    for name, target in aliases.items():
        cur = target
        for _ in range(4):
            if cur in cmds:
                cmds[name] = cmds[cur]
                break
            cur = aliases.get(cur, "")

    return cmds, aliases


CTYPE = {"v": "void", "u": "uint32_t", "p": "uint64_t", "f": "float", "d": "double"}


def emit_trampoline(sig: str, ret: str, params: List[str]) -> str:
    fn_name = f"vk_tramp_{sig}"
    p_types = ", ".join(CTYPE[k] for k in params) if params else "void"
    lines = [
        f"static void {fn_name}(CPU64 *c, void *ud) {{",
        f"    typedef {CTYPE[ret]} (*Fn)({p_types});",
        f"    Fn fn = (Fn)ud;",
    ]
    gp = 0
    fp = 0
    stack_slot = 0
    sysv_args = []
    win64_args = []
    for i, k in enumerate(params):
        if k in ("p", "u"):
            if gp < 6:
                expr = f"sysv_arg_i(c, {gp})"
                gp += 1
            else:
                expr = f"R64(c->rsp + 8ULL + {stack_slot * 8}ULL)"
                stack_slot += 1
            sysv_args.append(f"({CTYPE[k]})({expr})")
            win64_args.append(f"({CTYPE[k]})(win64_arg_i(c, {i}))")
        elif k == "f":
            if fp < 8:
                expr = f"sysv_arg_f(c, {fp})"
                fp += 1
            else:
                expr = f"({{ uint32_t _u = R32(c->rsp + 8ULL + {stack_slot * 8}ULL); float _f; memcpy(&_f, &_u, 4); _f; }})"
                stack_slot += 1
            sysv_args.append(expr)
            if i < 4:
                win64_args.append(f"win64_arg_f(c, {i})")
            else:
                win64_args.append(f"({{ uint32_t _u = R32(c->rsp + 8ULL + {i * 8}ULL); float _f; memcpy(&_f, &_u, 4); _f; }})")
        elif k == "d":
            if fp < 8:
                expr = f"sysv_arg_d(c, {fp})"
                fp += 1
            else:
                expr = f"({{ uint64_t _u = R64(c->rsp + 8ULL + {stack_slot * 8}ULL); double _d; memcpy(&_d, &_u, 8); _d; }})"
                stack_slot += 1
            sysv_args.append(expr)
            if i < 4:
                win64_args.append(f"win64_arg_d(c, {i})")
            else:
                win64_args.append(f"({{ uint64_t _u = R64(c->rsp + 8ULL + {i * 8}ULL); double _d; memcpy(&_d, &_u, 8); _d; }})")

    s_str = ", ".join(sysv_args)
    w_str = ", ".join(win64_args)
    if not params:
        call_e = "fn()"
    else:
        call_e = f"(g_rt_is_win64 ? fn({w_str}) : fn({s_str}))"
    if ret == "v":
        lines.append(f"    {call_e};")
    elif ret == "u":
        lines.append(f"    c->rax = (uint64_t)(uint32_t){call_e};")
    elif ret == "p":
        lines.append(f"    c->rax = (uint64_t){call_e};")
    elif ret == "f":
        lines.append(f"    c->xmm[0].f[0] = {call_e};")
    elif ret == "d":
        lines.append(f"    c->xmm[0].df[0] = {call_e};")
    lines.append("}")
    return "\n".join(lines)


def generate(xml_path: str, out_path: str) -> Tuple[int, int]:
    cmds, _ = parse_vk_xml(xml_path)
    sigs: Dict[str, Tuple[str, List[str]]] = {}
    for _name, (ret, params) in cmds.items():
        sig = f"{ret}_{''.join(params) or 'v'}"
        if sig not in sigs:
            sigs[sig] = (ret, params)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as f:
        f.write("/* Auto-generated by tools/gen_vulkan64.py from Khronos vk.xml. Do not edit. */\n\n")
        for sig in sorted(sigs.keys()):
            ret, params = sigs[sig]
            f.write(emit_trampoline(sig, ret, params))
            f.write("\n\n")

        f.write("typedef struct { const char *name; RTShimFn tramp; } VkCmdTramp;\n\n")
        f.write("static const VkCmdTramp g_vk_cmd_tramps[] = {\n")
        for name in sorted(cmds.keys()):
            ret, params = cmds[name]
            sig = f"{ret}_{''.join(params) or 'v'}"
            f.write(f'    {{ "{name}", vk_tramp_{sig} }},\n')
        f.write("};\n")
        f.write(f"static const size_t g_vk_cmd_tramp_count = {len(cmds)};\n")

    return len(cmds), len(sigs)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate Vulkan System V -> Darwin ARM64 trampolines.")
    ap.add_argument("--xml", default=DEFAULT_VK_XML, help="Path to Khronos vk.xml")
    ap.add_argument("-o", "--out", required=True, help="Output .inc file path")
    args = ap.parse_args()
    ncmds, nsigs = generate(args.xml, args.out)
    print(f"gen_vulkan64: generated {ncmds} Vulkan command mappings using {nsigs} unique trampolines -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
