#!/usr/bin/env python3
"""Audit a real Windows x64 game directory (e.g. Portal: Revolution bin/win64).

Runs peprep64 across the game's .exe + .dll graph, compares every unresolved
host DLL import against the shims registered in runtime/*.c/*.m, and optionally
dry-run lifts all modules to rank missing x86_64 instructions by frequency.
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import sys
import tempfile
from typing import List, Set

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
RUNTIME_DIR = os.path.join(REPO_ROOT, "runtime")

sys.path.insert(0, TOOLS_DIR)
import lift64  # noqa: E402
import peprep64  # noqa: E402


def collect_implemented_shims() -> Set[str]:
    shims: Set[str] = set()
    pat = re.compile(r'(?:REG|rt_register_shim)\(\s*"([^"]+)"')
    for fn in os.listdir(RUNTIME_DIR):
        if fn.endswith((".c", ".m")):
            with open(os.path.join(RUNTIME_DIR, fn)) as f:
                shims.update(pat.findall(f.read()))
    return shims


def collect_pe_files(target: str, main_exe: str | None = None) -> List[str]:
    if os.path.isfile(target):
        return [os.path.abspath(target)]
    exes, dlls = [], []
    for name in sorted(os.listdir(target)):
        full = os.path.join(target, name)
        if not os.path.isfile(full):
            continue
        low = name.lower()
        if low.endswith(".exe"):
            exes.append(full)
        elif low.endswith(".dll"):
            dlls.append(full)
    if main_exe:
        exes = [p for p in exes if os.path.basename(p).lower() == main_exe.lower()] + [
            p for p in exes if os.path.basename(p).lower() != main_exe.lower()
        ]
    ordered = (exes[:1] if exes else []) + dlls
    if not ordered:
        raise FileNotFoundError(f"no .exe/.dll found in {target}")
    return ordered


def audit_target(target: str, main_exe: str | None = None, lift_audit: bool = False) -> dict:
    pes = collect_pe_files(target, main_exe=main_exe)
    impl_shims = collect_implemented_shims()

    with tempfile.TemporaryDirectory(prefix="pe64_audit_") as tmp:
        layout = peprep64.prepare_pe_modules(pes, tmp)
        by_dll = collections.defaultdict(list)
        missing_by_dll = collections.defaultdict(list)
        for imp in layout["imports"]:
            dll = imp.get("dll") or "?"
            sym = imp["name"]
            by_dll[dll].append(sym)
            if sym not in impl_shims and f"{dll}!{sym}" not in impl_shims:
                missing_by_dll[dll].append(sym)

        unimpl_counts = collections.Counter()
        total_funcs = 0
        if lift_audit:
            res = lift64.lift_layout(os.path.join(tmp, "layout.json"), os.path.join(tmp, "lift"), shards=4, strict=False)
            total_funcs = res["funcs"]
            for item in res["unimpl"]:
                if hasattr(item, "mnemonic"):
                    mnem = item.mnemonic.lower()
                else:
                    insn_txt = item.split(":", 1)[1].strip() if ":" in item else item
                    mnem = insn_txt.split(None, 1)[0].lower() if insn_txt else "?"
                unimpl_counts[mnem] += 1

        return {
            "modules": len(layout["modules"]),
            "total_imports": len(layout["imports"]),
            "missing_imports": sum(len(v) for v in missing_by_dll.values()),
            "by_dll": {k: sorted(v) for k, v in sorted(by_dll.items())},
            "missing_by_dll": {k: sorted(v) for k, v in sorted(missing_by_dll.items())},
            "total_funcs": total_funcs,
            "unimpl_mnemonics": unimpl_counts.most_common(30),
        }


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit a Windows x64 game directory for PE64 static recompilation.")
    ap.add_argument("target", help="Directory containing .exe/.dll files (e.g. bin/win64) or single PE64 file")
    ap.add_argument("--main", help="Preferred main .exe filename")
    ap.add_argument("--lift", action="store_true", help="Also dry-run lift all modules and rank missing instructions")
    args = ap.parse_args()

    rep = audit_target(args.target, main_exe=args.main, lift_audit=args.lift)
    covered = rep["total_imports"] - rep["missing_imports"]
    print(f"PE64 Audit: {rep['modules']} module(s), {rep['total_imports']} host import(s) ({covered} covered, {rep['missing_imports']} missing)")
    print("\nMissing host imports by DLL:")
    for dll, syms in sorted(rep["missing_by_dll"].items(), key=lambda kv: -len(kv[1])):
        preview = ", ".join(syms[:12]) + (f", ... (+{len(syms) - 12})" if len(syms) > 12 else "")
        print(f"  {dll:28s} ({len(syms):3d}): {preview}")
    if args.lift:
        print(f"\nLifted functions: {rep['total_funcs']}")
        if rep["unimpl_mnemonics"]:
            print("Top missing x86_64 mnemonics:")
            for mnem, cnt in rep["unimpl_mnemonics"]:
                print(f"  {mnem:16s} {cnt}")
        else:
            print("All x86_64 instructions covered (0 unimplemented)!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
