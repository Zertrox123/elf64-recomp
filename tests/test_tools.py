#!/usr/bin/env python3
"""Unit tests for elfprep64.py, lift64.py, and gen_vulkan64.py."""

import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

import audit_pe64  # noqa: E402
import gen_status  # noqa: E402
import gen_vulkan64  # noqa: E402
import lift64  # noqa: E402
import peprep64  # noqa: E402
import subprocess  # noqa: E402


class TestLift64(unittest.TestCase):
    def test_parse_mem_rip_relative(self):
        w, expr = lift64.parse_mem("qword ptr [rip + 0x1125]", 0x700000133B)
        self.assertEqual(w, 64)
        self.assertIn("0x700000133bULL", expr)
        self.assertIn("0x1125ULL", expr)

    def test_parse_mem_fs_canary(self):
        w, expr = lift64.parse_mem("qword ptr fs:[0x28]", 0x7000001000)
        self.assertEqual(w, 64)
        self.assertIn("c->fs_base +", expr)
        self.assertIn("0x28ULL", expr)

    def test_parse_mem_sib_negative_disp(self):
        w, expr = lift64.parse_mem("dword ptr [rbp + rcx*4 - 0x10]", 0x7000001000)
        self.assertEqual(w, 32)
        self.assertIn("c->rbp", expr)
        self.assertIn("c->rcx", expr)
        self.assertIn("* 4ULL", expr)
        self.assertIn("- 0x10ULL", expr)

    def test_32bit_write_zero_extends(self):
        ins = lift64.Insn(0x1000, 3, "mov eax, ebx", "", "mov", ["eax", "ebx"])
        unimpl = []
        code = lift64.lift_insn(ins, {0x1000}, False, unimpl)
        self.assertEqual(unimpl, [])
        self.assertIn("SET32(c->rax", code)

    def test_lock_xadd(self):
        ins = lift64.Insn(0x1000, 5, "lock xadd qword ptr [rdi], rax", "lock", "xadd", ["qword ptr [rdi]", "rax"])
        unimpl = []
        code = lift64.lift_insn(ins, {0x1000}, False, unimpl)
        self.assertEqual(unimpl, [])
        self.assertIn("__atomic_fetch_add", code)

    def test_cmpxchg16b(self):
        ins = lift64.Insn(0x1000, 5, "lock cmpxchg16b xmmword ptr [r9]", "lock", "cmpxchg16b", ["xmmword ptr [r9]"])
        unimpl = []
        code = lift64.lift_insn(ins, {0x1000}, False, unimpl)
        self.assertEqual(unimpl, [])
        self.assertIn("__atomic_compare_exchange_n((__uint128_t *)", code)

    def test_sse_scalar_and_packed(self):
        for txt in (
            "addsd xmm0, xmm1",
            "mulss xmm2, dword ptr [rdi]",
            "xorps xmm0, xmm0",
            "pshufd xmm0, xmm1, 0xe4",
            "pshufb xmm0, xmm1",
            "palignr xmm0, xmm1, 0x4",
            "ptest xmm0, xmm1",
            "pmovzxbd xmm0, dword ptr [rsi]",
            "pmovsxdq xmm1, qword ptr [rcx - 0x10]",
            "cmpltps xmm3, xmmword ptr [rcx + 0x10]",
            "roundss xmm0, xmm1, 0x1",
            "roundps xmm0, xmm1, 0x2",
            "blendvps xmm1, xmm2, xmm0",
            "dpps xmm0, xmm1, 0x71",
            "insertps xmm0, xmm1, 0x10",
            "extractps eax, xmm0, 0x2",
            "pextrd eax, xmm0, 0x2",
            "pinsrd xmm0, eax, 0x1",
        ):
            pfx, mnem, ops = lift64.parse_insn_text(txt)
            ins = lift64.Insn(0x1000, 4, txt, pfx, mnem, ops)
            unimpl = []
            code = lift64.lift_insn(ins, {0x1000}, False, unimpl)
            self.assertEqual(unimpl, [], f"failed on {txt}")
            self.assertTrue(len(code) > 0)

    def test_movsd_mem_xmm_not_string_op(self):
        txt = "movsd qword ptr [rsp + 0x58], xmm1"
        pfx, mnem, ops = lift64.parse_insn_text(txt)
        ins = lift64.Insn(0x1000, 6, txt, pfx, mnem, ops)
        unimpl = []
        code = lift64.lift_insn(ins, {0x1000}, False, unimpl)
        self.assertEqual(unimpl, [])
        self.assertIn("W64(", code)
        self.assertIn("xmm[1].q[0]", code)
        self.assertNotIn("c->rsi", code)


class TestGenVulkan64(unittest.TestCase):
    def test_vk_xml_parses_core_commands(self):
        if not os.path.exists(gen_vulkan64.DEFAULT_VK_XML):
            self.skipTest("vk.xml not installed")
        cmds, _ = gen_vulkan64.parse_vk_xml(gen_vulkan64.DEFAULT_VK_XML)
        self.assertGreater(len(cmds), 500)
        self.assertEqual(cmds["vkCreateInstance"], ("u", ["p", "p", "p"]))
        self.assertEqual(cmds["vkCmdSetViewport"], ("v", ["p", "u", "u", "p"]))
        self.assertEqual(cmds["vkCmdSetDepthBias"], ("v", ["p", "f", "f", "f"]))
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "vk.inc")
            ncmds, nsigs = gen_vulkan64.generate(gen_vulkan64.DEFAULT_VK_XML, out)
            self.assertGreater(ncmds, 500)
            self.assertGreater(nsigs, 30)


class TestPePrep64(unittest.TestCase):
    def test_pe64_prepare_and_lift_cross_dll(self):
        lld_link = "/opt/homebrew/bin/lld-link"
        if not os.path.exists(lld_link):
            self.skipTest("lld-link not installed")
        with tempfile.TemporaryDirectory() as d:
            dll_c = os.path.join(d, "helper.c")
            dll_o = os.path.join(d, "helper.obj")
            dll_p = os.path.join(d, "helper.dll")
            dll_lib = os.path.join(d, "helper.lib")
            exe_c = os.path.join(d, "app.c")
            exe_o = os.path.join(d, "app.obj")
            exe_p = os.path.join(d, "app.exe")

            with open(dll_c, "w") as f:
                f.write("__declspec(dllexport) int helper_add(int a, int b) { return a + b + 5; }\n")
            with open(exe_c, "w") as f:
                f.write(
                    "__declspec(dllimport) int helper_add(int a, int b);\n"
                    "int main(void) { return helper_add(10, 20); }\n"
                )
            subprocess.check_call(["clang", "-target", "x86_64-pc-windows-msvc", "-O2", "-c", dll_c, "-o", dll_o])
            subprocess.check_call([lld_link, "/dll", "/noentry", f"/implib:{dll_lib}", dll_o, f"/out:{dll_p}"])
            subprocess.check_call(["clang", "-target", "x86_64-pc-windows-msvc", "-O2", "-c", exe_c, "-o", exe_o])
            subprocess.check_call([lld_link, "/entry:main", "/subsystem:console", exe_o, dll_lib, f"/out:{exe_p}"])

            prep_dir = os.path.join(d, "prep")
            lift_dir = os.path.join(d, "lift")
            layout = peprep64.prepare_pe_modules([exe_p, dll_p], prep_dir)
            self.assertEqual(layout["format"], "pe64")
            self.assertEqual(layout["abi"], "win64")
            self.assertEqual(len(layout["modules"]), 2)
            # helper_add resolved inside guest DLL -> 0 external host imports!
            self.assertEqual(len(layout["imports"]), 0)
            self.assertIn("helper_add", layout["modules"][1]["exports"])

            res = lift64.lift_layout(os.path.join(prep_dir, "layout.json"), lift_dir, shards=2, strict=True)
            self.assertEqual(res["unimpl"], [])
            self.assertGreaterEqual(res["funcs"], 2)

            rep = audit_pe64.audit_target(d, main_exe="app.exe", lift_audit=True)
            self.assertEqual(rep["modules"], 2)
            self.assertEqual(rep["missing_imports"], 0)
            self.assertEqual(rep["unimpl_mnemonics"], [])
            self.assertIn("D3D11CreateDeviceAndSwapChain", audit_pe64.collect_implemented_shims())


class TestGenStatus(unittest.TestCase):
    def test_squarify_and_svg_bounds(self):
        rects = gen_status.squarify_layout([("a", 50.0), ("b", 30.0), ("c", 20.0)], 0, 0, 400, 200)
        self.assertEqual(len(rects), 3)
        total_area = sum(rw * rh for _, _, _, rw, rh in rects)
        self.assertAlmostEqual(total_area, 80000.0, places=2)
        svg = gen_status.render_full_svg({"kernel32": (10, 20)}, {"GPR": (5, 5)})
        self.assertIn("<svg", svg)
        self.assertIn("kernel32", svg)
        self.assertIn("GPR", svg)


if __name__ == "__main__":
    unittest.main()
