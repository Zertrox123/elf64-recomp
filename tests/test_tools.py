#!/usr/bin/env python3
"""Unit tests for elfprep64.py, lift64.py, and gen_vulkan64.py."""

import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

import gen_vulkan64  # noqa: E402
import lift64  # noqa: E402


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

    def test_sse_scalar_and_packed(self):
        for txt in ("addsd xmm0, xmm1", "mulss xmm2, dword ptr [rdi]", "xorps xmm0, xmm0", "pshufd xmm0, xmm1, 0xe4"):
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


if __name__ == "__main__":
    unittest.main()
