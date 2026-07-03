#!/usr/bin/env python3
"""End-to-end proof for the Cell — the primitive working out of the box.
Run: python -m pytest -q tests/test_cell.py"""
import tempfile
import unittest
from pathlib import Path

from deponent import Cell


class TestCell(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="cell-"))
        # use_jail=False: exercise the gate + ledger surface deterministically
        # everywhere (the jail itself is proven separately in test_jail.py, macOS-only).
        self.cell = Cell(self.work, ledger_path=self.work / "ledger.jsonl", use_jail=False)

    def test_allowed_write_is_executed_and_recorded(self):
        r = self.cell.act("write_file", {"path": "hi.txt", "content": "ok"}, agent="t")
        self.assertTrue(r.allowed)
        self.assertIn("wrote 2 bytes", r.output)
        self.assertTrue((self.work / "hi.txt").exists())
        self.assertEqual(len(self.cell.ledger.entries), 1)

    def test_rogue_command_blocked_and_recorded(self):
        r = self.cell.act("run_cmd", {"cmd": "rm -rf /"}, agent="t")
        self.assertFalse(r.allowed)
        self.assertIn("BLOCKED", r.output)
        self.assertEqual(r.decision.blast_class, "destructive-or-out-of-scope")
        # a BLOCK is still recorded — the testimony includes what was refused
        self.assertEqual(len(self.cell.ledger.entries), 1)

    def test_unknown_tool_denied_by_default(self):
        r = self.cell.act("exfiltrate", {"to": "evil.example"}, agent="t")
        self.assertFalse(r.allowed)
        self.assertEqual(r.decision.blast_class, "unknown-tool")

    def test_path_escape_blocked(self):
        r = self.cell.act("write_file", {"path": "../../etc/passwd", "content": "x"}, agent="t")
        self.assertFalse(r.allowed)

    def test_chain_verifies_after_mixed_actions(self):
        self.cell.act("write_file", {"path": "a.txt", "content": "1"})
        self.cell.act("run_cmd", {"cmd": "rm -rf /"})           # blocked
        self.cell.act("read_file", {"path": "a.txt"})
        ok, msg = self.cell.verify()
        self.assertTrue(ok, msg)
        self.assertEqual(len(self.cell.ledger.entries), 3)

    def test_malformed_call_fails_soft_not_crash(self):
        # wrong param name -> the cell feeds the error back, never raises
        r = self.cell.act("write_file", {"wrong": "x"}, agent="t")
        self.assertTrue(r.allowed)  # gate allowed it (path defaults empty -> in-sandbox)
        self.assertIn("ERROR executing write_file", r.output)
        # the loop survived and recorded the attempt
        self.assertEqual(len(self.cell.ledger.entries), 1)


if __name__ == "__main__":
    unittest.main()
