#!/usr/bin/env python3
"""Gate-only containment: interpreters opted-in, single-segment, no shell."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deponent import Cell, Gate
from deponent import receipts as RA


class TestGateOnlyContainment(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="goc-"))
        self.unjailed = Gate(self.work, unjailed=True)

    def test_python3_c_blocked_interpreter_unjailed(self):
        d = self.unjailed.evaluate(
            "run_cmd",
            {"cmd": 'python3 -c "__import__(chr(111)+chr(115)).getcwd()"'},
        )
        self.assertEqual(d.verdict, "BLOCK")
        self.assertEqual(d.blast_class, "interpreter-unjailed")

    def test_python3_script_blocked_unless_opted_in(self):
        d = self.unjailed.evaluate("run_cmd", {"cmd": "python3 script.py"})
        self.assertEqual(d.verdict, "BLOCK")
        opted = Gate(self.work, unjailed=True, allow_unjailed_interpreters=True)
        self.assertEqual(
            opted.evaluate("run_cmd", {"cmd": "python3 script.py"}).verdict, "ALLOW"
        )

    def test_unjailed_chains_blocked(self):
        d = self.unjailed.evaluate("run_cmd", {"cmd": "echo a && echo b"})
        self.assertEqual(d.verdict, "BLOCK")
        self.assertEqual(d.blast_class, "chain-unjailed")
        glued = self.unjailed.evaluate("run_cmd", {"cmd": "echo a;echo b"})
        self.assertEqual(glued.verdict, "BLOCK")

    def test_quoted_separator_is_data(self):
        d = self.unjailed.evaluate("run_cmd", {"cmd": "grep 'a;b' somefile"})
        self.assertEqual(d.verdict, "ALLOW")

    def test_gate_only_echo_runs_shell_false(self):
        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs

            class R:
                returncode = 0
                stdout = "hi"
                stderr = ""

            return R()

        cell = Cell(self.work, use_jail=False)
        with patch("deponent.cell.subprocess.run", fake_run):
            cell.act("run_cmd", {"cmd": "echo hi"})
        self.assertIsInstance(captured["args"][0], list)
        self.assertFalse(captured["kwargs"].get("shell", False))

    def test_jail_mode_chain_still_allowed(self):
        jailed = Gate(self.work, unjailed=False)
        d = jailed.evaluate("run_cmd", {"cmd": "echo a && echo b"})
        self.assertEqual(d.verdict, "ALLOW")

    def test_ledger_and_receipt_carry_containment_fields(self):
        cell = Cell(self.work, ledger_path=self.work / "ledger.jsonl", use_jail=False)
        r = cell.act("run_cmd", {"cmd": "echo hi"})
        self.assertTrue(r.entry["gate_only"] is True)
        self.assertEqual(r.entry["containment"], "none")
        root = Path(tempfile.mkdtemp(prefix="goc-rcpt-"))
        receipt = RA.persist(
            cell.ledger, session_id="goc0001", task="containment", root=root
        )
        self.assertTrue(receipt["gate_only"] is True)
        self.assertEqual(receipt["containment"], "none")

    def test_newline_still_blocks(self):
        d = self.unjailed.evaluate("run_cmd", {"cmd": "echo ok\nshred x"})
        self.assertEqual(d.verdict, "BLOCK")


if __name__ == "__main__":
    unittest.main()
