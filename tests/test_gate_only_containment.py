#!/usr/bin/env python3
"""Gate-only containment: interpreters opted-in, single-segment, no shell."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deponent import Cell, Gate
from deponent import receipts as RA
from deponent.gate import ALLOW_HEADS, GateDecision


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
        # both heads allow-listed: the newline itself must be the reason
        d2 = self.unjailed.evaluate("run_cmd", {"cmd": "echo a\necho b"})
        self.assertEqual(d2.verdict, "BLOCK")
        self.assertEqual(d2.blast_class, "chain-unjailed")

    def test_versioned_and_launcher_heads_are_interpreters(self):
        heads = {"python3.12", "python2", "pypy3", "bash", "sh", "env", "node", "uvx"}
        g = Gate(self.work, unjailed=True, allow_heads=ALLOW_HEADS | heads)
        for head in sorted(heads):
            d = g.evaluate("run_cmd", {"cmd": f"{head} -c pass"})
            self.assertEqual((head, d.verdict, d.blast_class),
                             (head, "BLOCK", "interpreter-unjailed"))

    def test_caller_supplied_jail_gate_is_tightened_for_gate_only(self):
        # A Gate built for jail mode (unjailed=False) handed to a gate-only Cell is
        # the original allow-listed-interpreter configuration. It must not run.
        foreign = Gate(self.work)  # unjailed=False, python3 allow-listed
        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False, gate=foreign)
        self.assertTrue(cell.gate.unjailed)
        with patch("deponent.cell.subprocess.run", side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "python3 -c pass"})
        self.assertEqual(r.decision.verdict, "BLOCK")
        self.assertEqual(r.decision.blast_class, "interpreter-unjailed")
        self.assertEqual(r.entry["verdict"], "BLOCK")

    def test_permissive_gate_allow_is_recorded_as_block_not_error(self):
        class Permissive(Gate):
            def evaluate(self, tool, params):  # noqa: ARG002
                return GateDecision("ALLOW", "bounded-local-exec", "permissive test gate")

        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False,
                    gate=Permissive(self.work, unjailed=True))
        with patch("deponent.cell.subprocess.run", side_effect=AssertionError("must not execute")):
            chain = cell.act("run_cmd", {"cmd": "echo a && echo b"})
            interp = cell.act("run_cmd", {"cmd": "python3 -c pass"})
            bad = cell.act("run_cmd", {"cmd": "echo 'unterminated"})
        for r, cls in ((chain, "chain-unjailed"), (interp, "interpreter-unjailed"),
                       (bad, "unparsable-command")):
            self.assertEqual(r.decision.verdict, "BLOCK")
            self.assertEqual(r.decision.blast_class, cls)
            self.assertEqual(r.entry["verdict"], "BLOCK")
            self.assertTrue(r.output.startswith("BLOCKED ["))
        ok, msg = cell.verify()
        self.assertTrue(ok, msg)

    def test_build_cell_gate_only_refuses_interpreters(self):
        from deponent.profiles import build_cell
        cell = build_cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False)
        self.assertTrue(cell.gate.unjailed)
        with patch("deponent.cell.subprocess.run", side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "python3 -c pass"})
        self.assertEqual(r.decision.blast_class, "interpreter-unjailed")


if __name__ == "__main__":
    unittest.main()
