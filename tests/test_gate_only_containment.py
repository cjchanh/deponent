#!/usr/bin/env python3
"""Gate-only containment: interpreters opted-in, single-segment, no shell."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deponent import Cell, Gate
from deponent import receipts as RA
from deponent.gate import ALLOW_HEADS, GateDecision, is_interpreter_head


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
        self.assertEqual(captured["args"][0], ["echo", "hi"])
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
        heads = {"python3.12", "python2", "pypy3", "bash", "sh", "env", "node", "uvx",
                 "python3.13t", "python3.12.1"}
        g = Gate(self.work, unjailed=True, allow_heads=ALLOW_HEADS | heads)
        for head in sorted(heads):
            d = g.evaluate("run_cmd", {"cmd": f"{head} -c pass"})
            self.assertEqual((head, d.verdict, d.blast_class),
                             (head, "BLOCK", "interpreter-unjailed"))

    def test_alt_launcher_heads_blocked_as_interpreter_unjailed(self):
        heads = {
            "python.exe", "pythonw", "pythonw.exe", "pythonw3", "pythonw3.exe",
            "ipython", "nodejs", "deno", "bun",
        }
        g = Gate(self.work, unjailed=True, allow_heads=ALLOW_HEADS | heads)
        for head in sorted(heads):
            d = g.evaluate("run_cmd", {"cmd": f"{head} -c pass"})
            self.assertEqual((head, d.verdict, d.blast_class),
                             (head, "BLOCK", "interpreter-unjailed"))

    def test_python_exe_allowlisted_gate_only_never_reaches_subprocess(self):
        g = Gate(self.work, unjailed=True, allow_heads=ALLOW_HEADS | {"python.exe"})
        cell = Cell(self.work, ledger_path=self.work / "l-pyexe.jsonl",
                    use_jail=False, gate=g)
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "python.exe -c pass"})
        self.assertEqual(r.decision.verdict, "BLOCK")
        self.assertEqual(r.decision.blast_class, "interpreter-unjailed")
        self.assertEqual(r.entry["verdict"], "BLOCK")

    def test_mixed_case_interpreter_never_reaches_subprocess(self):
        class Permissive(Gate):
            def evaluate(self, tool, params):  # noqa: ARG002
                return GateDecision("ALLOW", "bounded-local-exec", "permissive test gate")

        self.assertTrue(is_interpreter_head("Python3"))
        self.assertTrue(is_interpreter_head("PYTHON3"))
        cell = Cell(self.work, ledger_path=self.work / "l-case.jsonl", use_jail=False,
                    gate=Permissive(self.work, unjailed=True))
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            for cmd in ("Python3 -c pass", "PYTHON3 -c pass", "/usr/bin/Python3 -c pass"):
                r = cell.act("run_cmd", {"cmd": cmd})
                self.assertEqual(
                    (cmd, r.decision.verdict, r.decision.blast_class, r.entry["verdict"]),
                    (cmd, "BLOCK", "interpreter-unjailed", "BLOCK"),
                )

    def test_py_exe_allowlisted_gate_only_never_reaches_subprocess(self):
        g = Gate(self.work, unjailed=True, allow_heads=ALLOW_HEADS | {"py", "py.exe", "Py.exe"})
        cell = Cell(self.work, ledger_path=self.work / "l-py.jsonl",
                    use_jail=False, gate=g)
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            for cmd in ("py -c pass", "py.exe -c pass", "Py.exe -c pass"):
                r = cell.act("run_cmd", {"cmd": cmd})
                self.assertEqual(
                    (cmd, r.decision.verdict, r.decision.blast_class, r.entry["verdict"]),
                    (cmd, "BLOCK", "interpreter-unjailed", "BLOCK"),
                )

    def test_disclosure_records_selected_backend_name(self):
        class _Docker:
            name = "docker"

            def run(self, *a, **k):  # noqa: ARG002
                return {"returncode": 0, "output": "from-docker\n", "killed": ""}

        cell = Cell(self.work, ledger_path=self.work / "l-docker.jsonl", use_jail=True)
        with patch("deponent.cell.select_backend", return_value=_Docker()), \
             patch("deponent.cell.jail_available", return_value=True):
            r = cell.act("run_cmd", {"cmd": "echo hi"})
        self.assertEqual(r.decision.verdict, "ALLOW")
        self.assertIn("from-docker", r.output)
        self.assertEqual(r.entry["containment"], "docker")
        self.assertIs(r.entry["gate_only"], False)

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
            pathed = cell.act("run_cmd", {"cmd": "/usr/bin/python3 -c pass"})
            relative = cell.act("run_cmd", {"cmd": "./venv/bin/python3.12 -c pass"})
            shell = cell.act("run_cmd", {"cmd": "/bin/bash -c id"})
            launcher = cell.act("run_cmd", {"cmd": "/usr/bin/env python3 -c pass"})
            free_threaded = cell.act("run_cmd", {"cmd": "python3.13t -c pass"})
            three_part = cell.act("run_cmd", {"cmd": "python3.12.1 -c pass"})
            bad = cell.act("run_cmd", {"cmd": "echo 'unterminated"})
        for r, cls in ((chain, "chain-unjailed"), (interp, "interpreter-unjailed"),
                       (pathed, "interpreter-unjailed"), (relative, "interpreter-unjailed"),
                       (shell, "interpreter-unjailed"), (launcher, "interpreter-unjailed"),
                       (free_threaded, "interpreter-unjailed"),
                       (three_part, "interpreter-unjailed"),
                       (bad, "unparsable-command")):
            self.assertEqual(r.decision.verdict, "BLOCK")
            self.assertEqual(r.decision.blast_class, cls)
            self.assertEqual(r.entry["verdict"], "BLOCK")
            self.assertTrue(r.output.startswith("BLOCKED ["))
        ok, msg = cell.verify()
        self.assertTrue(ok, msg)

    def test_tightening_does_not_mutate_the_callers_gate(self):
        shared = Gate(self.work)
        Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False, gate=shared)
        self.assertFalse(shared.unjailed)  # a jailed Cell sharing it keeps jail policy
        d = shared.evaluate("run_cmd", {"cmd": "echo a && echo b"})
        self.assertEqual(d.verdict, "ALLOW")

    def test_interpreter_opt_in_is_the_tighter_of_cell_and_gate(self):
        permissive = Gate(self.work, unjailed=True, allow_unjailed_interpreters=True)
        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False, gate=permissive)
        self.assertFalse(cell.allow_unjailed_interpreters)
        with patch("deponent.cell.subprocess.run", side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "python3 -c pass"})
        self.assertEqual((r.decision.verdict, r.decision.blast_class), ("BLOCK", "interpreter-unjailed"))
        strict_gate = Gate(self.work, unjailed=True, allow_unjailed_interpreters=False)
        cell2 = Cell(self.work, ledger_path=self.work / "l2.jsonl", use_jail=False,
                     gate=strict_gate, allow_unjailed_interpreters=True)
        r2 = cell2.act("run_cmd", {"cmd": "python3 -c pass"})
        self.assertEqual(r2.decision.verdict, "BLOCK")  # gate refused it first

    def test_build_cell_gate_only_refuses_interpreters(self):
        from deponent.profiles import build_cell
        cell = build_cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False)
        self.assertTrue(cell.gate.unjailed)
        with patch("deponent.cell.subprocess.run", side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "python3 -c pass"})
        self.assertEqual(r.decision.blast_class, "interpreter-unjailed")

    def test_permissive_non_string_cmd_is_blocked_not_typeerror(self):
        class Permissive(Gate):
            def evaluate(self, tool, params):  # noqa: ARG002
                return GateDecision("ALLOW", "bounded-local-exec", "permissive test gate")

        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False,
                    gate=Permissive(self.work, unjailed=True))
        with patch("deponent.cell.subprocess.run", side_effect=AssertionError("must not execute")):
            none = cell.act("run_cmd", {"cmd": None})
            argv = cell.act("run_cmd", {"cmd": ["echo", "hi"]})
        for r in (none, argv):
            self.assertEqual(r.decision.verdict, "BLOCK")
            self.assertEqual(r.decision.blast_class, "empty-command")
            self.assertEqual(r.entry["verdict"], "BLOCK")
            self.assertTrue(r.output.startswith("BLOCKED ["))

    def test_permissive_empty_cmd_is_empty_command_not_chain(self):
        class Permissive(Gate):
            def evaluate(self, tool, params):  # noqa: ARG002
                return GateDecision("ALLOW", "bounded-local-exec", "permissive test gate")

        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False,
                    gate=Permissive(self.work, unjailed=True))
        with patch("deponent.cell.subprocess.run", side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": ""})
        self.assertEqual(r.decision.verdict, "BLOCK")
        self.assertEqual(r.decision.blast_class, "empty-command")
        self.assertEqual(r.entry["verdict"], "BLOCK")

    def test_build_cell_gate_only_drops_make(self):
        from deponent.profiles import build_cell, build_gate
        cell = build_cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False)
        with patch("deponent.cell.subprocess.run", side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "make"})
        self.assertEqual(r.decision.verdict, "BLOCK")
        self.assertEqual(r.decision.blast_class, "program-not-allowlisted")
        jailed = build_gate(self.work, unjailed=False)
        self.assertEqual(jailed.evaluate("run_cmd", {"cmd": "make"}).verdict, "ALLOW")

    def test_unjailed_build_drops_make_keeps_cargo_git(self):
        from deponent.profiles import UNJAILED_DROP_HEADS, build_cell, build_gate
        self.assertEqual(UNJAILED_DROP_HEADS, frozenset({"make"}))
        self.assertTrue({"cargo", "git"}.isdisjoint(UNJAILED_DROP_HEADS))
        cell = build_cell(self.work, ledger_path=self.work / "l-build.jsonl", use_jail=False)
        self.assertEqual(cell.gate.evaluate("run_cmd", {"cmd": "make"}).verdict, "BLOCK")
        self.assertEqual(cell.gate.evaluate("run_cmd", {"cmd": "cargo test"}).verdict, "ALLOW")
        self.assertEqual(cell.gate.evaluate("run_cmd", {"cmd": "git status"}).verdict, "ALLOW")
        jailed = build_gate(self.work, unjailed=False)
        self.assertEqual(jailed.evaluate("run_cmd", {"cmd": "make"}).verdict, "ALLOW")
        self.assertEqual(jailed.evaluate("run_cmd", {"cmd": "cargo test"}).verdict, "ALLOW")

    def test_readme_gate_only_is_opt_in_not_linux_default(self):
        text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("On Linux and every other host Deponent runs gate-only", text)
        self.assertIn("opt into gate-only", text)
        self.assertIn("defaults to `use_jail=True`", text)
        self.assertIn("both the Cell and its Gate", text)
        self.assertIn("ClassifyCell", text)
        self.assertIn("chain-unjailed", text)

    def test_classify_cell_blocks_chains_jail_mode_would_allow(self):
        from deponent.playground import ClassifyCell
        cell = ClassifyCell(self.work, ledger_path=self.work / "l-cls.jsonl")
        r = cell.act("run_cmd", {"cmd": "echo a && echo b"})
        self.assertEqual(r.decision.verdict, "BLOCK")
        self.assertEqual(r.decision.blast_class, "chain-unjailed")
        self.assertEqual(r.entry["verdict"], "BLOCK")
        jailed = Gate(self.work, unjailed=False)
        self.assertEqual(
            jailed.evaluate("run_cmd", {"cmd": "echo a && echo b"}).verdict, "ALLOW"
        )


if __name__ == "__main__":
    unittest.main()
