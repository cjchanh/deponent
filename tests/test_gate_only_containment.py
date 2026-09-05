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
        opted = Gate(self.work, unjailed=True, allow_unjailed_interpreters=True,
                     allow_unjailed_heads=frozenset({"python3"}))
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
        permissive = Gate(self.work, unjailed=True, allow_unjailed_interpreters=True,
                          allow_unjailed_heads=frozenset({"python3"}))
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
        self.assertGreaterEqual(text.lower().count("interpreters need both knobs"), 2)
        self.assertGreaterEqual(
            text.count("other heads need `allow_unjailed_heads` on both the Cell and its Gate"),
            2,
        )
        self.assertGreaterEqual(text.count("the Cell heads kwarg alone does not opt in a foreign gate"), 2)
        self.assertNotIn(
            "other heads need `allow_unjailed_heads`, interpreters need `allow_unjailed_interpreters`",
            text,
        )
        self.assertNotIn(
            "other heads need `allow_unjailed_heads`. Interpreters need",
            text,
        )
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

    def test_default_unjailed_gate_blocks_non_safe_heads(self):
        for cmd, extra in (
            ("ruff check .", frozenset()),
            ("cargo build", frozenset({"cargo"})),
            ("git status", frozenset({"git"})),
            ("make", frozenset({"make"})),
        ):
            g = Gate(self.work, unjailed=True, allow_heads=ALLOW_HEADS | extra)
            d = g.evaluate("run_cmd", {"cmd": cmd})
            self.assertEqual((cmd, d.verdict, d.blast_class),
                             (cmd, "BLOCK", "head-unjailed"))
            self.assertIn(cmd.split()[0], d.reason)
            self.assertIn("allow_unjailed_heads", d.reason)

    def test_allow_unjailed_heads_opts_in_named_head_only(self):
        g = Gate(self.work, unjailed=True,
                 allow_heads=ALLOW_HEADS | {"git", "cargo"},
                 allow_unjailed_heads=frozenset({"git"}))
        self.assertEqual(g.evaluate("run_cmd", {"cmd": "git status"}).verdict, "ALLOW")
        d = g.evaluate("run_cmd", {"cmd": "cargo build"})
        self.assertEqual((d.verdict, d.blast_class), ("BLOCK", "head-unjailed"))

    def test_interpreter_in_allow_unjailed_heads_still_needs_flag(self):
        g = Gate(self.work, unjailed=True, allow_unjailed_heads=frozenset({"python3"}))
        d = g.evaluate("run_cmd", {"cmd": "python3 -c pass"})
        self.assertEqual((d.verdict, d.blast_class), ("BLOCK", "interpreter-unjailed"))

    def test_every_gate_only_safe_head_allows_unjailed(self):
        from deponent.gate import GATE_ONLY_SAFE_HEADS
        expected = frozenset({
            "ls", "cat", "head", "tail", "pwd", "echo", "grep", "wc",
            "mkdir", "touch", "diff", "true", "sort", "uniq",
        })
        self.assertEqual(GATE_ONLY_SAFE_HEADS, expected)
        g = Gate(self.work, unjailed=True)
        for head in sorted(GATE_ONLY_SAFE_HEADS):
            d = g.evaluate("run_cmd", {"cmd": head})
            self.assertEqual((head, d.verdict), (head, "ALLOW"))

    def test_jail_mode_ruff_and_chain_still_allow(self):
        jailed = Gate(self.work, unjailed=False)
        self.assertEqual(jailed.evaluate("run_cmd", {"cmd": "ruff check ."}).verdict, "ALLOW")
        self.assertEqual(jailed.evaluate("run_cmd", {"cmd": "echo a && echo b"}).verdict, "ALLOW")

    def test_permissive_gate_cargo_is_head_unjailed_not_executed(self):
        class Permissive(Gate):
            def evaluate(self, tool, params):  # noqa: ARG002
                return GateDecision("ALLOW", "bounded-local-exec", "permissive test gate")

        cell = Cell(self.work, ledger_path=self.work / "l-cargo.jsonl", use_jail=False,
                    gate=Permissive(self.work, unjailed=True))
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "cargo build"})
        self.assertEqual(r.decision.verdict, "BLOCK")
        self.assertEqual(r.decision.blast_class, "head-unjailed")
        self.assertEqual(r.entry["verdict"], "BLOCK")
        self.assertTrue(r.output.startswith("BLOCKED ["))

    def test_interpreter_flag_alone_is_still_head_unjailed(self):
        cell = Cell(self.work, ledger_path=self.work / "l-interp-only.jsonl",
                    use_jail=False, allow_unjailed_interpreters=True)
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "python3 script.py"})
        self.assertEqual((r.decision.verdict, r.decision.blast_class),
                         ("BLOCK", "head-unjailed"))

    def test_gate_only_head_decision_allow_returns_none(self):
        from deponent.gate import gate_only_head_decision
        self.assertIsNone(gate_only_head_decision(
            "echo", allow_unjailed_interpreters=False, allow_unjailed_heads=frozenset(),
        ))

    def test_gate_only_head_decision_suite_does_not_lock_return_none_indent(self):
        src = Path(__file__).read_text(encoding="utf-8")
        needle = "inspect" + ".getsource"
        self.assertEqual(src.count(needle), 0)

    def test_gate_only_guard_docstring_names_head_unjailed(self):
        doc = Cell._gate_only_guard.__doc__ or ""
        self.assertIn("head-unjailed", doc)
        self.assertIn("interpreter-unjailed", doc)
        self.assertNotIn("no interpreter unless the gate opted in", doc)

    def test_cell_allow_unjailed_heads_is_conjunction_with_gate(self):
        foreign = Gate(self.work, unjailed=True,
                       allow_heads=ALLOW_HEADS | {"git"},
                       allow_unjailed_heads=frozenset({"git"}))
        tight = Cell(self.work, ledger_path=self.work / "l-heads-tight.jsonl",
                     use_jail=False, gate=foreign)
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            r = tight.act("run_cmd", {"cmd": "git status"})
        self.assertEqual((r.decision.verdict, r.decision.blast_class),
                         ("BLOCK", "head-unjailed"))
        both = Cell(self.work, ledger_path=self.work / "l-heads-both.jsonl",
                    use_jail=False, gate=foreign, allow_unjailed_heads=frozenset({"git"}))
        captured = {}

        def fake_run(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs

            class R:
                returncode = 0
                stdout = ""
                stderr = ""

            return R()

        with patch("deponent.cell.subprocess.run", fake_run):
            ok = both.act("run_cmd", {"cmd": "git status"})
        self.assertEqual(ok.decision.verdict, "ALLOW")
        self.assertEqual(captured["args"][0], ["git", "status"])
        cell_only = Cell(self.work, ledger_path=self.work / "l-heads-cell.jsonl",
                         use_jail=False, gate=Gate(self.work, unjailed=True,
                                                  allow_heads=ALLOW_HEADS | {"git"}),
                         allow_unjailed_heads=frozenset({"git"}))
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            r2 = cell_only.act("run_cmd", {"cmd": "git status"})
        self.assertEqual((r2.decision.verdict, r2.decision.blast_class),
                         ("BLOCK", "head-unjailed"))

    def test_gate_only_safe_heads_comment_is_the_allowlist(self):
        from deponent import gate as gate_mod
        src = Path(gate_mod.__file__).read_text(encoding="utf-8")
        self.assertNotIn(
            "This is a denylist over heads an integrator might allow-list", src,
        )
        marker = "GATE_ONLY_SAFE_HEADS = frozenset({"
        idx = src.index(marker)
        preamble = src[max(0, idx - 280):idx]
        self.assertIn("allowlist", preamble)

    def test_build_cell_gate_only_git_allow_make_and_python_block(self):
        from deponent.profiles import build_cell
        cell = build_cell(self.work, ledger_path=self.work / "l-bc-heads.jsonl", use_jail=False)
        self.assertEqual(cell.gate.evaluate("run_cmd", {"cmd": "git status"}).verdict, "ALLOW")
        self.assertEqual(cell.act("run_cmd", {"cmd": "make"}).decision.verdict, "BLOCK")
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "python3 -c pass"})
        self.assertEqual(r.decision.verdict, "BLOCK")

    def test_sort_o_glued_tmp_is_arg_path_escape_jailed_and_unjailed(self):
        cmd = "sort -o/tmp/x data.txt"
        for g in (self.unjailed, Gate(self.work, unjailed=False)):
            d = g.evaluate("run_cmd", {"cmd": cmd})
            self.assertEqual((d.verdict, d.blast_class), ("BLOCK", "arg-path-escape"))
            self.assertIn("-o/tmp/x", d.reason)

    def test_sort_output_equals_glued_tmp_is_arg_path_escape(self):
        cmd = "sort --output=/tmp/x data.txt"
        for g in (self.unjailed, Gate(self.work, unjailed=False)):
            d = g.evaluate("run_cmd", {"cmd": cmd})
            self.assertEqual((d.verdict, d.blast_class), ("BLOCK", "arg-path-escape"))
            self.assertIn("--output=/tmp/x", d.reason)

    def test_sort_o_glued_parent_blocks_and_dot_slash_inside_allows(self):
        stripped = Gate(self.work, unjailed=True, deny=())
        parent = stripped.evaluate("run_cmd", {"cmd": "sort -o../x data.txt"})
        self.assertEqual((parent.verdict, parent.blast_class), ("BLOCK", "arg-path-escape"))
        self.assertIn("-o../x", parent.reason)
        for g in (self.unjailed, Gate(self.work, unjailed=False), stripped):
            d = g.evaluate("run_cmd", {"cmd": "sort -o../x data.txt"})
            self.assertEqual(d.verdict, "BLOCK", g)
            inside = g.evaluate("run_cmd", {"cmd": "sort -o./inside.txt data.txt"})
            self.assertEqual(inside.verdict, "ALLOW", g)

    def test_grep_f_glued_private_tmp_is_arg_path_escape(self):
        cmd = "grep -f/private/tmp/x data.txt"
        for g in (self.unjailed, Gate(self.work, unjailed=False)):
            d = g.evaluate("run_cmd", {"cmd": cmd})
            self.assertEqual((d.verdict, d.blast_class), ("BLOCK", "arg-path-escape"))
            self.assertIn("-f/private/tmp/x", d.reason)

    def test_cat_n_allows_sort_t_slash_fail_closed_blocks(self):
        self.assertEqual(
            self.unjailed.evaluate("run_cmd", {"cmd": "cat -n data.txt"}).verdict, "ALLOW"
        )
        d = self.unjailed.evaluate("run_cmd", {"cmd": "sort -t/ data.txt"})
        self.assertEqual((d.verdict, d.blast_class), ("BLOCK", "arg-path-escape"))
        self.assertIn("-t/", d.reason)

    def test_permissive_gate_glued_sort_never_reaches_subprocess(self):
        class Permissive(Gate):
            def evaluate(self, tool, params):  # noqa: ARG002
                return GateDecision("ALLOW", "bounded-local-exec", "permissive test gate")

        cell = Cell(self.work, ledger_path=self.work / "l-glued.jsonl", use_jail=False,
                    gate=Permissive(self.work, unjailed=True))
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "sort -o/tmp/x data.txt"})
        self.assertEqual((r.decision.verdict, r.decision.blast_class),
                         ("BLOCK", "arg-path-escape"))
        self.assertEqual(r.entry["verdict"], "BLOCK")
        self.assertIn("-o/tmp/x", r.decision.reason)
        self.assertTrue(r.output.startswith("BLOCKED ["))

    def test_flag_path_candidates_four_forms(self):
        from deponent.gate import flag_path_candidates
        self.assertIn("/tmp/x", flag_path_candidates("-o/tmp/x"))
        self.assertIn("/tmp/x", flag_path_candidates("--output=/tmp/x"))
        self.assertIn("../x", flag_path_candidates("-o../x"))
        self.assertIn("./inside.txt", flag_path_candidates("-o./inside.txt"))

    def test_readme_mentions_glued_flag_path_containment(self):
        text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "argument paths are containment-checked whether spaced, glued to a flag "
            "(`-o/tmp/x`, `--output=/tmp/x`), or reached through a symlink that "
            "already exists inside the sandbox",
            text,
        )

    def test_symlink_inside_sandbox_pointing_outside_is_blocked(self):
        outside = Path(tempfile.mkdtemp(prefix="goc-outside-"))
        secret = outside / "x"
        secret.write_text("secret-outside")
        (self.work / "link").symlink_to(outside)
        cell = Cell(self.work, ledger_path=self.work / "l-sym-out.jsonl", use_jail=False)
        read = cell.act("read_file", {"path": "link/x"})
        write = cell.act("write_file", {"path": "link/x", "content": "pwned"})
        cat = cell.act("run_cmd", {"cmd": "cat link/x"})
        for r, cls in (
            (read, "out-of-sandbox-read"),
            (write, "out-of-sandbox-write"),
            (cat, "arg-path-escape"),
        ):
            self.assertEqual(r.decision.verdict, "BLOCK", r.decision)
            self.assertEqual(r.decision.blast_class, cls)
        self.assertEqual(secret.read_text(), "secret-outside")

    def test_symlink_inside_sandbox_pointing_inside_is_allowed(self):
        inside = self.work / "inside"
        inside.mkdir()
        (inside / "x").write_text("ok")
        (self.work / "link").symlink_to(inside)
        cell = Cell(self.work, ledger_path=self.work / "l-sym-in.jsonl", use_jail=False)
        read = cell.act("read_file", {"path": "link/x"})
        self.assertEqual(read.decision.verdict, "ALLOW")
        self.assertEqual(read.output, "ok")
        write = cell.act("write_file", {"path": "link/x", "content": "new"})
        self.assertEqual(write.decision.verdict, "ALLOW")
        self.assertEqual((inside / "x").read_text(), "new")
        cat = cell.act("run_cmd", {"cmd": "cat link/x"})
        self.assertEqual(cat.decision.verdict, "ALLOW")
        self.assertIn("new", cat.output)

    def test_write_through_outside_symlink_never_lands_outside(self):
        outside = Path(tempfile.mkdtemp(prefix="goc-outside-hole-"))
        secret = outside / "x"
        sentinel = "sentinel-bytes"
        secret.write_text(sentinel)
        (self.work / "link").symlink_to(outside)

        class Permissive(Gate):
            def evaluate(self, tool, params):  # noqa: ARG002
                return GateDecision("ALLOW", "reversible-local-write", "permissive test gate")

        cell = Cell(self.work, ledger_path=self.work / "l-sym-hole.jsonl", use_jail=False,
                    gate=Permissive(self.work, unjailed=True))
        write = cell.act("write_file", {"path": "link/x", "content": "pwned"})
        self.assertEqual(write.decision.verdict, "BLOCK")
        self.assertEqual(write.decision.blast_class, "out-of-sandbox-write")
        self.assertEqual(write.entry["verdict"], "BLOCK")
        self.assertTrue(write.output.startswith("BLOCKED ["))
        self.assertEqual(secret.read_text(), sentinel)
        read = cell.act("read_file", {"path": "link/x"})
        self.assertEqual(read.decision.verdict, "BLOCK")
        self.assertEqual(read.decision.blast_class, "out-of-sandbox-read")
        self.assertEqual(read.entry["verdict"], "BLOCK")
        self.assertNotIn(sentinel, read.output)
        self.assertNotIn("pwned", secret.read_text())
        self.assertFalse(write.output.startswith("wrote "))

    def test_write_read_file_direct_call_rechecks_resolved_parent(self):
        outside = Path(tempfile.mkdtemp(prefix="goc-direct-"))
        secret = outside / "x"
        sentinel = "sentinel-direct"
        secret.write_text(sentinel)
        (self.work / "link").symlink_to(outside)
        cell = Cell(self.work, ledger_path=self.work / "l-direct.jsonl", use_jail=False)
        with self.assertRaises(ValueError) as ctx:
            cell._write_file("link/x", "pwned")
        self.assertIn("path escapes sandbox", str(ctx.exception))
        self.assertEqual(secret.read_text(), sentinel)
        with self.assertRaises(ValueError) as ctx_read:
            cell._read_file("link/x")
        self.assertIn("path escapes sandbox", str(ctx_read.exception))
        self.assertEqual(secret.read_text(), sentinel)
        write_doc = Cell._write_file.__doc__ or ""
        read_doc = Cell._read_file.__doc__ or ""
        self.assertIn("direct call", write_doc)
        self.assertIn("direct call", read_doc)

    def test_write_read_opens_resolved_path_not_live_symlink(self):
        """S2: check sees sandbox/link -> inside; swap link to outside before
        the open. Opening the unresolved join would write/read outside; opening
        the resolved path from the check stays inside."""
        inside = self.work / "inside"
        inside.mkdir()
        (inside / "x").write_text("inside-ok")
        outside = Path(tempfile.mkdtemp(prefix="goc-toctou-"))
        secret = outside / "x"
        sentinel = "sentinel-toctou"
        secret.write_text(sentinel)
        link = self.work / "link"
        link.symlink_to(inside)
        cell = Cell(self.work, ledger_path=self.work / "l-toctou.jsonl", use_jail=False)
        real = cell.gate._in_sandbox

        def swap_after_check(path):
            ok = real(path)
            if ok:
                link.unlink()
                link.symlink_to(outside)
            return ok

        cell.gate._in_sandbox = swap_after_check
        wrote = cell._write_file("link/x", "pwned")
        self.assertTrue(wrote.startswith("wrote "))
        self.assertEqual(secret.read_text(), sentinel)
        self.assertEqual((inside / "x").read_text(), "pwned")
        link.unlink()
        link.symlink_to(inside)
        got = cell._read_file("link/x")
        self.assertEqual(got, "pwned")
        self.assertEqual(secret.read_text(), sentinel)

    def test_write_read_docstring_names_resolved_path_open(self):
        write_doc = Cell._write_file.__doc__ or ""
        read_doc = Cell._read_file.__doc__ or ""
        helper_doc = Cell._checked_sandbox_path.__doc__ or ""
        for doc in (write_doc, read_doc):
            self.assertIn("resolved path", doc)
            self.assertNotIn("resolved parent", doc)
        self.assertIn("same Path", helper_doc)
        self.assertIn("swapped", helper_doc)


class TestPrePlantedSymlinkContainment(unittest.TestCase):
    """D-2 (external reviewer recheck, 2026-09-05): a symlink that ALREADY sits
    inside the sandbox and points outside it turns a bare token into an
    out-of-sandbox read. Every argv token is resolved, not only path-looking ones."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="goc-d2-"))
        self.outside = Path(tempfile.mkdtemp(prefix="goc-out-"))
        (self.outside / "secret.txt").write_text("OUTSIDE-SECRET\n")
        (self.work / "inside.txt").write_text("INSIDE\n")
        (self.work / "hn").symlink_to(self.outside / "secret.txt")
        (self.work / "outdir").symlink_to(self.outside)
        (self.work / "inlink").symlink_to(self.work / "inside.txt")
        self.gate = Gate(self.work, unjailed=True)

    def test_bare_token_naming_an_outside_symlink_is_blocked(self):
        for cmd in ("cat hn", "head hn", "sort hn", "wc hn",
                    "grep localhost hn", "ls outdir", "diff hn inside.txt"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            self.assertEqual((cmd, d.verdict, d.blast_class),
                             (cmd, "BLOCK", "arg-path-escape"))

    def test_glued_flag_value_naming_an_outside_symlink_is_blocked(self):
        d = self.gate.evaluate("run_cmd", {"cmd": "sort -ohn inside.txt"})
        self.assertEqual((d.verdict, d.blast_class), ("BLOCK", "arg-path-escape"))

    def test_jail_mode_blocks_the_same_bare_token(self):
        jailed = Gate(self.work)
        d = jailed.evaluate("run_cmd", {"cmd": "cat hn"})
        self.assertEqual((d.verdict, d.blast_class), ("BLOCK", "arg-path-escape"))

    def test_in_sandbox_names_and_plain_arguments_still_allowed(self):
        for cmd in ("cat inlink", "cat inside.txt", "grep localhost inside.txt",
                    "echo hello", "sort -o out.txt inside.txt", "cat -n inside.txt"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            self.assertEqual((cmd, d.verdict), (cmd, "ALLOW"))

    def test_permissive_gate_cell_never_executes_the_outside_read(self):
        class Permissive(Gate):
            def evaluate(self, tool, params):  # noqa: ARG002
                return GateDecision("ALLOW", "bounded-local-exec", "permissive test gate")

        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False,
                    gate=Permissive(self.work, unjailed=True))
        with patch("deponent.cell.subprocess.run",
                   side_effect=AssertionError("must not execute")):
            r = cell.act("run_cmd", {"cmd": "cat hn"})
        self.assertEqual((r.decision.verdict, r.decision.blast_class),
                         ("BLOCK", "arg-path-escape"))
        self.assertEqual(r.entry["verdict"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
