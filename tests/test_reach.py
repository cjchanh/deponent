#!/usr/bin/env python3
"""The moat: the gate reasons about REAL blast radius (graph reverse-dependency),
not a substring guess. Verifies the open-core import-graph oracle + the gate's
reach-aware policy (advisory records reach; strict enforces a ceiling; fail-closed
on an unresolved graph; default gate byte-unchanged).
Run: python3 -m pytest -q tests/test_reach.py"""
import tempfile
import unittest
from pathlib import Path

from deponent.gate import Gate
from deponent.reach import ImportGraphReach, ReachReport


def _fixture() -> Path:
    """util <- a,b,c ; a <- b ; orphan <- nobody."""
    root = Path(tempfile.mkdtemp(prefix="reach-"))
    (root / "util.py").write_text("VALUE = 1\n")
    (root / "a.py").write_text("import util\n")
    (root / "b.py").write_text("import util\nimport a\n")
    (root / "c.py").write_text("import util\n")
    (root / "orphan.py").write_text("x = 0\n")
    return root


class TestImportGraphReach(unittest.TestCase):
    def setUp(self):
        self.oracle = ImportGraphReach(_fixture())

    def test_hub_reverse_dependency_reach(self):
        rr = self.oracle.blast_radius("util.py")
        self.assertTrue(rr.resolved)
        self.assertEqual(rr.score, 3)                    # a, b, c transitively depend on util
        self.assertEqual(rr.dependents, ("a", "b", "c"))  # direct importers, sorted

    def test_mid_node_reach(self):
        rr = self.oracle.blast_radius("a.py")
        self.assertEqual(rr.score, 1)                    # only b imports a
        self.assertEqual(rr.dependents, ("b",))

    def test_leaf_zero_reach(self):
        rr = self.oracle.blast_radius("orphan.py")
        self.assertTrue(rr.resolved)
        self.assertEqual(rr.score, 0)

    def test_new_file_zero_reach(self):
        rr = self.oracle.blast_radius("brand_new_module.py")  # does not exist yet -> nothing depends on it
        self.assertTrue(rr.resolved)
        self.assertEqual(rr.score, 0)


class TestReachAwareGate(unittest.TestCase):
    def setUp(self):
        self.root = _fixture()
        self.oracle = ImportGraphReach(self.root)

    def test_advisory_gate_records_real_reach(self):
        gate = Gate(self.root, reach=self.oracle)         # no ceiling -> advisory
        d = gate.evaluate("write_file", {"path": "util.py", "content": "VALUE=2"})
        self.assertEqual(d.verdict, "ALLOW")
        self.assertIsNotNone(d.reach)
        self.assertEqual(d.reach.score, 3)                # the decision now TESTIFIES to real blast radius

    def test_strict_gate_blocks_high_reach_write(self):
        gate = Gate(self.root, reach=self.oracle, max_reach=2)
        d = gate.evaluate("write_file", {"path": "util.py", "content": "VALUE=2"})
        self.assertEqual(d.verdict, "BLOCK")
        self.assertEqual(d.blast_class, "reach-exceeds-policy")
        self.assertEqual(d.reach.score, 3)

    def test_strict_gate_allows_low_reach_write(self):
        gate = Gate(self.root, reach=self.oracle, max_reach=2)
        d = gate.evaluate("write_file", {"path": "orphan.py", "content": "x=1"})
        self.assertEqual(d.verdict, "ALLOW")

    def test_strict_gate_fails_closed_on_unresolved_graph(self):
        class _DeadOracle:
            basis = "dead"
            def blast_radius(self, target):
                return ReachReport(target, 0, (), self.basis, resolved=False)
        gate = Gate(self.root, reach=_DeadOracle(), max_reach=1)
        d = gate.evaluate("write_file", {"path": "anything.py", "content": "x"})
        self.assertEqual(d.verdict, "BLOCK")
        self.assertEqual(d.blast_class, "reach-unresolved")

    def test_default_gate_unchanged_when_no_oracle(self):
        gate = Gate(self.root)                            # no oracle -> opt-out, zero behaviour change
        d = gate.evaluate("write_file", {"path": "util.py", "content": "x"})
        self.assertEqual(d.verdict, "ALLOW")
        self.assertEqual(d.blast_class, "reversible-local-write")
        self.assertIsNone(d.reach)

    def test_path_escape_still_blocks_before_reach(self):
        gate = Gate(self.root, reach=self.oracle, max_reach=99)
        d = gate.evaluate("write_file", {"path": "../escape.py", "content": "x"})
        self.assertEqual(d.verdict, "BLOCK")
        self.assertEqual(d.blast_class, "out-of-sandbox-write")  # containment runs first


if __name__ == "__main__":
    unittest.main()
