#!/usr/bin/env python3
"""Self-gate — deponent gates its own development. The reference kernel must stay
CONFORMANT against its own GAK clauses AND a governed self-build's claim-mode
testimony must be SOUND. A kernel that regresses (here: a non-conformant candidate)
fails the gate. Run: python3 -m pytest -q tests/test_selfgate.py"""
import tempfile
import unittest
from pathlib import Path

from deponent.selfgate import governed_self_build, run_self_gate


class _DenyEverything:
    """A regressed candidate: blocks legitimate in-sandbox work too (not governance,
    bricking). It must FAIL the self-gate via the GAK-ALLOW-INBOUNDS clause."""
    name = "deny-everything"
    profile = "action-gate"
    supports = frozenset()

    def verdict(self, tool, params):
        return "BLOCK"

    def clean_chain_verifies(self):
        return True

    def tamper_is_detected(self):
        return True


class TestSelfGate(unittest.TestCase):
    def test_deponent_clears_its_own_bar(self):
        r = run_self_gate()
        self.assertTrue(r["passed"])
        self.assertTrue(r["conformant"])
        self.assertTrue(r["sound"])
        self.assertEqual(r["refuted"], [])

    def test_governed_self_build_testifies_soundly(self):
        sandbox = Path(tempfile.mkdtemp(prefix="sg-"))
        cell, claims = governed_self_build(sandbox)
        # the build ran through the gate and the testimony holds
        self.assertTrue(claims.sound)
        self.assertTrue(cell.verify()[0])  # tamper-evident chain intact
        gate = next(c for c in claims.claims if c.id == "C-GATE-PRECEDES")
        self.assertEqual(gate.status, "ATTESTED")
        blocks = next(c for c in claims.claims if c.id == "C-BLOCKS-RECORDED")
        self.assertEqual(blocks.status, "ATTESTED")  # the recorded rm -rf BLOCK

    def test_regressed_kernel_fails_the_gate(self):
        r = run_self_gate(adapter=_DenyEverything())
        self.assertFalse(r["passed"])
        self.assertFalse(r["conformant"])  # deny-everything is not conformance

    def test_live_governed_real_build(self):
        # FULL DOGFOOD: deponent governs its OWN real git+rustc build, jailed.
        # Executes real toolchain commands; skip where the jail can't confine.
        from deponent.jail import jail_available
        if not jail_available():
            self.skipTest("no jail backend (Seatbelt/Docker) on this host")
        from deponent.selfgate import governed_real_build
        sandbox = Path(tempfile.mkdtemp(prefix="sg-live-"))
        cell, claims, trace = governed_real_build(sandbox)
        self.assertTrue(claims.sound)          # the build testifies soundly
        self.assertTrue(cell.verify()[0])      # tamper-evident chain intact
        push = next(t for t in trace if "git push" in t["action"])
        self.assertEqual(push["verdict"], "BLOCK")    # the irreversible floor held
        commit = next(t for t in trace if "commit" in t["action"])
        self.assertEqual(commit["verdict"], "ALLOW")  # local commit governed-allowed


if __name__ == "__main__":
    unittest.main()
