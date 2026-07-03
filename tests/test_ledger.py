#!/usr/bin/env python3
"""Tamper-evidence proof for the hash-chained ledger.
Run: python -m pytest -q tests/test_ledger.py"""
import tempfile
import unittest
from pathlib import Path

from deponent import Gate, Ledger


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp())
        self.log = self.work / "ledger.jsonl"
        self.gate = Gate(self.work)

    def test_chain_intact_and_verifies(self):
        led = Ledger(self.log)
        for cmd in ("ls", "python -m pytest -q", "rm -rf /"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="builder", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="done")
        ok, msg = led.verify()
        self.assertTrue(ok, msg)
        self.assertEqual(len(led.entries), 3)

    def test_tamper_is_detected(self):
        led = Ledger(self.log)
        d = self.gate.evaluate("run_cmd", {"cmd": "ls"})
        led.record(agent="builder", tool="run_cmd", params={"cmd": "ls"}, decision=d)
        # forge a BLOCK into an ALLOW after the fact
        led.entries[0]["verdict"] = "ALLOW_FORGED"
        ok, msg = led.verify()
        self.assertFalse(ok)
        self.assertIn("hash mismatch", msg)

    def test_reordering_is_detected(self):
        led = Ledger(self.log)
        for cmd in ("ls", "wc -l", "echo hi"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d)
        led.entries[0], led.entries[1] = led.entries[1], led.entries[0]
        ok, _ = led.verify()
        self.assertFalse(ok)

    def test_persist_and_reload_roundtrip(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo hi"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        reloaded = Ledger.load(self.log)
        ok, _ = reloaded.verify()
        self.assertTrue(ok)
        self.assertEqual(len(reloaded.entries), 2)

    # --- truncation: the disclosed limit + its anchor (2026-07-03 audit) ---
    # A hash chain has no built-in length commitment: drop the tail and the shorter
    # chain still re-links from genesis. This test LOCKS that disclosed limit so it
    # can never silently become a false "any tamper is caught" claim.
    def test_truncation_passes_verify_alone(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        truncated = led.entries[:1]                       # drop the last two decisions
        ok, _ = Ledger.verify_entries(truncated)          # verify() alone: still "intact"
        self.assertTrue(ok, "documents the disclosed limit — chain-only verify misses truncation")

    # ...and the anchor that DOES catch it: a known expected length (from a receipt).
    def test_expected_len_catches_truncation(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        truncated = led.entries[:1]
        ok, msg = Ledger.verify_entries(truncated, expected_len=3)
        self.assertFalse(ok, "expected_len must fail-closed on a short chain")
        self.assertIn("truncation", msg.lower())


if __name__ == "__main__":
    unittest.main()
