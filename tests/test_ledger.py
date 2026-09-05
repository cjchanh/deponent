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
        self.assertIn("length mismatch", msg)

    def test_head_returns_last_hash_and_count(self):
        led = Ledger(self.log)
        self.assertEqual(led.head(), (Ledger.GENESIS, 0))
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        h, n = led.head()
        self.assertEqual(n, 3)
        self.assertEqual(h, led.entries[-1]["entry_hash"])

    def test_empty_head_is_genesis_and_anchors_against_rechain(self):
        led = Ledger(self.log)
        self.assertEqual(led.head(), (Ledger.GENESIS, 0))
        ok, msg = led.verify(expected_head=Ledger.GENESIS)
        self.assertTrue(ok, msg)
        ok_skip, _ = led.verify()
        self.assertTrue(ok_skip)
        d = self.gate.evaluate("run_cmd", {"cmd": "ls"})
        led.record(agent="b", tool="run_cmd", params={"cmd": "ls"}, decision=d, outcome="x")
        ok_after, msg_after = led.verify(expected_head=Ledger.GENESIS)
        self.assertFalse(ok_after)
        self.assertIn("head mismatch", msg_after)

    def test_module_docstring_anchor_line_is_not_over_indented(self):
        from deponent import ledger as ledger_mod
        doc = ledger_mod.__doc__ or ""
        self.assertIn(
            "and\n`verify_entries(..., expected_length=N, expected_head=h)`",
            doc,
        )
        self.assertNotIn("and\n    `verify_entries(", doc)

    def test_truncation_fails_expected_length_and_head(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        original_head, original_n = led.head()
        self.assertEqual(original_n, 3)
        led.entries = led.entries[:1]
        ok, _ = led.verify()
        self.assertTrue(ok, "chain-only verify still misses tail truncation")
        ok_len, msg_len = led.verify(expected_length=original_n)
        self.assertFalse(ok_len)
        self.assertIn("length mismatch", msg_len)
        ok_head, msg_head = led.verify(expected_head=original_head)
        self.assertFalse(ok_head)
        self.assertIn("head mismatch", msg_head)

    def test_rechain_after_edit_fails_expected_head(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        original_head, _ = led.head()
        led.entries[1]["verdict"] = "ALLOW_FORGED"
        prev = Ledger.GENESIS
        for e in led.entries:
            payload = {k: e[k] for k in e if k not in ("prev_hash", "entry_hash")}
            e["prev_hash"] = prev
            e["entry_hash"] = Ledger._hash(prev, payload)
            prev = e["entry_hash"]
        led.prev = prev
        ok, _ = led.verify()
        self.assertTrue(ok, "a full re-chain looks intact to verify() alone")
        ok_head, msg = led.verify(expected_head=original_head)
        self.assertFalse(ok_head)
        self.assertIn("head mismatch", msg)

    def test_middle_deletion_is_detected(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        del led.entries[1]
        ok, _ = led.verify()
        self.assertFalse(ok)

    def test_readme_names_external_head_anchor(self):
        text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "The ledger is tamper-evident for edits, deletions and reordering; "
            "truncation and re-chaining are caught only against a head published "
            "outside the ledger (`Ledger.head()` / receipt `ledger_head`)",
            text,
        )


if __name__ == "__main__":
    unittest.main()
