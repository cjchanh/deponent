#!/usr/bin/env python3
"""Fail-closed proof for the receipt store. Run: python -m pytest -q tests/test_receipts.py
Uses a TEMP root — never touches a real receipt store."""
import json
import tempfile
import unittest
from pathlib import Path

from deponent import Gate, Ledger
from deponent import receipts as RA


def _ledger_with_entries(tmp: Path, n=3) -> Ledger:
    gate = Gate(tmp)
    led = Ledger(tmp / "ledger.jsonl")
    cmds = ["ls", "python -m pytest -q", "rm -rf /"]
    for i in range(n):
        d = gate.evaluate("run_cmd", {"cmd": cmds[i % len(cmds)]})
        led.record(agent="builder", tool="run_cmd", params={"cmd": cmds[i % len(cmds)]},
                   decision=d, outcome="done")
    return led


class TestReceipts(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rcpt-root-"))
        self.work = Path(tempfile.mkdtemp(prefix="rcpt-work-"))

    def _persist(self):
        led = _ledger_with_entries(self.work)
        return RA.persist(led, session_id="testsess0001", model="north-mini-code-mlx",
                          task="cidr matcher", outcome="GOVERNED_PASS", root=self.root)

    def test_persist_and_verify(self):
        r = self._persist()
        self.assertTrue(RA.verify(r["receipt_id"], root=self.root))

    def test_receipt_file_and_index_written(self):
        r = self._persist()
        rid = r["receipt_id"]
        self.assertTrue((self.root / RA.PRODUCER / f"{rid}.json").exists())
        idx = (self.root / RA.PRODUCER / "index.jsonl").read_text()
        self.assertIn(rid, idx)
        self.assertEqual((self.root / RA.PRODUCER / "LATEST").read_text(), rid)

    def test_missing_receipt_fails_closed(self):
        self.assertFalse(RA.verify("nope_does_not_exist", root=self.root))

    def test_tamper_chain_entry_detected(self):
        r = self._persist()
        p = self.root / RA.PRODUCER / f"{r['receipt_id']}.json"
        data = json.loads(p.read_text())
        # flip a gate verdict inside the chain (an attacker turning a BLOCK into ALLOW)
        data["chain"]["entries"][2]["verdict"] = "ALLOW"
        p.write_text(json.dumps(data))
        self.assertFalse(RA.verify(r["receipt_id"], root=self.root))

    def test_tamper_metadata_detected(self):
        r = self._persist()
        p = self.root / RA.PRODUCER / f"{r['receipt_id']}.json"
        data = json.loads(p.read_text())
        # flip the outcome without re-signing
        data["outcome"] = "GOVERNED_PASS_FORGED"
        p.write_text(json.dumps(data))
        self.assertFalse(RA.verify(r["receipt_id"], root=self.root))

    def test_refuses_broken_chain(self):
        led = _ledger_with_entries(self.work)
        led.entries[0]["entry_hash"] = "deadbeef"  # corrupt before persist
        with self.assertRaises(ValueError):
            RA.persist(led, session_id="x", root=self.root)

    def test_operator_receipt_written(self):
        r = self._persist()
        p = RA.write_operator_receipt(r, root=self.root)
        self.assertTrue(p.exists())
        self.assertIn("verified   : YES", p.read_text())


if __name__ == "__main__":
    unittest.main()
