#!/usr/bin/env python3
"""
ledger.py — the tamper-evident hash chain of decisions (the testimony).

Every gate decision + its outcome is appended as one entry, hash-linked to the
entry before it (genesis-anchored). Mutating any past entry breaks the re-link,
so the chain cannot be silently edited after the fact: you can prove what the
agent was allowed to do, and what it actually did, or prove the record was
tampered with. There is no third option. That is the whole point — the run does
not *claim* it behaved; it *testifies*, and the testimony is verifiable.

Tamper-evidence is sha256-only. There is no key material and no signing here:
the chain proves *internal consistency* (no entry was altered or reordered), not
*authorship* (who wrote it). Cryptographic signing (e.g. ed25519) is a deliberate
non-goal of this reference layer — it would introduce key handling, which is a
separate, heavier security surface. Keep that boundary honest in anything you
build on top: a sha256 chain is tamper-EVIDENT, not tamper-PROOF against an
attacker who can rewrite the whole file from genesis.

One specific limit to keep honest: `verify()` on its own does NOT detect
TRUNCATION of the tail. Dropping the most-recent entries leaves a shorter chain
that still re-links cleanly from genesis, so a chain missing its last N decisions
verifies as intact — a hash chain has no built-in length commitment. To detect
truncation you need an external anchor that commits the head + length: that is
exactly what a sealed receipt does (receipts.py binds a specific head hash), and
`verify_entries(..., expected_len=N)` below enforces a known length when the caller
has one. Truncation is caught by the receipt/length anchor, not by the chain alone.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .gate import GateDecision


class Ledger:
    """Append-only, hash-chained, tamper-evident record of governed actions."""

    GENESIS = "GENESIS"

    def __init__(self, path: os.PathLike | str | None = None):
        self.path = Path(path) if path is not None else None
        self.prev = self.GENESIS
        self.entries: list[dict] = []

    @staticmethod
    def _hash(prev: str, payload: dict) -> str:
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(f"{prev}\n{body}".encode("utf-8")).hexdigest()

    def record(self, *, agent: str, tool: str, params: dict, decision: GateDecision,
               outcome: str = "") -> dict:
        """Append one entry: (who, what, the verdict, a hash of the outcome). The
        outcome is stored as a sha256, not verbatim — the ledger testifies that a
        specific output occurred without itself becoming a data-exfiltration sink."""
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agent": agent,
            "tool": tool,
            "params": {k: (str(v)[:200]) for k, v in (params or {}).items()},
            "verdict": decision.verdict,
            "blast_class": decision.blast_class,
            "reason": decision.reason,
            "outcome_sha256": hashlib.sha256(outcome.encode("utf-8")).hexdigest() if outcome else "",
        }
        entry = dict(payload)
        entry["prev_hash"] = self.prev
        entry["entry_hash"] = self._hash(self.prev, payload)
        self.prev = entry["entry_hash"]
        self.entries.append(entry)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    @classmethod
    def verify_entries(cls, entries: list[dict], genesis: str | None = None,
                       expected_len: int | None = None) -> tuple[bool, str]:
        """Recompute a chain from a list of stored entries (no live chain needed).
        Returns (ok, message). Any mutated/reordered entry -> (False, where).

        `expected_len`: when the caller knows how many entries the chain SHOULD
        have (from a sealed receipt or an out-of-band count), pass it to catch
        TRUNCATION — a shorter chain re-links cleanly from genesis and would
        otherwise verify as intact. Fail-closed: a length mismatch is a break."""
        if expected_len is not None and len(entries) != expected_len:
            return False, f"length mismatch: {len(entries)} entries, expected {expected_len} (truncation?)"
        prev = genesis if genesis is not None else cls.GENESIS
        for i, e in enumerate(entries):
            payload = {k: e[k] for k in e if k not in ("prev_hash", "entry_hash")}
            if e.get("prev_hash") != prev:
                return False, f"entry {i}: prev_hash break"
            if e.get("entry_hash") != cls._hash(prev, payload):
                return False, f"entry {i}: hash mismatch (tampered)"
            prev = e["entry_hash"]
        return True, f"chain intact ({len(entries)} entries)"

    def verify(self) -> tuple[bool, str]:
        """Recompute the live chain; returns (ok, message)."""
        return self.verify_entries(self.entries, self.GENESIS)

    def to_dict(self) -> dict:
        """Serializable snapshot of the chain for persistence (see receipts.py)."""
        return {"genesis": self.GENESIS, "entries": list(self.entries)}

    @classmethod
    def load(cls, path: os.PathLike | str) -> "Ledger":
        """Rehydrate a ledger from a .jsonl log (one entry per line)."""
        led = cls(path)
        p = Path(path)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    led.entries.append(json.loads(line))
            if led.entries:
                led.prev = led.entries[-1].get("entry_hash", cls.GENESIS)
        return led


__all__ = ["Ledger"]
