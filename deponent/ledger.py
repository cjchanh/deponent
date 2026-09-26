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
`verify_entries(..., expected_length=N, expected_head=h)` (and `verify` likewise)
enforces a known length and head when the caller has one. Truncation and a full
re-chain are caught by that external head/length anchor, not by the chain alone.

Absent testimony is the limit case, and it fails closed. A ledger that `load()`
rehydrates from a missing or empty file holds zero entries, which is exactly what
deleting or emptying the file produces, so `verify()` never calls it intact on its
own: it returns (False, "no testimony: ...") unless an external anchor commits to an
empty chain (`expected_head=Ledger.GENESIS` or `expected_length=0`, e.g. the
`ledger_head` / `ledger_length` of a receipt for a run that recorded nothing).

A fresh chain never forks an existing file. `Ledger(path)` starts at GENESIS, so it
refuses (FileExistsError) a path that already holds a chain instead of appending a
second chain there; continuing an existing chain is explicit: `Ledger.load(path)`.
Every append also checks that the file still ends where this ledger left it (same
byte length, same last entry hash). If another writer appended to it, cut it or
replaced it, `record()` raises `LedgerForkError` (a FileExistsError) and writes
nothing, instead of forking the chain from a stale head.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .gate import GateDecision

# The writer ends every record with "\n" and never puts a raw "\n" or "\r" inside one
# (JSON escapes both), while U+2028, U+2029 and U+0085 stay raw inside strings. So every
# reader splits records on "\n" only, never str.splitlines(), and a line is blank only if
# it holds nothing but JSON whitespace. "\r" is included because released text-mode
# writers ended each record with "\r\n" on Windows.
_JSON_BLANK = " \t\r\n"
_JSON_BLANK_BYTES = _JSON_BLANK.encode("ascii")


class LedgerForkError(FileExistsError):
    """Appending would fork the chain in the ledger's file: the file already holds a
    chain this ledger did not start, or no longer ends where this ledger left it."""


class Ledger:
    """Append-only, hash-chained, tamper-evident record of governed actions."""

    GENESIS = "GENESIS"

    def __init__(self, path: os.PathLike | str | None = None):
        """Start a NEW chain at GENESIS, persisted to `path` when one is given.
        Raises FileExistsError if `path` already holds a chain: appending a fresh
        chain there would fork it. Continue an existing chain with `Ledger.load()`."""
        self.path = Path(path) if path is not None else None
        self.prev = self.GENESIS
        self.entries: list[dict] = []
        # Provenance, set only by load(): True if the file existed, False if not. None
        # marks a live ledger, whose emptiness is first-hand, not read from disk.
        self._loaded_file_found: bool | None = None
        # Byte length of the file as this ledger last saw it: at load(), then after
        # each of its own appends. None until the ledger has read or written the file.
        self._seen_size: int | None = None
        self._refuse_to_fork()

    @staticmethod
    def _file_size(path: Path) -> int | None:
        try:
            return path.stat().st_size
        except FileNotFoundError:
            return None

    @staticmethod
    def _read_tail(path: Path, chunk: int = 4096) -> tuple[int, bytes]:
        """(byte length, last non-blank line) of `path`, read backwards from the end,
        so an append costs one short read rather than a re-read of the whole file."""
        with path.open("rb") as f:
            size = end = f.seek(0, os.SEEK_END)
            buf = b""
            while end > 0:
                start = max(0, end - chunk)
                f.seek(start)
                buf = f.read(end - start) + buf
                end = start
                tail = buf.rstrip(_JSON_BLANK_BYTES)
                cut = tail.rfind(b"\n")
                if tail and (cut != -1 or end == 0):
                    return size, tail[cut + 1:].strip(_JSON_BLANK_BYTES)
            return size, b""

    @staticmethod
    def _holds_entries(path: Path) -> bool:
        """True if `path` is a regular file with at least one non-blank line. Read as
        bytes split on "\\n", so undecodable content, and whitespace JSON does not
        allow (e.g. "\\v"), still count as content."""
        if not path.is_file():
            return False
        with path.open("rb") as f:
            return any(line.strip(_JSON_BLANK_BYTES) for line in f)

    def _refuse_to_fork(self) -> None:
        """Fail closed before a GENESIS-rooted chain lands on a file holding entries."""
        if self.path is not None and self._holds_entries(self.path):
            raise LedgerForkError(
                f"ledger file already holds a chain: {self.path}; continue it with "
                "Ledger.load(path) or record to a new path"
            )

    def _refuse_stale_file(self) -> None:
        """Before an append, the file must still end where this ledger left it: the
        same byte length and the same last entry hash. Otherwise another writer has
        appended to it, cut it or replaced it, and appending from here would fork it."""
        if not self.entries and self.prev == self.GENESIS:
            self._refuse_to_fork()  # a fresh chain: the file may have gained one since
            self._seen_size = self._file_size(self.path)
            return
        try:
            size, last = self._read_tail(self.path)
        except FileNotFoundError:
            raise LedgerForkError(
                f"ledger file vanished since this ledger last saw it: {self.path}; "
                "refusing to append a chain with no head"
            ) from None
        try:
            head = json.loads(last).get("entry_hash") if last else None
        except (ValueError, AttributeError):
            head = None
        if size != self._seen_size or head != self.prev:
            raise LedgerForkError(
                f"ledger file changed since this ledger last saw it: {self.path} "
                f"(expected {self._seen_size} bytes ending at {self.prev[:12]}, found "
                f"{size} bytes ending at {str(head)[:12]}); appending would fork its "
                "chain, so reload it with Ledger.load(path)"
            )

    @staticmethod
    def _hash(prev: str, payload: dict) -> str:
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(f"{prev}\n{body}".encode("utf-8")).hexdigest()

    def record(self, *, agent: str, tool: str, params: dict, decision: GateDecision,
               outcome: str = "", gate_only: bool | None = None,
               containment: str | None = None) -> dict:
        """Append one entry: (who, what, the verdict, a hash of the outcome). The
        outcome is stored as a sha256, not verbatim — the ledger testifies that a
        specific output occurred without itself becoming a data-exfiltration sink.
        Raises LedgerForkError, writing nothing, when the file no longer ends where
        this ledger left it; memory advances only after the write lands."""
        if self.path is not None:
            self._refuse_stale_file()
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
        if gate_only is not None:
            payload["gate_only"] = gate_only
        if containment is not None:
            payload["containment"] = containment
        entry = dict(payload)
        entry["prev_hash"] = self.prev
        entry["entry_hash"] = self._hash(self.prev, payload)
        if self.path is not None:
            data = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
            with self.path.open("ab") as f:
                f.write(data)
            # Expected, not re-read: a write that slipped in between the check and this
            # one leaves the file longer than expected, so the next append refuses.
            self._seen_size = (self._seen_size or 0) + len(data)
        self.prev = entry["entry_hash"]
        self.entries.append(entry)
        return entry

    def head(self) -> tuple[str, int]:
        """Last `entry_hash` and entry count. Empty chain -> `(GENESIS, 0)` so a
        published empty head is distinct from `verify(expected_head=None)` skip."""
        if not self.entries:
            return self.GENESIS, 0
        return self.entries[-1].get("entry_hash", self.GENESIS), len(self.entries)

    @classmethod
    def verify_entries(cls, entries: list[dict], genesis: str | None = None,
                       expected_len: int | None = None, *,
                       expected_head: str | None = None,
                       expected_length: int | None = None) -> tuple[bool, str]:
        """Recompute a chain from a list of stored entries (no live chain needed).
        Returns (ok, message). Any mutated/reordered entry -> (False, where).

        Third positional is `expected_len` (legacy). `expected_head` and
        `expected_length` are keyword-only so `verify_entries(entries, genesis, 3)`
        still means length 3, not a head hash. `expected_length` aliases
        `expected_len`. When the caller has an external anchor (a sealed receipt
        or `Ledger.head()`), pass them to catch TRUNCATION and a full re-chain —
        a shorter or rewritten chain re-links cleanly from genesis and would
        otherwise verify as intact. Fail-closed: a mismatch is a break.

        A bare list carries no provenance, so an empty list with no anchor still
        re-links (vacuously). To verify a log FILE, use `Ledger.load(path).verify()`,
        which refuses a missing or empty file."""
        length = expected_length if expected_length is not None else expected_len
        if length is not None and len(entries) != length:
            return False, f"length mismatch: {len(entries)} entries, expected {length}"
        prev = genesis if genesis is not None else cls.GENESIS
        for i, e in enumerate(entries):
            payload = {k: e[k] for k in e if k not in ("prev_hash", "entry_hash")}
            if e.get("prev_hash") != prev:
                return False, f"entry {i}: prev_hash break"
            if e.get("entry_hash") != cls._hash(prev, payload):
                return False, f"entry {i}: hash mismatch (tampered)"
            prev = e["entry_hash"]
        if expected_head is not None:
            actual = entries[-1].get("entry_hash") if entries else cls.GENESIS
            if actual != expected_head:
                return False, f"head mismatch: {actual}, expected {expected_head}"
        return True, f"chain intact ({len(entries)} entries)"

    def verify(self, expected_head: str | None = None,
               expected_length: int | None = None) -> tuple[bool, str]:
        """Recompute the live chain; returns (ok, message).

        Fail-closed on absent testimony: a chain that `load()` rehydrated with zero
        entries (the file was missing or empty) never verifies as intact on its own,
        because zero entries is exactly what deleting or emptying the file produces.
        It verifies only against an external anchor that commits to an empty chain
        (`expected_head=Ledger.GENESIS` or `expected_length=0`). A live ledger that
        has recorded nothing is unaffected: its emptiness is first-hand."""
        unanchored = expected_head is None and expected_length is None
        if self._loaded_file_found is not None and not self.entries and unanchored:
            state = ("loaded ledger has no entries" if self._loaded_file_found
                     else "ledger file not found")
            return False, (f"no testimony: {state} ({self.path}); an empty chain "
                           "verifies only against an external anchor "
                           "(expected_head / expected_length)")
        return self.verify_entries(
            self.entries, self.GENESIS,
            expected_head=expected_head, expected_length=expected_length,
        )

    def to_dict(self) -> dict:
        """Serializable snapshot of the chain for persistence (see receipts.py)."""
        return {"genesis": self.GENESIS, "entries": list(self.entries)}

    @classmethod
    def load(cls, path: os.PathLike | str) -> "Ledger":
        """Rehydrate a ledger from a .jsonl log: one JSON record per "\\n"-terminated
        line, split on "\\n" only (a record may hold raw U+2028 / U+2029 / U+0085).

        This is how an existing chain is continued: `record()` on the result appends
        from the file's head. A missing path still returns an empty ledger, so a new
        chain can be started there with `record()`. It does not verify as intact on
        its own, and neither does one loaded from an empty file: see `verify()`."""
        p = Path(path)
        led = cls()  # bound after construction: a resume is not a fresh chain
        led.path = p
        led._loaded_file_found = p.exists()
        if led._loaded_file_found:
            data = p.read_bytes()
            led._seen_size = len(data)  # the next append must find the file unchanged
            for line in data.decode("utf-8").split("\n"):  # never splitlines(): see _JSON_BLANK
                if line.strip(_JSON_BLANK):
                    led.entries.append(json.loads(line))
            if led.entries:
                led.prev = led.entries[-1].get("entry_hash", cls.GENESIS)
        return led


__all__ = ["Ledger", "LedgerForkError"]
