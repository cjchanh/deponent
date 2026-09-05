#!/usr/bin/env python3
"""
receipts.py — persist a Ledger as a verifiable receipt, fail-closed.

A receipt is a self-contained, re-verifiable record of one governed run: the full
hash chain plus signed metadata (model, task, outcome, provenance). Receipts land
in a per-producer directory with an append-only index and a LATEST pointer, so a
downstream gate (CI, a release check, an operator dashboard) can ask one question
— "did this run testify cleanly?" — and get a fail-closed answer.

The verifier RECOMPUTES. It does not trust a stored boolean (there is no
`return True` stub):
  1. the hash chain is re-linked from genesis (any mutated entry breaks it),
     consulting published ledger_head / ledger_length when present so a
     truncated or re-chained tail is caught against that external anchor, AND
  2. the receipt's own signature is recomputed over its canonical body (any
     mutated metadata breaks it).
persist() runs that real verifier as a write-time round-trip and RAISES if it
fails — so a corrupt write can never be reported as success. That is the rule the
whole project is built on: self-reported health is never the evidence.

Tamper-evidence is sha256-only — no key material. The "signature" is a content
hash, proving the body was not altered after writing; it is NOT an authorship
signature. ed25519/asymmetric signing would introduce key handling (a separate
security surface) and is a deliberate non-goal here. Keep that honest downstream.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .ledger import Ledger

#: Default store root. Override per call, or via the DEPONENT_RECEIPTS_ROOT env var.
RECEIPTS_ROOT = Path(os.environ.get("DEPONENT_RECEIPTS_ROOT", "~/.deponent/receipts")).expanduser()
PRODUCER = "deponent"
RECEIPT_SCHEMA = "deponent-receipt/v1"


def _sha256(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _best_effort_commit(repo: Path) -> str:
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else "n/a"
    except Exception:
        return "n/a"


def _producer_dir(root: Path, producer: str) -> Path:
    d = Path(root) / producer
    d.mkdir(parents=True, exist_ok=True)
    return d


def persist(ledger: Ledger, *, session_id: str | None = None,
            model: str = "unknown", task: str = "unknown",
            outcome: str = "GOVERNED_PASS", runtime: str = "unknown",
            producer: str = PRODUCER, root: Path = RECEIPTS_ROOT) -> dict:
    """Serialize + persist a ledger as a verifiable receipt. Fail-closed: raises
    if the chain doesn't verify before write OR the round-trip verify fails."""
    sid = session_id or uuid.uuid4().hex[:12]

    # Refuse to emit a receipt for a chain that isn't internally consistent.
    ok, msg = ledger.verify()
    if not ok:
        raise ValueError(f"refusing to persist a broken chain: {msg}")

    pdir = _producer_dir(root, producer)
    stamp = _utc_stamp()
    receipt_id = f"{stamp}_{sid}"

    body = {
        "receipt_id": receipt_id,
        "schema": RECEIPT_SCHEMA,
        "producer": producer,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "session_id": sid,
        "model": model,
        "task": task[:160],
        "outcome": outcome,
        "chain": ledger.to_dict(),
        "provenance": {
            "host": os.uname().nodename,
            "runtime": runtime,
            "commit": _best_effort_commit(Path.cwd()),
        },
    }
    for key in ("gate_only", "containment"):
        for entry in reversed(ledger.entries):
            if key in entry:
                body[key] = entry[key]
                break
    ledger_head, ledger_length = ledger.head()
    body["ledger_head"] = ledger_head
    body["ledger_length"] = ledger_length
    body["signature"] = _sha256(body)  # content hash over everything above (no signature key yet)

    # Atomic write: temp file -> rename on the same filesystem.
    run_file = pdir / f"{receipt_id}.json"
    tmp = pdir / f".{receipt_id}.json.tmp"
    tmp.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, run_file)

    # Producer-local index (append-only).
    with (pdir / "index.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"receipt_id": receipt_id, "ts": body["ts"],
                            "model": model, "task": task[:80], "outcome": outcome}) + "\n")

    # Fail-closed round-trip: this verifier RECOMPUTES, so the assert is meaningful.
    if not verify(receipt_id, producer=producer, root=root):
        raise RuntimeError(f"receipt {receipt_id} failed verification immediately after write")

    (pdir / "LATEST").write_text(receipt_id, encoding="utf-8")
    print(f"receipt -> {run_file}  (verified, chain {len(body['chain']['entries'])} entries)", flush=True)
    return body


def verify(receipt_id: str, *, producer: str = PRODUCER, root: Path = RECEIPTS_ROOT) -> bool:
    """Real verifier (recomputes; no stub). Returns False fail-closed on any
    missing/corrupt/tampered receipt. Safe to call from a release gate."""
    p = Path(root) / producer / f"{receipt_id}.json"
    if not p.exists():
        return False
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return False
    chain = data.get("chain") or {}
    entries = chain.get("entries")
    if not isinstance(entries, list):
        return False
    # 1) hash-chain integrity (any mutated entry breaks the re-link).
    # Published ledger_head/ledger_length catch truncation or a re-chain that
    # still re-links from genesis *when those fields still name the original
    # chain*. Content-hash receipts cannot stop a full rewrite: truncate, set
    # ledger_head and ledger_length to the short chain, recompute _sha256, and
    # this verifier returns True. README is the honest claim — only an external
    # copy of the original head catches that.
    ok, _ = Ledger.verify_entries(
        entries, chain.get("genesis"),
        expected_head=data.get("ledger_head"),
        expected_length=data.get("ledger_length"),
    )
    if not ok:
        return False
    # 2) receipt signature over the canonical body (any mutated metadata breaks it)
    sig = data.get("signature")
    canonical = {k: v for k, v in data.items() if k != "signature"}
    return bool(sig) and (_sha256(canonical) == sig)


def write_operator_receipt(receipt: dict, *, producer: str = PRODUCER,
                           root: Path = RECEIPTS_ROOT) -> Path:
    """Human-readable one-pager beside the JSON receipt."""
    pdir = _producer_dir(root, producer)
    p = pdir / f"{receipt['receipt_id']}.txt"
    p.write_text(
        f"GOVERNED RECEIPT\n"
        f"  receipt_id : {receipt['receipt_id']}\n"
        f"  model      : {receipt['model']}\n"
        f"  task       : {receipt['task']}\n"
        f"  outcome    : {receipt['outcome']}\n"
        f"  actions    : {len(receipt['chain']['entries'])} (hash-chained)\n"
        f"  verified   : YES (recomputed)\n"
        f"  signature  : {receipt['signature'][:16]}...\n", encoding="utf-8")
    return p


__all__ = ["persist", "verify", "write_operator_receipt", "RECEIPTS_ROOT", "PRODUCER", "RECEIPT_SCHEMA"]
