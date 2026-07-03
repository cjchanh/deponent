#!/usr/bin/env python3
"""sworn_adapter.py — GAK commit-gate adapter for sworncode (the commit-time sibling).

Runs the GAK conformance harness's `commit-gate` profile against the REAL sworncode
kernel. sworncode is lazy-imported INSIDE the methods so deponent's conformance core
stays zero-dependency; importing this module never requires sworncode.

sworncode is not pip-installed in every env. Run with it on the path:
    PYTHONPATH=/path/to/sworn/src python3 -m deponent.sworn_adapter

Mapping: sworncode `run_pipeline(...).decision` (PASS/BLOCKED) -> harness ALLOW/BLOCK.
The universal chain-intact / tamper-evident clauses use sworncode's hash-chained
evidence log (`verify_chain`). sworncode claims neither `reconcile` nor `attest`, so
those clauses report NA (never a false FAIL).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from .adapters.sworn import SwornAdapter
from .conformance import run_conformance


def main() -> int:
    receipt = run_conformance(SwornAdapter())
    print(receipt.render())
    runs = Path(__file__).resolve().parent.parent / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    out = runs / "sworn_conformance_receipt.json"
    out.write_text(json.dumps(receipt.to_dict(), indent=2), encoding="utf-8")
    print(f"\nreceipt -> {out}")
    return 0 if receipt.conformant else 1


__all__ = ["SwornAdapter"]


if __name__ == "__main__":
    raise SystemExit(main())
