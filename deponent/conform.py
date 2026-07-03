#!/usr/bin/env python3
"""deponent.conform — CLI entry point for the GAK conformance harness.

Run against the reference kernel:
    python3 -m deponent.conform --kernel deponent

Run against sworncode (commit-time kernel):
    PYTHONPATH=/path/to/sworn/src python3 -m deponent.conform --kernel sworn

List the clauses any kernel must satisfy:
    python3 -m deponent.conform --list-clauses
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import BUILTIN_ADAPTERS
from .conformance import CLAUSES, run_conformance


def _list_clauses() -> int:
    for c in CLAUSES:
        req = f" (requires: {c.requires})" if c.requires else ""
        print(f"[{c.id}] ({c.profile}){req}\n    {c.statement}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="GAK conformance harness CLI")
    ap.add_argument("--kernel", default="deponent",
                    choices=list(BUILTIN_ADAPTERS.keys()),
                    help="kernel adapter to run conformance against")
    ap.add_argument("--list-clauses", action="store_true",
                    help="print all GAK clauses and exit")
    ap.add_argument("--out", type=Path, default=None,
                    help="write ConformanceReceipt JSON to this path")
    args = ap.parse_args(argv)

    if args.list_clauses:
        return _list_clauses()

    adapter_cls = BUILTIN_ADAPTERS[args.kernel]
    receipt = run_conformance(adapter_cls())
    print(receipt.render())

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(receipt.to_dict(), indent=2), encoding="utf-8")
        print(f"\njson receipt -> {args.out}")

    return 0 if receipt.conformant else 1


if __name__ == "__main__":
    raise SystemExit(main())
