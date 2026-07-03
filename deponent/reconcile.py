#!/usr/bin/env python3
"""
reconcile.py — two-plane reconciliation: declared intent vs. observed reality.

The gate authorizes what an agent SAYS it will do (plane A). This module observes
what ACTUALLY changed on disk (plane B) and reconciles the two. A write that
declares one file but quietly changes another, or a "read" that mutates state, is a
structural intent mismatch — exactly the signature of a compromised or buggy tool
doing more than it declared. "Self-report is not evidence": we do not trust the
agent's account of what it did; we diff the workspace and let the delta testify.

Hidden files (kernel bookkeeping — the jail profile, tmp, run log, ledger) are
excluded from the snapshot so the kernel's own writes never look like an anomaly.

No key material. No execution — snapshot only reads + hashes the workspace.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReconcileReport:
    """declared intent vs. observed change. `match` is False iff something changed
    that the declared action did not authorize (`anomalies`)."""
    declared: str
    observed_changes: tuple[str, ...]   # workspace paths that actually changed
    expected: tuple[str, ...]           # paths the declared action was allowed to change
    match: bool
    anomalies: tuple[str, ...]          # observed changes the declaration did NOT authorize


def snapshot(root: Path | str) -> dict[str, str]:
    """Map every non-hidden workspace file -> sha256. Hidden files/dirs (any path
    part starting with '.') are kernel bookkeeping and are intentionally ignored."""
    root = Path(root).resolve()
    out: dict[str, str] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if any(part.startswith(".") for part in rel.parts):
            continue
        try:
            out[str(rel)] = hashlib.sha256(p.read_bytes()).hexdigest()
        except Exception:
            out[str(rel)] = "UNREADABLE"
    return out


def _expected(tool: str, params: dict) -> set[str] | None:
    """The paths a declared action is allowed to change. None => unpredicted
    (e.g. run_cmd may legitimately touch many files: observe + record, don't flag)."""
    if tool == "write_file":
        return {params.get("path", "").lstrip("./")}
    if tool == "read_file":
        return set()        # a read must change nothing
    return None             # run_cmd / anything else: unpredicted


def reconcile_action(tool: str, params: dict, before: dict, after: dict) -> ReconcileReport:
    changed = {k for k in (set(before) | set(after)) if before.get(k) != after.get(k)}
    label = params.get("path") or params.get("cmd") or ""
    declared = f"{tool}:{str(label)[:48]}"
    exp = _expected(tool, params)
    if exp is None:
        # unpredicted action — record what actually changed; no anomaly judgement
        return ReconcileReport(declared, tuple(sorted(changed)), (), True, ())
    expn = {e.lstrip("./") for e in exp}
    anomalies = tuple(sorted(c for c in changed if c not in expn))
    return ReconcileReport(declared, tuple(sorted(changed)), tuple(sorted(expn)),
                           len(anomalies) == 0, anomalies)


__all__ = ["ReconcileReport", "snapshot", "reconcile_action"]
