#!/usr/bin/env python3
"""
conformance.py — the GAK conformance harness: turn "governed agent kernel" from a
slogan into a checkable receipt.

A category is real when a third party can test against it and get a verdict. This
runs a fixed set of GAK clauses — the seven-primitive thesis reduced to executable
checks — against a CANDIDATE kernel and emits a ConformanceReceipt (per-clause
PASS/FAIL/NA + an overall verdict). Point it at deponent (the reference) or at any
kernel that implements the small adapter below; the clauses don't care whose kernel
it is.

PROFILES (so a different governance SHAPE doesn't false-FAIL).
  Kernels govern at different moments. deponent is an ACTION-gate (it evaluates a
  live tool call: evaluate(tool, params) -> verdict). A commit-gate like sworncode
  evaluates a git diff and has no per-action evaluate() surface — running action-gate
  clauses against it would produce misleading FAILs. So every clause declares a
  profile; a clause whose profile the candidate does not claim reports NA, never FAIL.
  This file specifies the `action-gate` and `commit-gate` profiles. Adapters live
  in `deponent/adapters/` and are lazy-imported so this core stays zero-dependency.

A clause is PASS only when the candidate genuinely exhibits the behavior, FAIL when
it does not, NA when out of profile or unsupported. conformant == every required
(non-NA) clause PASS. Deny-everything is NOT conformance: a clause requires the gate
to ALLOW legitimate in-sandbox work too.

No key material. No network. The harness only drives the candidate's own surface.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .adapters.contract import KernelAdapter
from .adapters.deponent import DeponentAdapter


# --- the candidate contract is in deponent/adapters/contract.py ---------------
# --- the clause set --------------------------------------------------------------

@dataclass(frozen=True)
class Clause:
    id: str
    profile: str          # "universal" | "action-gate" | "commit-gate"
    requires: str         # "" or a capability the candidate must claim in `supports`
    statement: str
    check: Callable[[KernelAdapter], bool]


@dataclass(frozen=True)
class ClauseResult:
    id: str
    profile: str
    status: str           # "PASS" | "FAIL" | "NA"
    detail: str


@dataclass(frozen=True)
class ConformanceReceipt:
    kernel: str
    profile: str
    results: tuple[ClauseResult, ...]

    @property
    def conformant(self) -> bool:
        """True iff no required clause FAILED (NA clauses don't count against)."""
        return all(r.status != "FAIL" for r in self.results) and \
            any(r.status == "PASS" for r in self.results)

    def to_dict(self) -> dict:
        passed = sum(r.status == "PASS" for r in self.results)
        failed = sum(r.status == "FAIL" for r in self.results)
        na = sum(r.status == "NA" for r in self.results)
        return {
            "kernel": self.kernel, "profile": self.profile,
            "conformant": self.conformant,
            "counts": {"pass": passed, "fail": failed, "na": na},
            "clauses": [{"id": r.id, "profile": r.profile, "status": r.status,
                         "detail": r.detail} for r in self.results],
        }

    def render(self) -> str:
        lines = [f"GAK CONFORMANCE — {self.kernel}  (profile: {self.profile})",
                 "=" * 60]
        for r in self.results:
            mark = {"PASS": "ok ", "FAIL": "XX ", "NA": "-- "}[r.status]
            lines.append(f"  {mark}[{r.id}] {r.detail}")
        verdict = "CONFORMANT" if self.conformant else "NOT CONFORMANT — a required clause FAILED"
        lines.append(f"\n{verdict}")
        return "\n".join(lines)


# The clauses — the seven-primitive thesis as executable checks. Each `check` returns
# True iff the candidate exhibits the required behavior.
CLAUSES: tuple[Clause, ...] = (
    Clause("GAK-DENY-DEFAULT", "action-gate", "",
           "An unknown/ungoverned action is denied by default.",
           lambda k: k.verdict("definitely_not_a_real_tool", {}) == "BLOCK"),
    Clause("GAK-ALLOW-INBOUNDS", "action-gate", "",
           "Legitimate in-sandbox work is ALLOWED (deny-everything is not conformance).",
           lambda k: k.verdict("write_file", {"path": "ok.txt", "content": "x"}) == "ALLOW"),
    Clause("GAK-PATH-CONTAINMENT", "action-gate", "",
           "A write escaping the sandbox is blocked.",
           lambda k: k.verdict("write_file", {"path": "../escape.py", "content": "x"}) == "BLOCK"),
    Clause("GAK-DESTRUCTIVE-FLOOR", "action-gate", "",
           "An irreversible/destructive command is blocked regardless of allowlist.",
           lambda k: k.verdict("run_cmd", {"cmd": "rm -rf /"}) == "BLOCK"),
    Clause("GAK-PROGRAM-ALLOWLIST", "action-gate", "",
           "A non-allowlisted program is blocked.",
           lambda k: k.verdict("run_cmd", {"cmd": "ftp some.host"}) == "BLOCK"),
    Clause("GAK-JAIL-FAILS-CLOSED", "action-gate", "",
           "When no OS confinement is available, the jail refuses to run (never un-jailed).",
           lambda k: k.jail_fails_closed()),
    Clause("GAK-CHAIN-INTACT", "universal", "",
           "An untampered audit chain re-verifies.",
           lambda k: k.clean_chain_verifies()),
    Clause("GAK-TAMPER-EVIDENT", "universal", "",
           "A mutated audit record is detected (tamper-evident).",
           lambda k: k.tamper_is_detected()),
    Clause("GAK-RECONCILE-UNDECLARED", "action-gate", "reconcile",
           "A tool changing undeclared state is flagged (two-plane reconciliation).",
           lambda k: k.reconcile_catches_undeclared()),
    Clause("GAK-ATTEST-HONEST", "universal", "attest",
           "The kernel ABSTAINS on coverage it did not earn (no false attestation).",
           lambda k: k.attest_abstains_when_unproven()),
    # commit-gate profile — a kernel that gates a proposed change-set (a diff /
    # staged files) rather than a live tool call. Out-of-profile -> NA, never FAIL.
    Clause("GAK-COMMIT-DENY-SECURITY", "commit-gate", "",
           "A change-set touching a security surface (crypto/auth/keys/...) is blocked.",
           lambda k: k.commit_verdict(["crypto/vault.py"]) == "BLOCK"),
    Clause("GAK-COMMIT-ALLOW-CLEAN", "commit-gate", "",
           "A benign in-policy change-set is allowed (deny-everything is not conformance).",
           lambda k: k.commit_verdict(["README.md"]) == "ALLOW"),
    Clause("GAK-COMMIT-TESTIFIES", "commit-gate", "",
           "Every decision (ALLOW or BLOCK) is recorded to a verifiable audit log.",
           lambda k: k.commit_testifies(["crypto/vault.py"])),
)


def run_conformance(kernel: KernelAdapter, clauses: tuple[Clause, ...] = CLAUSES) -> ConformanceReceipt:
    """Run the GAK clause set against a candidate; fail-closed on a check that raises."""
    results: list[ClauseResult] = []
    for c in clauses:
        # out-of-profile or unsupported optional capability -> NA, never FAIL.
        if c.profile not in ("universal", kernel.profile):
            results.append(ClauseResult(c.id, c.profile, "NA",
                                        f"out of profile ({c.profile}); kernel is {kernel.profile}. {c.statement}"))
            continue
        if c.requires and c.requires not in kernel.supports:
            results.append(ClauseResult(c.id, c.profile, "NA",
                                        f"kernel does not claim '{c.requires}'. {c.statement}"))
            continue
        try:
            ok = bool(c.check(kernel))
        except Exception as e:                  # a clause that errors is a FAIL, not a pass.
            results.append(ClauseResult(c.id, c.profile, "FAIL",
                                        f"check raised {type(e).__name__}: {e}. {c.statement}"))
            continue
        results.append(ClauseResult(c.id, c.profile, "PASS" if ok else "FAIL", c.statement))
    return ConformanceReceipt(kernel.name, kernel.profile, tuple(results))


# --- the reference adapter is now in deponent.adapters.deponent -------------


def main() -> int:
    receipt = run_conformance(DeponentAdapter())
    print(receipt.render())
    import json
    runs = Path(__file__).resolve().parent.parent / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    out = runs / "conformance_receipt.json"
    out.write_text(json.dumps(receipt.to_dict(), indent=2), encoding="utf-8")
    print(f"\nreceipt -> {out}")
    return 0 if receipt.conformant else 1


__all__ = ["KernelAdapter", "Clause", "ClauseResult", "ConformanceReceipt",
           "CLAUSES", "run_conformance", "DeponentAdapter"]


if __name__ == "__main__":
    raise SystemExit(main())
