#!/usr/bin/env python3
"""
selfgate.py — deponent gates its OWN development (the dogfood / quality ratchet).

The engine, applied to the engine. Every change to deponent must clear two bars,
both expressed in deponent's own primitives:

  1. CONFORMANT — the reference kernel still passes its own GAK conformance clause
     set (conformance.py). The standard stays load-bearing on its own development;
     a regression that breaks a clause fails the gate.
  2. SOUND — a governed self-build (a real write/read/build cycle run THROUGH a
     deponent Cell) produces a claim-mode testimony with no REFUTED line: no
     self-contradiction, no undeclared change, honest abstentions where a mechanism
     didn't run. The kernel testifies about building itself, and the testimony holds.

Wire it as a pre-commit / CI check (`make self-gate`): deponent can never silently
regress below its own bar. Exit 0 iff conformant AND sound; emits a receipt.

No network, no key material. The self-build runs in a fresh temp sandbox.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .cell import Cell
from .claims import ClaimSet
from .conformance import DeponentAdapter, run_conformance
from .jail import jail_available
from .profiles import build_cell


def governed_self_build(sandbox: Path) -> tuple[Cell, ClaimSet]:
    """Run a real build-and-test slice THROUGH a deponent Cell: write a module +
    its test under governance, read it back, exercise an allowlisted command if the
    jail is available, and record a destructive command as a BLOCK. Returns the cell
    and its claim-mode testimony (cell.attest())."""
    use_jail = jail_available()
    cell = Cell(sandbox, ledger_path=sandbox / "selfbuild.jsonl", use_jail=use_jail)
    cell.act("write_file", {"path": "mod.py",
                            "content": "def add(a, b):\n    return a + b\n"})
    cell.act("write_file", {"path": "test_mod.py",
                            "content": "from mod import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"})
    cell.act("read_file", {"path": "mod.py"})
    if use_jail:
        cell.act("run_cmd", {"cmd": "cat mod.py"})        # a real jailed, allowlisted exec
    cell.act("run_cmd", {"cmd": "rm -rf ."})              # the destructive floor: a recorded BLOCK
    return cell, cell.attest()


def governed_real_build(repo_root: Path) -> tuple[Cell, ClaimSet, list[dict]]:
    """FULL DOGFOOD: run a REAL git+rustc build THROUGH the build profile, jailed.
    Write source, compile it with rustc, init+add+commit locally — all ALLOWed and
    actually EXECUTED under the gate — then attempt a push, which the irreversible
    floor BLOCKs (never executed). Reads are allowed, writes confined to repo_root,
    network denied — so the local build runs and the push dies at the boundary even
    if it slipped the gate. Returns (cell, testimony, per-action trace)."""
    cell = build_cell(repo_root, ledger_path=repo_root / ".build.jsonl", use_jail=True)
    plan = [
        ("write_file", {"path": "src/main.rs",
                        "content": 'fn main() { println!("governed build"); }\n'}),
        ("run_cmd", {"cmd": "rustc src/main.rs -o app"}),                       # real compile
        ("run_cmd", {"cmd": "git init"}),
        ("run_cmd", {"cmd": "git add ."}),
        ("run_cmd", {"cmd": 'git -c user.name=dogfood -c user.email=dogfood@local '
                            'commit -m "governed build"'}),                      # LOCAL commit: ALLOW
        ("run_cmd", {"cmd": "git push origin main"}),                            # irreversible floor: BLOCK
    ]
    trace = []
    for tool, params in plan:
        r = cell.act(tool, params, agent="self-build")
        out = " ".join((r.output or "").split())[:90]
        trace.append({"action": params.get("cmd") or f"{tool} {params.get('path', '')}",
                      "verdict": r.decision.verdict, "blast_class": r.decision.blast_class,
                      "outcome": out})
    return cell, cell.attest(), trace


def run_self_gate(adapter=None, *, live: bool = False) -> dict:
    """Run both bars. `adapter` defaults to the deponent reference; inject a
    different candidate to test the gate itself. `live=True` runs a REAL jailed
    git+rustc build (full dogfood) for the sound check, instead of the python
    sandbox slice. PASSES iff the kernel is conformant AND the governed build is
    sound (and, when live, the push was actually blocked)."""
    receipt = run_conformance(adapter or DeponentAdapter())
    conformant = receipt.conformant

    sandbox = Path(tempfile.mkdtemp(prefix="selfgate-"))
    trace = None
    if live and jail_available():
        _, claims, trace = governed_real_build(sandbox)
        mode = "live (git+rustc, jailed)"
    else:
        _, claims = governed_self_build(sandbox)
        mode = "live (unavailable: no jail)" if live else "python-sandbox"
    sound = claims.sound
    # When live, the irreversible floor must have held: the push action BLOCKed.
    push_blocked = True
    if trace is not None:
        push = next((t for t in trace if "git push" in t["action"]), None)
        push_blocked = bool(push and push["verdict"] == "BLOCK")

    passed = conformant and sound and push_blocked
    return {
        "passed": passed,
        "mode": mode,
        "conformant": conformant,
        "sound": sound,
        "push_blocked": push_blocked,
        "conformance": receipt.to_dict()["counts"],
        "self_build_claims": claims.to_dict()["counts"],
        "refuted": [c.id for c in claims.refuted],   # empty iff sound — names any self-contradiction
        "trace": trace,
        "kernel": receipt.kernel,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="deponent gates its own development")
    ap.add_argument("--live", action="store_true",
                    help="run a REAL jailed git+rustc self-build (full dogfood) for the sound check")
    args = ap.parse_args(argv)

    r = run_self_gate(live=args.live)
    print("DEPONENT SELF-GATE — the engine gates its own development")
    print("=" * 58)
    print(f"  mode       : {r['mode']}")
    print(f"  CONFORMANT : {r['conformant']}  (GAK clauses {r['conformance']})")
    print(f"  SOUND      : {r['sound']}  (self-build testimony {r['self_build_claims']})")
    if r["trace"] is not None:
        print("  governed real build (the engine building itself):")
        for t in r["trace"]:
            mark = "ok " if t["verdict"] == "ALLOW" else "XX "
            print(f"    {mark}[{t['verdict']:<5} {t['blast_class']}] {t['action'][:64]}")
        print(f"  PUSH BLOCKED: {r['push_blocked']}  <- the irreversible floor held")
    if r["refuted"]:
        print(f"  REFUTED    : {r['refuted']}  <- the kernel testifying against itself")
    print(f"\n{'PASS — deponent clears its own bar.' if r['passed'] else 'FAIL — deponent regressed below its own standard.'}")

    runs = Path(__file__).resolve().parent.parent / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    out = runs / "selfgate_receipt.json"
    out.write_text(json.dumps(r, indent=2), encoding="utf-8")
    print(f"receipt -> {out}")
    return 0 if r["passed"] else 1


__all__ = ["governed_self_build", "governed_real_build", "run_self_gate"]


if __name__ == "__main__":
    raise SystemExit(main())
