#!/usr/bin/env python3
"""
cell.py — the sovereign primitive: gate -> (jail) -> ledger, one testified action.

A Cell is the whole architecture in one object. Give it a sandbox directory; then
every action an agent takes goes through .act(), which:

  1. classifies the action's BLAST RADIUS with the Gate (deny-by-default,
     fail-closed) — unknown tool / path escape / destructive command -> BLOCK;
  2. executes ALLOWed actions — file ops confined to the sandbox, and commands
     run inside the Seatbelt jail (no network, writes confined, resource-bounded);
  3. records the decision + a hash of the outcome to a tamper-evident Ledger.

Closure is never the agent saying "done" — it is the Ledger that testifies, and
Ledger.verify() that proves the testimony intact.

Cells compose. One agent or a whole team can share a Cell; the Ledger is their
shared, verifiable record. That is the point: a small local primitive that holds
its shape at every scale — one tool call, one agent, one team.

Out of the box the Cell implements write_file / read_file / run_cmd. Subclass and
override _execute (or the per-tool helpers) to govern your own tool surface; the
gate + ledger + jail wrapping is inherited unchanged.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .claims import ClaimSet, attest
from .gate import Gate, GateDecision
from .jail import jail_available, run_jailed
from .ledger import Ledger

try:
    from .reconcile import ReconcileReport, reconcile_action, snapshot
    _RECONCILE_AVAILABLE = True
except ImportError:
    # OPTIONAL CAPABILITY: reconcile is an optional module — a minimal deployment can
    # omit it. Absent -> reconcile is simply OFF; the kernel still governs (gate ->
    # jail -> ledger), and the C-NO-UNDECLARED-CHANGE claim + the GAK-RECONCILE
    # conformance clause report it absent honestly rather than faking it.
    ReconcileReport = None  # type: ignore  (annotations are strings via __future__)
    _RECONCILE_AVAILABLE = False


@dataclass(frozen=True)
class ActResult:
    """The result of one governed action: the verdict, the output, the record."""
    decision: GateDecision
    output: str
    entry: dict  # the ledger entry that was recorded
    reconcile: ReconcileReport | None = None  # observed-vs-declared (two-plane), when enabled

    @property
    def allowed(self) -> bool:
        return self.decision.verdict == "ALLOW"


class Cell:
    """A governed-action cell. Deny-by-default, jailed, tamper-evident."""

    def __init__(self, sandbox: Path | str, *, ledger_path: Path | str | None = None,
                 use_jail: bool = True, mem_cap_mb: int = 2048, wall_s: int = 90,
                 gate: Gate | None = None, reconcile: bool = True):
        self.sandbox = Path(sandbox).resolve()
        self.sandbox.mkdir(parents=True, exist_ok=True)
        self.gate = gate or Gate(self.sandbox)
        self.ledger = Ledger(ledger_path)
        self.use_jail = use_jail
        self.mem_cap_mb = mem_cap_mb
        self.wall_s = wall_s
        # Two-plane reconciliation: snapshot the workspace before/after each action
        # and compare what ACTUALLY changed against what was declared (self-report is
        # not evidence). A mismatch is surfaced + recorded into the testimony, never
        # hidden. The ledger write happens AFTER the after-snapshot, so it never
        # appears as a spurious change.
        self._reconcile = reconcile and _RECONCILE_AVAILABLE
        # Live transcript of this run's governed actions. attest() reads it to derive
        # the run's claim-set — what this run can and cannot honestly testify to.
        self.transcript: list[ActResult] = []

    def act(self, tool: str, params: dict, *, agent: str = "agent") -> ActResult:
        """Gate -> execute (if allowed) -> record. One call, one testified action."""
        decision = self.gate.evaluate(tool, params)
        if decision.verdict == "BLOCK":
            entry = self.ledger.record(agent=agent, tool=tool, params=params,
                                       decision=decision, outcome="")
            result = ActResult(decision, f"BLOCKED [{decision.blast_class}]: {decision.reason}", entry)
            self.transcript.append(result)
            return result
        before = snapshot(self.sandbox) if self._reconcile else {}
        try:
            output = self._execute(tool, params)
        except Exception as e:
            # Fail-soft execution, fail-closed policy: a malformed call is fed back
            # (so an agent can self-correct) and never crashes the loop. The gate
            # verdict still stands and is recorded — the policy never fails open.
            output = (f"ERROR executing {tool}: {type(e).__name__}: {e}. "
                      f"You sent parameters {list(params)}; the tool expects exact names.")
        rr = None
        if self._reconcile:
            # observe reality AFTER execution but BEFORE the ledger write, so the
            # ledger's own append never counts as a change.
            rr = reconcile_action(tool, params, before, snapshot(self.sandbox))
            if not rr.match:
                output += (f"\n[RECONCILE ANOMALY] declared {rr.declared} but also changed: "
                           f"{', '.join(rr.anomalies)}")
        entry = self.ledger.record(agent=agent, tool=tool, params=params,
                                   decision=decision, outcome=output)
        result = ActResult(decision, output, entry, rr)
        self.transcript.append(result)
        return result

    def verify(self) -> tuple[bool, str]:
        """Prove the testimony intact. Returns (ok, message)."""
        return self.ledger.verify()

    def attest(self) -> ClaimSet:
        """Testify about this run's OWN coverage: the claims it can, cannot, and
        must-not make. Derived from the transcript + the (re-verified) ledger, with
        coverage attested only where the mechanism (jail / reach / reconcile) actually
        ran — so an auditor reading the artifact is never misled about the guarantee's
        edge. See claims.py."""
        return attest(
            self.transcript,
            ledger=self.ledger,
            jailed=self.use_jail and jail_available(),
            reach_enabled=self.gate.reach is not None,
            reconcile_enabled=self._reconcile,
        )

    # ---- default tool implementations (override _execute to govern your own) ----
    def _execute(self, tool: str, params: dict) -> str:
        if tool == "write_file":
            return self._write_file(**params)
        if tool == "read_file":
            return self._read_file(**params)
        if tool == "run_cmd":
            return self._run_cmd(**params)
        return f"ERROR: no implementation for tool {tool!r}"

    def _write_file(self, path: str, content: str) -> str:
        p = self.sandbox / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return f"wrote {len(content)} bytes -> {path}"

    def _read_file(self, path: str) -> str:
        p = self.sandbox / path
        return p.read_text() if p.exists() else f"ERROR: {path} not found"

    def _run_cmd(self, cmd: str, env: dict | None = None) -> str:
        if self.use_jail:
            # Defense in depth: the gate already constrained shell + path; the jail
            # constrains the *code* an allowed command runs. Fail-closed off-macOS.
            if not jail_available():
                return "ERROR: sandbox-exec unavailable — refusing to run un-jailed (fail-closed)."
            r = run_jailed(cmd, self.sandbox, env=env,
                           mem_cap_mb=self.mem_cap_mb, wall_s=self.wall_s)
            return f"exit={r['returncode']}\n{r['output']}"
        # Gate-only mode (explicit opt-out of the in-language jail): the shell/path
        # policy still holds, but there is no network/write confinement. Use only
        # where the gate is sufficient or another sandbox wraps this process.
        r = subprocess.run(cmd, shell=True, cwd=str(self.sandbox), env=env,
                           capture_output=True, text=True, timeout=self.wall_s)
        return f"exit={r.returncode}\n{(r.stdout + r.stderr)[-2800:]}"


__all__ = ["Cell", "ActResult"]
