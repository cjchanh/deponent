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

import copy
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .claims import ClaimSet, attest
from .gate import Gate, GateDecision, gate_only_head_decision, tokenize_command
from .jail import jail_available, run_jailed, select_backend
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
                 gate: Gate | None = None, reconcile: bool = True,
                 allow_unjailed_interpreters: bool = False,
                 allow_unjailed_heads: frozenset[str] = frozenset()):
        self.sandbox = Path(sandbox).resolve()
        self.sandbox.mkdir(parents=True, exist_ok=True)
        if gate is None:
            gate = Gate(
                self.sandbox,
                unjailed=not use_jail,
                allow_unjailed_interpreters=allow_unjailed_interpreters,
                allow_unjailed_heads=allow_unjailed_heads,
            )
        elif not use_jail and not getattr(gate, "unjailed", False):
            # A caller-supplied gate built for jail mode would ALLOW interpreters and
            # chains that gate-only mode cannot contain. Tighten a Cell-owned copy;
            # never loosen, and never mutate an object another (jailed) Cell may share.
            gate = copy.copy(gate)
            gate.unjailed = True
        self.gate = gate
        self.ledger = Ledger(ledger_path)
        self.use_jail = use_jail
        self.allow_unjailed_interpreters = allow_unjailed_interpreters
        self.allow_unjailed_heads = frozenset(allow_unjailed_heads)
        self._last_backend_name = None
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
        self._last_backend_name = None
        decision = self.gate.evaluate(tool, params)
        if decision.verdict != "BLOCK":
            # Gate-only mode re-checks containment on the execute path so that a
            # permissive or foreign gate's ALLOW is still recorded as the BLOCK it is.
            guard = self._gate_only_guard(tool, params)
            if guard is not None:
                decision = guard
        if decision.verdict == "BLOCK":
            entry = self.ledger.record(agent=agent, tool=tool, params=params,
                                       decision=decision, outcome="",
                                       **self._disclosure())
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
                                   decision=decision, outcome=output,
                                   **self._disclosure())
        result = ActResult(decision, output, entry, rr)
        self.transcript.append(result)
        return result

    def _gate_only_guard(self, tool: str, params: dict) -> GateDecision | None:
        """Containment check for gate-only execution: exactly one parsable segment;
        interpreters unless Cell and Gate both opted in (`interpreter-unjailed`);
        non-safe heads unless both named them (`head-unjailed`). Returns a BLOCK
        decision to record, or None when the command may run. Jail mode returns
        None (policy unchanged)."""
        if self.use_jail or tool != "run_cmd":
            return None
        cmd = params.get("cmd", "") if isinstance(params, dict) else ""
        if not isinstance(cmd, str) or not cmd.strip():
            return GateDecision("BLOCK", "empty-command", "empty or non-string command")
        try:
            segments = tokenize_command(cmd)
        except ValueError as e:
            return GateDecision("BLOCK", "unparsable-command",
                                f"gate-only mode refused an unparsable command: {e}")
        if len(segments) != 1:
            return GateDecision("BLOCK", "chain-unjailed",
                                f"gate-only mode runs exactly one command segment; got {len(segments)}")
        if not segments[0]:
            return GateDecision("BLOCK", "unparsable-command",
                                "gate-only mode refused an empty command segment")
        return gate_only_head_decision(
            segments[0][0],
            allow_unjailed_interpreters=self._interpreters_opted_in(),
            allow_unjailed_heads=self._unjailed_heads(),
        )

    def _interpreters_opted_in(self) -> bool:
        """Gate-only interpreters run only when BOTH the Cell and its gate opted in:
        the tighter of the two policies wins, so a permissive foreign gate cannot
        loosen a Cell that did not ask for interpreters (and vice versa)."""
        return bool(self.allow_unjailed_interpreters) and bool(
            getattr(self.gate, "allow_unjailed_interpreters", False))

    def _unjailed_heads(self) -> frozenset[str]:
        """Gate-only extra heads run only when BOTH the Cell and its gate named them:
        intersection, so a permissive foreign gate cannot loosen a Cell that did not
        opt the head in (and vice versa). A foreign gate lacking the attribute
        contributes nothing (fail-closed)."""
        cell_heads = frozenset(h.casefold() for h in self.allow_unjailed_heads)
        gate_heads = frozenset(
            h.casefold() for h in getattr(self.gate, "allow_unjailed_heads", frozenset())
        )
        return cell_heads & gate_heads

    def _disclosure(self) -> dict:
        if not self.use_jail:
            return {"gate_only": True, "containment": "none"}
        name = self._last_backend_name
        if name is None:
            backend = select_backend()
            name = getattr(backend, "name", None) if backend is not None else None
        return {
            "gate_only": False,
            "containment": name if name else "none",
        }

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
            backend = select_backend()
            self._last_backend_name = getattr(backend, "name", None) if backend is not None else None
            r = run_jailed(cmd, self.sandbox, env=env, backend=backend,
                           mem_cap_mb=self.mem_cap_mb, wall_s=self.wall_s)
            return f"exit={r['returncode']}\n{r['output']}"
        # Gate-only mode: no OS confinement. act() has already recorded a BLOCK for
        # chains, unparsable input and interpreters via _gate_only_guard; this path
        # runs the single argv the gate tokenized, without a shell. Re-derived with the
        # same tokenizer (one function) and re-checked in case _execute is called
        # directly by a subclass.
        try:
            segments = tokenize_command(cmd)
        except ValueError:
            return "ERROR: gate-only mode refused an unparsable command."
        if len(segments) != 1:
            return ("ERROR: gate-only mode runs exactly one command segment; "
                    f"got {len(segments)} — refusing (fail-closed).")
        argv = segments[0]
        if not argv:
            return "ERROR: gate-only mode refused an empty command segment."
        blocked = gate_only_head_decision(
            argv[0],
            allow_unjailed_interpreters=self._interpreters_opted_in(),
            allow_unjailed_heads=self._unjailed_heads(),
        )
        if blocked is not None:
            return f"ERROR: {blocked.reason}"
        r = subprocess.run(argv, shell=False, cwd=str(self.sandbox), env=env,
                           capture_output=True, text=True, timeout=self.wall_s)
        return f"exit={r.returncode}\n{(r.stdout + r.stderr)[-2800:]}"


__all__ = ["Cell", "ActResult"]
