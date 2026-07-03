#!/usr/bin/env python3
"""safetyspine_action_governor.py — use deponent to testify safety decisions.

A drone or robotics safety kernel must not trust an effector's self-report that
it "fired safely." This example wraps a weapon-release decision in deponent's
gate + ledger so every authorize/deny decision is hash-chained and re-verifiable.

In a real SafetySpine integration the `_execute` hook would talk to the actual
actuator bus; here it simulates the effector and records the outcome hash.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass

from deponent import Cell, Gate, GateDecision
from deponent.profiles import BUILD_DENY_SUBSTR


@dataclass(frozen=True)
class FireCommand:
    target_id: str
    confidence: float
    human_affirm: bool
    roe_authorization: bool


# A tighter gate than the default coding sandbox: fire-related keywords and
# irreversible commands are denied by default.
SAFETYSPINE_DENY_EXTRA = (
    "rm -rf", "sudo", "mkfs", "dd if=", "shutdown", "reboot",
    "fire", "release", "launch", "arm", "weapon", "payload",
)
SAFETYSPINE_DENY_SUBSTR = BUILD_DENY_SUBSTR + SAFETYSPINE_DENY_EXTRA


class SafetySpineGate(Gate):
    """Gate for a fire-decision effector. Deny unless human + ROE + confidence."""

    def evaluate(self, tool: str, params: dict) -> GateDecision:
        if tool == "authorize_fire":
            cmd = FireCommand(**params)
            if cmd.confidence < 0.95:
                return GateDecision("BLOCK", "confidence-below-threshold",
                                    f"confidence {cmd.confidence} < 0.95")
            if not cmd.human_affirm:
                return GateDecision("BLOCK", "human-in-the-loop-required",
                                    "fire requires explicit human affirmation")
            if not cmd.roe_authorization:
                return GateDecision("BLOCK", "roe-denied",
                                    "target not in current rules-of-engagement")
            return GateDecision("ALLOW", "fire-authorized",
                                "human + ROE + confidence pass")
        return super().evaluate(tool, params)


class SafetySpineCell(Cell):
    """Execute the ALLOWed fire command. Every decision is testified before commit."""

    def _execute(self, tool: str, params: dict) -> str:
        if tool == "authorize_fire":
            cmd = FireCommand(**params)
            # Simulate actuator commit. In production this is the real hardware interface.
            return (f"effector: WEAPON_RELEASED (target={cmd.target_id}, "
                    f"confidence={cmd.confidence})")
        return super()._execute(tool, params)


def main() -> int:
    sandbox = tempfile.mkdtemp()
    gate = SafetySpineGate(sandbox, deny=SAFETYSPINE_DENY_SUBSTR,
                           allow_heads=frozenset())  # no shell commands allowed
    cell = SafetySpineCell(sandbox, gate=gate, ledger_path=sandbox + "/safety.jsonl",
                            use_jail=False)

    scenarios = [
        ("T-001", 0.97, True, True),    # ALLOW
        ("T-002", 0.97, True, False),   # BLOCK: ROE
        ("T-003", 0.97, False, True),   # BLOCK: no human
        ("T-004", 0.80, True, True),    # BLOCK: low confidence
    ]

    for target, conf, human, roe in scenarios:
        cmd = FireCommand(target, conf, human, roe)
        result = cell.act("authorize_fire", cmd.__dict__, agent="safety-spine")
        tag = "ALLOW" if result.allowed else "BLOCK"
        print(f"{target}: {tag} [{result.decision.blast_class}]")

    ok, msg = cell.verify()
    print(f"\nsafety testimony: {ok} — {msg}")
    print(f"ledger: {sandbox}/safety.jsonl")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
