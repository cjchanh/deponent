#!/usr/bin/env python3
"""
claims.py — the kernel testifies about the boundaries of its OWN coverage.

A log says what happened. A policy engine says what is allowed. Neither says
what it *cannot vouch for*. This module closes that gap: given a governed run, it
emits a structured "claims we can and cannot make" artifact — the honesty clamp
turned from a docstring into a machine-checkable output.

Three statuses, and the discipline is in the difference:

  ATTESTED  the run's own record supports the claim (verified here, not asserted).
  ABSTAIN   the claim is out of scope — not enabled, not run, or a structural
            boundary of this reference kernel. Silence, stated honestly.
  REFUTED   the record CONTRADICTS the claim (a broken chain, an undeclared
            change). The kernel catching itself — the most valuable line.

Every run-scoped claim is DERIVED from the actual run (the ledger + the per-action
reconcile reports), via a path independent of any "it ran fine" self-report — the
same "self-report is not evidence" discipline the kernel applies to agents, applied
to the kernel. The permanent-boundary claims are always ABSTAIN: they name exactly
what this kernel does NOT prove (tamper-PROOF authorship, in-language safety,
complete blast radius, cross-platform confinement, adversarial security), so an
auditor reading the artifact is never misled about the edge of the guarantee.

No key material. No execution. attest() only reads a run's record and re-verifies
the chain it was given.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class Claim:
    """One thing the run can or cannot honestly say about itself."""
    id: str
    statement: str
    status: str   # "ATTESTED" | "ABSTAIN" | "REFUTED"
    basis: str    # the evidence (for ATTESTED/REFUTED) or the reason for silence (ABSTAIN)


@dataclass(frozen=True)
class ClaimSet:
    """The full attestation for a governed run: what it can, cannot, and must-not claim."""
    claims: tuple[Claim, ...]

    @property
    def attested(self) -> tuple[Claim, ...]:
        return tuple(c for c in self.claims if c.status == "ATTESTED")

    @property
    def abstained(self) -> tuple[Claim, ...]:
        return tuple(c for c in self.claims if c.status == "ABSTAIN")

    @property
    def refuted(self) -> tuple[Claim, ...]:
        return tuple(c for c in self.claims if c.status == "REFUTED")

    @property
    def sound(self) -> bool:
        """True iff nothing the run recorded contradicts a claim — no REFUTED line.
        A False here is the kernel testifying against itself, and it should be loud."""
        return not self.refuted

    def to_dict(self) -> dict:
        return {
            "sound": self.sound,
            "counts": {"attested": len(self.attested), "abstained": len(self.abstained),
                       "refuted": len(self.refuted)},
            "claims": [{"id": c.id, "statement": c.statement, "status": c.status,
                        "basis": c.basis} for c in self.claims],
        }

    def render(self) -> str:
        """A human- and auditor-readable attestation block."""
        lines = ["DEPONENT ATTESTATION — what this governed run can and cannot claim",
                 "=" * 66]
        for label, group in (("ATTESTED", self.attested), ("REFUTED", self.refuted),
                             ("ABSTAIN", self.abstained)):
            lines.append(f"\n{label} ({len(group)}):")
            if not group:
                lines.append("  (none)")
            for c in group:
                lines.append(f"  [{c.id}] {c.statement}")
                lines.append(f"      basis: {c.basis}")
        verdict = ("SOUND — no attestation was contradicted by the record."
                   if self.sound else
                   "NOT SOUND — the record REFUTES a claim above; do not rely on this run.")
        lines.append(f"\n{verdict}")
        return "\n".join(lines)


def attest(results: Sequence, *, ledger=None, jailed: bool = False,
           reach_enabled: bool = False, reconcile_enabled: bool = False,
           attestation: dict | None = None, trusted_pubkeys=None) -> ClaimSet:
    """Derive a ClaimSet from a governed run.

    `results` is the run's sequence of ActResult-shaped records (each exposing an
    `.entry` dict with tool/verdict/blast_class/reason, and a `.reconcile` report or
    None). `ledger` (optional) is re-verified here for the chain-integrity claim.
    The three flags describe what the cell actually had enabled, so coverage is
    attested only where the mechanism genuinely ran.

    `attestation` + `trusted_pubkeys` (optional, the operator-attestation overlay):
    when an operator ed25519 attestation over the ledger chain-head is supplied and
    verifies against a trusted public key, C-OPERATOR-ATTESTED is ATTESTED; a failed
    attestation is REFUTED (the kernel catching a forged/stale signature); absent, it
    ABSTAINS. Verification is the overlay's PUBLIC-key-only path — no signing here.
    """
    n = len(results)
    claims: list[Claim] = []

    # --- run-scoped: decided from THIS run's record ---

    # C-GATE-PRECEDES — every action met the gate before it ran.
    s_gate = "Every recorded action was classified by the deny-by-default gate before execution."
    if n == 0:
        claims.append(Claim("C-GATE-PRECEDES", s_gate, "ABSTAIN",
                            "no actions were recorded in this run; nothing to attest."))
    elif all(r.entry.get("verdict") in ("ALLOW", "BLOCK") for r in results):
        allow = sum(1 for r in results if r.entry.get("verdict") == "ALLOW")
        block = n - allow
        claims.append(Claim("C-GATE-PRECEDES", s_gate, "ATTESTED",
                            f"{n} action(s): {allow} allowed, {block} blocked, each with a recorded verdict."))
    else:
        claims.append(Claim("C-GATE-PRECEDES", s_gate, "REFUTED",
                            "one or more recorded actions carry no gate verdict."))

    # C-CHAIN-INTACT — the testimony re-verifies.
    s_chain = "The audit chain is internally consistent (tamper-evident): no entry altered or reordered."
    if ledger is None:
        claims.append(Claim("C-CHAIN-INTACT", s_chain, "ABSTAIN",
                            "no ledger supplied; chain integrity was not checked."))
    else:
        ok, msg = ledger.verify()
        claims.append(Claim("C-CHAIN-INTACT", s_chain, "ATTESTED" if ok else "REFUTED", msg))

    # C-BLOCKS-RECORDED — every denial is accounted for.
    s_blocks = "Every denied action was recorded with a named blast class and reason."
    if n == 0:
        claims.append(Claim("C-BLOCKS-RECORDED", s_blocks, "ABSTAIN", "no actions recorded."))
    else:
        blocks = [r for r in results if r.entry.get("verdict") == "BLOCK"]
        if all(r.entry.get("blast_class") and r.entry.get("reason") for r in blocks):
            claims.append(Claim("C-BLOCKS-RECORDED", s_blocks, "ATTESTED",
                                f"{len(blocks)} denial(s), each carrying a blast_class and reason."))
        else:
            claims.append(Claim("C-BLOCKS-RECORDED", s_blocks, "REFUTED",
                                "a denial is missing its blast_class or reason."))

    # C-NO-UNDECLARED-CHANGE — two-plane reconciliation came back clean.
    s_recon = "No action changed filesystem state it did not declare (two-plane reconciliation clean)."
    if not reconcile_enabled:
        claims.append(Claim("C-NO-UNDECLARED-CHANGE", s_recon, "ABSTAIN",
                            "two-plane reconciliation was not enabled for this run."))
    else:
        reconciled = [r for r in results if getattr(r, "reconcile", None) is not None]
        anomalous = [r for r in reconciled if not r.reconcile.match]
        if anomalous:
            detail = "; ".join(f"{r.entry.get('tool')} -> {', '.join(r.reconcile.anomalies)}"
                               for r in anomalous)
            claims.append(Claim("C-NO-UNDECLARED-CHANGE", s_recon, "REFUTED",
                                f"{len(anomalous)} action(s) changed undeclared paths: {detail}"))
        elif not reconciled:
            claims.append(Claim("C-NO-UNDECLARED-CHANGE", s_recon, "ABSTAIN",
                                "no executed actions to reconcile (nothing ran past the gate)."))
        else:
            claims.append(Claim("C-NO-UNDECLARED-CHANGE", s_recon, "ATTESTED",
                                f"{len(reconciled)} reconciled action(s); no undeclared change."))

    # C-COMMANDS-JAILED — executed commands were OS-confined.
    s_jail = "Every executed command ran inside OS confinement (network denied, writes confined)."
    allowed_cmds = sum(1 for r in results
                       if r.entry.get("tool") == "run_cmd" and r.entry.get("verdict") == "ALLOW")
    if allowed_cmds == 0:
        claims.append(Claim("C-COMMANDS-JAILED", s_jail, "ABSTAIN",
                            "no commands were executed in this run."))
    elif jailed:
        claims.append(Claim("C-COMMANDS-JAILED", s_jail, "ATTESTED",
                            f"{allowed_cmds} command(s) executed under the OS jail."))
    else:
        claims.append(Claim("C-COMMANDS-JAILED", s_jail, "ABSTAIN",
                            "jail disabled; commands ran under gate policy only — no network/write confinement."))

    # C-OPERATOR-ATTESTED — authorship binding via the optional ed25519 overlay.
    s_att = "The audit chain-head is bound to an authenticated operator (ed25519 authorship)."
    if attestation is None:
        claims.append(Claim("C-OPERATOR-ATTESTED", s_att, "ABSTAIN",
                            "no operator attestation supplied; the chain is tamper-evident "
                            "but unsigned — authorship is not established."))
    elif ledger is None:
        claims.append(Claim("C-OPERATOR-ATTESTED", s_att, "ABSTAIN",
                            "attestation supplied but no ledger to verify it against."))
    else:
        try:
            from .operator_attest import verify_attestation
            r = verify_attestation(attestation, ledger.entries, trusted_pubkeys or set())
            if r.valid:
                claims.append(Claim("C-OPERATOR-ATTESTED", s_att, "ATTESTED",
                                    f"operator '{r.operator_id}' ed25519-signed the chain-head; "
                                    "a from-genesis rewrite by anyone lacking the operator key "
                                    "invalidates it (attestation must be retained out-of-band)."))
            else:
                claims.append(Claim("C-OPERATOR-ATTESTED", s_att, "REFUTED",
                                    f"operator attestation FAILED verification: {r.reason}."))
        except Exception:
            claims.append(Claim("C-OPERATOR-ATTESTED", s_att, "ABSTAIN",
                                "attestation overlay unavailable (install deponent[attest]); "
                                "authorship not established (fail-closed)."))

    # --- permanent boundaries: always ABSTAIN, by design — the edge of the guarantee ---

    claims.append(Claim(
        "C-TAMPER-PROOF",
        "The record is tamper-PROOF against an author who can rewrite it from genesis.",
        "ABSTAIN",
        "the chain is tamper-EVIDENT (sha256), not tamper-PROOF. ed25519 AUTHORSHIP is "
        "available via the optional operator-attestation overlay (see C-OPERATOR-ATTESTED); "
        "even then the core chain itself remains tamper-evident, and authorship binding holds "
        "only against an author lacking the operator key."))

    claims.append(Claim(
        "C-INLANG-SAFETY",
        "An allowed interpreter cannot execute arbitrary logic.",
        "ABSTAIN",
        "the gate governs the shell + path surface; an allowed python/pytest can run arbitrary "
        "code WITHIN the sandbox. The jail confines its effects (network/writes), not its computation."))

    reach_basis = (
        "blast radius, when computed, is the STATIC Python-import reverse-dependency closure; "
        "dynamic imports, plugins, cross-language calls, reflection, and data-coupling are invisible."
        if reach_enabled else
        "reach gating was not enabled; blast radius was not computed for this run.")
    claims.append(Claim(
        "C-REACH-COMPLETE",
        "Blast radius covers every dependent of a change.",
        "ABSTAIN", reach_basis))

    claims.append(Claim(
        "C-CROSS-PLATFORM",
        "OS confinement holds on every platform.",
        "ABSTAIN",
        "confinement is verified for macOS Seatbelt only; the Docker backend is DRAFT/unverified. "
        "Off-macOS the kernel fails closed (refuses to run un-jailed)."))

    claims.append(Claim(
        "C-SECURITY-EVALUATED",
        "The kernel has passed an adversarial security evaluation.",
        "ABSTAIN",
        "tests prove capability under tested conditions, not adversarial security; there is no "
        "third-party audit or red-team, and the substring denylist is bypassable by a consumer "
        "who widens the allowlist."))

    return ClaimSet(tuple(claims))


__all__ = ["Claim", "ClaimSet", "attest"]
