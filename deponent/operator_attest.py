#!/usr/bin/env python3
"""
operator_attest.py — OPTIONAL operator-attestation overlay (the integrity layer).

The deponent CORE is deliberately keyless (ledger.py: sha256-only, no signing).
This is the SEPARATE, heavier security surface the core declines: an ed25519
operator attestation over a ledger's chain-head, plus the VERIFICATION-ONLY cells
(`integrity`, `operator-attestation`) that evidence the crypto/identity controls a
keyless ledger cannot.

KEY-HANDLING BOUNDARY (Rule 2 / Scope V — verification-only):
  * The CELL holds PUBLIC KEYS ONLY and only VERIFIES. It can never sign.
  * SIGNING uses the operator's PRIVATE key in `make_attestation` — an out-of-band
    operator-commit act, never performed by an agent or inside a governed run.
  * No persistent key storage/generation/rotation here (audit Section 3): callers
    pass keys in; where they live is the operator's concern. Tests/demos use
    EPHEMERAL keys that never touch disk.

HONESTY CLAMP (do not weaken):
  * A cell is emitted ONLY when verification PASSES. A failed / absent / tampered
    attestation yields NO cell — the control honestly stays a GAP. The
    presence-based catalog would misread a present-but-failed cell as Satisfied,
    so failure MUST mean absence, never a present Deny.
  * These cells evidence audit-integrity / key-management / identity / non-
    repudiation. They do NOT evidence FIPS-VALIDATED cryptography (CMMC
    SC.L2-3.13.11 / RMF SRG-APP-000514): ed25519 is a FIPS-approved *algorithm*,
    but "FIPS-validated" needs a CMVP-certified module. Those controls are bound to
    `fips-validated-module` (no implementing cell) and stay a permanent honest gap.

Optional dependency: `cryptography` (`pip install deponent[attest]`). Absent ->
verification is fail-closed (cells absent), the core stays zero-dep.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _CRYPTO_OK = True
except Exception:  # pragma: no cover - exercised by the fail-closed test via monkeypatch
    _CRYPTO_OK = False

SCHEMA = "deponent-attestation/v1"


@dataclass(frozen=True)
class AttestationResult:
    valid: bool
    operator_id: str
    reason: str


def chain_head(entries: list[dict]) -> str:
    """The identity the operator signs: the ledger chain head (last entry_hash), or
    the genesis sentinel for an empty ledger. Binding to the head means ANY mutated
    or reordered entry changes the head and invalidates the attestation."""
    return entries[-1].get("entry_hash", "GENESIS") if entries else "GENESIS"


def _signed_bytes(operator_id: str, head: str) -> bytes:
    return json.dumps({"schema": SCHEMA, "operator_id": operator_id,
                       "chain_head": head}, sort_keys=True).encode("utf-8")


def make_attestation(entries: list[dict], operator_id: str,
                     private_key: "Ed25519PrivateKey") -> dict:
    """OPERATOR-COMMIT act (private key). Sign the ledger chain-head. The private
    key is used here and NOT retained; in production this runs at the operator
    boundary, never in a governed run. Returns a verifiable attestation."""
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography unavailable: install deponent[attest] to sign")
    head = chain_head(entries)
    sig = private_key.sign(_signed_bytes(operator_id, head))
    return {
        "schema": SCHEMA,
        "operator_id": operator_id,
        "chain_head": head,
        "pubkey": private_key.public_key().public_bytes_raw().hex(),
        "signature": sig.hex(),
    }


def verify_attestation(attestation: dict, entries: list[dict],
                       trusted_pubkeys: set[str]) -> AttestationResult:
    """VERIFICATION-ONLY (public key). Fail-closed: returns valid=False on a missing
    crypto lib, an unknown operator key, a chain-head that no longer matches the
    ledger (tamper), or a bad signature."""
    if not _CRYPTO_OK:
        return AttestationResult(False, "", "cryptography unavailable (fail-closed)")
    try:
        pubkey_hex = attestation["pubkey"]
        operator_id = attestation["operator_id"]
        head = attestation["chain_head"]
        sig = bytes.fromhex(attestation["signature"])
    except (KeyError, ValueError, TypeError):
        return AttestationResult(False, "", "malformed attestation")
    if pubkey_hex not in trusted_pubkeys:
        return AttestationResult(False, operator_id, "operator key not trusted")
    # Bind to a VERIFIED chain, not the self-reported stored head: recompute the
    # ledger from genesis. A mutated payload leaves the stored entry_hash intact (so
    # the head still "matches") but breaks the re-link — recomputing catches it.
    from .ledger import Ledger
    chain_ok, _ = Ledger.verify_entries(entries)
    if not chain_ok:
        return AttestationResult(False, operator_id, "ledger chain broken (tampered)")
    if head != chain_head(entries):
        return AttestationResult(False, operator_id, "chain head mismatch (ledger changed)")
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(sig, _signed_bytes(operator_id, head))
    except (InvalidSignature, ValueError):
        return AttestationResult(False, operator_id, "signature invalid")
    return AttestationResult(True, operator_id, "ok")


def integrity_cell(attestation: dict, entries: list[dict],
                   trusted_pubkeys: set[str]) -> tuple[str, str] | None:
    """`integrity` cell-verdict, emitted ONLY on a passing verification (audit
    records cryptographically verified; key managed). Failure -> None (gap)."""
    r = verify_attestation(attestation, entries, trusted_pubkeys)
    return ("integrity", "Approve") if r.valid else None


def operator_attestation_cell(attestation: dict, entries: list[dict],
                              trusted_pubkeys: set[str]) -> tuple[str, str] | None:
    """`operator-attestation` cell-verdict (action bound to an authenticated
    operator; non-repudiation). Emitted ONLY on a passing verification."""
    r = verify_attestation(attestation, entries, trusted_pubkeys)
    return ("operator-attestation", "Approve") if r.valid else None


def attestation_cells(attestation: dict, entries: list[dict],
                      trusted_pubkeys: set[str]) -> list[tuple[str, str]]:
    """Both verification-only cells for a valid operator attestation, else []."""
    cells = []
    for fn in (integrity_cell, operator_attestation_cell):
        c = fn(attestation, entries, trusted_pubkeys)
        if c is not None:
            cells.append(c)
    return cells


__all__ = [
    "AttestationResult", "chain_head", "make_attestation", "verify_attestation",
    "integrity_cell", "operator_attestation_cell", "attestation_cells", "SCHEMA",
]
