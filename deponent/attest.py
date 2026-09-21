#!/usr/bin/env python3
"""
attest.py — OPTIONAL compliance-export backend (the `deponent[attest]` extra).

`operator_attest.py` verifies an operator's out-of-band ed25519 signature over a
run's chain-head. This module is the export half: it packages a VERIFIED
attestation into a self-contained, JSON-serializable record — the attestation
plus the verification-only cells it earned — so a downstream auditor replays the
same public-key check instead of trusting this producer's say-so.

HONESTY CLAMP (same rule as the overlay): a record is emitted ONLY when the
attestation verifies. Failure returns None — never a record carrying cells the
re-check did not earn.

Requires `cryptography` (`pip install deponent[attest]`); without it, importing
this module raises ImportError — the backend is absent unless installed. The
core kernel stays keyless and zero-dep: `import deponent` never touches this
module.

Name note: the claims generator `attest()` lives in `deponent.claims` and is
re-exported at package level. Importing THIS submodule rebinds `deponent.attest`
to it — `from deponent.claims import attest` is the stable path to the function.
"""
from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .operator_attest import SCHEMA as ATTESTATION_SCHEMA
from .operator_attest import attestation_cells, make_attestation, verify_attestation

EXPORT_SCHEMA = "deponent-attestation-export/v1"


def attestation_record(attestation: dict, entries: list[dict],
                       trusted_pubkeys: set[str]) -> dict | None:
    """Package an operator attestation as an exportable compliance record, or
    None (fail-closed) when it does not verify against `trusted_pubkeys`."""
    r = verify_attestation(attestation, entries, trusted_pubkeys)
    if not r.valid:
        return None
    return {
        "schema": EXPORT_SCHEMA,
        "attestation_schema": ATTESTATION_SCHEMA,
        "operator_id": r.operator_id,
        "attestation": attestation,
        "cell_verdicts": [list(c) for c in
                          attestation_cells(attestation, entries, trusted_pubkeys)],
    }


def demo_attestation_record(entries: list[dict], operator_id: str = "operator") -> dict | None:
    """Sign the ledger chain-head with an EPHEMERAL ed25519 key (generated for the
    call, never persisted), verify it against that same key, and return the export
    record round-tripped through JSON — proving the record serializes. None if
    the fresh attestation fails verification; fail-closed, always."""
    priv = Ed25519PrivateKey.generate()
    att = make_attestation(entries, operator_id, priv)
    rec = attestation_record(att, entries, {att["pubkey"]})
    return None if rec is None else json.loads(json.dumps(rec))


__all__ = ["EXPORT_SCHEMA", "attestation_record", "demo_attestation_record"]
