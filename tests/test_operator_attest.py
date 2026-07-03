"""Tests for operator_attest.py — the verification-only integrity/identity overlay.

The honesty clamp is the point: a cell is emitted ONLY when verification PASSES.
Tamper, untrusted key, bad signature, or absent crypto -> NO cell -> the control
stays an honest gap (never a present-but-failed cell the catalog would misread as
Satisfied). Ephemeral keys; nothing persisted.
"""
import pytest

from deponent import operator_attest as oa
from deponent.gate import Gate
from deponent.ledger import Ledger

# Skip the whole module if the optional crypto extra isn't installed (deponent[attest]).
crypto = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

try:  # the compliance-export backend is an optional extra; absent unless installed.
    import deponent.attest  # noqa: F401
    _HAS_ATTEST = True
except ImportError:
    _HAS_ATTEST = False


def _ledger():
    gate = Gate("/tmp")
    led = Ledger()
    for tool, params in [("read_file", {"path": "x"}), ("run_cmd", {"cmd": "rm -rf /"})]:
        # decisions only; /tmp containment is irrelevant to the chain we attest over
        led.record(agent="a", tool=tool, params=params, decision=gate.evaluate(tool, params))
    return led


def test_valid_attestation_emits_both_cells():
    led = _ledger()
    priv = Ed25519PrivateKey.generate()
    att = oa.make_attestation(led.entries, "operator", priv)
    trusted = {att["pubkey"]}
    assert oa.integrity_cell(att, led.entries, trusted) == ("integrity", "Approve")
    assert oa.operator_attestation_cell(att, led.entries, trusted) == ("operator-attestation", "Approve")
    cells = oa.attestation_cells(att, led.entries, trusted)
    assert ("integrity", "Approve") in cells and ("operator-attestation", "Approve") in cells


def test_tampered_ledger_invalidates_attestation_no_cell():
    # CLAMP: mutate the ledger after attestation -> chain head moves -> no cell -> gap.
    led = _ledger()
    priv = Ed25519PrivateKey.generate()
    att = oa.make_attestation(led.entries, "operator", priv)
    trusted = {att["pubkey"]}
    led.entries[0]["reason"] = "TAMPERED"  # tamper a payload field of an earlier entry
    r = oa.verify_attestation(att, led.entries, trusted)
    # Bound to a VERIFIED chain: the mutated payload breaks the re-link even though
    # the stored head hash is unchanged.
    assert not r.valid and "chain" in r.reason
    assert oa.integrity_cell(att, led.entries, trusted) is None
    assert oa.attestation_cells(att, led.entries, trusted) == []


def test_untrusted_key_no_cell():
    led = _ledger()
    att = oa.make_attestation(led.entries, "operator", Ed25519PrivateKey.generate())
    r = oa.verify_attestation(att, led.entries, trusted_pubkeys=set())  # nothing trusted
    assert not r.valid and "not trusted" in r.reason
    assert oa.attestation_cells(att, led.entries, set()) == []


def test_bad_signature_no_cell():
    led = _ledger()
    priv = Ed25519PrivateKey.generate()
    att = oa.make_attestation(led.entries, "operator", priv)
    att["signature"] = ("00" * 64)  # well-formed hex, wrong signature
    trusted = {att["pubkey"]}
    r = oa.verify_attestation(att, led.entries, trusted)
    assert not r.valid and "signature" in r.reason
    assert oa.attestation_cells(att, led.entries, trusted) == []


def test_fail_closed_when_crypto_absent(monkeypatch):
    # CLAMP: with no crypto lib, verification fails closed -> no cell -> gap.
    led = _ledger()
    priv = Ed25519PrivateKey.generate()
    att = oa.make_attestation(led.entries, "operator", priv)
    trusted = {att["pubkey"]}
    monkeypatch.setattr(oa, "_CRYPTO_OK", False)
    r = oa.verify_attestation(att, led.entries, trusted)
    assert not r.valid and "unavailable" in r.reason
    assert oa.attestation_cells(att, led.entries, trusted) == []


@pytest.mark.skipif(not _HAS_ATTEST, reason="compliance-export backend not installed")
def test_demo_attestation_record_round_trips():
    from deponent.attest import demo_attestation_record
    led = _ledger()
    rec = demo_attestation_record(led.entries)
    assert rec is not None
    cells = {c for c, _ in rec["cell_verdicts"]}
    assert cells == {"integrity", "operator-attestation"}
