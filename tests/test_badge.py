#!/usr/bin/env python3
"""
test_badge.py — the 'GAK-conformant (self-assessed)' mark is EARNED, not asserted.

The badge is worthless if it can be faked. These prove: the reference kernel earns
it; a kernel that fails a clause gets a RED badge, never green; verify fails closed;
the certification digest is reproducible; and the SVG is self-contained/offline.
"""
from __future__ import annotations

import json

import pytest

from deponent import badge
from deponent.adapters.deponent import DeponentAdapter
from deponent.badge import certify, render_markdown, render_svg, verify

# SVG namespace declarations / internal anchor refs are NOT network loads.
_REAL_LOAD_PATTERNS = ("@font-face", "url(http", '<image', 'xlink:href="http', 'src="http')


class _BrokenAdapter(DeponentAdapter):
    """A kernel that allows everything — it must FAIL GAK-DENY-DEFAULT and earn no mark."""
    name = "broken"

    def verdict(self, tool, params):  # noqa: ARG002
        return "ALLOW"


# --- the reference kernel earns the mark --------------------------------------
def test_reference_kernel_is_certified():
    cert = certify("deponent")
    assert cert.conformant is True
    assert cert.mark == "GAK-conformant (self-assessed)"
    assert cert.mark != "GAK-conformant"  # bare mark is reserved for independent runs
    assert cert.self_assessed is True
    assert cert.third_party_verified is False
    assert cert.counts["fail"] == 0


def test_badge_svg_is_earned_green_and_offline():
    svg = render_svg(certify("deponent"))
    assert "deponent" in svg and "conformant" in svg
    assert badge._GREEN in svg and badge._RED not in svg
    low = svg.lower()
    for pat in _REAL_LOAD_PATTERNS:
        assert pat not in low, f"badge SVG must load nothing: found {pat!r}"


# --- a non-conformant kernel gets NO green badge (the honesty property) --------
def test_non_conformant_kernel_gets_red_badge_not_green():
    cert = certify(_BrokenAdapter)
    assert cert.conformant is False
    assert cert.mark == "not-conformant"
    assert cert.self_assessed is True
    assert cert.third_party_verified is False
    svg = render_svg(cert)
    assert "not conformant" in svg
    assert badge._RED in svg and badge._GREEN not in svg


def test_verify_fails_closed_on_non_conformant():
    ok, _ = verify(_BrokenAdapter)
    assert ok is False
    ok2, _ = verify("deponent")
    assert ok2 is True


# --- the mark is reproducible -------------------------------------------------
def test_certification_digest_is_deterministic():
    assert certify("deponent").clauses_digest == certify("deponent").clauses_digest


def test_broken_and_reference_have_different_digests():
    assert certify("deponent").clauses_digest != certify(_BrokenAdapter).clauses_digest


# --- the markdown claim is bounded, never overreaching ------------------------
def test_markdown_snippet_is_bounded_and_has_verify_cmd():
    md = render_markdown(certify("deponent"))
    assert "passes the deponent conformance harness" in md
    assert "python3 -m deponent.badge verify --kernel deponent" in md
    assert "does not certify adversarial security" in md   # explicit non-overclaim


# --- CLI ----------------------------------------------------------------------
def test_cli_verify_exit_zero_when_earned():
    assert badge.main(["verify", "--kernel", "deponent"]) == 0


def test_cli_certify_emits_offline_svg(tmp_path):
    out = tmp_path / "b.svg"
    assert badge.main(["certify", "--kernel", "deponent", "--svg", str(out)]) == 0
    svg = out.read_text()
    assert "conformant" in svg and badge._GREEN in svg


def test_cli_unknown_kernel_fails_closed():
    assert badge.main(["certify", "--kernel", "does-not-exist"]) == 2


def test_certification_to_dict_is_json_serializable():
    d = json.loads(json.dumps(certify("deponent").to_dict()))
    assert d["mark"] == "GAK-conformant (self-assessed)"
    assert d["self_assessed"] is True
    assert d["third_party_verified"] is False
    assert "clauses_digest" in d and d["counts"]["fail"] == 0


def test_render_text_carries_honesty_fields():
    text = badge.render_text(certify("deponent"))
    assert "GAK-conformant (self-assessed)" in text
    assert "self_assessed" in text
    assert "third_party_verified" in text


def test_unknown_kernel_raises():
    with pytest.raises(ValueError):
        certify("nope")
