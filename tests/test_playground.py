#!/usr/bin/env python3
"""
test_playground.py — the testify playground is coupled to the REAL kernel.

One test = one behavior. The point of these is that the score is NOT a vibe: each
number is proven to come from the real Gate / Ledger / attest(), and the honesty
properties (rogue still testifies; tamper drops the score; gaps are stated; offline
HTML) hold.
"""
from __future__ import annotations

import json

import pytest

from deponent.playground import (
    ClassifyCell, ScoreComponents, load_bundled_examples, load_trace, render_html,
    run_agent, run_conformance_suite,
)

# Patterns that constitute an external RESOURCE LOAD on render (a sovereignty
# violation). A navigation <a href="http..."> is NOT a load and is allowed — the
# property is "loads nothing over the network", not "links to nothing".
_LOAD_PATTERNS = ('src="http', "src='http", "@import", "url(http",
                  "<link", "<iframe", "srcset", "<script src")


def _by_name(name: str) -> dict:
    for ex in load_bundled_examples():
        if ex["agent"] == name:
            return ex
    raise AssertionError(f"bundled example {name!r} not found")


# --- coupling to the real gate -------------------------------------------------
def test_well_behaved_scores_perfect_and_does_real_work():
    rep = run_agent(_by_name("well-behaved-coder"))
    assert rep.score.testify_score == 1.0
    assert rep.score.useful_work == 1.0          # all five actions ALLOWED + governed
    assert rep.counts["contained"] == 0
    assert rep.chain_ok and rep.sound


def test_rogue_is_fully_contained_but_STILL_testifies_high():
    """The headline honesty property: a rogue agent scores HIGH on testify because the
    kernel caught + recorded every attempt — high testify != good agent."""
    rep = run_agent(_by_name("rogue-agent"))
    assert rep.score.testify_score == 1.0        # complete, intact, sound testimony
    assert rep.score.useful_work == 0.0          # it did zero legitimate work
    assert rep.counts["contained"] == 5          # 5 out-of-policy attempts, all blocked
    assert rep.counts["unmodelled"] == 1         # the unknown 'exfiltrate' tool, deny-by-default
    # every dangerous action is a real BLOCK from the real gate, with a named blast class
    assert all(a.verdict == "BLOCK" for a in rep.actions)
    assert any(a.blast_class == "out-of-sandbox-write" for a in rep.actions)
    assert any(a.blast_class == "destructive-or-out-of-scope" for a in rep.actions)


def test_mixed_agent_partial_useful_work():
    rep = run_agent(_by_name("mixed-agent"))
    assert rep.counts["allowed"] == 4
    assert rep.counts["contained"] == 2          # git push + pip install held at the floor
    assert 0.0 < rep.score.useful_work < 1.0


def test_unknown_tool_is_denied_by_default():
    rep = run_agent([{"tool": "exfiltrate", "params": {"to": "evil"}}])
    a = rep.actions[0]
    assert a.verdict == "BLOCK"
    assert a.kind == "DENIED-UNKNOWN"


# --- the trust-the-record axis is real: tamper drops it ------------------------
def test_tamper_breaks_chain_and_soundness(tmp_path):
    """If a ledger entry is forged, the substrate the playground scores on detects it:
    the chain fails to re-verify and attest() is no longer sound."""
    cell = ClassifyCell(tmp_path, ledger_path=tmp_path / "l.jsonl")
    cell.act("write_file", {"path": "a.py", "content": "1"})
    cell.act("write_file", {"path": "b.py", "content": "2"})
    assert cell.verify()[0] is True
    cell.ledger.entries[0]["verdict"] = "BLOCK"          # forge the record
    assert cell.verify()[0] is False
    assert cell.attest().sound is False                  # the kernel testifies against itself


def test_score_formula_drops_on_broken_chain():
    assert ScoreComponents(1.0, 0.0, 0.0, 1.0).testify_score == round(1 / 3, 4)
    assert ScoreComponents(1.0, 1.0, 1.0, 0.0).testify_score == 1.0


def test_score_is_deterministic():
    a = run_agent(_by_name("rogue-agent")).to_dict()
    b = run_agent(_by_name("rogue-agent")).to_dict()
    assert a["testify_score"] == b["testify_score"]
    assert a["components"] == b["components"]


# --- honest gaps are always present -------------------------------------------
def test_honest_gaps_state_the_meaning_and_jail_abstain():
    rep = run_agent(_by_name("well-behaved-coder"))
    ids = {g.id for g in rep.gaps}
    assert "RUN-SCORE-MEANING" in ids                    # the "high testify != good agent" note
    # classify mode ran no jailed commands -> confinement is honestly ABSTAINED, never faked
    jail = next(g for g in rep.gaps if g.id == "C-COMMANDS-JAILED")
    assert jail.status == "ABSTAIN"


def test_allowed_command_is_marked_needs_jail_not_equal_to_a_write():
    """A gate-allowed command must NOT look identical to a bounded file write: the gate
    vets shell/path, not in-language intent. classify mode marks commands 'needs-jail'."""
    rep = run_agent(_by_name("well-behaved-coder"))  # 3 file ops + 2 commands, all ALLOW
    conf = {a.summary: a.confinement for a in rep.actions}
    assert conf["run_cmd(pytest -q)"] == "needs-jail"
    assert conf["run_cmd(ruff check .)"] == "needs-jail"
    assert conf["write_file(app.py)"] == "bounded"        # a write IS fully bounded by the gate
    assert rep.counts["needs_jail"] == 2
    assert any(g.id == "RUN-NEEDS-JAIL" for g in rep.gaps)


def test_blocked_actions_have_no_confinement_claim():
    rep = run_agent(_by_name("rogue-agent"))
    assert all(a.confinement == "n/a" for a in rep.actions)  # nothing ran; nothing to confine
    assert rep.counts["needs_jail"] == 0


def test_html_escapes_injection_in_tool_name():
    """Defense-in-depth: an attacker-controlled tool name cannot inject into the report."""
    rep = run_agent([{"tool": "<img src=x onerror=alert(1)>", "params": {}}])
    out = render_html([rep])
    assert "<img src=x onerror=alert(1)>" not in out      # the raw payload must not survive
    assert "&lt;img" in out                               # it is present, escaped


# --- classify mode is safe: no side effects -----------------------------------
def test_classify_mode_executes_no_side_effects(tmp_path):
    run_agent(_by_name("well-behaved-coder"), execute=False, sandbox=tmp_path)
    assert not (tmp_path / "app.py").exists()            # the write was gated+recorded, NOT executed
    assert (tmp_path / "ledger.jsonl").exists()          # but the testimony was


# --- the HTML report is self-contained and offline (sovereign) ----------------
def test_html_is_self_contained_and_offline():
    reports = [run_agent(ex) for ex in load_bundled_examples()]
    out = render_html(reports)
    low = out.lower()
    # No external RESOURCE loads (network / CDN / web fonts). Note: escaped user content
    # may legitimately contain a URL string (a rogue agent's `curl http://...` command) —
    # that is display text, not a load. The sovereign property is "loads nothing".
    for pat in _LOAD_PATTERNS:
        assert pat not in low, f"external resource load found: {pat!r}"
    assert "Testify Score" in out
    assert "<script" in out                              # the tab switcher is inline


def test_html_with_conformance_does_not_crash_and_shows_verdict():
    """Regression guard for the conformance clause renderer (an f-string format bug
    here once would crash the whole report)."""
    reports = [run_agent(_by_name("well-behaved-coder"))]
    conf = run_conformance_suite("deponent")
    out = render_html(reports, conf)
    assert "CONFORMANT" in out


def test_inline_meaning_prevents_the_safe_misread():
    """A high score must never read as 'the agent is safe': the meaning folds in the
    useful-work contrast."""
    from deponent.playground import _meaning
    assert "nothing real ran" in _meaning(run_agent(_by_name("rogue-agent")))
    assert "prove exactly" in _meaning(run_agent(_by_name("well-behaved-coder")))


def test_html_has_hero_strip_reason_column_and_inline_badge():
    reports = [run_agent(ex) for ex in load_bundled_examples()]
    conf = run_conformance_suite("deponent")
    out = render_html(reports, conf)
    # 1. hero contrast strip — one clickable card per agent, switches tabs
    assert 'class="hero"' in out
    assert 'class="herocard" data-tab="2"' in out          # the 3rd agent's card exists
    # 2. per-action reason is now visible (the visceral evidence)
    assert "matched deny pattern" in out
    # 3. the earned badge is embedded inline as a self-contained green SVG
    assert "<svg" in out and "#3fb950" in out
    # still offline even with the badge inlined
    low = out.lower()
    for pat in _LOAD_PATTERNS:
        assert pat not in low, f"external resource load found: {pat!r}"


def test_demo_polish_legend_collapsible_footer_and_copy():
    reports = [run_agent(ex) for ex in load_bundled_examples()]
    out = render_html(reports, run_conformance_suite("deponent"))
    assert 'class="legend"' in out                         # the action-kind key
    assert "<details>" in out and "clause results" in out  # collapsible conformance block
    assert "<footer>" in out
    assert "Apache-2.0" in out and "gak-conformance/v1" in out
    assert "does NOT certify" in out                       # the honest boundary, stated
    assert "copyEl" in out                                 # copy-on-click wiring
    # offline preserved — the footer link is navigation (<a href>), not a resource load
    low = out.lower()
    for pat in _LOAD_PATTERNS:
        assert pat not in low, f"external resource load found: {pat!r}"


# --- the kernel-level proof ----------------------------------------------------
def test_test_suite_reference_kernel_is_conformant():
    conf = run_conformance_suite("deponent")
    assert conf["conformant"] is True
    assert conf["counts"]["fail"] == 0


# --- fail-closed on bad input --------------------------------------------------
def test_empty_trace_fails_closed():
    with pytest.raises(ValueError):
        load_trace([])
    with pytest.raises(ValueError):
        load_trace({"actions": []})


def test_malformed_action_fails_closed():
    with pytest.raises(ValueError):
        load_trace([{"params": {"path": "x"}}])          # no 'tool'


def test_report_to_dict_is_json_serializable():
    rep = run_agent(_by_name("mixed-agent"))
    s = json.dumps(rep.to_dict())                        # must not raise
    d = json.loads(s)
    assert set(d) >= {"agent", "testify_score", "components", "counts", "honest_gaps", "actions"}
