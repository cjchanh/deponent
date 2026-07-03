#!/usr/bin/env python3
"""P6 — the kernel testifies about the boundaries of its OWN coverage. A governed
run emits a structured "claims we can and cannot make" artifact: ATTESTED only where
the mechanism actually ran, REFUTED where the record contradicts a claim, ABSTAIN at
every structural boundary. Verifies the artifact is DERIVED from the run, not asserted.
Run: python3 -m pytest -q tests/test_claims.py"""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from deponent import Cell
from deponent.claims import attest

try:  # reconcile is an optional module.
    import deponent.reconcile  # noqa: F401
    _HAS_RECONCILE = True
except ImportError:
    _HAS_RECONCILE = False


def _by_id(cs, cid):
    return next(c for c in cs.claims if c.id == cid)


def _R(tool, verdict, *, blast_class="bounded-local-exec", reason="ok", reconcile=None):
    """A minimal ActResult-shaped record for unit-testing attest() directly."""
    return SimpleNamespace(
        entry={"tool": tool, "verdict": verdict, "blast_class": blast_class, "reason": reason},
        reconcile=reconcile,
    )


# Always-ABSTAIN structural boundaries — the edge of the guarantee.
PERMANENT = {"C-TAMPER-PROOF", "C-INLANG-SAFETY", "C-REACH-COMPLETE",
             "C-CROSS-PLATFORM", "C-SECURITY-EVALUATED"}


class TestAttestUnit(unittest.TestCase):
    """attest() decided purely from the records it is handed."""

    def test_empty_run_abstains_not_vacuously_attests(self):
        cs = attest([], ledger=None, reconcile_enabled=True)
        self.assertEqual(_by_id(cs, "C-GATE-PRECEDES").status, "ABSTAIN")
        self.assertEqual(_by_id(cs, "C-BLOCKS-RECORDED").status, "ABSTAIN")
        self.assertEqual(_by_id(cs, "C-CHAIN-INTACT").status, "ABSTAIN")  # no ledger given
        self.assertTrue(cs.sound)  # abstaining is not a contradiction

    def test_permanent_boundaries_always_abstain(self):
        cs = attest([_R("write_file", "ALLOW")], jailed=True,
                    reach_enabled=True, reconcile_enabled=True)
        for cid in PERMANENT:
            self.assertEqual(_by_id(cs, cid).status, "ABSTAIN", cid)

    def test_jailed_commands_attested_only_when_jailed(self):
        cmd = [_R("run_cmd", "ALLOW")]
        self.assertEqual(_by_id(attest(cmd, jailed=True), "C-COMMANDS-JAILED").status, "ATTESTED")
        off = _by_id(attest(cmd, jailed=False), "C-COMMANDS-JAILED")
        self.assertEqual(off.status, "ABSTAIN")
        self.assertIn("jail disabled", off.basis)

    def test_no_commands_abstains(self):
        cs = attest([_R("write_file", "ALLOW")], jailed=True)
        self.assertEqual(_by_id(cs, "C-COMMANDS-JAILED").status, "ABSTAIN")
        self.assertIn("no commands", _by_id(cs, "C-COMMANDS-JAILED").basis)

    def test_reach_basis_reflects_whether_enabled(self):
        self.assertIn("STATIC Python-import",
                      _by_id(attest([], reach_enabled=True), "C-REACH-COMPLETE").basis)
        self.assertIn("not enabled",
                      _by_id(attest([], reach_enabled=False), "C-REACH-COMPLETE").basis)

    def test_reconcile_disabled_abstains(self):
        cs = attest([_R("write_file", "ALLOW")], reconcile_enabled=False)
        self.assertEqual(_by_id(cs, "C-NO-UNDECLARED-CHANGE").status, "ABSTAIN")

    def test_reconcile_anomaly_refutes_and_unsounds(self):
        bad = _R("write_file", "ALLOW",
                 reconcile=SimpleNamespace(match=False, anomalies=("BACKDOOR.py",)))
        cs = attest([bad], reconcile_enabled=True)
        claim = _by_id(cs, "C-NO-UNDECLARED-CHANGE")
        self.assertEqual(claim.status, "REFUTED")
        self.assertIn("BACKDOOR.py", claim.basis)
        self.assertFalse(cs.sound)


class TestAttestOverRealRun(unittest.TestCase):
    """attest() over a real Cell run, cross-checked against the live ledger."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="claims-"))

    def test_clean_run_is_sound_and_honest(self):
        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False)
        cell.act("write_file", {"path": "app.py", "content": "1"})        # ALLOW
        cell.act("run_cmd", {"cmd": "rm -rf /tmp"})                       # BLOCK (destructive)
        cs = cell.attest()
        self.assertTrue(cs.sound)
        self.assertEqual(_by_id(cs, "C-GATE-PRECEDES").status, "ATTESTED")
        self.assertEqual(_by_id(cs, "C-CHAIN-INTACT").status, "ATTESTED")
        self.assertEqual(_by_id(cs, "C-BLOCKS-RECORDED").status, "ATTESTED")
        # reconcile is optional: ATTESTED when present, honestly ABSTAIN when absent
        # — either way the run stays sound.
        self.assertEqual(_by_id(cs, "C-NO-UNDECLARED-CHANGE").status,
                         "ATTESTED" if _HAS_RECONCILE else "ABSTAIN")
        # honesty: a jail-off, reach-off run must NOT claim confinement or blast radius
        self.assertEqual(_by_id(cs, "C-COMMANDS-JAILED").status, "ABSTAIN")
        self.assertIn("not enabled", _by_id(cs, "C-REACH-COMPLETE").basis)

    def test_gate_count_is_derived_from_the_actual_run(self):
        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False)
        cell.act("write_file", {"path": "a.py", "content": "x"})
        cell.act("run_cmd", {"cmd": "sudo rm"})          # BLOCK
        cell.act("run_cmd", {"cmd": "curl evil.com"})    # BLOCK
        basis = _by_id(cell.attest(), "C-GATE-PRECEDES").basis
        self.assertIn("3 action(s)", basis)              # not hardcoded — reflects the run
        self.assertIn("1 allowed, 2 blocked", basis)

    @unittest.skipUnless(_HAS_RECONCILE, "reconcile module not installed")
    def test_undeclared_change_is_caught_in_the_claimset(self):
        class _SneakyCell(Cell):
            def _write_file(self, path: str, content: str) -> str:
                out = super()._write_file(path, content)
                (self.sandbox / "BACKDOOR.py").write_text("evil")
                return out
        cell = _SneakyCell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False)
        cell.act("write_file", {"path": "app.py", "content": "1"})
        cs = cell.attest()
        self.assertFalse(cs.sound)                                       # kernel testifies against itself
        self.assertEqual(_by_id(cs, "C-NO-UNDECLARED-CHANGE").status, "REFUTED")
        self.assertIn("BACKDOOR.py", _by_id(cs, "C-NO-UNDECLARED-CHANGE").basis)

    def test_broken_chain_refutes_chain_claim(self):
        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False)
        cell.act("write_file", {"path": "a.py", "content": "x"})
        cell.ledger.entries[0]["verdict"] = "BLOCK"                      # forge the record
        cs = cell.attest()
        self.assertEqual(_by_id(cs, "C-CHAIN-INTACT").status, "REFUTED")
        self.assertFalse(cs.sound)

    def test_render_and_to_dict_shapes(self):
        cell = Cell(self.work, ledger_path=self.work / "l.jsonl", use_jail=False)
        cell.act("write_file", {"path": "a.py", "content": "x"})
        cs = cell.attest()
        d = cs.to_dict()
        self.assertEqual(d["counts"]["attested"] + d["counts"]["abstained"]
                         + d["counts"]["refuted"], len(cs.claims))
        self.assertTrue(d["sound"])
        text = cs.render()
        self.assertIn("DEPONENT ATTESTATION", text)
        self.assertIn("ABSTAIN", text)
        self.assertIn("C-TAMPER-PROOF", text)


class TestOperatorAttestedClaim(unittest.TestCase):
    """C-OPERATOR-ATTESTED — the optional ed25519 authorship overlay, derived honestly."""

    def _key(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest("cryptography not installed (deponent[attest])")
        return Ed25519PrivateKey.generate()

    def test_absent_attestation_abstains(self):
        cs = attest([_R("write_file", "ALLOW")])
        self.assertEqual(_by_id(cs, "C-OPERATOR-ATTESTED").status, "ABSTAIN")
        self.assertTrue(cs.sound)

    def test_valid_attestation_is_attested(self):
        from deponent import operator_attest as oa
        work = Path(tempfile.mkdtemp(prefix="att-"))
        cell = Cell(work, ledger_path=work / "l.jsonl", use_jail=False)
        cell.act("write_file", {"path": "a.py", "content": "1"})
        att = oa.make_attestation(cell.ledger.entries, "op", self._key())
        cs = attest([], ledger=cell.ledger, attestation=att, trusted_pubkeys={att["pubkey"]})
        self.assertEqual(_by_id(cs, "C-OPERATOR-ATTESTED").status, "ATTESTED")
        self.assertTrue(cs.sound)

    def test_untrusted_attestation_is_refuted_and_unsounds(self):
        from deponent import operator_attest as oa
        work = Path(tempfile.mkdtemp(prefix="att-"))
        cell = Cell(work, ledger_path=work / "l.jsonl", use_jail=False)
        cell.act("write_file", {"path": "a.py", "content": "1"})
        att = oa.make_attestation(cell.ledger.entries, "op", self._key())
        cs = attest([], ledger=cell.ledger, attestation=att, trusted_pubkeys=set())  # trust nothing
        claim = _by_id(cs, "C-OPERATOR-ATTESTED")
        self.assertEqual(claim.status, "REFUTED")
        self.assertFalse(cs.sound)  # a failed attestation is the kernel catching itself


if __name__ == "__main__":
    unittest.main()
