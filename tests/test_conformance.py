#!/usr/bin/env python3
"""GAK conformance harness — turn the seven-primitive thesis into a checkable
receipt. The reference kernel (deponent) is conformant; a deny-everything kernel
is NOT (deny-all is not governance); an out-of-profile or unclaimed-capability
clause is NA, never a false FAIL; a check that raises is a FAIL, never a pass.
Run: python3 -m pytest -q tests/test_conformance.py"""
import unittest

from deponent.conformance import (
    CLAUSES,
    DeponentAdapter,
    run_conformance,
)


class _Fake:
    """A configurable candidate kernel for testing the harness itself."""
    def __init__(self, *, profile="action-gate", supports=frozenset({"reconcile", "attest"}),
                 allow_inbounds=True, deny_unknown=True, raises=False):
        self.name = "fake"
        self.profile = profile
        self.supports = supports
        self._allow_inbounds = allow_inbounds
        self._deny_unknown = deny_unknown
        self._raises = raises

    def verdict(self, tool, params):
        if self._raises:
            raise RuntimeError("kernel exploded")
        if tool == "definitely_not_a_real_tool":
            return "BLOCK" if self._deny_unknown else "ALLOW"
        if tool == "write_file" and str(params.get("path", "")).startswith("ok"):
            return "ALLOW" if self._allow_inbounds else "BLOCK"
        return "BLOCK"  # escapes, destructive, non-allowlisted

    def clean_chain_verifies(self):
        return True

    def tamper_is_detected(self):
        return True

    def reconcile_catches_undeclared(self):
        return True

    def attest_abstains_when_unproven(self):
        return True


class _FakeCommit:
    """A configurable commit-gate candidate for testing the commit-gate clauses."""
    def __init__(self, *, allow_clean=True, deny_security=True, testifies=True,
                 supports=frozenset()):
        self.name = "fake-commit"
        self.profile = "commit-gate"
        self.supports = supports
        self._allow_clean = allow_clean
        self._deny_security = deny_security
        self._testifies = testifies

    def commit_verdict(self, files):
        if any(s in f for f in files for s in ("crypto/", "auth/", "keys/")):
            return "BLOCK" if self._deny_security else "ALLOW"
        return "ALLOW" if self._allow_clean else "BLOCK"

    def commit_testifies(self, files):
        return self._testifies

    def clean_chain_verifies(self):
        return True

    def tamper_is_detected(self):
        return True


class TestConformance(unittest.TestCase):
    def test_deponent_reference_is_conformant(self):
        r = run_conformance(DeponentAdapter())
        self.assertTrue(r.conformant)
        self.assertFalse(any(c.status == "FAIL" for c in r.results))
        self.assertTrue(any(c.status == "PASS" for c in r.results))

    def test_deny_everything_is_not_conformance(self):
        # The point of GAK-ALLOW-INBOUNDS: a kernel that blocks legitimate work too
        # is not governing, it is bricking. Must FAIL.
        r = run_conformance(_Fake(allow_inbounds=False))
        self.assertFalse(r.conformant)
        allow = next(c for c in r.results if c.id == "GAK-ALLOW-INBOUNDS")
        self.assertEqual(allow.status, "FAIL")

    def test_deny_default_violation_fails(self):
        r = run_conformance(_Fake(deny_unknown=False))
        self.assertFalse(r.conformant)
        dd = next(c for c in r.results if c.id == "GAK-DENY-DEFAULT")
        self.assertEqual(dd.status, "FAIL")

    def test_check_that_raises_is_fail_not_pass(self):
        # fail-closed: an erroring check is never silently a pass.
        r = run_conformance(_Fake(raises=True))
        self.assertFalse(r.conformant)
        self.assertTrue(any(c.status == "FAIL" for c in r.results))

    def test_unclaimed_capability_is_na_not_fail(self):
        r = run_conformance(_Fake(supports=frozenset()))  # claims neither reconcile nor attest
        recon = next(c for c in r.results if c.id == "GAK-RECONCILE-UNDECLARED")
        att = next(c for c in r.results if c.id == "GAK-ATTEST-HONEST")
        self.assertEqual(recon.status, "NA")
        self.assertEqual(att.status, "NA")

    def test_out_of_profile_clause_is_na(self):
        # A commit-gate kernel must not be false-FAILed by action-gate clauses.
        r = run_conformance(_FakeCommit())
        action_clauses = [c for c in r.results if c.profile == "action-gate"]
        self.assertTrue(action_clauses)
        self.assertTrue(all(c.status == "NA" for c in action_clauses))

    def test_commit_gate_fake_is_conformant(self):
        r = run_conformance(_FakeCommit())
        self.assertTrue(r.conformant)
        for cid in ("GAK-COMMIT-DENY-SECURITY", "GAK-COMMIT-ALLOW-CLEAN",
                    "GAK-COMMIT-TESTIFIES"):
            c = next(x for x in r.results if x.id == cid)
            self.assertEqual(c.status, "PASS", cid)

    def test_commit_gate_deny_everything_fails(self):
        r = run_conformance(_FakeCommit(allow_clean=False))
        self.assertFalse(r.conformant)
        c = next(x for x in r.results if x.id == "GAK-COMMIT-ALLOW-CLEAN")
        self.assertEqual(c.status, "FAIL")

    def test_sworn_reference_is_conformant(self):
        # Real sworncode commit-gate kernel, gated on sworncode being importable.
        try:
            import sworn  # noqa: F401
        except ImportError:
            self.skipTest("sworncode not on path")
        from deponent.sworn_adapter import SwornAdapter
        r = run_conformance(SwornAdapter())
        self.assertTrue(r.conformant, r.render())

    def test_receipt_serializes(self):
        r = run_conformance(DeponentAdapter())
        d = r.to_dict()
        self.assertEqual(d["counts"]["pass"] + d["counts"]["fail"] + d["counts"]["na"],
                         len(r.results))
        self.assertIn("CONFORMANT", r.render())


if __name__ == "__main__":
    unittest.main()
