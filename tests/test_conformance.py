#!/usr/bin/env python3
"""GAK conformance harness — turn the GAK clause set into a checkable
receipt. The reference kernel (deponent) is conformant; a deny-everything kernel
is NOT (deny-all is not governance); an out-of-profile or unclaimed-capability
clause is NA, never a false FAIL; a check that raises is a FAIL, never a pass.
Run: python3 -m pytest -q tests/test_conformance.py"""

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

import deponent
from deponent.conformance import (
    DeponentAdapter,
    run_conformance,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class _Fake:
    """A configurable candidate kernel for testing the harness itself."""

    def __init__(
        self,
        *,
        profile="action-gate",
        supports=frozenset({"reconcile", "attest"}),
        allow_inbounds=True,
        deny_unknown=True,
        raises=False,
    ):
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

    def __init__(self, *, allow_clean=True, deny_security=True, testifies=True, supports=frozenset()):
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
        for cid in ("GAK-COMMIT-DENY-SECURITY", "GAK-COMMIT-ALLOW-CLEAN", "GAK-COMMIT-TESTIFIES"):
            c = next(x for x in r.results if x.id == cid)
            self.assertEqual(c.status, "PASS", cid)

    def test_commit_gate_deny_everything_fails(self):
        r = run_conformance(_FakeCommit(allow_clean=False))
        self.assertFalse(r.conformant)
        c = next(x for x in r.results if x.id == "GAK-COMMIT-ALLOW-CLEAN")
        self.assertEqual(c.status, "FAIL")

    def test_deponent_is_the_only_current_builtin(self):
        from deponent.adapters import BUILTIN_ADAPTERS

        self.assertEqual(tuple(BUILTIN_ADAPTERS), ("deponent",))

    def test_receipt_serializes(self):
        r = run_conformance(DeponentAdapter())
        d = r.to_dict()
        self.assertEqual(d["counts"]["pass"] + d["counts"]["fail"] + d["counts"]["na"], len(r.results))
        self.assertIn("CONFORMANT", r.render())


class TestPublicDistributionTruth(unittest.TestCase):
    def test_public_executable_surfaces_have_no_root_or_home_target(self):
        surfaces = (
            "README.md",
            "deponent/__init__.py",
            "deponent/adapters/deponent.py",
            "deponent/playground.py",
            "examples/custom_tool.py",
            "examples/demo.py",
            "examples/governed_team.py",
            "examples/minimal.py",
            "examples/playground/rogue.json",
            "docs/demo.cast",
        )
        forbidden = (
            "rm -rf /",
            "rm -rf ~",
            "rm -rf $HOME",
            "rm -rf ${HOME}",
        )
        findings = []
        for relative in surfaces:
            text = (REPO_ROOT / relative).read_text(encoding="utf-8", errors="replace")
            for token in forbidden:
                if token in text:
                    findings.append(f"{relative}: {token}")
        self.assertEqual(findings, [], "public root/home targets: " + "; ".join(findings))

    def test_governed_team_never_recursively_deletes_an_override_path(self):
        source = (REPO_ROOT / "examples/governed_team.py").read_text(encoding="utf-8")
        self.assertNotIn("shutil.rmtree", source)
        self.assertNotIn("DEPONENT_EXAMPLE_WORKDIR", source)
        self.assertIn('tempfile.mkdtemp(prefix="deponent-team-")', source)

    def test_generic_safety_example_replaces_retired_brand_promotion(self):
        legacy_path = REPO_ROOT / "examples/safetyspine_action_governor.py"
        example_path = REPO_ROOT / "examples/safety_action_governor.py"
        self.assertFalse(legacy_path.exists(), "retired branded example remains public")
        self.assertTrue(example_path.is_file(), "generic safety-governance example is missing")

        forbidden = ("SafetySpine", "Governor Console")
        findings = []
        for relative in ("SPEC.md", "canaries/CANARIES.md", "examples/safety_action_governor.py"):
            text = (REPO_ROOT / relative).read_text(encoding="utf-8", errors="replace")
            for token in forbidden:
                if token.casefold() in text.casefold():
                    findings.append(f"{relative}: {token}")
        self.assertEqual(findings, [], "retired product promotion: " + "; ".join(findings))

        source = example_path.read_text(encoding="utf-8")
        self.assertIn("class SafetyActionGate", source)
        self.assertIn("class SafetyActionCell", source)
        self.assertIn('agent="safety-action"', source)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT)
        completed = subprocess.run(
            [sys.executable, str(example_path)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("T-001: ALLOW", completed.stdout)
        self.assertIn("T-002: BLOCK", completed.stdout)
        self.assertIn("T-003: BLOCK", completed.stdout)
        self.assertIn("T-004: BLOCK", completed.stdout)
        self.assertIn("safety testimony: True", completed.stdout)

    def test_public_copy_has_no_non_current_promotion_or_private_residue(self):
        product_tokens = ("Archivist", "SafetySpine", "Governor Console", "Fleet Watch")
        forbidden_by_surface = {
            "README.md": product_tokens + ("centennialsystems.com",),
            "pyproject.toml": ("private compliance", "private source", "centennialsystems.com"),
            ".dockerignore": ("provenant", "private source"),
            "deponent/adapters/__init__.py": ("provenant",),
            "deponent/conform.py": product_tokens,
            "docs/demo.cast": product_tokens,
        }
        findings = []
        for relative, forbidden in forbidden_by_surface.items():
            text = (REPO_ROOT / relative).read_text(encoding="utf-8", errors="replace")
            for token in forbidden:
                if token.casefold() in text.casefold():
                    findings.append(f"{relative}: {token}")
        self.assertEqual(findings, [], "stale public copy: " + "; ".join(findings))

    def test_release_metadata_is_current_and_internally_consistent(self):
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        version = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
        self.assertIsNotNone(version)
        self.assertEqual(version.group(1), "0.1.2")
        self.assertEqual(deponent.__version__, version.group(1))
        self.assertIn('requires-python = ">=3.10"', pyproject)
        self.assertIn('license = "Apache-2.0"', pyproject)
        self.assertIn("dependencies = []", pyproject)
        self.assertIn('name = "Christopher \\"CJ\\" Chanhnourack"', pyproject)
        self.assertIn('email = "contact@centennialdefense.systems"', pyproject)
        for excluded in (
            "AGENTS.md",
            "deponent/adapters/sworn.py",
            "deponent/sworn_adapter.py",
        ):
            self.assertIn(f'  "{excluded}",', pyproject)
        for included in (
            "SPEC.md",
            "canaries/CANARIES.md",
            "examples/safety_action_governor.py",
        ):
            self.assertNotIn(f'  "{included}",', pyproject)

    def test_spec_matches_released_version_and_public_api(self):
        spec = (REPO_ROOT / "SPEC.md").read_text(encoding="utf-8")
        self.assertIn("`0.1.2`", spec)
        self.assertNotIn("Version `0.1.0`", spec)
        self.assertNotIn("44 tests pass", spec)
        api_section = spec.split("**Public API**", 1)[1].split("**Stability", 1)[0]
        for name in deponent.__all__:
            self.assertIn(f"`{name}`", api_section, name)

    def test_conformance_docs_do_not_undercount_clauses_as_seven(self):
        from deponent.conformance import CLAUSES

        src = (REPO_ROOT / "deponent/conformance.py").read_text(encoding="utf-8")
        if len(CLAUSES) != 7:
            self.assertNotIn("seven-primitive", src)

    def test_public_docs_do_not_claim_the_whole_tree_has_no_key_material(self):
        self.assertTrue((REPO_ROOT / "deponent/operator_attest.py").is_file())
        phrases = (
            "no key material anywhere in the project",
            "there is no key material in this project",
            "there is no key material in the project",
        )
        for relative in ("SPEC.md", "SECURITY.md", "canaries/CANARIES.md"):
            text = (REPO_ROOT / relative).read_text(encoding="utf-8").casefold()
            for phrase in phrases:
                self.assertNotIn(phrase, text, relative)

    def test_public_docs_do_not_advertise_sworn_as_current(self):
        from deponent.adapters import BUILTIN_ADAPTERS
        from deponent.adapters.sworn import SwornAdapter

        self.assertEqual(tuple(BUILTIN_ADAPTERS), ("deponent",))
        self.assertNotIn(SwornAdapter, BUILTIN_ADAPTERS.values())
        for relative in ("README.md", "SECURITY.md", "canaries/CANARIES.md"):
            text = (REPO_ROOT / relative).read_text(encoding="utf-8")
            self.assertNotIn("sworn", text.casefold(), relative)
        spec = (REPO_ROOT / "SPEC.md").read_text(encoding="utf-8")
        if "sworn" in spec.casefold():
            self.assertIn("not a current built-in", spec.casefold())
        sworn = (REPO_ROOT / "deponent/adapters/sworn.py").read_text(encoding="utf-8")
        wrapper = (REPO_ROOT / "deponent/sworn_adapter.py").read_text(encoding="utf-8")
        self.assertIn("legacy", sworn.casefold())
        self.assertIn("not a current built-in", sworn.casefold())
        self.assertIn("legacy", wrapper.casefold())
        self.assertIn("not a current built-in", wrapper.casefold())

    def test_package_docstring_matches_gate_only_disposable_quickstart(self):
        src = (REPO_ROOT / "deponent/__init__.py").read_text(encoding="utf-8")
        self.assertIn("tempfile", src)
        self.assertIn("use_jail=False", src)
        self.assertNotIn('Cell("/tmp/agent-workdir")', src)

    def test_readme_does_not_claim_draft_docker_jail_is_live_verified(self):
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("Docker backend elsewhere (escape-proofs live-verified", text)
        self.assertIn("DRAFT", text)

    def test_canaries_document_the_disposable_relative_target_cell_proof(self):
        text = (REPO_ROOT / "canaries/CANARIES.md").read_text(encoding="utf-8")
        self.assertNotIn("44 passed", text)
        self.assertIn("test_disposable_relative_target_is_blocked_unchanged_and_testified", text)
        self.assertIn("test_block_redirect_glued_out_of_sandbox", text)
        self.assertIn("test_block_newline_second_command", text)


if __name__ == "__main__":
    unittest.main()
