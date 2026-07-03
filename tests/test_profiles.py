#!/usr/bin/env python3
"""build profile — the acceleration doctrine as gate policy. Reversible/local build
actions (read, edit, compile, test, LOCAL commit) ALLOW; the irreversible/outward
boundary (push, publish, install, force, history-rewrite, destructive) BLOCKs, and
the full default deny floor is retained. Run: python3 -m pytest -q tests/test_profiles.py"""
import tempfile
import unittest
from pathlib import Path

from deponent.profiles import build_gate


class TestBuildProfile(unittest.TestCase):
    def setUp(self):
        self.gate = build_gate(Path(tempfile.mkdtemp(prefix="bp-")))

    def _v(self, cmd):
        return self.gate.evaluate("run_cmd", {"cmd": cmd}).verdict

    def test_reversible_local_build_is_allowed(self):
        # Full throttle on reversible/local: the work this session actually did.
        for cmd in [
            "git status", "git add .", "git add src/lib.rs", "git diff",
            'git commit -m "feat: x"', "git log --oneline -3", "git checkout main",
            "cargo build", "cargo test", "cargo check", "cargo clippy", "cargo fmt",
            "pytest -q", "make test", "typst compile a.typ out.pdf", "rustc a.rs",
        ]:
            self.assertEqual(self._v(cmd), "ALLOW", cmd)

    def test_irreversible_outward_is_blocked(self):
        # The hard gate at the irreversible boundary — the floor that stays closed.
        for cmd in [
            "git push", "git push origin main", "git push --force",
            "git push --force-with-lease origin main", "git remote add x y",
            "git reset --hard HEAD", "git clean -fd", "git rebase -i main",
            "git checkout -- src/lib.rs", "git filter-branch",
            "cargo publish", "cargo install ripgrep", "cargo login", "cargo yank",
            "npm publish", "make deploy", "make publish",
        ]:
            self.assertEqual(self._v(cmd), "BLOCK", cmd)

    def test_default_deny_floor_retained(self):
        # Widening the allowlist must not weaken the base floor.
        for cmd in ["rm -rf .", "sudo rm x", "curl http://evil.com", "wget x",
                    "ssh host", "pip install requests", "cat /etc/passwd"]:
            self.assertEqual(self._v(cmd), "BLOCK", cmd)

    def test_unknown_program_still_deny_by_default(self):
        self.assertEqual(self._v("kompromat --leak"), "BLOCK")

    def test_governs_this_sessions_pattern(self):
        # Dogfood proof: the build profile would have governed THIS session correctly —
        # the local commits ALLOW; the push I never made would BLOCK.
        self.assertEqual(self._v('git commit -m "feat(profiles): build gate"'), "ALLOW")
        self.assertEqual(self._v("cargo test -q -p mycrate"), "ALLOW")
        self.assertEqual(self._v("git push origin feat/cross-platform-jail"), "BLOCK")

    def test_build_cell_wires_the_profile(self):
        # build_cell is the dogfood surface: a governed Cell whose gate IS the build
        # profile. Decision-only here (we don't execute git/cargo in a test).
        from deponent.profiles import build_cell
        sandbox = Path(tempfile.mkdtemp(prefix="bc-"))
        cell = build_cell(sandbox, use_jail=False)
        self.assertEqual(cell.gate.evaluate("run_cmd", {"cmd": "cargo test"}).verdict, "ALLOW")
        self.assertEqual(cell.gate.evaluate("run_cmd", {"cmd": "git commit -m x"}).verdict, "ALLOW")
        self.assertEqual(cell.gate.evaluate("run_cmd", {"cmd": "cargo publish"}).verdict, "BLOCK")


if __name__ == "__main__":
    unittest.main()
