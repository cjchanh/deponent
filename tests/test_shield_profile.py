#!/usr/bin/env python3
"""Unit tests for the credential shield — profile generation, env scrubbing,
receipt verification and command construction. No sandbox-exec is invoked here,
so these run on any platform.

Run: python -m pytest -q tests/test_shield_profile.py

Secrets discipline: a synthetic HOME under tempfile with obviously-fake key files
only. Never touches a real credential path.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from deponent import shield
from deponent.shield import (
    ReceiptWriter,
    ShieldConfig,
    ShieldError,
    build_profile,
    build_safehouse_overlay,
    profile_sha256,
    resolve_catalog,
    scrub_env,
    validate_sbpl_path,
    verify_receipt,
    _write_anchor,
    _hardlink_offenders,
)

_IS_MAC = sys.platform == "darwin"


def _fake_home(tmp: Path) -> Path:
    home = tmp / "home"
    (home / ".ssh").mkdir(parents=True, exist_ok=True)
    (home / ".myown").mkdir(parents=True, exist_ok=True)
    (home / ".ssh" / "id_rsa").write_text("FAKE-KEY-FOR-TEST-ssh")
    (home / ".myown" / "key").write_text("FAKE-KEY-FOR-TEST-own")
    return home


def _cfg(tmp: Path, **kw) -> ShieldConfig:
    home = kw.pop("home", None) or _fake_home(tmp)
    work = tmp / "work"
    work.mkdir(exist_ok=True)
    base = dict(
        command=["true"],
        workspace=work,
        home=home,
        own_keys=(home / ".myown" / "key",),
        receipt_dir=tmp / "receipts",
        anchor_dir=tmp / "anchors",
    )
    base.update(kw)
    return ShieldConfig(**base)


class TestProfileDeterminism(unittest.TestCase):
    def test_identical_inputs_identical_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp)
            a = build_profile(cfg)
            b = build_profile(cfg)
            self.assertEqual(a, b)
            self.assertEqual(profile_sha256(a), profile_sha256(b))

    def test_catalog_order_is_sorted_and_stable(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            home.mkdir()
            c1 = resolve_catalog(home)
            c2 = resolve_catalog(home)
            self.assertEqual(c1, c2)
            self.assertEqual(list(c1), sorted(c1))


class TestInjectionGuard(unittest.TestCase):
    def test_rejects_quote_backslash_control(self):
        for bad in ['/tmp/a"b', "/tmp/a\\b", "/tmp/a\nb", "/tmp/a\tb", "/tmp/a\x00b"]:
            with self.assertRaises(ShieldError):
                validate_sbpl_path(bad)

    def test_injection_path_fails_profile_build(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp, allow_reads=(Path('/tmp/eviltext") (allow default) ;'),))
            with self.assertRaises(ShieldError):
                build_profile(cfg)


class TestProfileContent(unittest.TestCase):
    def test_deny_by_default_home_and_catalog_present(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp)
            prof = build_profile(cfg)
            home = str(cfg.home.resolve())
            self.assertIn(f'(deny file-read* (subpath "{home}"))', prof)
            # a representative catalog entry
            self.assertIn(os.path.join(home, ".ssh"), prof)
            self.assertIn(os.path.join(home, ".aws"), prof)
            self.assertIn(os.path.join(home, "Library", "Keychains"), prof)

    def test_own_key_allow_comes_after_catalog_deny(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp)
            prof = build_profile(cfg)
            own = str((cfg.home / ".myown" / "key").resolve())
            own_line = f'(allow file-read* (literal "{own}"))'
            catalog_deny = f'(deny file-read* (subpath "{os.path.join(str(cfg.home.resolve()), ".ssh")}"))'
            self.assertIn(own_line, prof)
            self.assertIn(catalog_deny, prof)
            # last-match-wins: own-key allow MUST appear after the catalog deny
            self.assertGreater(prof.index(own_line), prof.index(catalog_deny),
                               "own-key allow must be last so it overrides the catalog deny")

    def test_allow_read_cannot_override_catalog(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            extra = tmp / "toolsdir"
            extra.mkdir()
            cfg = _cfg(tmp, allow_reads=(extra,))
            prof = build_profile(cfg)
            allow_read = f'(allow file-read* (subpath "{extra.resolve()}"))'
            catalog_deny = f'(deny file-read* (subpath "{os.path.join(str(cfg.home.resolve()), ".ssh")}"))'
            # allow-read must come BEFORE the catalog deny, so the catalog deny wins
            self.assertLess(prof.index(allow_read), prof.index(catalog_deny),
                            "allow-read must precede catalog deny so it cannot re-open a catalog path")

    def test_keychain_and_side_channel_denies(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            prof = build_profile(_cfg(tmp))
            self.assertIn('(deny mach-lookup (global-name "com.apple.SecurityServer"))', prof)
            self.assertIn("(deny appleevent-send)", prof)
            self.assertIn('(deny mach-lookup (global-name "com.apple.coreservices.launchservicesd"))', prof)
            self.assertIn("(deny process-info* (target others))", prof)
            for b in ("/usr/bin/osascript", "/usr/bin/open", "/bin/launchctl", "/usr/bin/security"):
                self.assertIn(f'(deny process-exec* (literal "{b}"))', prof)

    def test_allow_keychain_removes_the_deny(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            prof = build_profile(_cfg(tmp, allow_keychain=True))
            self.assertNotIn('(deny mach-lookup (global-name "com.apple.SecurityServer"))', prof)

    def test_no_network_toggles_rule(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self.assertIn("(deny network*)", build_profile(_cfg(tmp, no_network=True)))
            self.assertNotIn("(deny network*)", build_profile(_cfg(tmp, no_network=False)))

    def test_write_deny_by_default_with_workspace_allow(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp)
            prof = build_profile(cfg)
            self.assertIn("(deny file-write*)", prof)
            self.assertIn(f'(allow file-write* (subpath "{cfg.workspace.resolve()}"))', prof)


class TestAuditSurfaceOrdering(unittest.TestCase):
    """S1 regression: audit dirs are READ- and write-denied, and those denies come
    after every allow (SBPL last-match-wins), in both emitters."""

    def _idx(self, lines: list[str], needle: str) -> int:
        hits = [i for i, l in enumerate(lines) if needle in l]
        self.assertTrue(hits, f"missing rule containing {needle!r}")
        return hits[-1]

    def test_standalone_profile_denies_audit_read_and_write_last(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp)
            lines = build_profile(cfg).splitlines()
            rdir, adir = str(Path(cfg.receipt_dir).resolve()), str(Path(cfg.anchor_dir).resolve())
            r = self._idx(lines, f'(deny file-read* file-write* (subpath "{rdir}"))')
            a = self._idx(lines, f'(deny file-read* file-write* (subpath "{adir}"))')
            last_allow = max(i for i, l in enumerate(lines) if l.startswith("(allow"))
            self.assertGreater(min(r, a), last_allow, "audit denies must follow every allow")

    def test_overlay_denies_audit_after_own_keys(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp)
            lines = shield.build_safehouse_overlay(cfg).splitlines()
            own = self._idx(lines, "(allow file-read* (literal")
            adir = str(Path(cfg.anchor_dir).resolve())
            a = self._idx(lines, f'(deny file-read* file-write* (subpath "{adir}"))')
            self.assertGreater(a, own, "overlay audit denies must follow own-key allows")


class TestPathHelpers(unittest.TestCase):
    """Direct tests of the two path predicates the preflight relies on, so the
    ancestor fix is proven on its own, not only through a refusal that another
    check could also produce (found by the cross-family review, 2026-09-26)."""

    def test_reopens_true_for_home_parent_and_root(self):
        home = Path("/a/b/home")
        for surface in (home, Path("/a/b"), Path("/a"), Path("/")):
            self.assertTrue(shield._reopens(surface, home), surface)

    def test_reopens_false_for_children_and_siblings(self):
        home = Path("/a/b/home")
        for surface in (Path("/a/b/home/work"), Path("/a/b/other"), Path("/elsewhere")):
            self.assertFalse(shield._reopens(surface, home), surface)

    def test_overlaps_both_directions_and_disjoint(self):
        self.assertTrue(shield._overlaps(Path("/x/y"), Path("/x")))
        self.assertTrue(shield._overlaps(Path("/x"), Path("/x/y")))
        self.assertTrue(shield._overlaps(Path("/x"), Path("/x")))
        self.assertFalse(shield._overlaps(Path("/x/y"), Path("/x/z")))


class TestEnvScrub(unittest.TestCase):
    def test_drops_secret_shaped_names_keeps_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp, own_envs=("MY_DECLARED",))
            parent = {
                "PATH": "/usr/bin", "HOME": "/should/override", "TERM": "xterm",
                "LANG": "en_US.UTF-8", "LC_ALL": "C",
                "OPENAI_API_KEY": "FAKE", "GITHUB_TOKEN": "FAKE", "AWS_SECRET": "FAKE",
                "MY_DECLARED": "keepme", "RANDOM_VAR": "drop",
            }
            child, dropped = scrub_env(cfg, parent_env=parent)
            # allowlist kept
            self.assertEqual(child["PATH"], "/usr/bin")
            self.assertEqual(child["TERM"], "xterm")
            self.assertEqual(child["LC_ALL"], "C")
            # declared kept
            self.assertEqual(child["MY_DECLARED"], "keepme")
            # secret-shaped dropped
            for name in ("OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET", "RANDOM_VAR"):
                self.assertIn(name, dropped)
                self.assertNotIn(name, child)
            # HOME is forced to the shield HOME, not the parent's
            self.assertEqual(child["HOME"], str(cfg.home.resolve()))

    def test_dropped_is_names_only_no_values(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp)
            parent = {"SECRET_TOKEN": "super-secret-value", "PATH": "/bin"}
            _, dropped = scrub_env(cfg, parent_env=parent)
            self.assertIn("SECRET_TOKEN", dropped)
            self.assertNotIn("super-secret-value", " ".join(dropped))


class TestSafehouseOverlay(unittest.TestCase):
    def test_overlay_deterministic_and_own_key_last(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            cfg = _cfg(tmp)
            a = build_safehouse_overlay(cfg)
            b = build_safehouse_overlay(cfg)
            self.assertEqual(a, b)
            own = str((cfg.home / ".myown" / "key").resolve())
            own_line = f'(allow file-read* (literal "{own}"))'
            ssh_deny = f'(deny file-read* (subpath "{os.path.join(str(cfg.home.resolve()), ".ssh")}"))'
            self.assertIn(own_line, a)
            self.assertGreater(a.index(own_line), a.index(ssh_deny))

    def test_overlay_has_side_channel_denies(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            ov = build_safehouse_overlay(_cfg(tmp))
            self.assertIn('(deny mach-lookup (global-name "com.apple.SecurityServer"))', ov)
            self.assertIn("(deny appleevent-send)", ov)
            self.assertIn("(deny process-info* (target others))", ov)


class TestHardlinkPreflight(unittest.TestCase):
    def test_hardlink_offenders_detects_nlink_gt_1(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            work = tmp / "work"
            work.mkdir()
            target = tmp / "outside_secret"
            target.write_text("FAKE-KEY-FOR-TEST")
            link = work / "innocent_name"
            os.link(target, link)  # hardlink into the workspace
            offenders = _hardlink_offenders(work)
            self.assertIn(str(link), offenders)

    def test_no_offenders_on_clean_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d) / "work"
            work.mkdir()
            (work / "file.txt").write_text("ok")
            self.assertEqual(_hardlink_offenders(work), [])


@unittest.skipUnless(_IS_MAC, "preflight refusals gate on macOS first")
class TestPreflightRefusals(unittest.TestCase):
    def test_refuses_workspace_ancestor_of_home(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            home = tmp / "a" / "home"
            home.mkdir(parents=True)
            cfg = ShieldConfig(command=["true"], workspace=tmp / "a", home=home,
                               anchor_dir=tmp / "anchors", receipt_dir=tmp / "receipts")
            with self.assertRaises(ShieldError):
                shield.preflight(cfg)

    def test_refuses_missing_own_key(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            home = _fake_home(tmp)
            work = tmp / "work"; work.mkdir()
            cfg = ShieldConfig(command=["true"], workspace=work, home=home,
                               own_keys=(home / ".ssh" / "does_not_exist",),
                               anchor_dir=tmp / "anchors", receipt_dir=tmp / "receipts")
            with self.assertRaises(ShieldError):
                shield.preflight(cfg)

    def test_allow_missing_own_key_passes(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            home = _fake_home(tmp)
            work = tmp / "work"; work.mkdir()
            cfg = ShieldConfig(command=["true"], workspace=work, home=home,
                               own_keys=(home / ".ssh" / "missing",),
                               allow_missing_own_key=True,
                               anchor_dir=tmp / "anchors", receipt_dir=tmp / "receipts")
            shield.preflight(cfg)  # should not raise

    def test_refuses_hardlink_in_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            home = _fake_home(tmp)
            work = tmp / "work"; work.mkdir()
            os.link(home / ".ssh" / "id_rsa", work / "sneaky")
            cfg = ShieldConfig(command=["true"], workspace=work, home=home,
                               anchor_dir=tmp / "anchors", receipt_dir=tmp / "receipts")
            with self.assertRaises(ShieldError):
                shield.preflight(cfg)

    # -- S1 regressions (found by the cross-family dream-loop review, 2026-09-26) --
    def _base(self, tmp: Path, **kw) -> ShieldConfig:
        home = _fake_home(tmp)
        work = tmp / "work"; work.mkdir(exist_ok=True)
        base = dict(command=["true"], workspace=work, home=home, allow_hardlinks=True,
                    anchor_dir=tmp / "anchors", receipt_dir=tmp / "receipts")
        base.update(kw)
        return ShieldConfig(**base)

    def test_refuses_workspace_root(self):
        """S1: workspace "/" slipped past a string-prefix ancestor check and its
        subpath read-allow re-opened the whole filesystem after the HOME deny."""
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ShieldError, "^workspace .*re-open the whole home directory"):
                shield.preflight(self._base(Path(d), workspace=Path("/")))

    def test_refuses_allow_read_root(self):
        """Ripple of the same S1: --allow-read / re-opens HOME at the same step."""
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ShieldError, "^--allow-read .*re-open the whole home directory"):
                shield.preflight(self._base(Path(d), allow_reads=(Path("/"),)))

    def test_refuses_state_dir_ancestor_of_home(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            with self.assertRaisesRegex(ShieldError, "^--state-dir .*re-open the whole home directory"):
                shield.preflight(self._base(tmp, state_dirs=(tmp,)))  # tmp contains home

    def test_refuses_receipt_dir_inside_workspace(self):
        """S1: an audit dir the agent can reach lets it touch its own evidence."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            with self.assertRaisesRegex(ShieldError, "^receipt dir .*overlaps workspace .*reach its own evidence"):
                shield.preflight(self._base(tmp, receipt_dir=tmp / "work" / "receipts"))

    def test_refuses_anchor_dir_containing_workspace(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            with self.assertRaisesRegex(ShieldError, "^anchor dir .*overlaps workspace .*reach its own evidence"):
                shield.preflight(self._base(tmp, anchor_dir=tmp))  # tmp contains work

    def test_refuses_own_key_inside_anchor_dir(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "anchors").mkdir()
            (tmp / "anchors" / "k").write_text("FAKE")
            with self.assertRaisesRegex(ShieldError, "^anchor dir .*overlaps --own-key .*reach its own evidence"):
                shield.preflight(self._base(tmp, own_keys=(tmp / "anchors" / "k",)))

    def test_positive_control_clean_config_passes(self):
        """Anti-vacuity: the refusals above are specific, not a blanket refusal."""
        with tempfile.TemporaryDirectory() as d:
            shield.preflight(self._base(Path(d)))  # must not raise

    def test_with_safehouse_missing_binary_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            home = _fake_home(tmp)
            work = tmp / "work"; work.mkdir()
            cfg = ShieldConfig(command=["true"], workspace=work, home=home,
                               with_safehouse=True,
                               safehouse_bin="/nonexistent/safehouse",
                               anchor_dir=tmp / "anchors", receipt_dir=tmp / "receipts")
            with self.assertRaises(ShieldError):
                shield.preflight(cfg)


class TestReceiptVerify(unittest.TestCase):
    """verify_receipt covers MISSING / TAMPERED / UNANCHORED / ANCHORED_OK.
    Built by writing real chained receipts; no sandbox needed."""

    def _make_anchored(self, tmp: Path, anchored: bool = True):
        rpath = tmp / "r.jsonl"
        w = ReceiptWriter(rpath)
        w.append({"type": "session_start", "session_id": "sid1", "anchored": anchored})
        w.append({"type": "reach_event", "path": "/x/.ssh", "verdict": "deny"})
        w.append({"type": "session_end", "exit_status": 0})
        head, length = w.head()
        anchor_dir = tmp / "anchors"
        if anchored:
            _write_anchor(anchor_dir, "sid1", head, length)
        return rpath, anchor_dir

    def test_anchored_ok(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rpath, anchor_dir = self._make_anchored(tmp)
            status, _ = verify_receipt(rpath, anchor_dir)
            self.assertEqual(status, "ANCHORED_OK")

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            status, _ = verify_receipt(Path(d) / "nope.jsonl", Path(d))
            self.assertEqual(status, "MISSING")

    def test_empty_file_is_missing_not_intact(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "empty.jsonl"
            p.write_text("")
            status, _ = verify_receipt(p, Path(d))
            self.assertEqual(status, "MISSING")

    def test_edit_is_tampered(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rpath, anchor_dir = self._make_anchored(tmp)
            lines = rpath.read_text().splitlines()
            rec = json.loads(lines[1])
            rec["verdict"] = "ALLOW_FORGED"
            lines[1] = json.dumps(rec)
            rpath.write_text("\n".join(lines) + "\n")
            status, _ = verify_receipt(rpath, anchor_dir)
            self.assertEqual(status, "TAMPERED")

    def test_truncation_is_tampered_via_anchor(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rpath, anchor_dir = self._make_anchored(tmp)
            lines = rpath.read_text().splitlines()
            rpath.write_text("\n".join(lines[:-1]) + "\n")  # drop the tail
            status, _ = verify_receipt(rpath, anchor_dir)
            self.assertEqual(status, "TAMPERED")

    def test_rechain_is_tampered_via_anchor(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rpath, anchor_dir = self._make_anchored(tmp)
            # rebuild a fully self-consistent but DIFFERENT chain, keep old anchor
            w = ReceiptWriter(rpath)
            w.append({"type": "session_start", "session_id": "sid1", "anchored": True})
            w.append({"type": "session_end", "exit_status": 0})
            status, _ = verify_receipt(rpath, anchor_dir)
            self.assertEqual(status, "TAMPERED")

    def test_bad_json_line_is_tampered(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rpath, anchor_dir = self._make_anchored(tmp)
            rpath.write_text(rpath.read_text() + "{not json\n")
            status, _ = verify_receipt(rpath, anchor_dir)
            self.assertEqual(status, "TAMPERED")

    def test_anchor_missing_is_tampered(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rpath, anchor_dir = self._make_anchored(tmp)
            for f in anchor_dir.iterdir():
                f.unlink()
            status, _ = verify_receipt(rpath, anchor_dir)
            self.assertEqual(status, "TAMPERED")

    def test_unanchored(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rpath, anchor_dir = self._make_anchored(tmp, anchored=False)
            status, _ = verify_receipt(rpath, anchor_dir)
            self.assertEqual(status, "UNANCHORED")


if __name__ == "__main__":
    unittest.main()
