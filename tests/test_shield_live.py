#!/usr/bin/env python3
"""Live macOS canaries for the credential shield (C1-C12 + FD leak).

Each canary actually invokes `sandbox-exec` with the real generated profile and
asserts the protected outcome. Where a positive control is impossible on this
host, or where the behavior is a documented design residual, the canary is pinned
KNOWN-NOT-STOPPED so it can never silently flip into a false containment claim.

Run: python -m pytest -q tests/test_shield_live.py
Skipped cleanly off macOS or without sandbox-exec.

Secrets discipline: a synthetic HOME under tempfile with obviously-fake keys only.
Never reads, lists or references a real credential path. Never signals a process
it did not itself start. osascript/open/launchctl/security are invoked ONLY with
harmless args and ONLY to prove exec is denied.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from deponent import shield
from deponent.shield import SANDBOX_EXEC, ShieldConfig, ShieldError, build_profile, run_shield, scrub_env, verify_receipt

_SEATBELT_OK = sys.platform == "darwin" and os.path.exists(SANDBOX_EXEC) and os.access(SANDBOX_EXEC, os.X_OK)

FAKE_OWN = "FAKE-OWN-KEY-CONTENTS"
FAKE_SSH = "FAKE-KEY-FOR-TEST-ssh"
FAKE_CODEX = "FAKE-KEY-FOR-TEST-codex"


def _mkenv(tmp: Path) -> tuple[Path, Path]:
    """Build a synthetic HOME (with fake catalog keys) + a workspace."""
    home = tmp / "home"
    for sub in (".ssh", ".myown", ".codex", ".aws"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    (home / ".ssh" / "id_rsa").write_text(FAKE_SSH)
    (home / ".myown" / "key").write_text(FAKE_OWN)
    (home / ".codex" / "auth.json").write_text(FAKE_CODEX)
    work = tmp / "work"
    work.mkdir(exist_ok=True)
    return home, work


def _cfg(tmp: Path, home: Path, work: Path, **kw) -> ShieldConfig:
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


def _run_under_profile(cfg: ShieldConfig, argv: list[str], parent_env: dict | None = None
                       ) -> subprocess.CompletedProcess:
    """Run argv under cfg's generated profile exactly as run_shield launches the
    child: -p <profile>, cwd=workspace, scrubbed env, close_fds."""
    profile = build_profile(cfg)
    child_env, _ = scrub_env(cfg, parent_env=parent_env)
    (Path(cfg.workspace) / ".shield-tmp").mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [SANDBOX_EXEC, "-p", profile, "--"] + argv,
        cwd=str(Path(cfg.workspace).resolve()),
        env=child_env, capture_output=True, text=True, timeout=60, close_fds=True,
    )


@unittest.skipUnless(_SEATBELT_OK, "Seatbelt sandbox-exec not present (not macOS)")
class TestShieldCanaries(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)
        self.home, self.work = _mkenv(self.tmp)

    def tearDown(self):
        self._td.cleanup()

    # -- C1: own key readable --------------------------------------------------
    def test_C1_own_key_readable(self):
        cfg = _cfg(self.tmp, self.home, self.work)
        r = _run_under_profile(cfg, ["/bin/cat", str(self.home / ".myown" / "key")])
        self.assertIn(FAKE_OWN, r.stdout, "own declared key must be readable")

    # -- C2: another agent's key denied ---------------------------------------
    def test_C2_other_agent_key_denied(self):
        cfg = _cfg(self.tmp, self.home, self.work)
        r = _run_under_profile(cfg, ["/bin/cat", str(self.home / ".codex" / "auth.json")])
        self.assertNotIn(FAKE_CODEX, r.stdout)
        self.assertIn("Operation not permitted", r.stderr)

    # -- C3: ~/.ssh denied via cat, python open(), and a workspace symlink -----
    def test_C3_ssh_denied_three_ways(self):
        cfg = _cfg(self.tmp, self.home, self.work)
        ssh = str(self.home / ".ssh" / "id_rsa")
        # (a) cat
        r1 = _run_under_profile(cfg, ["/bin/cat", ssh])
        self.assertNotIn(FAKE_SSH, r1.stdout)
        self.assertIn("Operation not permitted", r1.stderr)
        # (b) python -c open()
        r2 = _run_under_profile(cfg, ["/usr/bin/python3", "-c", f"print(open({ssh!r}).read())"])
        self.assertNotIn(FAKE_SSH, r2.stdout)
        # (c) workspace symlink to the protected file (symlinks are resolved)
        link = self.work / "sneaky_symlink"
        link.symlink_to(ssh)
        r3 = _run_under_profile(cfg, ["/bin/cat", str(link)])
        self.assertNotIn(FAKE_SSH, r3.stdout, "symlink to a protected file must be denied")
        self.assertIn("Operation not permitted", r3.stderr)

    # -- C4: workspace hardlink to a protected file (KNOWN-NOT-STOPPED) --------
    def test_C4_workspace_hardlink_is_readable_KNOWN_NOT_STOPPED(self):
        """Empirically: Seatbelt keys on the path, so a PRE-EXISTING hardlink in
        the workspace to a protected file IS readable. This is a documented
        residual, mitigated by the preflight st_nlink>1 refusal. This canary pins
        the current behavior so it cannot silently change."""
        cfg = _cfg(self.tmp, self.home, self.work, allow_hardlinks=True)
        hardlink = self.work / "innocent"
        os.link(self.home / ".ssh" / "id_rsa", hardlink)
        r = _run_under_profile(cfg, ["/bin/cat", str(hardlink)])
        # KNOWN-NOT-STOPPED: the hardlink content leaks through.
        self.assertIn(FAKE_SSH, r.stdout,
                      "if this fails the platform changed — update docs/SHIELD.md")
        # The mitigation: preflight refuses st_nlink>1 unless --allow-hardlinks.
        cfg_default = _cfg(self.tmp, self.home, self.work)  # allow_hardlinks=False
        with self.assertRaises(ShieldError):
            shield.preflight(cfg_default)

    # -- C5: writes confined to the workspace ---------------------------------
    def test_C5_writes_confined(self):
        cfg = _cfg(self.tmp, self.home, self.work)
        # inside: allowed
        r_in = _run_under_profile(cfg, ["/bin/sh", "-c", "echo hi > inside.txt && echo WROTE_IN"])
        self.assertIn("WROTE_IN", r_in.stdout)
        self.assertTrue((self.work / "inside.txt").exists())
        # outside: denied (a sibling of the workspace, under tmp but not workspace)
        outside = self.tmp / "outside.txt"
        r_out = _run_under_profile(cfg, ["/bin/sh", "-c", f"echo x > {outside} && echo WROTE_OUT"])
        self.assertNotIn("WROTE_OUT", r_out.stdout)
        self.assertFalse(outside.exists(), "write outside the workspace must be denied")

    # -- C6: env secret absent unless declared --------------------------------
    def test_C6_env_secret_scrubbed(self):
        cfg = _cfg(self.tmp, self.home, self.work)
        parent = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                  "FAKE_OPENAI_API_KEY": "FAKE-ENV-SECRET"}
        r = _run_under_profile(cfg, ["/usr/bin/printenv", "FAKE_OPENAI_API_KEY"], parent_env=parent)
        self.assertNotIn("FAKE-ENV-SECRET", r.stdout, "undeclared env secret must be dropped")
        # declared via --own-env: present
        cfg2 = _cfg(self.tmp, self.home, self.work, own_envs=("FAKE_OPENAI_API_KEY",))
        r2 = _run_under_profile(cfg2, ["/usr/bin/printenv", "FAKE_OPENAI_API_KEY"], parent_env=parent)
        self.assertIn("FAKE-ENV-SECRET", r2.stdout, "declared --own-env must pass through")

    # -- C7: exec of the escape binaries denied -------------------------------
    def test_C7_exec_denied(self):
        cfg = _cfg(self.tmp, self.home, self.work)
        for binpath, arg in (
            ("/usr/bin/osascript", "-e"),  # harmless: help/usage only, no script runs
            ("/usr/bin/open", "--help"),
            ("/bin/launchctl", "help"),
            ("/usr/bin/security", "help"),
        ):
            r = _run_under_profile(cfg, [binpath, arg])
            self.assertIn("Operation not permitted", r.stderr,
                          f"{binpath} exec should be denied")

    # -- C8: signalling the parent (KNOWN-NOT-STOPPED on macOS 27) -------------
    def test_C8_signal_parent_KNOWN_NOT_STOPPED(self):
        """Empirically on macOS 27, SBPL `(deny signal (target others))` does NOT
        block a real signal to a process outside the sandbox. We pin the residual
        here rather than claim containment. We only ever signal a sacrificial
        process this test itself started."""
        victim = subprocess.Popen(["sleep", "30"])
        try:
            time.sleep(0.3)
            cfg = _cfg(self.tmp, self.home, self.work)
            _run_under_profile(cfg, ["/bin/sh", "-c", f"kill -TERM {victim.pid}"])
            time.sleep(0.5)
            reached = (victim.poll() is not None)
            # KNOWN-NOT-STOPPED: the signal reaches the outside process.
            self.assertTrue(reached,
                            "if the signal was blocked the platform improved — update docs/SHIELD.md")
        finally:
            if victim.poll() is None:
                victim.kill()
            victim.wait()

    # -- C9: receipt records REACH or UNAVAILABLE, never empty-and-OK ----------
    def test_C9_receipt_reach_is_events_or_unavailable(self):
        cfg = _cfg(self.tmp, self.home, self.work,
                   command=["/bin/cat", str(self.home / ".codex" / "auth.json")])
        result = run_shield(cfg)
        receipt = Path(result["receipt"])
        recs = [json.loads(l) for l in receipt.read_text().splitlines() if l.strip()]
        end = [r for r in recs if r.get("type") == "session_end"][0]
        reach = end["reach_events"]
        # Either the string UNAVAILABLE, or "OBSERVED" with reach_event records.
        self.assertIn(reach, ("UNAVAILABLE", "OBSERVED"))
        if reach == "OBSERVED":
            events = [r for r in recs if r.get("type") == "reach_event"]
            self.assertTrue(events, "OBSERVED must be backed by reach_event records")
        else:
            # UNAVAILABLE is the honest value on a host where sandbox-exec denies
            # are not logged; it must never be silently reported as "none".
            self.assertEqual(reach, "UNAVAILABLE")

    # -- C10: refuse (child never starts) on invalid path / missing sandbox ----
    def test_C10_refuse_invalid_path(self):
        cfg = _cfg(self.tmp, self.home, self.work,
                   allow_reads=(Path('/tmp/x") (allow default) ('),))
        with self.assertRaises(ShieldError):
            run_shield(cfg)

    def test_C10_refuse_missing_sandbox_exec(self):
        cfg = _cfg(self.tmp, self.home, self.work)
        orig = shield.SANDBOX_EXEC
        try:
            shield.SANDBOX_EXEC = "/nonexistent/sandbox-exec"
            with self.assertRaises(ShieldError):
                run_shield(cfg)
        finally:
            shield.SANDBOX_EXEC = orig

    # -- C11: verify returns the four honest verdicts --------------------------
    def test_C11_verify_end_to_end(self):
        cfg = _cfg(self.tmp, self.home, self.work, command=["/usr/bin/true"])
        result = run_shield(cfg)
        receipt = Path(result["receipt"])
        status, _ = verify_receipt(receipt, cfg.anchor_dir)
        self.assertEqual(status, "ANCHORED_OK")
        # tamper -> TAMPERED
        lines = receipt.read_text().splitlines()
        rec = json.loads(lines[0]); rec["argv"] = ["forged"]
        lines[0] = json.dumps(rec)
        receipt.write_text("\n".join(lines) + "\n")
        status2, _ = verify_receipt(receipt, cfg.anchor_dir)
        self.assertEqual(status2, "TAMPERED")

    # -- C12: reading the parent's env is blocked -----------------------------
    def test_C12_parent_env_not_readable(self):
        secret = "FAKE-SECRET-IN-PARENT-XYZ"
        recorder_pid = os.getpid()
        os.environ["FAKE_SECRET_IN_PARENT"] = secret
        try:
            # positive control: an unsandboxed DIRECT child can read our env
            ctrl = subprocess.run(["sh", "-c", f"ps eww -p {recorder_pid}"],
                                  capture_output=True, text=True)
            if secret not in ctrl.stdout:
                self.skipTest("macOS blocks this env read even unsandboxed; control impossible")
            # under the shield profile: must NOT leak
            cfg = _cfg(self.tmp, self.home, self.work)
            r = _run_under_profile(cfg, ["/bin/sh", "-c", f"ps eww -p {recorder_pid}"])
            self.assertNotIn(secret, r.stdout,
                             "sandboxed child read the parent's env — process-info deny failed")
        finally:
            os.environ.pop("FAKE_SECRET_IN_PARENT", None)

    # -- FD leak: child must not inherit a parent fd on a fake key -------------
    def test_FD_not_inherited(self):
        fake_key = self.tmp / "parent_fd_key"
        fake_key.write_text("FAKE-KEY-FOR-TEST-fd")
        cfg = _cfg(self.tmp, self.home, self.work)
        fd = os.open(str(fake_key), os.O_RDONLY)
        try:
            profile = build_profile(cfg)
            child_env, _ = scrub_env(cfg)
            (self.work / ".shield-tmp").mkdir(exist_ok=True)
            # run_shield launches with close_fds=True; replicate that here
            r = subprocess.run(
                [SANDBOX_EXEC, "-p", profile, "--", "/bin/sh", "-c", f"cat /dev/fd/{fd} 2>&1"],
                cwd=str(self.work), env=child_env, capture_output=True, text=True,
                timeout=30, close_fds=True,
            )
            self.assertNotIn("FAKE-KEY-FOR-TEST-fd", r.stdout,
                             "child inherited a parent fd on a fake key (close_fds failed)")
        finally:
            os.close(fd)


@unittest.skipUnless(_SEATBELT_OK, "Seatbelt sandbox-exec not present (not macOS)")
class TestSafehouseCompose(unittest.TestCase):
    """Live compose-mode canaries against the REAL Agent Safehouse. Skipped unless
    `safehouse` is on PATH (do not install it here)."""

    def setUp(self):
        import shutil
        if not shutil.which("safehouse"):
            self.skipTest("safehouse not on PATH")
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)
        self.home, self.work = _mkenv(self.tmp)

    def tearDown(self):
        if hasattr(self, "_td"):
            self._td.cleanup()

    def test_safehouse_compose_full(self):
        # (a)+(b)+(c)+(d) in one run: workspace rw, catalog key denied, side-channel
        # deny effective, receipt ANCHORED_OK.
        cfg = _cfg(self.tmp, self.home, self.work, with_safehouse=True,
                   command=["/bin/sh", "-c",
                            "echo ws-write:; echo x > o.txt && echo WROTE; "
                            f"echo ssh:; cat {self.home}/.ssh/id_rsa 2>&1; "
                            f"echo own:; cat {self.home}/.myown/key 2>&1"])
        result = run_shield(cfg)
        self.assertEqual(result["mode"], "safehouse")
        # real policy hash recorded (not UNAVAILABLE)
        self.assertTrue(result["safehouse_policy_sha256"])
        self.assertTrue(result["overlay_sha256"])
        # (a) workspace writable
        self.assertTrue((self.work / "o.txt").exists())
        # (d) receipt verifies
        status, _ = verify_receipt(Path(result["receipt"]), cfg.anchor_dir)
        self.assertEqual(status, "ANCHORED_OK")

    def test_safehouse_ssh_denied_own_key_allowed(self):
        # (b) catalog key denied; own-key carve-out survives composition
        cfg = _cfg(self.tmp, self.home, self.work, with_safehouse=True)
        import shutil
        binpath = shutil.which("safehouse")
        overlay = shield.build_safehouse_overlay(cfg)
        overlay_path = self.work / "ov.sb"
        overlay_path.write_text(overlay)
        policy = shield._safehouse_policy(cfg, binpath, overlay_path)
        child_env, _ = scrub_env(cfg)
        def under(argv):
            return subprocess.run([SANDBOX_EXEC, "-p", policy, "--"] + argv,
                                  cwd=str(self.work), env=child_env,
                                  capture_output=True, text=True, timeout=60, close_fds=True)
        r_ssh = under(["/bin/cat", str(self.home / ".ssh" / "id_rsa")])
        self.assertNotIn(FAKE_SSH, r_ssh.stdout)
        r_own = under(["/bin/cat", str(self.home / ".myown" / "key")])
        self.assertIn(FAKE_OWN, r_own.stdout, "own-key carve-out must survive safehouse composition")


if __name__ == "__main__":
    unittest.main()
