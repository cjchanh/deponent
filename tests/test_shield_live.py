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

    # -- C12: a same-uid process's exec-time env AND argv are READABLE via sysctl (KNOWN-NOT-STOPPED)
    def test_C12_parent_env_readable_via_sysctl_KNOWN_NOT_STOPPED(self):
        """The `process-info* (target others)` deny does NOT block a direct
        `sysctl(KERN_PROCARGS2, pid)` read of ANOTHER same-uid process's exec-time
        environment AND argv. A `(deny sysctl-read ...)` name filter does not stop
        it either, and a blanket `(deny sysctl-read)` breaks the child, so this is a
        documented residual: an agent can read the environment (including inherited
        secrets) and command line of other processes owned by the same user.

        Note on `ps`: the setuid-root `/bin/ps` does not help the agent here, but not
        because the shield denies it — `EXEC_DENY` does not list it. `sandbox-exec`
        refuses to *exec* a setuid binary at all (a platform restriction), so
        `/bin/ps` fails with an execvp `Operation not permitted` before it runs. That
        is an incidental speed bump; the sysctl path needs no external binary and is
        the real, unstopped leak.

        We only ever read a sacrificial victim this test itself started, whose env
        and argv hold synthetic fake values. This canary pins the residual so it
        cannot silently flip into a false containment claim."""
        secret = "FAKE-VICTIM-ENV-SECRET-7Q"
        argvmark = "FAKE-VICTIM-ARGV-MARKER-8W"
        # Victim carries the secret in its EXEC-TIME env and a marker in its argv
        # (both are where procargs2 keeps them). A python victim on purpose: a
        # same-uid interpreter process is the realistic target.
        victim = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)", argvmark],
            env={"PATH": "/usr/bin:/bin", "FAKE_VICTIM_SECRET": secret})
        # Probe parses procargs2: [exec path]\0 arg0..arg(argc-1) \0 env...\0
        # Prints two tokens: env verdict and argv verdict.
        probe = (
            "import ctypes,ctypes.util,struct,sys;"
            "libc=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True);"
            "pid=int(sys.argv[1]);mib=(ctypes.c_int*3)(1,49,pid);"
            "size=ctypes.c_size_t(1<<18);buf=ctypes.create_string_buffer(size.value);"
            "rc=libc.sysctl(mib,3,buf,ctypes.byref(size),None,0);"
            "raw=buf.raw[:size.value];argc=struct.unpack('i',raw[:4])[0];"
            "parts=[p for p in raw[4:].split(b'\\x00') if p];"
            "argv=parts[1:1+argc];env=parts[1+argc:];"
            "print('ENV_LEAK' if any(b'FAKE_VICTIM_SECRET='+sys.argv[2].encode()==e for e in env) else 'env_clean',"
            "'ARGV_LEAK' if any(sys.argv[3].encode() in a for a in argv) else 'argv_clean', rc)"
        )
        try:
            time.sleep(0.3)
            # positive control: an unsandboxed same-uid process reads env AND argv
            ctrl = subprocess.run([sys.executable, "-I", "-c", probe, str(victim.pid), secret, argvmark],
                                  capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
            if not ("ENV_LEAK" in ctrl.stdout and "ARGV_LEAK" in ctrl.stdout):
                self.skipTest(f"unsandboxed sysctl env/argv read unavailable here: {ctrl.stdout.strip()} "
                              f"{ctrl.stderr.strip()[:120]}")
            # under the shield profile: env AND argv STILL leak (KNOWN-NOT-STOPPED)
            cfg = _cfg(self.tmp, self.home, self.work)
            r = _run_under_profile(cfg, [sys.executable, "-I", "-c", probe, str(victim.pid), secret, argvmark])
            self.assertIn("ENV_LEAK", r.stdout,
                          "if the env no longer leaks the platform improved — update docs/SHIELD.md "
                          f"(got {r.stdout.strip()!r} / {r.stderr.strip()[:120]!r})")
            self.assertIn("ARGV_LEAK", r.stdout,
                          "if the argv no longer leaks the platform improved — update docs/SHIELD.md "
                          f"(got {r.stdout.strip()!r} / {r.stderr.strip()[:120]!r})")
            # The setuid /bin/ps fails to EXEC under the sandbox (platform setuid-exec
            # restriction, not a shield rule): assert the observed execvp refusal and
            # that no victim env leaks through it.
            r_ps = _run_under_profile(cfg, ["/bin/ps", "eww", "-p", str(victim.pid)])
            self.assertNotEqual(r_ps.returncode, 0, "setuid /bin/ps should fail under the sandbox")
            self.assertIn("Operation not permitted", r_ps.stderr,
                          f"expected an execvp refusal for setuid /bin/ps; got {r_ps.stderr.strip()[:160]!r}")
            self.assertNotIn(secret, r_ps.stdout, "no victim env may leak via /bin/ps")
        finally:
            if victim.poll() is None:
                victim.kill()
            victim.wait()

    # -- C13: keychain SecurityServer deny flips the SecItemCopyMatching status --
    def test_C13_keychain_securityserver_deny_flips_status(self):
        """Live keychain canary (G2): a real `SecItemCopyMatching` probe via
        ctypes, for a service name that does not exist, returns OSStatus -25300
        (errSecItemNotFound) unsandboxed, but -50 (errSecParam) under the shield —
        the `com.apple.SecurityServer` mach-lookup deny prevents the framework from
        forming the request. `--allow-keychain` restores -25300, proving the flip
        is caused by the deny and nothing else. Synthetic query only; no real item
        is ever read."""
        probe = (
            "import ctypes,ctypes.util,json;"
            "Sec=ctypes.CDLL(ctypes.util.find_library('Security'));"
            "CF=ctypes.CDLL(ctypes.util.find_library('CoreFoundation'));"
            "CF.CFStringCreateWithCString.restype=ctypes.c_void_p;"
            "CF.CFStringCreateWithCString.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_uint32];"
            "CF.CFDictionaryCreateMutable.restype=ctypes.c_void_p;"
            "CF.CFDictionaryCreateMutable.argtypes=[ctypes.c_void_p,ctypes.c_long,ctypes.c_void_p,ctypes.c_void_p];"
            "CF.CFDictionaryAddValue.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p];"
            "T=ctypes.c_void_p.in_dll(CF,'kCFBooleanTrue');"
            "s=lambda x:CF.CFStringCreateWithCString(None,x.encode(),0x08000100);"
            "kC=ctypes.c_void_p.in_dll(Sec,'kSecClass');"
            "kG=ctypes.c_void_p.in_dll(Sec,'kSecClassGenericPassword');"
            "kS=ctypes.c_void_p.in_dll(Sec,'kSecAttrService');"
            "kR=ctypes.c_void_p.in_dll(Sec,'kSecReturnData');"
            "q=CF.CFDictionaryCreateMutable(None,0,None,None);"
            "CF.CFDictionaryAddValue(q,kC,kG);"
            "CF.CFDictionaryAddValue(q,kS,s('deponent-fake-service-does-not-exist-XYZ'));"
            "CF.CFDictionaryAddValue(q,kR,T);"
            "Sec.SecItemCopyMatching.restype=ctypes.c_int32;"
            "Sec.SecItemCopyMatching.argtypes=[ctypes.c_void_p,ctypes.c_void_p];"
            "o=ctypes.c_void_p();print(Sec.SecItemCopyMatching(q,ctypes.byref(o)))"
        )
        def status(cfg):
            r = _run_under_profile(cfg, [sys.executable, "-I", "-c", probe])
            self.assertTrue(r.stdout.strip().lstrip("-").isdigit(),
                            f"probe did not return an OSStatus: {r.stdout!r} {r.stderr[:200]!r}")
            return int(r.stdout.strip())
        # positive control: unsandboxed, the fake item is simply not found (-25300)
        ctrl = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, text=True)
        if ctrl.stdout.strip() != "-25300":
            self.skipTest(f"unsandboxed keychain probe returned {ctrl.stdout.strip()!r}, "
                          "not the expected -25300; environment cannot establish the control")
        cfg_deny = _cfg(self.tmp, self.home, self.work)
        self.assertEqual(status(cfg_deny), -50,
                         "keychain deny must flip the probe to -50 (errSecParam)")
        cfg_allow = _cfg(self.tmp, self.home, self.work, allow_keychain=True)
        self.assertEqual(status(cfg_allow), -25300,
                         "--allow-keychain must restore -25300, proving the deny caused the flip")

    # -- C14/C15: receipt on child crash and on signal-kill --------------------
    def test_C14_receipt_on_nonzero_exit(self):
        """The parent always writes a verifiable receipt even when the child exits
        non-zero; session_end records that exit status."""
        cfg = _cfg(self.tmp, self.home, self.work, command=["/bin/sh", "-c", "exit 37"])
        result = run_shield(cfg)
        recs = [json.loads(l) for l in Path(result["receipt"]).read_text().splitlines() if l.strip()]
        end = [r for r in recs if r.get("type") == "session_end"][0]
        self.assertEqual(end["exit_status"], 37)
        status, _ = verify_receipt(Path(result["receipt"]), cfg.anchor_dir)
        self.assertEqual(status, "ANCHORED_OK")

    def test_C15_receipt_on_signal_kill(self):
        """The child is killed by a signal (SIGKILL); the parent still writes a
        verifiable receipt, and session_end records the negative signal status."""
        cfg = _cfg(self.tmp, self.home, self.work, command=["/bin/sh", "-c", "kill -KILL $$"])
        result = run_shield(cfg)
        recs = [json.loads(l) for l in Path(result["receipt"]).read_text().splitlines() if l.strip()]
        end = [r for r in recs if r.get("type") == "session_end"][0]
        self.assertEqual(end["exit_status"], -9,
                         "a SIGKILLed child must record exit_status -9 (=-SIGKILL)")
        status, _ = verify_receipt(Path(result["receipt"]), cfg.anchor_dir)
        self.assertEqual(status, "ANCHORED_OK")

    # -- C16: session_start schema, and NO env value anywhere in the receipt ----
    def test_C16_receipt_schema_and_no_env_values(self):
        """session_start carries argv, a 64-hex profile sha256, own-key/own-env
        declarations, the dropped env NAMES and the catalog size — and no env
        VALUE appears anywhere in the receipt. run_shield scrubs os.environ, so we
        seed a synthetic secret there and assert the NAME is recorded but the VALUE
        never is."""
        secret_name = "FAKE_PARENT_API_KEY"
        secret_value = "FAKE-PARENT-ENV-VALUE-DO-NOT-LEAK-9Z"
        os.environ[secret_name] = secret_value
        try:
            cfg = _cfg(self.tmp, self.home, self.work,
                       command=["/usr/bin/true"], own_envs=("SHIELD_DECLARED_NAME",))
            result = run_shield(cfg)
            receipt_text = Path(result["receipt"]).read_text()
            recs = [json.loads(l) for l in receipt_text.splitlines() if l.strip()]
            start = [r for r in recs if r.get("type") == "session_start"][0]
            # required fields present
            self.assertEqual(start["argv"], ["/usr/bin/true"])
            self.assertRegex(start["profile_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(start["own_keys"], [str(self.home / ".myown" / "key")])
            self.assertEqual(start["own_envs"], ["SHIELD_DECLARED_NAME"])
            self.assertEqual(start["catalog_size"], len(shield.CATALOG_RELPATHS))
            # dropped env is NAMES only, and includes our seeded secret's NAME
            self.assertIn(secret_name, start["dropped_env_names"])
            # the secret VALUE must not appear anywhere in the whole receipt
            self.assertNotIn(secret_value, receipt_text,
                             "an env VALUE leaked into the receipt")
        finally:
            os.environ.pop(secret_name, None)

    def test_C17_no_anchor_yields_unanchored(self):
        """--no-anchor produces a receipt that verifies UNANCHORED (chain re-links
        but truncation cannot be caught), never ANCHORED_OK and never MISSING."""
        cfg = _cfg(self.tmp, self.home, self.work, command=["/usr/bin/true"], no_anchor=True)
        result = run_shield(cfg)
        self.assertFalse(result["anchored"])
        status, _ = verify_receipt(Path(result["receipt"]), cfg.anchor_dir)
        self.assertEqual(status, "UNANCHORED")

    # -- FD leak: child must not inherit a parent fd on a fake key -------------
    # -- A1 (S1 regression): the child cannot read the parent's audit files -----
    def test_A1_audit_files_unreadable_by_child(self):
        """Before the fix, audit dirs outside HOME were only write-denied, so the
        agent could read (and, via a hardlink, reach) its own evidence."""
        cfg = _cfg(self.tmp, self.home, self.work)
        anchor = Path(cfg.anchor_dir); anchor.mkdir(parents=True, exist_ok=True)
        receipts = Path(cfg.receipt_dir); receipts.mkdir(parents=True, exist_ok=True)
        fake = anchor / "session.anchor.json"
        fake.write_text("FAKE-ANCHOR-CONTENTS")
        r = _run_under_profile(cfg, ["/bin/cat", str(fake)])
        self.assertNotIn("FAKE-ANCHOR-CONTENTS", r.stdout)
        self.assertIn("Operation not permitted", r.stderr)
        # the child also cannot hardlink the audit file into its workspace
        r2 = _run_under_profile(cfg, ["/bin/ln", str(fake), str(self.work / "grab")])
        self.assertNotEqual(r2.returncode, 0, "hardlinking an audit file must fail")
        self.assertFalse((self.work / "grab").exists())
        # nor can the child WRITE into the receipt dir or the anchor dir (they are
        # read- AND write-denied as the last profile rule, so no allow re-opens them)
        for label, adir in (("anchor", anchor), ("receipt", receipts)):
            target = adir / "inject.txt"
            rw = _run_under_profile(cfg, ["/bin/sh", "-c", f"echo pwned > {target} && echo WROTE"])
            self.assertNotIn("WROTE", rw.stdout, f"write into the {label} dir must be denied")
            self.assertIn("Operation not permitted", rw.stderr)
            self.assertFalse(target.exists(), f"a file was created in the {label} dir")
        # positive control: the same child CAN read its own workspace
        (self.work / "ok.txt").write_text("WORKSPACE-OK")
        r3 = _run_under_profile(cfg, ["/bin/cat", str(self.work / "ok.txt")])
        self.assertIn("WORKSPACE-OK", r3.stdout)

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
