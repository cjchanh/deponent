#!/usr/bin/env python3
"""Cross-platform jail: backend dispatch + fail-closed (verifiable everywhere) and
the Docker confinement escape-proofs (auto-run iff a Docker daemon is present,
auto-skipped otherwise). Until the Docker block runs GREEN on your host, Docker
confinement is a DRAFT claim — these tests are how it earns the claim.

Run:  python3 -m pytest -q tests/test_jail_backends.py
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import deponent.jail as J
from deponent.jail import DockerBackend, SeatbeltBackend, run_jailed, select_backend


class TestDispatchFailClosed(unittest.TestCase):
    """The security-critical contract: pick a real confiner, or refuse. No bare exec."""

    def test_some_backend_or_none(self):
        b = select_backend()
        self.assertTrue(b is None or hasattr(b, "run"))

    @unittest.skipUnless(sys.platform == "darwin", "macOS dispatch policy")
    def test_macos_prefers_seatbelt(self):
        b = select_backend()
        self.assertIsNotNone(b)
        self.assertEqual(b.name, "seatbelt")  # never silently substitute Docker for the native primitive

    @unittest.skipUnless(sys.platform == "darwin", "needs the Seatbelt path present")
    def test_fail_closed_when_native_sandbox_missing(self):
        # Disable Seatbelt; macOS policy does NOT fall back to Docker, so there is
        # no confiner -> run_jailed must refuse, never run un-jailed.
        original = J.SANDBOX_EXEC
        try:
            J.SANDBOX_EXEC = "/nonexistent/sandbox-exec"
            self.assertFalse(J.jail_available())
            r = run_jailed("echo SHOULD_NOT_RUN", Path(tempfile.mkdtemp()))
            self.assertEqual(r["killed"], "no-jail")
            self.assertIsNone(r["returncode"])
            self.assertNotIn("SHOULD_NOT_RUN", r["output"])
        finally:
            J.SANDBOX_EXEC = original

    def test_explicit_unavailable_backend_is_refused(self):
        # If the only backend reports unavailable, dispatch must yield no-jail, not run.
        class _Dead:
            name = "dead"
            def available(self):
                return False
            def run(self, *a, **k):
                raise AssertionError("must never be called when unavailable")
        original = J._candidate_backends
        try:
            J._candidate_backends = lambda: [_Dead()]
            self.assertFalse(J.jail_available())
            r = run_jailed("echo NOPE", Path(tempfile.mkdtemp()))
            self.assertEqual(r["killed"], "no-jail")
        finally:
            J._candidate_backends = original


# The Docker daemon presence gate. With it down (default on this build host) the
# whole class is skipped and Docker stays an explicitly-unverified DRAFT.
_DOCKER = DockerBackend()


@unittest.skipUnless(os.environ.get("DEPONENT_TEST_DOCKER") == "1", "Docker backend is DRAFT; set DEPONENT_TEST_DOCKER=1 to run")
class TestDockerBackend(unittest.TestCase):
    """Escape-proofs against the live Docker backend. Same contract as Seatbelt:
    network denied, writes confined, resources bounded, positive work still runs."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="dockerjail-"))
        self.canary = Path("/private/tmp") / f"docker_canary_{os.getpid()}.txt"
        if self.canary.exists():
            self.canary.unlink()

    def test_positive_python_runs(self):
        r = _DOCKER.run("python3 -c \"print('PY_OK')\"", self.work, wall_s=60)
        self.assertIn("PY_OK", r["output"])

    def test_write_inside_ok(self):
        r = _DOCKER.run("python3 -c \"open('inside.txt','w').write('x'); print('IN_OK')\"",
                        self.work, wall_s=60)
        self.assertIn("IN_OK", r["output"])

    def test_network_blocked(self):
        r = _DOCKER.run(
            "python3 -c \"import urllib.request as u; u.urlopen('http://1.1.1.1',timeout=5); print('NET_OK')\"",
            self.work, wall_s=60)
        self.assertNotIn("NET_OK", r["output"])

    def test_write_outside_blocked(self):
        # The host canary path is not bind-mounted; a write there cannot escape.
        r = _DOCKER.run(
            f"python3 -c \"open('{self.canary}','w').write('x'); print('OUT_OK')\"",
            self.work, wall_s=60)
        self.assertNotIn("OUT_OK", r["output"])
        self.assertFalse(self.canary.exists(), "Docker jail let a write escape to the host!")

    def test_memory_cap_contained(self):
        # Outcome-based (Docker OOM-kills natively; the signal differs from Seatbelt's
        # watchdog, but the protected outcome is identical: the bomb does not complete).
        (self.work / "bomb.py").write_text(
            "x=[]\nfor i in range(200):\n    x.append(bytearray(64*1024*1024))\n"
            "print('BOMB_DONE')\n")
        r = _DOCKER.run("python3 bomb.py", self.work, mem_cap_mb=256, wall_s=60)
        self.assertNotIn("BOMB_DONE", r["output"])

    def test_wallclock_killed(self):
        r = _DOCKER.run("python3 -c \"import time; time.sleep(40); print('SLEPT')\"",
                        self.work, wall_s=4)
        self.assertEqual(r["killed"], "wallclock>4s")
        self.assertNotIn("SLEPT", r["output"])


if __name__ == "__main__":
    unittest.main()
