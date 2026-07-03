#!/usr/bin/env python3
"""Escape-proof for the Seatbelt jail. Run: python -m pytest -q tests/test_jail.py
Each test actually invokes sandbox-exec; all escape attempts run INSIDE the jail.
Skipped automatically off-macOS (no sandbox-exec)."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from deponent.jail import jail_available, jail_command, run_jailed as sb_run_jailed


def run_jailed(cmd: str, work: Path) -> subprocess.CompletedProcess:
    wrapped = jail_command(cmd, work)
    return subprocess.run(wrapped, shell=True, cwd=work, capture_output=True, text=True, timeout=60)


@unittest.skipUnless(jail_available(), "sandbox-exec not present (not macOS)")
class TestJail(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="jailtest-"))
        # a canary genuinely OUTSIDE the sandbox subpath (/private/tmp is not allowed)
        self.canary = Path("/private/tmp") / f"jail_canary_{os.getpid()}.txt"
        if self.canary.exists():
            self.canary.unlink()

    # ---- positive: legitimate work still runs ----
    def test_python_runs(self):
        r = run_jailed("python3 -c \"print('PY_OK')\"", self.work)
        self.assertIn("PY_OK", r.stdout)

    def test_write_inside_ok(self):
        r = run_jailed("python3 -c \"open('inside.txt','w').write('x'); print('IN_OK')\"", self.work)
        self.assertIn("IN_OK", r.stdout)
        self.assertTrue((self.work / "inside.txt").exists())

    def test_pytest_runs(self):
        (self.work / "t_x.py").write_text("def test_a():\n    assert 1+1==2\n")
        r = run_jailed("python3 -m pytest -q t_x.py", self.work)
        self.assertIn("1 passed", r.stdout + r.stderr)

    # ---- negative: escapes are blocked ----
    def test_network_blocked(self):
        r = run_jailed("python3 -c \"import urllib.request as u; u.urlopen('http://captive.apple.com',timeout=5); print('NET_OK')\"", self.work)
        self.assertNotIn("NET_OK", r.stdout)

    def test_socket_connect_blocked(self):
        r = run_jailed("python3 -c \"import socket; socket.create_connection(('1.1.1.1',80),timeout=5); print('SOCK_OK')\"", self.work)
        self.assertNotIn("SOCK_OK", r.stdout)

    def test_write_outside_home_blocked(self):
        target = str(Path.home() / "JAIL_ESCAPE_HOME.txt")
        if os.path.exists(target):
            os.unlink(target)
        r = run_jailed(f"python3 -c \"open('{target}','w').write('x'); print('OUT_OK')\"", self.work)
        self.assertNotIn("OUT_OK", r.stdout)
        self.assertFalse(os.path.exists(target), "wrote outside sandbox to HOME!")

    def test_write_outside_tmp_blocked(self):
        # /private/tmp must NOT be writable (only the specific sandbox subpath is)
        r = run_jailed(f"python3 -c \"open('{self.canary}','w').write('x'); print('TMP_OK')\"", self.work)
        self.assertNotIn("TMP_OK", r.stdout)
        self.assertFalse(self.canary.exists(), "wrote outside sandbox to /private/tmp!")

    def test_child_process_also_jailed(self):
        # a child spawned by the jailed process must inherit the sandbox
        target = str(Path.home() / "JAIL_ESCAPE_CHILD.txt")
        if os.path.exists(target):
            os.unlink(target)
        r = run_jailed(f"python3 -c \"import subprocess; subprocess.run(['/bin/sh','-c','echo x > {target}']); print('done')\"", self.work)
        self.assertFalse(os.path.exists(target), "child process escaped the sandbox!")


@unittest.skipUnless(jail_available(), "sandbox-exec not present (not macOS)")
class TestMemoryWatchdog(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="memtest-"))

    def test_pytest_survives_watchdog(self):
        (self.work / "t_x.py").write_text("def test_a():\n    assert 1+1==2\n")
        r = sb_run_jailed("python3 -m pytest -q t_x.py", self.work, mem_cap_mb=2048, wall_s=60)
        self.assertEqual(r["killed"], "")
        self.assertIn("1 passed", r["output"])

    def test_memory_bomb_killed(self):
        # grow ~80MB every 40ms; a 512MB cap must trip the RSS watchdog before BOMB_DONE
        (self.work / "bomb.py").write_text(
            "import time\nx=[]\n"
            "for i in range(400):\n    x.append(bytearray(80*1024*1024))\n    time.sleep(0.04)\n"
            "print('BOMB_DONE')\n")
        r = sb_run_jailed("python3 bomb.py", self.work, mem_cap_mb=512, wall_s=30)
        self.assertEqual(r["killed"], "memory>512MB")
        self.assertNotIn("BOMB_DONE", r["output"])

    def test_wallclock_killed(self):
        r = sb_run_jailed("python3 -c \"import time; time.sleep(40); print('SLEPT')\"",
                          self.work, mem_cap_mb=2048, wall_s=3)
        self.assertEqual(r["killed"], "wallclock>3s")
        self.assertNotIn("SLEPT", r["output"])

    def test_run_jailed_still_confines_writes(self):
        target = str(Path.home() / "JAIL_RUNJAILED_ESCAPE.txt")
        if os.path.exists(target):
            os.unlink(target)
        sb_run_jailed(f"python3 -c \"open('{target}','w').write('x')\"", self.work)
        self.assertFalse(os.path.exists(target), "run_jailed failed to confine writes!")


class TestFailClosed(unittest.TestCase):
    @unittest.skipUnless(jail_available(), "sandbox-exec not present (not macOS)")
    def test_jail_command_contains_sandbox_exec(self):
        from deponent.jail import SANDBOX_EXEC
        work = Path(tempfile.mkdtemp())
        wrapped = jail_command("ls", work)
        self.assertIn(SANDBOX_EXEC, wrapped)
        self.assertIn("ulimit", wrapped)

    def test_run_jailed_fails_closed_when_unavailable(self):
        # Simulate "no jail" by pointing the check at a missing binary.
        import deponent.jail as J
        original = J.SANDBOX_EXEC
        try:
            J.SANDBOX_EXEC = "/nonexistent/sandbox-exec"
            r = J.run_jailed("ls", Path(tempfile.mkdtemp()))
            self.assertEqual(r["killed"], "no-jail")
            self.assertIsNone(r["returncode"])
        finally:
            J.SANDBOX_EXEC = original


if __name__ == "__main__":
    unittest.main()
