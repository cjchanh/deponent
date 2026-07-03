#!/usr/bin/env python3
"""
jail.py — cross-platform OS confinement for agent-executed commands (the code surface).

The Gate (gate.py) governs the SHELL + PATH surface — which programs, which paths.
The jail closes the remaining gap: arbitrary code *inside* an allowed command (e.g.
`python -c ...`, or whatever `pytest` imports). Confinement is provided by a
platform **Backend**, selected fail-closed:

  - macOS  -> SeatbeltBackend (`sandbox-exec`): native, no daemon (live-verified).
  - Linux  -> DockerBackend (bwrap/nsjail native backend is a follow-up; draft).
  - other  -> DockerBackend (draft, not yet live-verified).

Every backend enforces the SAME contract: network denied (no exfil), file-writes
confined to the sandbox dir (no tamper/persistence), resources bounded (memory +
wall-clock), reads otherwise inert. And the dispatch is FAIL-CLOSED: if no backend
can confine on this host, `run_jailed` REFUSES (`killed="no-jail"`) rather than run
the command un-jailed. `jail_available()` is the check; never execute on a False.

VERIFICATION STATUS — claims track what has actually RUN (self-report is not evidence):
  - Seatbelt: live-verified by tests/test_jail.py — escape-proofs against the real
    `sandbox-exec` (network BLOCK, write-out BLOCK, child-jailed, mem-bomb killed,
    wall-clock killed, positive pytest works).
  - Docker:   IMPLEMENTED, NOT YET LIVE-VERIFIED. tests/test_jail_backends.py runs
    the Docker escape-proofs automatically *iff* a daemon is present, and skips
    otherwise. Until those run green on your machine, Docker confinement is a
    DRAFT claim — do not represent it as proven.

No key material anywhere in this module.
"""
from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# ---- macOS Seatbelt profile + rlimits (unchanged from v0.1; live-verified) ----
_PROFILE = '''(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write*
  (subpath "{work}")
  (literal "/dev/null") (literal "/dev/zero")
  (literal "/dev/stdout") (literal "/dev/stderr") (literal "/dev/dtracehelper"))
(allow file-write-data (regex #"^/dev/tty"))
'''

# CPU 60s, max file 256MB (512Ki blocks). No nproc cap (per-UID on macOS — unusable);
# fork-bombs are bounded by the caller's wall-clock timeout + CPU-time cap.
_ULIMITS = "ulimit -t 60; ulimit -f 524288;"


# ---------------------------------------------------------------------------
# Shared helpers (the RSS watchdog is used where the OS lacks a native mem cap)
# ---------------------------------------------------------------------------
def _pg_rss_kb(pgid: int) -> int:
    """Total resident memory (KB) of every process in the group."""
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-g", str(pgid)],
                             capture_output=True, text=True, timeout=5).stdout
        return sum(int(x) for x in out.split() if x.strip().isdigit())
    except Exception:
        return 0


def _killpg(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


# ---------------------------------------------------------------------------
# Seatbelt (macOS) — behaviour byte-identical to v0.1
# ---------------------------------------------------------------------------
def write_profile(workdir: Path) -> Path:
    work = str(Path(workdir).resolve())
    prof = Path(workdir).resolve() / ".jail.sb"
    prof.write_text(_PROFILE.format(work=work))
    return prof


def jail_command(cmd: str, workdir: Path) -> str:
    """Return a shell string that runs `cmd` network-denied, write-confined to
    `workdir`, and resource-bounded via Seatbelt. Run with shell=True, cwd=workdir.

    Fail-closed contract: caller MUST check jail_available() first; this raises
    if the Seatbelt binary is missing rather than degrade to an un-jailed run.
    """
    if not (os.path.exists(SANDBOX_EXEC) and os.access(SANDBOX_EXEC, os.X_OK)):
        raise RuntimeError("sandbox-exec unavailable — refusing to build an un-jailed command")
    prof = write_profile(workdir)
    # Confine temp files to the sandbox too (so /var/folders need not be allowed).
    tmp = Path(workdir).resolve() / ".tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    return (f"export TMPDIR={shlex.quote(str(tmp))}; {_ULIMITS} "
            f"exec {SANDBOX_EXEC} -f {shlex.quote(str(prof))} /bin/sh -c {shlex.quote(cmd)}")


def _seatbelt_run(cmd: str, workdir: Path, *, env: dict | None,
                  mem_cap_mb: int, wall_s: int, poll_s: float) -> dict:
    """Run `cmd` inside the Seatbelt jail with an RSS-watchdog mem cap + wall cap.
    (This is v0.1's run_jailed body, unchanged.)"""
    wrapped = jail_command(cmd, workdir)
    logf = Path(workdir).resolve() / ".run_out"
    cap_kb = mem_cap_mb * 1024
    killed = ""
    # Output to a file (not a pipe) so a chatty child can't deadlock the watchdog
    # by filling the pipe buffer while we poll.
    with open(logf, "w") as fh:
        p = subprocess.Popen(wrapped, shell=True, cwd=str(workdir), env=env,
                             stdout=fh, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            pgid = os.getpgid(p.pid)
        except ProcessLookupError:
            pgid = p.pid
        t0 = time.monotonic()
        while p.poll() is None:
            if _pg_rss_kb(pgid) > cap_kb:
                killed = f"memory>{mem_cap_mb}MB"; _killpg(pgid); break
            if time.monotonic() - t0 > wall_s:
                killed = f"wallclock>{wall_s}s"; _killpg(pgid); break
            time.sleep(poll_s)
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _killpg(pgid)
            p.wait(timeout=5)
    try:
        out = logf.read_text(errors="replace")
    except Exception:
        out = ""
    if killed:
        out = f"[KILLED: {killed}]\n" + out
    return {"returncode": p.returncode, "output": out[-2800:], "killed": killed}


class SeatbeltBackend:
    """macOS `sandbox-exec` confinement. Native, no daemon. Live-verified."""
    name = "seatbelt"
    platform = "darwin"

    def available(self) -> bool:
        return os.path.exists(SANDBOX_EXEC) and os.access(SANDBOX_EXEC, os.X_OK)

    def run(self, cmd: str, workdir: Path, *, env: dict | None = None,
            mem_cap_mb: int = 2048, wall_s: int = 90, poll_s: float = 0.25) -> dict:
        return _seatbelt_run(cmd, workdir, env=env, mem_cap_mb=mem_cap_mb,
                             wall_s=wall_s, poll_s=poll_s)


# ---------------------------------------------------------------------------
# Docker (cross-platform) — DRAFT: implemented, not yet live-verified.
# Confinement contract mapped to container primitives:
#   --network none        -> no exfil/callback/download (native namespace isolation)
#   --read-only + tmpfs   -> rootfs immutable; only the sandbox bind + /tmp writable
#   -v WORK:WORK:rw        -> writes confined to the sandbox dir (and nowhere else)
#   --memory / --pids/cpus -> resource caps enforced by the kernel cgroup (no watchdog
#                             needed; an over-cap process is OOM-killed by the kernel)
# wall-clock is enforced by the client timeout + `docker kill` of the named container.
# ---------------------------------------------------------------------------
class DockerBackend:
    """Container confinement. Cross-platform (Linux/macOS/Windows w/ a daemon).

    DRAFT — must pass tests/test_jail_backends.py::TestDockerBackend against a live
    daemon before its confinement is claimed. Image must contain the tools the
    command needs (default: a python image); override via DEPONENT_JAIL_IMAGE.
    """
    name = "docker"
    platform = "any"

    def __init__(self, image: str | None = None):
        self.image = image or os.environ.get("DEPONENT_JAIL_IMAGE", "python:3.12-slim")

    def available(self) -> bool:
        # Conservative: the CLI must exist AND the daemon must answer. A present CLI
        # with a dead daemon is NOT available (we will not claim confinement we
        # cannot exercise).
        if not shutil.which("docker"):
            return False
        try:
            return subprocess.run(["docker", "info"], capture_output=True,
                                  timeout=8).returncode == 0
        except Exception:
            return False

    def run(self, cmd: str, workdir: Path, *, env: dict | None = None,
            mem_cap_mb: int = 2048, wall_s: int = 90, poll_s: float = 0.25) -> dict:
        work = str(Path(workdir).resolve())
        name = f"deponent-jail-{os.getpid()}-{int(time.monotonic() * 1000) % 1_000_000}"
        # Pass env as -e KEY (value from the caller env), never the host environment.
        env_flags: list[str] = []
        for k, v in (env or {}).items():
            env_flags += ["-e", f"{k}={v}"]
        argv = [
            "docker", "run", "--rm", "--name", name,
            "--network", "none",
            "--memory", f"{mem_cap_mb}m", "--memory-swap", f"{mem_cap_mb}m",
            "--pids-limit", "512", "--cpus", "2",
            "--read-only", "--tmpfs", "/tmp:rw,exec,size=256m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{work}:{work}:rw", "--workdir", work,
            *env_flags, self.image, "sh", "-c", cmd,
        ]
        killed = ""
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=wall_s)
            out = (p.stdout + p.stderr)[-2800:]
            rc = p.returncode
        except subprocess.TimeoutExpired as e:
            killed = f"wallclock>{wall_s}s"
            subprocess.run(["docker", "kill", name], capture_output=True)
            raw = e.output or ""
            if isinstance(raw, bytes):
                raw = raw.decode(errors="replace")
            out = f"[KILLED: {killed}]\n{raw[-2800:]}"
            rc = None
        return {"returncode": rc, "output": out, "killed": killed}


# ---------------------------------------------------------------------------
# Fail-closed backend dispatch
# ---------------------------------------------------------------------------
def _candidate_backends() -> list:
    """Platform policy: prefer the native OS sandbox; Docker is the portable
    fallback. macOS uses Seatbelt ONLY (Docker is not silently substituted for the
    native primitive). A Linux-native (bwrap/nsjail) backend is a planned follow-up."""
    if sys.platform == "darwin":
        return [SeatbeltBackend()]
    if sys.platform.startswith("linux"):
        return [DockerBackend()]  # + LinuxBwrapBackend() once live-verified on Linux
    return [DockerBackend()]


def select_backend():
    """Return the first available confinement backend for this host, or None."""
    for b in _candidate_backends():
        try:
            if b.available():
                return b
        except Exception:
            continue
    return None


def jail_available() -> bool:
    """True iff SOME backend can confine on this host (else callers must refuse)."""
    return select_backend() is not None


def run_jailed(cmd: str, workdir: Path, *, backend=None, env: dict | None = None,
               mem_cap_mb: int = 2048, wall_s: int = 90, poll_s: float = 0.25) -> dict:
    """Run `cmd` confined by the best available backend, fail-closed.

    Returns {"returncode": int|None, "output": str, "killed": str}. `killed` is ""
    on clean exit, else a reason ("memory>NMB" / "wallclock>Ns" / "no-jail").
    Fail-closed: if no backend is available, REFUSES (`killed="no-jail"`) — never
    runs `cmd` un-confined.
    """
    b = backend or select_backend()
    if b is None:
        return {"returncode": None,
                "output": "ERROR: no confinement backend available on this host (fail-closed)",
                "killed": "no-jail"}
    return b.run(cmd, workdir, env=env, mem_cap_mb=mem_cap_mb, wall_s=wall_s, poll_s=poll_s)


__all__ = [
    "jail_available", "jail_command", "write_profile", "run_jailed",
    "select_backend", "SeatbeltBackend", "DockerBackend", "SANDBOX_EXEC",
]
