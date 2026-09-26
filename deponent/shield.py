#!/usr/bin/env python3
"""
shield.py — the credential shield: run an agent as a whole process tree under a
macOS Seatbelt profile that reads deny-by-default inside HOME, with the PARENT
(outside the sandbox) writing a hash-chained, externally anchored, recomputable
receipt of the run: argv, profile sha256, own-key/own-env declarations, dropped
env NAMES only, catalog size and exit status. Denied reads are captured only
where the OS logs them (usually UNAVAILABLE on macOS 27).

This is a DEFENSE-IN-DEPTH proof layer, not a credential-theft prevention system.
Read docs/SHIELD.md for the honest "what it stops / what it does not stop" list:
every protection claim there names the test behind it; three known limits are
pinned by KNOWN-NOT-STOPPED canaries and the rest are documented without one.

Boundary with the rest of the kernel:
  - gate.py governs the SHELL + PATH surface (which programs, which paths).
  - jail.py confines WRITES + network for an allowed command.
  - shield.py closes the READ surface: an untrusted agent that is ALLOWED to run
    (it needs its own key + the network for its model) must still be unable to
    read OTHER credentials on the host. Read-deny is the control, because once a
    secret is readable and the agent has network, it is exfiltrable.

Design facts settled empirically on macOS 27 (see docs/SHIELD.md §Empirical notes):
  - SBPL is LAST-MATCH-WINS. The rule order below relies on it.
  - Symlinks are resolved to their target before the profile is applied.
  - A PRE-EXISTING workspace hardlink to a protected file is READABLE (Seatbelt
    keys on the path); creating a new hardlink to a denied file from inside is
    blocked. -> preflight refuses st_nlink>1 in the workspace.
  - sandbox-exec custom-profile denies are NOT reliably emitted to the unified
    log, so reach capture self-reports UNAVAILABLE when its positive control is
    not observed. It never claims "none".

No key material is generated, read, hashed, or transmitted here. The shield
handles PATHS and env-var NAMES only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .jail import SANDBOX_EXEC

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
SCHEMA = "deponent-shield/v1"
GENESIS = "GENESIS"

#: Environment names the child is allowed to keep. Everything else is dropped.
#: LC_* is matched by prefix in addition to this exact set.
ENV_ALLOWLIST = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "TMPDIR", "PWD",
})

#: Default anchor + receipt roots (outside any workspace, so the profile denies
#: the agent writing them).
DEFAULT_ANCHOR_DIR = Path("~/.deponent/shield-anchors").expanduser()
DEFAULT_RECEIPT_DIR = Path("~/.deponent/shield-receipts").expanduser()

#: The always-deny credential catalog, as HOME-relative paths. Under the
#: deny-by-default HOME read policy these are redundant for plain reads, but they
#: are emitted as an ALWAYS-DENY layer that --allow-read / --state-dir can NOT
#: override (only an explicit --own-key can carve one out), and they are the
#: sentinel set the reach capture looks for. Kept sorted for determinism.
CATALOG_RELPATHS: tuple[str, ...] = tuple(sorted({
    # cloud + service credentials
    ".ssh", ".aws", ".config/gcloud", ".azure", ".kube", ".docker/config.json",
    ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".config/gh",
    # other coding agents' auth / session stores
    ".codex", ".claude", ".claude.json", ".config/claude",
    ".config/opencode", ".local/share/opencode", ".config/openrouter",
    # keychains + browser cookie/credential stores
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/Chromium",
    "Library/Containers/com.apple.Safari",
    "Library/Safari",
}))

#: Side-channel mach services / operations denied by default (empirically
#: verified names on macOS 27). Keychain is opt-in re-enabled with --allow-keychain.
KEYCHAIN_SERVICE = "com.apple.SecurityServer"
LAUNCHSERVICES_SERVICE = "com.apple.coreservices.launchservicesd"

#: Binaries whose exec is denied (harmless in a coding sandbox; they are the
#: usual "leave the sandbox" levers). Paths verified on macOS 27.
EXEC_DENY = (
    "/usr/bin/osascript", "/usr/bin/open", "/bin/launchctl", "/usr/bin/security",
)


class ShieldError(Exception):
    """A fail-closed refusal. The child never starts."""


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
@dataclass
class ShieldConfig:
    command: list[str]
    workspace: Path
    home: Path
    own_keys: tuple[Path, ...] = ()
    own_envs: tuple[str, ...] = ()
    state_dirs: tuple[Path, ...] = ()
    allow_reads: tuple[Path, ...] = ()
    no_network: bool = False
    no_anchor: bool = False
    allow_missing_own_key: bool = False
    allow_hardlinks: bool = False
    allow_keychain: bool = False
    receipt_dir: Path = DEFAULT_RECEIPT_DIR
    anchor_dir: Path = DEFAULT_ANCHOR_DIR
    with_safehouse: bool = False
    safehouse_bin: str | None = None
    print_profile: bool = False
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


# --------------------------------------------------------------------------- #
# Path validation (SBPL injection guard) — fail closed
# --------------------------------------------------------------------------- #
def validate_sbpl_path(raw: str | os.PathLike) -> str:
    """Resolve to an absolute path string safe to embed in an SBPL double-quoted
    literal. Rejects anything containing a double quote, a backslash, or a control
    character (incl. newline/tab). Fail-closed: raises ShieldError.

    An attacker who could smuggle `")` or a newline into a path could inject SBPL
    rules into the generated profile; this closes that vector (audit vector (h)).
    """
    s = os.fspath(raw)
    if not s:
        raise ShieldError("empty path is not allowed in a shield profile")
    for ch in s:
        if ch == '"' or ch == "\\" or ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ShieldError(
                f"unsafe character {ch!r} in path {s!r}: refusing to build profile "
                "(SBPL injection guard)"
            )
    resolved = str(Path(s).expanduser().resolve())
    # resolve() cannot introduce a quote/backslash, but re-check to be certain the
    # string we actually emit is clean.
    for ch in resolved:
        if ch == '"' or ch == "\\" or ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ShieldError(f"resolved path {resolved!r} is unsafe for SBPL")
    return resolved


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
def resolve_catalog(home: Path) -> tuple[str, ...]:
    """The always-deny catalog as absolute, validated, sorted path strings.
    Deterministic for a given HOME."""
    home_abs = Path(home).expanduser().resolve()
    out: list[str] = []
    for rel in CATALOG_RELPATHS:
        out.append(str((home_abs / rel)))  # not resolve() — the target may not exist
    return tuple(sorted(out))


# --------------------------------------------------------------------------- #
# Profile builder — deterministic, last-match-wins
# --------------------------------------------------------------------------- #
def build_profile(cfg: ShieldConfig) -> str:
    """Return the SBPL profile text. Deterministic: identical inputs -> identical
    bytes. Rule order is significant (SBPL is last-match-wins):

      1. (allow default)                         base
      2. (deny network*)                         if --no-network
      3. side-channel denies                     keychain / appleevents / LS / process-info
      4. exec denies                             osascript/open/launchctl/security
      5. (deny file-read* (subpath HOME))        deny-by-default inside HOME
      6. (allow file-read* workspace/state/allow-read)   re-open the declared surface
      7. (deny file-read* CATALOG)               always-deny (6 cannot override 7)
      8. (allow file-read* OWN-KEY)              carve-outs, LAST -> override 5 and 7
      9. write policy                            deny-by-default outside workspace/state/tmp/dev
     10. explicit deny-write of receipt+anchor dirs
    """
    home = validate_sbpl_path(cfg.home)
    workspace = validate_sbpl_path(cfg.workspace)
    child_tmp = validate_sbpl_path(Path(cfg.workspace) / ".shield-tmp")
    state_dirs = [validate_sbpl_path(p) for p in cfg.state_dirs]
    allow_reads = [validate_sbpl_path(p) for p in cfg.allow_reads]
    own_keys = [validate_sbpl_path(p) for p in cfg.own_keys]
    catalog = [validate_sbpl_path_lenient(p) for p in resolve_catalog(cfg.home)]
    receipt_dir = validate_sbpl_path(cfg.receipt_dir)
    anchor_dir = validate_sbpl_path(cfg.anchor_dir)

    L: list[str] = []
    L.append("(version 1)")
    L.append(";; deponent credential shield — generated, deny-by-default reads inside HOME")
    L.append(f";; schema {SCHEMA}")
    L.append("(allow default)")

    # 2. network
    if cfg.no_network:
        L.append("(deny network*)")

    # 3. side channels (audit vectors c, d, e-adjacent, f)
    if not cfg.allow_keychain:
        L.append(f'(deny mach-lookup (global-name "{KEYCHAIN_SERVICE}"))')
    L.append("(deny appleevent-send)")
    L.append(f'(deny mach-lookup (global-name "{LAUNCHSERVICES_SERVICE}"))')
    L.append("(deny process-info* (target others))")

    # 4. exec denies (belt-and-suspenders alongside the mach-lookup/appleevent
    #    denies, because in-process APIs bypass exec and exec bypasses those)
    for binpath in EXEC_DENY:
        L.append(f'(deny process-exec* (literal "{binpath}"))')

    # 5. deny-by-default reads inside HOME
    L.append(f'(deny file-read* (subpath "{home}"))')

    # 6. re-open the declared read surface (overrides the HOME deny)
    L.append(f'(allow file-read* (subpath "{workspace}"))')
    for d in state_dirs:
        L.append(f'(allow file-read* (subpath "{d}"))')
    for d in allow_reads:
        L.append(f'(allow file-read* (subpath "{d}"))')

    # 7. always-deny catalog (placed AFTER the allow surface -> --allow-read /
    #    --state-dir can NOT re-open a catalog path; only --own-key can, below)
    for c in catalog:
        L.append(f'(deny file-read* (subpath "{c}"))')

    # 8. own-key carve-outs — LAST, so they override both the HOME deny and the
    #    catalog deny (an agent whose key lives under ~/.ssh can still read it)
    for k in own_keys:
        L.append(f'(allow file-read* (literal "{k}"))')

    # 9. write policy: deny-by-default, allow workspace/state/child-tmp/dev
    L.append("(deny file-write*)")
    L.append(f'(allow file-write* (subpath "{workspace}"))')
    for d in state_dirs:
        L.append(f'(allow file-write* (subpath "{d}"))')
    L.append(f'(allow file-write* (subpath "{child_tmp}"))')
    L.append(
        '(allow file-write*'
        ' (literal "/dev/null") (literal "/dev/zero")'
        ' (literal "/dev/stdout") (literal "/dev/stderr") (literal "/dev/dtracehelper"))'
    )
    L.append('(allow file-write-data (regex #"^/dev/tty"))')

    # 10. the parent's audit surfaces: deny READ and write, LAST, so no allow
    #     surface above (workspace/state/allow-read/own-key) can re-open them.
    #     Read-deny also blocks creating a hardlink to them from inside.
    L.extend(_audit_surface_denies(receipt_dir, anchor_dir))

    return "\n".join(L) + "\n"


def _audit_surface_denies(receipt_dir: str, anchor_dir: str) -> list[str]:
    return [
        f'(deny file-read* file-write* (subpath "{receipt_dir}"))',
        f'(deny file-read* file-write* (subpath "{anchor_dir}"))',
    ]


def validate_sbpl_path_lenient(raw: str | os.PathLike) -> str:
    """Like validate_sbpl_path but does NOT resolve (catalog targets may not
    exist). Still rejects injection characters. Fail-closed."""
    s = os.fspath(raw)
    for ch in s:
        if ch == '"' or ch == "\\" or ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ShieldError(f"unsafe character {ch!r} in catalog path {s!r}")
    return s


def profile_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Environment scrubbing
# --------------------------------------------------------------------------- #
def scrub_env(cfg: ShieldConfig, parent_env: dict[str, str] | None = None
              ) -> tuple[dict[str, str], list[str]]:
    """Return (child_env, dropped_names). The child env is an allowlist
    (ENV_ALLOWLIST + LC_* + declared --own-env names). dropped_names is the sorted
    list of names present in the parent but not the child. VALUES are never
    recorded or returned as anything other than the live child env."""
    src = dict(parent_env if parent_env is not None else os.environ)
    keep: dict[str, str] = {}
    for name, val in src.items():
        if name in ENV_ALLOWLIST or name.startswith("LC_") or name in cfg.own_envs:
            keep[name] = val
    # Force HOME/PWD/TMPDIR to the shield-controlled values regardless of parent.
    keep["HOME"] = str(Path(cfg.home).expanduser().resolve())
    keep["PWD"] = str(Path(cfg.workspace).expanduser().resolve())
    keep["TMPDIR"] = str(Path(cfg.workspace).expanduser().resolve() / ".shield-tmp")
    dropped = sorted(set(src) - set(keep))
    return keep, dropped


# --------------------------------------------------------------------------- #
# Parent-written, hash-chained receipt (JSONL)
# --------------------------------------------------------------------------- #
def _chain_hash(prev: str, payload: dict) -> str:
    """Genesis-anchored sha256 over prev + canonical payload. Mirrors ledger.py's
    scheme so the chain is verifiable with the same discipline (any mutated or
    reordered record breaks the re-link)."""
    body = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(f"{prev}\n{body}".encode("utf-8")).hexdigest()


class ReceiptWriter:
    """Append-only hash-chained JSONL, written by the PARENT outside the sandbox."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev = GENESIS
        self.count = 0
        # Truncate/create the file for this session.
        self.path.write_text("", encoding="utf-8")

    def append(self, record: dict) -> dict:
        payload = dict(record)
        entry = dict(payload)
        entry["prev_hash"] = self.prev
        entry["entry_hash"] = _chain_hash(self.prev, payload)
        self.prev = entry["entry_hash"]
        self.count += 1
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def head(self) -> tuple[str, int]:
        return self.prev, self.count


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Reach capture (best-effort, self-reporting UNAVAILABLE)
# --------------------------------------------------------------------------- #
def _log_show_available() -> bool:
    return shutil.which("log") is not None


def _run_denied_sentinel(profile_arg: list[str], sentinel: Path) -> None:
    """Trigger one known-denied read of a shield-owned sentinel under the SAME
    profile. Best-effort; we only care that a deny is attempted (for the log)."""
    try:
        subprocess.run(
            profile_arg + ["/bin/cat", str(sentinel)],
            capture_output=True, text=True, timeout=20, close_fds=True,
        )
    except Exception:
        pass


def _query_log_denies(start_epoch: float, tag: str) -> list[str]:
    """Return unified-log lines that look like sandbox denies mentioning `tag`
    since start_epoch. Empty on any failure (caller decides UNAVAILABLE)."""
    if not _log_show_available():
        return []
    start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_epoch - 2))
    pred = f'eventMessage CONTAINS "deny(" AND eventMessage CONTAINS "{tag}"'
    try:
        r = subprocess.run(
            ["log", "show", "--start", start, "--style", "compact",
             "--info", "--debug", "--predicate", pred],
            capture_output=True, text=True, timeout=60,
        )
    except Exception:
        return []
    if r.returncode != 0:
        return []
    return [ln for ln in r.stdout.splitlines()
            if tag in ln and "deny(" in ln and "'log'" not in ln and "args:" not in ln]


# --------------------------------------------------------------------------- #
# Safehouse compose mode
# --------------------------------------------------------------------------- #
def _resolve_safehouse_bin(cfg: ShieldConfig) -> str:
    cand = cfg.safehouse_bin or shutil.which("safehouse")
    if not cand or not (os.path.exists(cand) and os.access(cand, os.X_OK)):
        raise ShieldError(
            "--with-safehouse given but no runnable 'safehouse' binary "
            "(pass --safehouse-bin PATH or put it on PATH). Refusing; child not started."
        )
    return cand


def _safehouse_version(binpath: str) -> str:
    try:
        r = subprocess.run([binpath, "--version"], capture_output=True, text=True, timeout=20)
        return r.stdout.strip() or r.stderr.strip() or "unknown"
    except Exception:
        return "unknown"


def build_safehouse_overlay(cfg: ShieldConfig) -> str:
    """The overlay Deponent hands to `safehouse --append-profile`. It carries the
    always-deny catalog (minus own-key carve-outs), the side-channel denies, and
    an explicit deny-write of the audit dirs. Own-key allows go LAST so they
    override the catalog denies (safehouse appends only terminal deny-WRITE rules
    after the overlay, which do not touch these read rules)."""
    catalog = [validate_sbpl_path_lenient(p) for p in resolve_catalog(cfg.home)]
    own_keys = [validate_sbpl_path(p) for p in cfg.own_keys]
    receipt_dir = validate_sbpl_path(cfg.receipt_dir)
    anchor_dir = validate_sbpl_path(cfg.anchor_dir)
    L: list[str] = [";; deponent overlay (appended after safehouse grants)"]
    if cfg.no_network:
        L.append("(deny network*)")
    if not cfg.allow_keychain:
        L.append(f'(deny mach-lookup (global-name "{KEYCHAIN_SERVICE}"))')
    L.append("(deny appleevent-send)")
    L.append(f'(deny mach-lookup (global-name "{LAUNCHSERVICES_SERVICE}"))')
    L.append("(deny process-info* (target others))")
    for binpath in EXEC_DENY:
        L.append(f'(deny process-exec* (literal "{binpath}"))')
    for c in catalog:
        L.append(f'(deny file-read* (subpath "{c}"))')
    for k in own_keys:  # after the catalog -> overrides the catalog denies above
        L.append(f'(allow file-read* (literal "{k}"))')
    # audit surfaces LAST: nothing above (incl. an own-key carve-out) re-opens them
    L.extend(_audit_surface_denies(receipt_dir, anchor_dir))
    return "\n".join(L) + "\n"


def _safehouse_policy(cfg: ShieldConfig, binpath: str, overlay_path: Path) -> str:
    """Ask safehouse to assemble the full policy text (policy mode, no command,
    no network). Fail-closed on any error."""
    workspace = str(Path(cfg.workspace).expanduser().resolve())
    argv = [binpath, "--stdout", f"--workdir={workspace}",
            f"--append-profile={overlay_path}"]
    for d in cfg.state_dirs:
        argv.append(f"--add-dirs={Path(d).expanduser().resolve()}")
    for d in cfg.allow_reads:
        argv.append(f"--add-dirs-ro={Path(d).expanduser().resolve()}")
    env = dict(os.environ)
    env["HOME"] = str(Path(cfg.home).expanduser().resolve())
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                           env=env, close_fds=True)
    except Exception as e:
        raise ShieldError(f"safehouse policy generation failed: {e}")
    if r.returncode != 0 or not r.stdout.strip():
        raise ShieldError(
            f"safehouse policy generation returned rc={r.returncode}; refusing. "
            f"stderr: {r.stderr[:200]}"
        )
    return r.stdout


# --------------------------------------------------------------------------- #
# Preflight — fail closed, child never starts on refusal
# --------------------------------------------------------------------------- #
def preflight(cfg: ShieldConfig) -> None:
    if sys.platform != "darwin":
        raise ShieldError("credential shield requires macOS Seatbelt; this host is "
                          f"{sys.platform!r}. Refusing (no unsandboxed fallback).")
    if not (os.path.exists(SANDBOX_EXEC) and os.access(SANDBOX_EXEC, os.X_OK)):
        raise ShieldError(f"{SANDBOX_EXEC} not available; refusing.")
    if not cfg.command:
        raise ShieldError("no command given after `--`; nothing to run.")

    ws = Path(cfg.workspace).expanduser().resolve()
    home = Path(cfg.home).expanduser().resolve()
    if not ws.is_dir():
        raise ShieldError(f"workspace {ws} is not a directory; refusing.")
    # No read-allow surface (workspace, --state-dir, --allow-read) may BE HOME or an
    # ancestor of it: its subpath allow would re-open all of HOME (defeating
    # deny-by-default). Path semantics, not string prefixes — a string check
    # missed "/" (str("/") + "/" == "//" prefixes nothing).
    surfaces = [("workspace", ws)]
    surfaces += [("--state-dir", Path(p).expanduser().resolve()) for p in cfg.state_dirs]
    surfaces += [("--allow-read", Path(p).expanduser().resolve()) for p in cfg.allow_reads]
    for label, surface in surfaces:
        if _reopens(surface, home):
            raise ShieldError(
                f"{label} {surface} is HOME or an ancestor of HOME {home}; its read-allow "
                "would re-open the whole home directory. Refusing."
            )
    # The parent's audit surfaces (receipts, anchors) must not overlap, in either
    # direction, any DECLARED surface the agent can reach: workspace, state dirs,
    # allow-reads, child tmp, own keys. Paths the base profile allows by default are
    # not enumerated here; the final profile rules deny the audit dirs outright.
    audit = [("receipt dir", Path(cfg.receipt_dir).expanduser().resolve()),
             ("anchor dir", Path(cfg.anchor_dir).expanduser().resolve())]
    child_tmp = (ws / ".shield-tmp").resolve()
    own = [("--own-key", Path(k).expanduser().resolve()) for k in cfg.own_keys]
    for a_label, a_path in audit:
        for s_label, s_path in surfaces + [("child tmp", child_tmp)] + own:
            if _overlaps(a_path, s_path):
                raise ShieldError(
                    f"{a_label} {a_path} overlaps {s_label} {s_path}; the agent could "
                    "reach its own evidence. Refusing."
                )

    # Own-key existence (unless explicitly allowed missing).
    for k in cfg.own_keys:
        kp = Path(k).expanduser()
        if not kp.exists() and not cfg.allow_missing_own_key:
            raise ShieldError(
                f"declared --own-key {kp} does not exist; refusing "
                "(pass --allow-missing-own-key to override)."
            )

    # Hardlink preflight: a pre-existing regular file with st_nlink>1 in the
    # workspace can be a hardlink to a protected file and IS readable (empirically
    # confirmed). Refuse unless --allow-hardlinks.
    if not cfg.allow_hardlinks:
        offenders = _hardlink_offenders(ws)
        if offenders:
            raise ShieldError(
                "workspace contains regular files with st_nlink>1 (possible hardlinks "
                f"to protected files): {offenders[:5]}"
                + (" ..." if len(offenders) > 5 else "")
                + " — refusing (pass --allow-hardlinks to override; see docs/SHIELD.md)."
            )

    # Anchor dir must be writable by the parent unless --no-anchor.
    if not cfg.no_anchor:
        try:
            cfg.anchor_dir.mkdir(parents=True, exist_ok=True)
            probe = cfg.anchor_dir / f".writeprobe-{cfg.session_id}"
            probe.write_text("x", encoding="utf-8")
            probe.unlink()
        except Exception as e:
            raise ShieldError(
                f"anchor dir {cfg.anchor_dir} is not writable ({e}); refusing "
                "(pass --no-anchor to emit an explicitly UNANCHORED receipt)."
            )

    if cfg.with_safehouse:
        _resolve_safehouse_bin(cfg)  # raises if missing


def _reopens(surface: Path, home: Path) -> bool:
    """True if a subpath read-allow on `surface` would re-open all of HOME:
    surface is HOME itself or one of its ancestors (including "/")."""
    return surface == home or surface in home.parents


def _overlaps(a: Path, b: Path) -> bool:
    """True if either path contains the other (or they are equal)."""
    return a == b or a in b.parents or b in a.parents


def _hardlink_offenders(root: Path) -> list[str]:
    out: list[str] = []
    try:
        for p in root.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink() and p.stat().st_nlink > 1:
                    out.append(str(p))
            except OSError:
                continue
    except OSError:
        pass
    return sorted(out)


# --------------------------------------------------------------------------- #
# The run
# --------------------------------------------------------------------------- #
def run_shield(cfg: ShieldConfig) -> dict:
    """Run the command under the shield and write an anchored receipt. Returns a
    summary dict. Fail-closed: any preflight/profile error raises ShieldError and
    the child never starts."""
    preflight(cfg)

    # Build the enforced policy text (standalone or safehouse-composed).
    overlay_sha = None
    safehouse_version = None
    safehouse_policy_sha = None
    mode = "standalone"
    child_tmp = Path(cfg.workspace).expanduser().resolve() / ".shield-tmp"
    child_tmp.mkdir(parents=True, exist_ok=True)

    if cfg.with_safehouse:
        mode = "safehouse"
        binpath = _resolve_safehouse_bin(cfg)
        safehouse_version = _safehouse_version(binpath)
        overlay = build_safehouse_overlay(cfg)
        overlay_sha = profile_sha256(overlay)
        overlay_path = child_tmp / f"overlay-{cfg.session_id}.sb"
        overlay_path.write_text(overlay, encoding="utf-8")
        policy_text = _safehouse_policy(cfg, binpath, overlay_path)
        safehouse_policy_sha = profile_sha256(policy_text)
        enforced_text = policy_text
    else:
        enforced_text = build_profile(cfg)

    enforced_sha = profile_sha256(enforced_text)

    if cfg.print_profile:
        sys.stdout.write(enforced_text)
        return {"printed_profile": True, "profile_sha256": enforced_sha, "mode": mode}

    profile_arg = [SANDBOX_EXEC, "-p", enforced_text]

    # Env scrub.
    child_env, dropped = scrub_env(cfg)

    # Sentinel for the bracketed positive controls: a shield-owned path the
    # profile denies reading.
    tag = f"deponent-shield-{cfg.session_id}"
    sentinel_dir = Path(cfg.home).expanduser().resolve() / ".deponent-shield-sentinels"
    sentinel_dir.mkdir(parents=True, exist_ok=True)
    sentinel = sentinel_dir / tag
    try:
        sentinel.write_text("FAKE-SENTINEL-FOR-REACH-CONTROL", encoding="utf-8")
    except Exception:
        pass

    receipt_path = Path(cfg.receipt_dir).expanduser().resolve() / f"{cfg.session_id}.jsonl"
    writer = ReceiptWriter(receipt_path)
    catalog = list(resolve_catalog(cfg.home))

    session_start = {
        "type": "session_start",
        "schema": SCHEMA,
        "ts": _utc(),
        "session_id": cfg.session_id,
        "mode": mode,
        "argv": list(cfg.command),
        "profile_sha256": enforced_sha,
        "own_keys": [str(Path(k).expanduser()) for k in cfg.own_keys],
        "own_envs": list(cfg.own_envs),
        "dropped_env_names": dropped,
        "catalog_size": len(catalog),
        "no_network": cfg.no_network,
        "anchored": (not cfg.no_anchor),
        "safehouse_version": safehouse_version,
        "safehouse_policy_sha256": safehouse_policy_sha,
        "overlay_sha256": overlay_sha,
    }
    t0 = time.time()
    exit_status: int | None = None
    reach_events: object = "UNAVAILABLE"

    try:
        writer.append(session_start)

        # Bracketed positive control BEFORE the agent.
        ctrl_before = time.time()
        _run_denied_sentinel(profile_arg, sentinel)

        # Launch the agent as a whole process tree, confined, env-scrubbed,
        # fds closed (only 0/1/2), own session.
        proc = subprocess.Popen(
            profile_arg + ["--"] + list(cfg.command),
            cwd=str(Path(cfg.workspace).expanduser().resolve()),
            env=child_env,
            close_fds=True,
            start_new_session=True,
        )
        proc.wait()
        exit_status = proc.returncode

        # Bracketed positive control AFTER the agent.
        _run_denied_sentinel(profile_arg, sentinel)
        ctrl_after = time.time()

        # Reach capture: require BOTH control events to be observed, else
        # UNAVAILABLE (never "none").
        reach_events = _capture_reach(ctrl_before, ctrl_after, tag, catalog)
        if isinstance(reach_events, list):
            for ev in reach_events:
                writer.append({"type": "reach_event", "ts": _utc(), **ev})
    finally:
        duration = round(time.time() - t0, 3)
        session_end = {
            "type": "session_end",
            "ts": _utc(),
            "session_id": cfg.session_id,
            "exit_status": exit_status,
            "duration_s": duration,
            "reach_events": reach_events if not isinstance(reach_events, list) else "OBSERVED",
            "reach_note": "list is OBSERVED denials only, never a completeness claim",
        }
        writer.append(session_end)
        head, length = writer.head()
        # Anchor (external head+length the agent cannot write).
        if not cfg.no_anchor:
            _write_anchor(cfg.anchor_dir, cfg.session_id, head, length)
        try:
            sentinel.unlink()
        except Exception:
            pass

    head, length = writer.head()
    return {
        "mode": mode,
        "session_id": cfg.session_id,
        "receipt": str(receipt_path),
        "profile_sha256": enforced_sha,
        "safehouse_policy_sha256": safehouse_policy_sha,
        "overlay_sha256": overlay_sha,
        "exit_status": exit_status,
        "reach_events": reach_events if not isinstance(reach_events, list) else f"{len(reach_events)} observed",
        "anchored": (not cfg.no_anchor),
        "head": head,
        "length": length,
        "dropped_env_count": len(dropped),
    }


def _capture_reach(before: float, after: float, tag: str, catalog: list[str]) -> object:
    """Return a NON-EMPTY list of observed catalog-read deny events, or the string
    "UNAVAILABLE". Never an empty list.

    Honest by construction: sandbox-exec custom-profile denies are not reliably
    emitted to the unified log on macOS 27, so this typically returns UNAVAILABLE.
    UNAVAILABLE is returned when the log tool is absent, when the bracketed positive
    control was not observed at BOTH brackets, OR when the control WAS observed but
    no catalog denial was captured in the window — an empty capture cannot be
    reported as observation (that would be the "empty-and-OK" the shield forbids),
    so it collapses to UNAVAILABLE."""
    if not _log_show_available():
        return "UNAVAILABLE"
    control_hits = _query_log_denies(before, tag)
    if len(control_hits) < 2:
        # Need the before AND after control denies to prove capture is working.
        return "UNAVAILABLE"
    # Controls observed -> capture real catalog denials in the window (path + verdict
    # only, no detection mechanics). Kept minimal; this branch is unreachable on a
    # host where sandbox-exec denies are not logged.
    events: list[dict] = []
    for line in _query_log_denies(before, ""):
        if after and _line_epoch(line) and _line_epoch(line) > after + 2:
            continue
        for c in catalog:
            if _line_mentions_catalog_path(line, c):
                events.append({"path": c, "verdict": "deny"})
                break
    # de-dup while preserving order
    seen = set()
    uniq = []
    for e in events:
        if e["path"] not in seen:
            seen.add(e["path"])
            uniq.append(e)
    # An empty capture is NOT observation: controls were seen but no catalog denial
    # was matched in the window. Report UNAVAILABLE, never an empty "OBSERVED".
    return uniq if uniq else "UNAVAILABLE"


#: Characters that legitimately terminate a path token in a unified-log deny line.
_PATH_BOUNDARY = frozenset({"/", '"', "'", " ", "\t", "\n", ")", ","})

#: Characters that may legitimately PRECEDE a path token (it must never follow a
#: path character, or `/Volumes/Backup/Users/me/.ssh` would match `/Users/me/.ssh`).
_PATH_LEADING_BOUNDARY = frozenset({" ", "\t", "\n", '"', "'", "(", "=", ":"})


def _line_mentions_catalog_path(line: str, c: str) -> bool:
    """True iff catalog path ``c`` appears in ``line`` as a whole path token.

    LEADING: the occurrence starts at the beginning of the line or right after
    whitespace, a quote, ``(``, ``=`` or ``:`` — never after a path character, so a
    path that merely ENDS in a copy of HOME (``/Volumes/Backup/Users/me/.ssh/id``,
    ``/tmp/x/Users/me/.ssh``) is not credited to ``/Users/me/.ssh``.

    TRAILING: it is followed by a path separator, a quote, whitespace, ``)``/``,``
    or the end of the line, so a sibling like ``<c>2`` or ``<c>_backup`` is not
    credited to ``<c>``, while an exact hit and any subpath (``<c>/id_x``) are."""
    n = len(c)
    start = 0
    while True:
        i = line.find(c, start)
        if i < 0:
            return False
        end = i + n
        leading_ok = i == 0 or line[i - 1] in _PATH_LEADING_BOUNDARY
        trailing_ok = end == len(line) or line[end] in _PATH_BOUNDARY
        if leading_ok and trailing_ok:
            return True
        start = i + 1


def _line_epoch(line: str) -> float | None:
    try:
        stamp = " ".join(line.split()[:2])
        dt = datetime.strptime(stamp[:19], "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Anchor + verify
# --------------------------------------------------------------------------- #
def _anchor_path(anchor_dir: Path, session_id: str) -> Path:
    return Path(anchor_dir).expanduser().resolve() / f"{session_id}.anchor.json"


def _write_anchor(anchor_dir: Path, session_id: str, head: str, length: int) -> Path:
    ap = _anchor_path(anchor_dir, session_id)
    ap.parent.mkdir(parents=True, exist_ok=True)
    ap.write_text(json.dumps({
        "session_id": session_id, "head": head, "length": length, "ts": _utc(),
    }, indent=2), encoding="utf-8")
    return ap


def verify_receipt(receipt: Path, anchor_dir: Path = DEFAULT_ANCHOR_DIR) -> tuple[str, str]:
    """Recompute the receipt chain and compare against its external anchor.

    Returns one of:
      MISSING     — file absent or empty (never reported as intact)
      TAMPERED    — chain re-link broken (edit) OR head/length mismatch vs anchor
                    (truncate / re-chain) OR unparseable line OR anchor expected
                    but absent
      UNANCHORED  — chain re-links but the receipt was written with --no-anchor
                    (weaker guarantee: truncation cannot be caught)
      ANCHORED_OK — chain re-links AND head+length match the external anchor
    """
    p = Path(receipt).expanduser()
    if not p.exists():
        return "MISSING", f"no receipt at {p}"
    raw = p.read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return "MISSING", "receipt is empty"

    entries: list[dict] = []
    for i, ln in enumerate(lines):
        try:
            entries.append(json.loads(ln))
        except Exception:
            return "TAMPERED", f"line {i} is not valid JSON"

    # Recompute the chain from genesis.
    prev = GENESIS
    for i, e in enumerate(entries):
        payload = {k: v for k, v in e.items() if k not in ("prev_hash", "entry_hash")}
        if e.get("prev_hash") != prev:
            return "TAMPERED", f"record {i}: prev_hash break"
        if e.get("entry_hash") != _chain_hash(prev, payload):
            return "TAMPERED", f"record {i}: hash mismatch (edited)"
        prev = e["entry_hash"]
    head, length = prev, len(entries)

    start = entries[0]
    anchored_intent = bool(start.get("anchored"))
    session_id = start.get("session_id", "")

    if not anchored_intent:
        return "UNANCHORED", (
            f"chain re-links ({length} records) but receipt was written --no-anchor; "
            "truncation cannot be detected without an external anchor"
        )

    ap = _anchor_path(anchor_dir, session_id)
    if not ap.exists():
        return "TAMPERED", f"receipt claims anchored but anchor {ap} is missing"
    try:
        anchor = json.loads(ap.read_text(encoding="utf-8"))
    except Exception:
        return "TAMPERED", f"anchor {ap} is not valid JSON"
    if anchor.get("head") != head or anchor.get("length") != length:
        return "TAMPERED", (
            f"head/length mismatch vs anchor "
            f"(receipt head={head[:12]} len={length}, "
            f"anchor head={str(anchor.get('head'))[:12]} len={anchor.get('length')}) "
            "— truncation or re-chain"
        )
    return "ANCHORED_OK", f"chain re-links and matches anchor ({length} records)"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split argv at the first bare `--`: (options, command)."""
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def _build_run_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="deponent shield",
        description="Run a command as a whole process tree under a deny-by-default "
                    "macOS Seatbelt read profile, with anchored receipts.")
    ap.add_argument("--workspace", type=Path, default=Path.cwd(),
                    help="read/write sandbox root (default: cwd)")
    ap.add_argument("--home", type=Path, default=Path(os.environ.get("HOME", "~")),
                    help="HOME to resolve the catalog against (default: $HOME)")
    ap.add_argument("--own-key", dest="own_keys", action="append", default=[], type=Path,
                    help="a credential path the agent IS allowed to read (repeatable)")
    ap.add_argument("--own-env", dest="own_envs", action="append", default=[],
                    help="an env var NAME to pass through to the child (repeatable)")
    ap.add_argument("--state-dir", dest="state_dirs", action="append", default=[], type=Path,
                    help="a dir the agent may read AND write (repeatable)")
    ap.add_argument("--allow-read", dest="allow_reads", action="append", default=[], type=Path,
                    help="a dir the agent may read (cannot override the catalog) (repeatable)")
    ap.add_argument("--no-network", action="store_true", help="deny the child all network")
    ap.add_argument("--no-anchor", action="store_true",
                    help="do not write an external anchor (receipt is UNANCHORED)")
    ap.add_argument("--allow-missing-own-key", action="store_true",
                    help="do not refuse if a declared --own-key does not exist")
    ap.add_argument("--allow-hardlinks", action="store_true",
                    help="do not refuse on workspace files with st_nlink>1")
    ap.add_argument("--allow-keychain", action="store_true",
                    help="do NOT deny the keychain mach-lookup (agent key is in keychain)")
    ap.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR,
                    help=f"receipt dir (default: {DEFAULT_RECEIPT_DIR})")
    ap.add_argument("--anchor-dir", type=Path, default=DEFAULT_ANCHOR_DIR,
                    help=f"anchor dir (default: {DEFAULT_ANCHOR_DIR})")
    ap.add_argument("--with-safehouse", action="store_true",
                    help="compose with Agent Safehouse: safehouse assembles the base "
                         "policy, Deponent appends an overlay and launches it")
    ap.add_argument("--safehouse-bin", default=None,
                    help="path to the safehouse binary (default: found on PATH)")
    ap.add_argument("--print-profile", action="store_true",
                    help="print the profile/policy text and exit (dry-run)")
    return ap


def cmd_shield(argv: list[str]) -> int:
    options, command = _split_command(argv)
    ap = _build_run_parser()
    args = ap.parse_args(options)
    cfg = ShieldConfig(
        command=command,
        workspace=args.workspace,
        home=args.home,
        own_keys=tuple(args.own_keys),
        own_envs=tuple(args.own_envs),
        state_dirs=tuple(args.state_dirs),
        allow_reads=tuple(args.allow_reads),
        no_network=args.no_network,
        no_anchor=args.no_anchor,
        allow_missing_own_key=args.allow_missing_own_key,
        allow_hardlinks=args.allow_hardlinks,
        allow_keychain=args.allow_keychain,
        receipt_dir=args.receipt_dir,
        anchor_dir=args.anchor_dir,
        with_safehouse=args.with_safehouse,
        safehouse_bin=args.safehouse_bin,
        print_profile=args.print_profile,
    )
    try:
        result = run_shield(cfg)
    except ShieldError as e:
        print(f"REFUSE: {e}", file=sys.stderr)
        return 2
    if result.get("printed_profile"):
        return 0
    print(json.dumps(result, indent=2))
    # exit code mirrors the child's, so the shield is transparent to callers
    rc = result.get("exit_status")
    return rc if isinstance(rc, int) else 0


def cmd_verify(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="deponent shield-verify",
        description="Recompute a shield receipt against its external anchor.")
    ap.add_argument("receipt", type=Path, help="path to the receipt .jsonl")
    ap.add_argument("--anchor-dir", type=Path, default=DEFAULT_ANCHOR_DIR)
    args = ap.parse_args(argv)
    status, detail = verify_receipt(args.receipt, args.anchor_dir)
    print(f"{status}: {detail}")
    return 0 if status == "ANCHORED_OK" else 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("run", "shield"):
        return cmd_shield(argv[1:])
    if argv and argv[0] in ("verify", "shield-verify"):
        return cmd_verify(argv[1:])
    # default: treat as a shield run
    return cmd_shield(argv)


__all__ = [
    "ShieldConfig", "ShieldError", "build_profile", "profile_sha256",
    "resolve_catalog", "scrub_env", "validate_sbpl_path", "run_shield",
    "verify_receipt", "build_safehouse_overlay", "cmd_shield", "cmd_verify",
    "main", "CATALOG_RELPATHS", "ENV_ALLOWLIST",
]


if __name__ == "__main__":
    raise SystemExit(main())
