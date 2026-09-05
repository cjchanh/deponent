#!/usr/bin/env python3
"""
gate.py — the deny-by-default action gate.

Every action an agent wants to take is classified by BLAST RADIUS and either
ALLOWed (reversible + in-sandbox + bounded) or BLOCKed (deny-by-default). The
gate governs the SHELL + PATH surface: which programs may run, which paths may
be touched, and whether a command chains or substitutes its way out of policy.

It does not decide alone — it is one half of the cell. The other half is the
Ledger (ledger.py), which records every decision to a tamper-evident hash chain
so the run can be audited after the fact. The protected output is the host:
nothing irreversible or out-of-sandbox executes without a recorded ALLOW.

SECURITY POSTURE (read this — it is a feature, not a disclaimer):
  This is a reference governance primitive, not a hardened production sandbox.
  Threat surface : agent-authored shell commands + file paths.
  Fail-closed    : unknown tool / unclassifiable command / path escape -> BLOCK.
  Covered        : path traversal out of the sandbox (read + write); a curated
                   program allowlist (heads) + denylist (irreversible, network,
                   privilege, out-of-tree); shell chaining, command substitution,
                   shell redirects, and newline-separated commands.
  NOT covered    : in-language execution — an ALLOWed `python`/`pytest` can still
                   run arbitrary Python *inside* the sandbox dir. That gap is
                   closed by jail.py (Seatbelt: no network, writes confined). Use
                   the two together (see cell.py) for the full surface.
  Key material   : none. The gate makes decisions; it holds no secrets or keys.
  Verification   : tests/test_gate.py — negative BLOCK + positive ALLOW + an
                   unknown-tool deny-by-default proof.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from .reach import ReachOracle, ReachReport


@dataclass(frozen=True)
class GateDecision:
    """An immutable verdict. `blast_class` names *why*, for the audit record."""
    verdict: str        # "ALLOW" | "BLOCK"
    blast_class: str    # reversible-local-read | bounded-local-exec | out-of-sandbox-write | ...
    reason: str
    reach: ReachReport | None = None   # graph-derived blast radius, when a ReachOracle is wired


# Irreversible / out-of-scope / privilege / network signatures -> hard BLOCK.
DENY_SUBSTR = (
    "rm -rf", "rm -r ", "rm -fr", "rmdir", "sudo", "mkfs", "dd if=", "dd of=",
    "> /dev", ":(){", "fork", "shutdown", "reboot", "halt",
    "curl", "wget", "ssh", "scp", "sftp", "nc ", "ncat", "telnet", "nmap",
    "git push", "git remote", "pip install", "pip3 install", "uv pip", "npm i",
    "brew ", "launchctl", "systemctl", "crontab", "defaults write",
    "kill ", "pkill", "killall", "chmod -r", "chown", "chflags",
    "/etc/", "/usr/", "/bin/", "/sbin/", "/system/", "/library/", "/var/",
    "$home", "${home}", "~/", "..", "osascript", "open -a",
)
# Programs an agent worker may legitimately invoke in a coding sandbox.
ALLOW_HEADS = frozenset({
    "python", "python3", "pytest", "ruff", "black", "mypy",
    "ls", "cat", "head", "tail", "pwd", "echo", "grep", "wc",
    "mkdir", "touch", "diff", "true", "sort", "uniq",
})
# Interpreter / launcher heads refused in gate-only (unjailed) mode unless explicitly
# opted in. This is a denylist over heads an integrator might allow-list; a head not in
# ALLOW_HEADS is already refused as program-not-allowlisted before this check runs.
INTERPRETER_HEADS = frozenset({
    "python", "python3", "pytest", "pypy", "pypy3", "uv", "uvx", "pip", "pip3",
    "node", "nodejs", "perl", "ruby", "bash", "sh", "zsh", "dash", "env", "xargs",
    "ipython", "deno", "bun", "python.exe", "pythonw",
    "py", "py.exe",
})
_INTERPRETER_HEAD_RE = re.compile(
    r"^(?:python\d.*(?:\.exe)?|python\.exe|pythonw(?:\d.*)?(?:\.exe)?|pypy\d.*|py(?:\.exe)?)$"
)


def is_interpreter_head(head: str) -> bool:
    """True for heads that execute caller-supplied code (versioned interpreters such
    as `python3.12` and path-qualified forms such as `/usr/bin/python3` included).
    Used only in gate-only mode. Comparison is case-insensitive (`Python3`, `PY.EXE`)."""
    base = os.path.basename(head or "").casefold()
    return base in INTERPRETER_HEADS or bool(_INTERPRETER_HEAD_RE.match(base))
# Segment operators after shlex tokenization (quoted copies stay inside words).
_OPERATORS = frozenset({";", "&&", "||", "|"})
_SUBST = ("$(", "`", "${")
# Shell redirects write/read arbitrary host paths the gate cannot reliably extract
# from the token stream (a target glued to the operator, e.g. `x>>/etc/p`, tokenizes
# as one relative-looking arg and slips past path containment). Deny-by-default:
# block the redirect class wholesale — legitimate writes go through the gated
# `write_file` tool, not a shell redirect.
_REDIR = (">", "<")


def tokenize_command(cmd: str) -> list[list[str]]:
    """Split on physical lines, then shlex-tokenize each into argv segments.

    `;`, `&&`, `||`, `|` become standalone tokens even when glued (`echo a;echo b`);
    a quoted separator stays inside its word. Raises ValueError on unparsable input.
    """
    segments: list[list[str]] = []
    for line in re.split(r"[\n\r]+", cmd):
        line = line.strip()
        if not line:
            continue
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.wordchars += "-./_"
        current: list[str] = []
        for tok in lexer:
            if tok in _OPERATORS:
                if current:
                    segments.append(current)
                    current = []
            else:
                current.append(tok)
        if current:
            segments.append(current)
    return segments


class Gate:
    """Deny-by-default action gate scoped to a sandbox directory.

    The policy (DENY_SUBSTR / ALLOW_HEADS) is module-level and overridable per
    instance — pass `deny=` / `allow_heads=` to tune it for your tool surface.
    The defaults are a sane coding-agent sandbox: read/write/run inside the box,
    nothing that reaches the network, escalates privilege, or leaves the tree.
    """

    def __init__(self, sandbox: os.PathLike | str, *,
                 deny: tuple[str, ...] = DENY_SUBSTR,
                 allow_heads: frozenset[str] = ALLOW_HEADS,
                 reach: ReachOracle | None = None,
                 max_reach: int | None = None,
                 unjailed: bool = False,
                 allow_unjailed_interpreters: bool = False):
        self.sandbox = Path(sandbox).resolve()
        self.deny = tuple(deny)
        self.allow_heads = frozenset(allow_heads)
        # Optional graph-derived blast-radius oracle. When set, write decisions carry
        # real reach; with max_reach set, a write whose blast radius exceeds the
        # ceiling is BLOCKed. Reach can only make the gate STRICTER, never looser —
        # default (reach=None) behaviour is byte-identical to the substring gate.
        self.reach = reach
        self.max_reach = max_reach
        self.unjailed = bool(unjailed)
        self.allow_unjailed_interpreters = bool(allow_unjailed_interpreters)

    # ---- path containment ----
    def _in_sandbox(self, path: str) -> bool:
        if not isinstance(path, str) or "\x00" in path:
            return False
        try:
            full = (self.sandbox / path).resolve()
        except Exception:
            return False
        s, root = str(full), str(self.sandbox)
        return s == root or s.startswith(root + os.sep)

    # ---- classifier ----
    def evaluate(self, tool: str, params: dict) -> GateDecision:
        if tool == "read_file":
            p = params.get("path", "")
            if not self._in_sandbox(p):
                return GateDecision("BLOCK", "out-of-sandbox-read", f"path escapes sandbox: {p!r}")
            return GateDecision("ALLOW", "reversible-local-read", "read inside sandbox")

        if tool == "write_file":
            p = params.get("path", "")
            if not self._in_sandbox(p):
                return GateDecision("BLOCK", "out-of-sandbox-write", f"path escapes sandbox: {p!r}")
            if self.reach is not None:
                return self._reach_gated_write(p)
            return GateDecision("ALLOW", "reversible-local-write", "write inside sandbox")

        if tool == "run_cmd":
            return self._evaluate_cmd(params.get("cmd", ""))

        # deny-by-default: anything unrecognized
        return GateDecision("BLOCK", "unknown-tool", f"no policy for tool {tool!r} (deny-by-default)")

    def _evaluate_cmd(self, cmd: str) -> GateDecision:
        if not isinstance(cmd, str) or not cmd.strip():
            return GateDecision("BLOCK", "empty-command", "empty or non-string command")
        low = cmd.lower()
        for bad in self.deny:
            if bad in low:
                return GateDecision("BLOCK", "destructive-or-out-of-scope", f"matched deny pattern {bad!r}")
        if any(s in cmd for s in _SUBST):
            return GateDecision("BLOCK", "command-substitution", "shell substitution/expansion not allowed")
        if any(r in cmd for r in _REDIR):
            return GateDecision("BLOCK", "shell-redirect",
                                "shell redirection not allowed; use the write_file tool for gated writes")
        try:
            segments = tokenize_command(cmd)
        except ValueError:
            return GateDecision("BLOCK", "unparsable-command", f"cannot tokenize: {cmd!r}")
        if not segments:
            return GateDecision("BLOCK", "empty-command", "empty or non-string command")
        for toks in segments:
            if not toks:
                continue
            head = os.path.basename(toks[0])
            if head not in self.allow_heads:
                return GateDecision("BLOCK", "program-not-allowlisted", f"program {head!r} not in allowlist")
            for t in toks[1:]:
                if t.startswith("-"):
                    continue
                if "/" in t or t in (".", ".."):
                    if not self._in_sandbox(t):
                        return GateDecision("BLOCK", "arg-path-escape", f"argument path escapes sandbox: {t!r}")
        if self.unjailed:
            if not self.allow_unjailed_interpreters:
                for toks in segments:
                    head = os.path.basename(toks[0])
                    if is_interpreter_head(head):
                        return GateDecision(
                            "BLOCK", "interpreter-unjailed",
                            f"interpreter {head!r} refused in gate-only mode",
                        )
            if len(segments) > 1:
                return GateDecision(
                    "BLOCK", "chain-unjailed",
                    "gate-only mode allows a single command segment",
                )
        return GateDecision("ALLOW", "bounded-local-exec", "allowlisted, in-sandbox, non-chained-to-deny")

    # ---- graph-derived blast radius (the real reach classifier) ----
    def _reach_gated_write(self, p: str) -> GateDecision:
        """Classify a write by its REAL blast radius (reverse-dependency closure),
        not a substring guess. Advisory by default (records reach); with max_reach
        set, enforces a ceiling. Fail-closed: unknown reach under an enforcing
        policy is treated as exceeding, never as safe."""
        rr = self.reach.blast_radius(p)
        if self.max_reach is not None:
            if not rr.resolved:
                return GateDecision("BLOCK", "reach-unresolved",
                                    "blast-radius graph unavailable; refusing the write under an "
                                    "enforcing policy (fail-closed)", rr)
            if rr.score > self.max_reach:
                deps = ", ".join(rr.dependents[:5]) or "none"
                return GateDecision("BLOCK", "reach-exceeds-policy",
                                    f"blast radius {rr.score} > max_reach {self.max_reach} "
                                    f"(dependents: {deps})", rr)
        cls = "reversible-local-write" if rr.score == 0 else f"local-write-reach-{rr.score}"
        detail = ("leaf (nothing depends on it)" if rr.score == 0
                  else f"{rr.score} dependents: {', '.join(rr.dependents[:5])}")
        return GateDecision("ALLOW", cls, f"write inside sandbox; blast radius = {detail}", rr)


__all__ = ["Gate", "GateDecision", "DENY_SUBSTR", "ALLOW_HEADS",
           "INTERPRETER_HEADS", "is_interpreter_head", "tokenize_command"]
