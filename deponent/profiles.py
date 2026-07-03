#!/usr/bin/env python3
"""
profiles.py — gate policy PROFILES for different tool surfaces.

The default gate (gate.py) is a tight coding sandbox: python/pytest + reads, and it
DENIES git/cargo/network. Right for governing an LLM's freeform tool calls, but too
narrow to govern a real BUILD (commit, compile, test). The `build` profile widens
the allowlist to the build toolchain while KEEPING — and extending — the
irreversible floor.

The build profile IS the CDS acceleration doctrine encoded as gate policy:
  * full throttle on REVERSIBLE / LOCAL build actions — read, edit, compile, test,
    LOCAL commit — ALLOW.
  * a hard gate at the IRREVERSIBLE / OUTWARD boundary — push, publish, install,
    force, history-rewrite, destructive resets — BLOCK, by name.

Defense in depth: the gate denies the irreversible commands an agent issues
DIRECTLY; the Seatbelt jail (network-denied, writes confined) blocks the same
operations issued INDIRECTLY from inside an allowed tool (a `make` target or a
`build.rs` that tries to push/publish fails at the network layer). The two together
hold the irreversible floor even past the in-tool-execution gap gate.py documents
as out of scope.

SECURITY POSTURE: a privilege-boundary policy on a REFERENCE gate, not a hardened
production sandbox. No key material. Fail-closed: an unrecognized program is denied;
the full default deny floor (rm -rf, sudo, curl/wget/ssh, system paths, ~, ..) is
retained. `make` is a generic shell-runner — included for build ergonomics, sound
only because the jail confines its effects (no network, writes in-tree); deployments
that disable the jail should drop it. Verification: test_profiles.py.
"""
from __future__ import annotations

import os

from .gate import ALLOW_HEADS, DENY_SUBSTR, Gate

# Build-toolchain programs an agent may invoke for a real reversible/local build.
# Curated to the CDS stack; a consumer widens it explicitly for their toolchain.
BUILD_ALLOW_HEADS = ALLOW_HEADS | frozenset({
    "git", "cargo", "rustc", "typst", "make",
})

# Irreversible / outward build operations — the boundary that stays CLOSED even
# though the tool's head is allowlisted. Extends (never replaces) the default deny
# floor, which is kept in full (rm -rf, sudo, network, system paths, ~, ..).
BUILD_DENY_EXTRA = (
    "git push", "git remote", "git reset --hard", "git clean", "git rebase",
    "git checkout --", "git filter-branch", "git update-ref -d", "git reflog delete",
    "--force", "force-with-lease",
    "cargo publish", "cargo install", "cargo login", "cargo yank",
    "make publish", "make deploy", "make push", "npm publish",
)
BUILD_DENY_SUBSTR = DENY_SUBSTR + BUILD_DENY_EXTRA


def build_gate(repo_root: os.PathLike | str) -> Gate:
    """A Gate that governs a real build inside `repo_root`: reversible/local build
    actions (read, edit, compile, test, LOCAL commit) ALLOW; push/publish/install/
    force/history-rewrite/destructive BLOCK. Reads/writes/commands stay confined to
    repo_root; pair with a jailed Cell to confine in-tool effects."""
    return Gate(repo_root, deny=BUILD_DENY_SUBSTR, allow_heads=BUILD_ALLOW_HEADS)


def build_cell(repo_root: os.PathLike | str, **kwargs):
    """A governed Cell wired with the build profile — the dogfood surface: run a real
    build (read/edit/compile/test/LOCAL commit) THROUGH the kernel, with push/publish/
    destructive denied and (when jailed) in-tool effects confined. `kwargs` forward to
    Cell (e.g. `ledger_path`, `use_jail`). This is what lets the self-gate govern an
    actual git/cargo build instead of only the python sandbox."""
    from .cell import Cell
    return Cell(repo_root, gate=build_gate(repo_root), **kwargs)


__all__ = ["build_gate", "build_cell", "BUILD_ALLOW_HEADS", "BUILD_DENY_SUBSTR",
           "BUILD_DENY_EXTRA"]
