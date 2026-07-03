#!/usr/bin/env python3
"""deponent.adapters.contract — the GAK conformance interface.

A kernel implements `KernelAdapter` and drops it in `deponent/adapters/` to become
 testable by `python3 -m deponent.conform --kernel <name>`.
"""
from __future__ import annotations

from typing import Protocol


class KernelAdapter(Protocol):
    """What a kernel exposes to be GAK-tested. A new kernel ships one of these.

    `profile` names the governance shape ("action-gate" | "commit-gate"). `supports`
    lists optional capabilities the kernel claims ("reconcile", "attest"); a clause
    for an unclaimed capability reports NA, not FAIL.
    """
    name: str
    profile: str
    supports: frozenset

    def verdict(self, tool: str, params: dict) -> str:
        """Classify one action -> 'ALLOW' | 'BLOCK' (action-gate profile)."""

    def clean_chain_verifies(self) -> bool:
        """A run's untampered audit chain re-verifies."""

    def tamper_is_detected(self) -> bool:
        """A mutated audit record is caught by verification (tamper-evident)."""

    def jail_fails_closed(self) -> bool:
        """When no OS confinement is available, the jail refuses to run rather than
        run un-jailed (action-gate; fail-closed). A commit-gate kernel reports NA."""

    def reconcile_catches_undeclared(self) -> bool:
        """A tool that changes state it did not declare is flagged (optional)."""

    def attest_abstains_when_unproven(self) -> bool:
        """The kernel ABSTAINS (not falsely attests) on coverage it didn't earn (optional)."""

    # --- commit-gate profile: a kernel that gates a proposed change-set (a diff /
    # staged files), not a live tool call. The action-gate methods above report NA.
    def commit_verdict(self, files: list) -> str:
        """Classify a proposed change-set -> 'ALLOW' | 'BLOCK' (commit-gate profile)."""

    def commit_testifies(self, files: list) -> bool:
        """A gated change-set (ALLOW or BLOCK) is recorded to a verifiable audit log."""


__all__ = ["KernelAdapter"]
