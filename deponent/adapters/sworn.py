#!/usr/bin/env python3
"""GAK commit-gate adapter for sworncode (the commit-time sibling)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from .contract import KernelAdapter


class SwornAdapter(KernelAdapter):
    """GAK adapter for sworncode — profile: commit-gate."""

    name = "sworncode"
    profile = "commit-gate"
    supports = frozenset()  # no reconcile, no attest -> those clauses report NA

    def _repo(self) -> Path:
        """A fresh, isolated sandbox repo for ONE probe (a new tempdir per call)."""
        return Path(tempfile.mkdtemp(prefix="gak-sworn-"))

    def _config(self, repo: Path):
        from sworn.config import load_config
        return load_config(repo)  # no .sworn/config.toml -> secure defaults

    def _gate(self, repo: Path, files: list[str]) -> "tuple[Any, Path]":
        """One config load -> run the commit gate -> (PipelineResult, evidence_log_path).

        Single source for the gate call so every clause drives sworncode the same way
        and load_config runs exactly once per gated change-set.
        """
        from sworn.pipeline import run_pipeline
        cfg = self._config(repo)
        result = run_pipeline(repo, files, cfg)
        return result, repo / cfg.evidence_log_path

    def commit_verdict(self, files: list[str]) -> str:
        result, _ = self._gate(self._repo(), files)
        return "ALLOW" if result.decision == "PASS" else "BLOCK"

    def clean_chain_verifies(self) -> bool:
        from sworn.evidence.log import verify_chain
        _, log = self._gate(self._repo(), ["README.md"])  # a clean commit -> evidence written
        ok, _ = verify_chain(log)
        return ok

    def tamper_is_detected(self) -> bool:
        from sworn.evidence.log import verify_chain
        repo = self._repo()
        self._gate(repo, ["README.md"])            # two recorded decisions -> a real chain link
        _, log = self._gate(repo, ["docs/x.md"])
        lines = log.read_text().splitlines()
        if len(lines) < 2:
            return False
        # Forge the first record by parsing + re-serializing with a changed decision,
        # in the SAME canonical form the log uses. Assert the bytes actually changed so a
        # no-op forge can never masquerade as a passing tamper test (format-robust: no
        # dependency on exact separator spacing or on the probe's original decision).
        before = lines[0]
        entry = json.loads(before)
        entry["decision"] = "TAMPERED" if entry.get("decision") != "TAMPERED" else "FORGED"
        lines[0] = json.dumps(entry, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
        if lines[0] == before:
            return False                           # forge was a no-op -> cannot claim tamper-evidence
        log.write_text("\n".join(lines) + "\n")
        ok, _ = verify_chain(log)
        return not ok

    def commit_testifies(self, files: list[str]) -> bool:
        from sworn.evidence.log import read_entries
        result, log = self._gate(self._repo(), files)  # a security surface -> BLOCKED
        entries = read_entries(log)
        if not entries:
            return False
        # The BLOCK still produced an audit record: it testifies, it does not just answer.
        # sworncode logs its own raw decision ('PASS'/'BLOCKED'); also accept the harness-mapped
        # ALLOW/BLOCK form so a future log-vocabulary change can't silently false-FAIL this clause.
        mapped = "ALLOW" if result.decision == "PASS" else "BLOCK"
        return entries[-1].get("decision") in (result.decision, mapped)


__all__ = ["SwornAdapter"]
