#!/usr/bin/env python3
"""
reach.py — graph-derived blast radius. The *real* reach classifier.

The gate's substring/path checks answer "is this command shaped dangerously?" They
do NOT answer "how much does this action actually affect?" — and a substring guess
at blast radius is, in the operator's words, regex theater. This module computes
reach from a real dependency graph: change a file, and blast_radius() returns how
many modules transitively depend on it. A leaf utility scores low; a hub everything
imports scores high; a brand-new file scores zero.

OPEN-CORE BOUNDARY: ImportGraphReach below is the open reference oracle — a
deterministic Python import graph (stdlib `ast`, zero deps). The production oracle
(semantic + co-change + cross-repo signals) plugs into the SAME ReachOracle
interface and lives in the commercial layer. The gate reasons about real blast
radius either way; only the richness of the graph differs.

FAIL-CLOSED CONTRACT: if the graph cannot be built, blast_radius() returns
resolved=False and the CALLER (gate.py) decides — under an enforcing policy that
means "unknown reach -> treat as exceeding," never "unknown -> allow."

No key material. ast.parse only parses; it never executes the analyzed code.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class ReachReport:
    """The blast radius of touching `target`, for the gate decision + audit record."""
    target: str
    score: int                    # size of the reverse-dependency closure
    dependents: tuple[str, ...]   # direct importers of target (sorted)
    basis: str                    # which oracle produced this
    resolved: bool                # False -> graph could not be built; caller fails closed


class ReachOracle(Protocol):
    """Anything that can answer 'how much does touching this target affect?'.
    The open ImportGraphReach and the commercial graphify oracle both satisfy it."""
    basis: str

    def blast_radius(self, target: str) -> ReachReport: ...


class ImportGraphReach:
    """Reference oracle: reverse-dependency reach from a deterministic Python import
    graph over `root`. Zero third-party deps."""

    basis = "python-import-graph"

    def __init__(self, root: Path | str):
        self.root = Path(root).resolve()
        self._revdeps: dict[str, set[str]] = {}   # module -> set of modules that import it
        self._built = False
        try:
            self._build()
            self._built = True
        except Exception:
            self._built = False   # genuine build failure -> callers fail closed

    def _mod(self, path: Path) -> str:
        rel = path.resolve().relative_to(self.root).with_suffix("")
        parts = list(rel.parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)

    @staticmethod
    def _match_module(name: str, modules: set[str]) -> str | None:
        if name in modules:
            return name
        parts = name.split(".")           # `from pkg.sub import x` -> longest in-repo prefix
        for i in range(len(parts), 0, -1):
            cand = ".".join(parts[:i])
            if cand in modules:
                return cand
        return None

    def _build(self) -> None:
        files = [p for p in self.root.rglob("*.py") if p.is_file()]
        modules: set[str] = set()
        for p in files:
            try:
                modules.add(self._mod(p))
            except Exception:
                continue
        for p in files:
            try:
                src = p.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(src, filename=str(p))   # parse only — never executed
                me = self._mod(p)
            except Exception:
                continue
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    target = self._match_module(name, modules)
                    if target and target != me:
                        self._revdeps.setdefault(target, set()).add(me)

    def blast_radius(self, target: str) -> ReachReport:
        if not self._built:
            return ReachReport(target, 0, (), self.basis, resolved=False)
        try:
            tp = Path(target)
            tp = tp.resolve() if tp.is_absolute() else (self.root / target).resolve()
            mod = self._mod(tp)
        except Exception:
            # target resolves outside the repo -> no in-repo dependents (graph still built)
            return ReachReport(target, 0, (), self.basis, resolved=True)
        seen: set[str] = set()
        stack = [mod]
        while stack:
            m = stack.pop()
            for importer in self._revdeps.get(m, ()):  # transitive reverse-dependency closure
                if importer not in seen:
                    seen.add(importer)
                    stack.append(importer)
        direct = tuple(sorted(self._revdeps.get(mod, set())))
        return ReachReport(target, len(seen), direct, self.basis, resolved=True)


__all__ = ["ReachReport", "ReachOracle", "ImportGraphReach"]
