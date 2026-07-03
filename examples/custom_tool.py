#!/usr/bin/env python3
"""custom_tool.py — govern a non-coding tool surface with deponent.

This example shows how to subclass Gate + Cell so the same deny-by-default gate
and tamper-evident ledger govern your own agent's tools — not just files and shell.
"""
from __future__ import annotations

import tempfile

from deponent import Cell, Gate, GateDecision


class BrowserGate(Gate):
    """Extend the default gate with policy for browser tools."""

    def evaluate(self, tool: str, params: dict) -> GateDecision:
        if tool in ("browse", "click", "fill_form"):
            url = params.get("url", "")
            if "evil" in url.lower():
                return GateDecision("BLOCK", "denylist", f"url on denylist: {url!r}")
            return GateDecision("ALLOW", "browser-action", f"{tool} allowed")
        return super().evaluate(tool, params)


class BrowserCell(Cell):
    """A Cell that executes the fake browser tools governed by BrowserGate."""

    def _execute(self, tool: str, params: dict) -> str:
        if tool == "browse":
            return f"navigated to {params.get('url', '')}"
        if tool == "click":
            return f"clicked {params.get('selector', '?')}"
        if tool == "fill_form":
            return f"filled {params.get('field', '?')}"
        return super()._execute(tool, params)


def main() -> int:
    sandbox = tempfile.mkdtemp()
    cell = BrowserCell(sandbox, gate=BrowserGate(sandbox), use_jail=False)

    # ALLOW: in-policy browse action.
    print(cell.act("browse", {"url": "https://example.com/docs"}).output)

    # BLOCK: custom gate denylist.
    print(cell.act("browse", {"url": "https://evil.example.com"}).output)

    # BLOCK: unknown tool (deny-by-default) still caught by inherited Gate.
    print(cell.act("exfiltrate", {"to": "evil.example"}).output)

    # BLOCK: destructive shell command still caught by inherited run_cmd policy.
    print(cell.act("run_cmd", {"cmd": "rm -rf /"}).output)

    ok, msg = cell.verify()
    print(f"\ntestimony: {ok} — {msg}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
