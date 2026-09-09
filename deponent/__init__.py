"""Deponent — deny-by-default gate, jail, and tamper-evident ledger for agent tool calls.

    import tempfile
    from deponent import Cell
    cell = Cell(tempfile.mkdtemp(), use_jail=False)
    print(cell.act("run_cmd", {"cmd": "rm -rf ./blocked-example"}).output)
"""

from __future__ import annotations

from .cell import ActResult, Cell
from .claims import Claim, ClaimSet, attest
from .gate import ALLOW_HEADS, DENY_SUBSTR, Gate, GateDecision
from .jail import jail_available, jail_command, run_jailed
from .ledger import Ledger
from .profiles import build_cell, build_gate
from .receipts import persist, verify, write_operator_receipt

__version__ = "0.1.2"

__all__ = [
    "Cell",
    "ActResult",
    "Gate",
    "GateDecision",
    "DENY_SUBSTR",
    "ALLOW_HEADS",
    "build_gate",
    "build_cell",
    "Ledger",
    "Claim",
    "ClaimSet",
    "attest",
    "jail_available",
    "jail_command",
    "run_jailed",
    "persist",
    "verify",
    "write_operator_receipt",
    "__version__",
]
