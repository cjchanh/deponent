"""
Deponent — a governed sovereign agent kernel.

Make any local AI agent testify. A small, model-agnostic governance layer that
sits under an agent's tool calls and turns "trust me, it ran fine" into a
verifiable record:

    deny-by-default Gate  ->  Seatbelt jail  ->  tamper-evident Ledger  ->  Receipt

It does not answer. It testifies.

Quickstart
----------
    from deponent import Cell

    cell = Cell("/tmp/agent-workdir")          # a sovereign, local sandbox
    print(cell.act("run_cmd", {"cmd": "rm -rf /"}).output)   # BLOCKED [destructive...]
    print(cell.act("write_file", {"path": "hi.txt", "content": "ok"}).output)  # wrote 2 bytes
    ok, msg = cell.verify()                    # prove the testimony intact
    print(ok, msg)                             # True  chain intact (2 entries)

The pieces compose at every scale: one tool call, one agent, a whole team. See
examples/ for a model-agnostic governed agent team (North Mini Code, Ollama, or
any backend you plug in).
"""
from __future__ import annotations

from .cell import ActResult, Cell
from .claims import Claim, ClaimSet, attest
from .gate import ALLOW_HEADS, DENY_SUBSTR, Gate, GateDecision
from .jail import jail_available, jail_command, run_jailed
from .ledger import Ledger
from .profiles import build_cell, build_gate
from .receipts import persist, verify, write_operator_receipt

__version__ = "0.1.0"

__all__ = [
    "Cell", "ActResult",
    "Gate", "GateDecision", "DENY_SUBSTR", "ALLOW_HEADS",
    "build_gate", "build_cell",
    "Ledger",
    "Claim", "ClaimSet", "attest",
    "jail_available", "jail_command", "run_jailed",
    "persist", "verify", "write_operator_receipt",
    "__version__",
]
