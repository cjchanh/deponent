#!/usr/bin/env python3
"""
minimal.py — the smallest possible demonstration: an agent's actions testify.

A Cell is a sovereign, local sandbox. Every action proposed against it is gated
(deny-by-default), executed only if allowed, and recorded to a tamper-evident
ledger. At the end you can PROVE what happened — or prove the record was altered.

Run:  python3 examples/minimal.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # run without install

from deponent import Cell

cell = Cell(tempfile.mkdtemp(), use_jail=False)  # use_jail=True on macOS adds the Seatbelt jail

# An agent proposes actions. The cell gates, executes, and records each one.
print(cell.act("write_file", {"path": "notes.txt", "content": "hello"}).output)
print(cell.act("read_file", {"path": "notes.txt"}).output)
print(cell.act("run_cmd", {"cmd": "rm -rf /"}).output)          # destructive  -> BLOCK
print(cell.act("exfiltrate", {"to": "evil.example"}).output)    # unknown tool -> BLOCK (deny-by-default)

ok, msg = cell.verify()   # recompute the hash chain — prove it was not tampered with
print(f"\ntestimony intact: {ok} — {msg}")
for e in cell.ledger.entries:
    print(f"  {e['verdict']:5} {e['tool']:11} [{e['blast_class']}]")
