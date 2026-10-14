# Deponent SDK — Public API Surface Inventory

Generated during Phase 1 of the GAK SDK extraction plan.

## Baseline test status

| Repo | Command | Result |
|---|---|---|
| `deponent` | `python3 -m pytest --collect-only -q` | 181 tests across 19 files (this checkout) |
| downstream consumers | not re-run from this repo | out of scope for a deponent-only checkout |

## Module inventory

| Module | Current public symbols | Role |
|---|---|---|
| `deponent` (package) | `Cell`, `ActResult`, `Gate`, `GateDecision`, `DENY_SUBSTR`, `ALLOW_HEADS`, `build_gate`, `build_cell`, `Ledger`, `Claim`, `ClaimSet`, `attest`, `jail_available`, `jail_command`, `run_jailed`, `persist`, `verify`, `write_operator_receipt`, `__version__` | Convenience re-exports |
| `deponent.gate` | `Gate`, `GateDecision`, `DENY_SUBSTR`, `ALLOW_HEADS` | Deny-by-default action classifier |
| `deponent.cell` | `Cell`, `ActResult` | Gate → execute → ledger wrapper |
| `deponent.ledger` | `Ledger` | Tamper-evident hash chain |
| `deponent.receipts` | `persist`, `verify`, `write_operator_receipt`, `RECEIPTS_ROOT`, `PRODUCER`, `RECEIPT_SCHEMA` | Verifiable receipt persistence |
| `deponent.profiles` | `build_gate`, `build_cell`, `BUILD_ALLOW_HEADS`, `BUILD_DENY_SUBSTR`, `BUILD_DENY_EXTRA` | Pre-tuned policy profiles |
| `deponent.jail` | `jail_available`, `jail_command`, `run_jailed` | macOS Seatbelt sandbox wrapper |
| `deponent.reconcile` | `ReconcileReport`, `snapshot`, `reconcile_action` | Two-plane declared-vs-observed diff |
| `deponent.attest` | `Claim`, `ClaimSet`, `attest`, `map_decision`, `ledger_to_ext_trace`, `cell_results_to_ext_trace`, `render_coverage` | Compliance coverage derivation |
| `deponent.conformance` | `KernelAdapter`, `Clause`, `ClauseResult`, `ConformanceReceipt`, `CLAUSES`, `run_conformance`, `DeponentAdapter` | Cross-kernel GAK conformance harness |
| `deponent.sworn_adapter` | `SwornAdapter` | Commit-gate adapter for sworncode |
| `deponent.reach` | `ReachOracle`, `ReachReport`, `classify_reach` | Graph-derived blast radius |
| `deponent.selfgate`, `claims`, `operator_attest`, `jail_backends` | Internal / advanced | Extensions and attest plumbing |

## Stable public surface (Phase 2 target)

These are the symbols the SDK guarantees for external consumers:

```python
from deponent import (
    Cell, ActResult,
    Gate, GateDecision,
    Ledger,
    persist, verify, write_operator_receipt,
    build_gate, build_cell,
    __version__,
)
```

Advanced but documented:

```python
from deponent import (
    Claim, ClaimSet, attest,
    jail_available, run_jailed,
)
```

## Internal / provisional surface

These should not be in the top-level `__all__` until stabilized:

- `deponent.reconcile` internals (optional capability)
- `deponent.operator_attest` (Ed25519, opt-in security surface)
- `deponent.selfgate` (dogfooding deponent's own git commits)
- `deponent.reach` graph plumbing (experimental)

## consumer-kernel compatibility matrix

| consumer-kernel symbol | deponent equivalent | Action |
|---|---|---|
| `cds_gate.CDSGate` | `deponent.gate.Gate` | Direct replacement; identical behavior |
| `cds_gate.GateDecision` | `deponent.gate.GateDecision` | Direct replacement |
| `cds_gate.AuditChain` | `deponent.ledger.Ledger` | Direct replacement; same `GENESIS`, `_hash`, `verify_entries` |
| `receipt_adapter.persist_chain` | `deponent.receipts.persist` | Add a caller-supplied `producer=` override |
| `receipt_adapter.verify_receipt` | `deponent.receipts.verify` | Add a caller-supplied `producer=` override |
| `dst_conformance.FaultyAuditChain` | No direct equivalent | Keep as consumer-kernel-specific adapter; may move to deponent later |
| `dst_conformance.RunResult / Receipt` | No direct equivalent | Keep as DST harness types |

## Notable deltas

1. **Policy defaults are identical.** Both use the same `DENY_SUBSTR` and `ALLOW_HEADS` tuples/frozensets.
2. **Ledger vs AuditChain naming.** deponent calls the chain `Ledger`; consumer-kernel calls it `AuditChain`. Same implementation.
3. **Receipt schema field names differ slightly.** consumer-kernel adds `gate_version`; deponent adds `schema`. A compatibility wrapper is trivial.
4. **deponent has jail + reconcile + attest; consumer-kernel does not.** consumer-kernel gets these for free by importing deponent.
5. **consumer-kernel's `dst_conformance.py` is a specialized DST harness for the gate.** It can stay in consumer-kernel as a deponent-compatible conformance test.

## Recommended extraction order

1. Stabilize deponent public API (Phase 2).
2. Port consumer-kernel `cds_gate.py` → `deponent.gate` / `deponent.ledger` (Phase 3).
3. Port consumer-kernel `receipt_adapter.py` → `deponent.receipts` (Phase 3).
4. Promote conformance harness to CLI (Phase 4).
5. Write SDK docs, SafetySpine example, Rust adapter spec (Phase 5).

## Risk notes

- The top-level `deponent/__init__.py` currently re-exports `DENY_SUBSTR` / `ALLOW_HEADS`. Keeping these as mutable module globals in the public API is acceptable because consumers can pass custom tuples to `Gate`, but we should document that mutating the module globals affects all default gates.
- `deponent.cell.Cell.__init__` has a `use_jail=True` default. On non-macOS platforms `jail_available()` returns False and commands fail closed. This is correct but must be documented for external users.
