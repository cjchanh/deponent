# Deponent SDK — public API inventory

This inventory describes the 0.2.0 source tree. Listed symbols are present in that
tree; provisional APIs are not a compatibility promise. Host-specific verification
is recorded in [docs/SDK_REVIEW_VERIFICATION.md](docs/SDK_REVIEW_VERIFICATION.md).

## Module inventory

| Module | Public symbols | Role |
|---|---|---|
| `deponent` | `Cell`, `ActResult`, `Gate`, `GateDecision`, `DENY_SUBSTR`, `ALLOW_HEADS`, `build_gate`, `build_cell`, `Ledger`, `Claim`, `ClaimSet`, `attest`, `jail_available`, `jail_command`, `run_jailed`, `persist`, `verify`, `write_operator_receipt`, `__version__` | Standard-library-only convenience exports |
| `deponent.gate` | `Gate`, `GateDecision`, `DENY_SUBSTR`, `ALLOW_HEADS` | Action classification and policy defaults |
| `deponent.cell` | `Cell`, `ActResult` | Gate → execute → ledger |
| `deponent.ledger` | `Ledger`, `LedgerForkError` | Hash chain and stale-writer refusal |
| `deponent.receipts` | `persist`, `verify`, `write_operator_receipt`, `RECEIPTS_ROOT`, `PRODUCER`, `RECEIPT_SCHEMA` | Receipt persistence and verification |
| `deponent.profiles` | `build_gate`, `build_cell`, `BUILD_ALLOW_HEADS`, `BUILD_DENY_SUBSTR`, `BUILD_DENY_EXTRA` | Workload policy profiles |
| `deponent.jail` | `jail_available`, `jail_command`, `write_profile`, `run_jailed`, `select_backend`, `SeatbeltBackend`, `DockerBackend`, `SANDBOX_EXEC` | Backend dispatch; `jail_command` is Seatbelt-specific |
| `deponent.reconcile` | `ReconcileReport`, `snapshot`, `reconcile_action` | Observed versus declared workspace changes |
| `deponent.claims` | `Claim`, `ClaimSet`, `attest` | Coverage derivation; no cryptography dependency |
| `deponent.attest` | `EXPORT_SCHEMA`, `attestation_record`, `demo_attestation_record` | Optional operator-attestation export; requires `deponent[attest]` |
| `deponent.conformance` | `KernelAdapter`, `Clause`, `ClauseResult`, `ConformanceReceipt`, `CLAUSES`, `run_conformance`, `DeponentAdapter` | Executable conformance probes |
| `deponent.adapters.contract` | `KernelAdapter` | Protocol definition |
| `deponent.adapters` | `DeponentAdapter` | Built-in adapter export; no `KernelAdapter` re-export |
| `deponent.reach` | `ReachOracle`, `ReachReport`, `ImportGraphReach` | Experimental graph-derived reach |

`deponent/adapters/sworn.py` and `deponent/sworn_adapter.py` are **source-only
legacy wrappers**, excluded from the distribution. Sworn is not the current
built-in validator. The built-in registry contains only `deponent`.

There is no `deponent.jail_backends` module; backend classes live in
`deponent.jail`. There is no `classify_reach` function; use the reach types above.

## Common imports

```python
from deponent import (
    Cell, ActResult, Gate, GateDecision, Ledger,
    persist, verify, write_operator_receipt,
    build_gate, build_cell, __version__,
)
from deponent.claims import Claim, ClaimSet, attest
from deponent.adapters.contract import KernelAdapter
from deponent.conformance import run_conformance
```

The top-level `attest` callable is the coverage function from `deponent.claims`.
Keep it distinct from the optional `deponent.attest` **module**. Import the
coverage function from `deponent.claims` when using both surfaces in one process.

## Provisional and optional surfaces

- `deponent.reach`: experimental graph plumbing.
- `deponent.reconcile`: optional observed-versus-declared checking.
- `deponent.operator_attest`: opt-in Ed25519 surface requiring cryptography.
- `deponent.selfgate`: repository commit checks, not a top-level SDK export.
- Backend-specific jail helpers: host-dependent and subject to the
  [threat model](docs/THREAT_MODEL.md); availability is not security assurance.

## Migration from an earlier consumer kernel

The earlier consumer implementation is not part of this checkout. These are
integration targets, not a verified behavioral-equivalence claim.

| Earlier consumer concept | Candidate interface | Required integration check |
|---|---|---|
| Action classifier | `deponent.gate.Gate` | Compare policy, verdicts, and gate-only settings on the consumer's corpus |
| Audit chain | `deponent.ledger.Ledger` | Compare serialization, load/append behavior, anchors, and errors |
| Persist a chain | `deponent.receipts.persist` | Supply `producer=` and `root=`; translate metadata deliberately |
| Verify a receipt | `deponent.receipts.verify` | Use the same producer/root; establish accepted schemas |
| Consumer-specific fault injection | Consumer's harness | Preserve its acceptance criteria and compare outcomes |

Downstream consumers have not been tested in this documentation repair.

## Policy and platform behavior

`DENY_SUBSTR` is a tuple and `ALLOW_HEADS` is a frozenset. `Gate.__init__` captures
its defaults at function definition and copies policy per instance. Rebinding
those module names does **not** change new default gates. Configure each gate
explicitly, preserving the defaults when adding a restriction:

```python
from deponent import Gate, DENY_SUBSTR, ALLOW_HEADS

def restricted_gate(workspace):
    return Gate(
        workspace,
        deny=DENY_SUBSTR + ("example-denied-token",),
        allow_heads=ALLOW_HEADS,
    )
```

`Cell` defaults to `use_jail=True`. macOS selects Seatbelt; other platforms select
Docker. Docker availability requires the CLI and a responding daemon. With no
backend, jailed commands are refused. Docker remains DRAFT in its class and tests,
despite a conflicting historical module-level claim; run the opt-in live tests on
the target host before claiming confinement. The threat model retains the detailed
limits, including the Cell/jail control-file issue.
