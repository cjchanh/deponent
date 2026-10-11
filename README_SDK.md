# Deponent — GAK SDK for Python

Deponent is a standard-library-only core for classifying an agent's tool calls,
executing allowed actions, and recording decisions in a tamper-evident hash chain.
It is a research prototype, not a security accreditation. The caller must route
its actions through `Cell`.

```bash
pip install deponent
```

This guide describes the 0.2.0 source tree. It does not establish that the same
version has been published to a package index.

## Quickstart

This gate-only example uses a temporary workspace and a disposable deletion
target. Gate-only mode has no OS confinement.

```python
import tempfile
from pathlib import Path
from deponent import Cell

with tempfile.TemporaryDirectory() as work:
    sentinel = Path(work) / "blocked-example" / "sentinel.txt"
    sentinel.parent.mkdir()
    sentinel.write_text("keep", encoding="utf-8")
    cell = Cell(work, use_jail=False)
    written = cell.act("write_file", {"path": "notes.txt", "content": "hello"})
    refused = cell.act("run_cmd", {"cmd": "rm -rf ./blocked-example"})
    assert written.allowed
    assert (Path(work) / "notes.txt").read_text(encoding="utf-8") == "hello"
    assert refused.decision.verdict == "BLOCK"
    assert refused.entry["verdict"] == "BLOCK"
    assert sentinel.read_text(encoding="utf-8") == "keep"
    ok, message = cell.verify()
    assert ok, message
    print(message)  # chain intact (2 entries)
```

## Core concepts

| Primitive | What it does | Class / function |
|---|---|---|
| Gate | Classifies the configured surface; unknown tools are denied | `deponent.Gate` |
| Cell | Gate → execute → ledger | `deponent.Cell` |
| Ledger | Hash-linked decision record | `deponent.Ledger` |
| Receipt | Persisted, re-verifiable record | `deponent.persist`, `deponent.verify` |
| Profile | Workload policy | `deponent.build_gate`, `deponent.build_cell` |

`ActResult.allowed` describes the policy verdict. An execution error can still
have an ALLOW verdict; inspect the output and verify the intended result.

## Govern a custom tool surface

Extend **both** `Gate.evaluate()` and `Cell._execute()`, then pass the custom gate
to the cell. An execution override alone cannot admit an unknown tool.

This example only simulates browsing. The exact-URL rule illustrates the wiring;
it is not a production browser security policy.

```python
import tempfile
from deponent import Cell, Gate, GateDecision

class BrowserGate(Gate):
    def evaluate(self, tool: str, params: dict) -> GateDecision:
        if tool == "browse":
            if params.get("url") == "https://example.com/docs":
                return GateDecision("ALLOW", "browser-demo", "approved demo URL")
            return GateDecision("BLOCK", "browser-demo", "URL is not approved")
        return super().evaluate(tool, params)

class BrowserCell(Cell):
    def _execute(self, tool: str, params: dict) -> str:
        if tool == "browse":
            return f"would browse {params['url']}"
        return super()._execute(tool, params)

with tempfile.TemporaryDirectory() as work:
    cell = BrowserCell(work, gate=BrowserGate(work), use_jail=False)
    allowed = cell.act("browse", {"url": "https://example.com/docs"})
    refused = cell.act("browse", {"url": "https://unapproved.example"})
    assert allowed.allowed and allowed.output == "would browse https://example.com/docs"
    assert refused.decision.verdict == "BLOCK"
    assert cell.act("unknown_tool", {}).decision.verdict == "BLOCK"
    assert cell.verify()[0]
```

See [examples/custom_tool.py](examples/custom_tool.py) for another simulation.
A custom `_execute()` does not automatically run inside the command jail; its
implementation must provide confinement appropriate to that tool.

## Run GAK conformance

```bash
python3 -m deponent.conform --kernel deponent
python3 -m deponent.conform --kernel deponent --out receipt.json
python3 -m deponent.conform --list-clauses
```

The current harness contains 13 clauses. For the built-in Deponent action-gate
adapter, 10 apply and three commit-gate clauses report NA. Required checks cover
unknown-tool refusal, an allowed inbounds write, path escape, a destructive
command, the program allowlist, jail fail-closed behavior, an intact chain, and
tamper detection. Reconciliation and attestation checks apply when the adapter
claims those capabilities.

Conformance is a **self-assessed result for these probes**. Redirect and newline
handling have separate gate regression tests; the conformance clause set does
not probe them. A conformant receipt does not establish those properties for an
arbitrary adapter, live OS confinement, or external certification.

## Rust and other kernels

See [docs/RUST_ADAPTER_SPEC.md](docs/RUST_ADAPTER_SPEC.md). External adapters can
call `run_conformance(adapter)` directly. The CLI currently recognizes only the
built-in `deponent` adapter; creating a shim does not register a CLI name.

## Security posture

- Default policy denies unknown tools and checks paths and command syntax. It
  cannot inspect every effect of allowed code.
- Gate-only commands use one tokenized argv with `shell=False`. Interpreters and
  additional program heads require explicit opt-ins in both Cell and Gate.
- Jailed commands use Seatbelt on macOS or Docker elsewhere when the selected
  backend is available. Otherwise execution is refused. Availability is not proof
  of containment; see the Cell/jail control-file risks and Docker verification
  limits in the [threat model](docs/THREAT_MODEL.md).
- The ledger stores request parameters and reasons in plaintext. There is no
  content-blind mode. Do not pass secrets expecting hashing to hide them.
- Hashes detect inconsistent edits. They do not authenticate authorship or stop
  complete record replacement followed by recomputation of all hashes.

## Optional dependencies

The core uses only the Python standard library. Optional extras are separate:

```bash
pip install 'deponent[mlx]'     # Apple MLX example backend
pip install 'deponent[attest]'  # Ed25519 operator attestation
pip install 'deponent[dev]'     # pytest + cryptography
```

Coverage claims live in `deponent.claims`; the top-level `attest` callable comes
from that module. The optional `deponent.attest` module exports operator-attestation
records and requires the cryptography extra.

## Links

- [Full README](README.md)
- [Public API inventory](API_SURFACE.md)
- [Conformance harness](deponent/conformance.py)
- [Threat model](docs/THREAT_MODEL.md)
