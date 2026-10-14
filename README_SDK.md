# Deponent — GAK SDK for Python

**A governed sovereign agent kernel. It doesn't answer. It testifies.**

`deponent` is a small, zero-dependency Python SDK that turns any local AI agent's
tool calls into a verifiable record: every action is gated before it runs, and the
decision is appended to a tamper-evident hash chain.

```bash
pip install deponent
```

## Five-line quickstart

```python
import tempfile
from deponent import Cell

cell = Cell(tempfile.mkdtemp(), use_jail=False)
cell.act("write_file", {"path": "notes.txt", "content": "hello"})
cell.act("run_cmd", {"cmd": "rm -rf /"})   # BLOCKED

ok, msg = cell.verify()
print(ok, msg)  # True  chain intact (2 entries)
```

## Core concepts

| Primitive | What it does | Class / function |
|---|---|---|
| **Gate** | deny-by-default classifier | `deponent.Gate` |
| **Cell** | gate → execute → ledger | `deponent.Cell` |
| **Ledger** | tamper-evident hash chain | `deponent.Ledger` |
| **Receipt** | persisted, re-verifiable record | `deponent.persist`, `deponent.verify` |
| **Profile** | pre-tuned policy (build, sandbox) | `deponent.build_gate`, `deponent.build_cell` |

## Govern a custom tool surface

Subclass `Cell` and override `_execute` to govern any tool surface — not just
files and shell. See `examples/custom_tool.py`.

```python
from deponent import Cell

class BrowserCell(Cell):
    def _execute(self, tool: str, params: dict) -> str:
        if tool == "browse":
            return f"would browse {params['url']}"
        return super()._execute(tool, params)
```

## Run GAK conformance

```bash
python3 -m deponent.conform --kernel deponent
python3 -m deponent.conform --kernel deponent --out receipt.json
python3 -m deponent.conform --list-clauses
```

A kernel is **GAK-conformant** when every required clause passes: deny-default,
allow inbounds, path containment, destructive floor, program allowlist,
redirect-denied, newline-chained command heads, jail-fails-closed, chain
intact, tamper-evident, and optional reconcile/attest honesty.

## For Rust kernels

See `docs/RUST_ADAPTER_SPEC.md` for the language-neutral `KernelAdapter`
contract. Implement the same interface in Rust and expose it to the Python
conformance harness (or implement an equivalent harness in Rust) without
inventing a second standard.

## Security posture

- Fail-closed: unknown tool / path escape / destructive command / network /
  privilege → BLOCK.
- Tamper-evident: sha256 hash chain; mutating any entry breaks re-verification.
- No key material in the core. Ed25519 operator attestation is opt-in only.
- macOS Seatbelt jail confines in-tool effects when `use_jail=True`.

## Zero dependencies

The core SDK uses only the Python standard library. Optional extras:

```bash
pip install deponent[mlx]     # Apple MLX example backend
pip install deponent[attest]  # Ed25519 operator attestation
pip install deponent[dev]     # pytest + cryptography
```

## Links

- Full README: `README.md`
- Conformance harness: `deponent/conformance.py`
- Examples: `examples/`
- Rust adapter spec: `docs/RUST_ADAPTER_SPEC.md`
