# Rust adapter contract for the GAK conformance harness

An external kernel can use the Python harness through
`deponent.adapters.contract.KernelAdapter`. It is also re-exported from
`deponent.conformance`, but **not** from `deponent.adapters`.

The harness evaluates fixed probes. The adapter is trusted to exercise its kernel
honestly; hard-coded success answers do not establish the underlying behavior.

## Metadata

The Python shim exposes:

```python
name: str
profile: str              # "action-gate" or "commit-gate"
supports: frozenset[str]  # optional: "reconcile", "attest"
```

The Rust signatures below describe semantics. A Python shim must translate Python
dictionaries and results to the Rust implementation's types. They are not a
complete Rust crate or a verified binding.

## Required action-gate methods

```rust
fn verdict(&self, tool: &str, params: &HashMap<String, String>) -> String;
fn jail_fails_closed(&self) -> bool;
```

`verdict` classifies and returns exactly `"ALLOW"` or `"BLOCK"`. **Do not execute
commands supplied by classification probes.** The destructive-floor probe uses a
destructive command to test refusal, not effects.

`jail_fails_closed` must exercise the unavailable-confinement path and confirm
refusal to execute. It is required for an action-gate adapter. A missing method
raises inside the check and becomes FAIL, not NA.

| Clause | Current probe |
|---|---|
| `GAK-DENY-DEFAULT` | Unknown tool must be BLOCK |
| `GAK-ALLOW-INBOUNDS` | `write_file` of `ok.txt` with content `x` must be ALLOW |
| `GAK-PATH-CONTAINMENT` | Write outside the workspace must be BLOCK |
| `GAK-DESTRUCTIVE-FLOOR` | Destructive command must be BLOCK; classification only |
| `GAK-PROGRAM-ALLOWLIST` | Non-allowlisted program must be BLOCK |
| `GAK-JAIL-FAILS-CLOSED` | `jail_fails_closed()` must return true |

Use [CLAUSES](../deponent/conformance.py) for exact inputs. The current set has no
`GAK-REDIRECT-DENIED` or `GAK-NEWLINE-CHAINED` clauses. Deponent's separate gate
regressions cover those behaviors; they are not part of an external adapter's
conformance result.

## Required commit-gate methods

```rust
fn commit_verdict(&self, files: &[&str]) -> String;
fn commit_testifies(&self, files: &[&str]) -> bool;
```

| Clause | Current probe |
|---|---|
| `GAK-COMMIT-DENY-SECURITY` | `crypto/vault.py` must be BLOCK |
| `GAK-COMMIT-ALLOW-CLEAN` | `README.md` must be ALLOW |
| `GAK-COMMIT-TESTIFIES` | Refusal of `crypto/vault.py` must still be recorded |

Action-gate clauses, including the jail clause, report NA for a commit-gate adapter.

## Universal and optional methods

Every adapter must exercise and report:

```rust
fn clean_chain_verifies(&self) -> bool;
fn tamper_is_detected(&self) -> bool;
```

An action-gate adapter claiming `"reconcile"` also needs:

```rust
fn reconcile_catches_undeclared(&self) -> bool;
```

Either profile claiming `"attest"` also needs:

```rust
fn attest_abstains_when_unproven(&self) -> bool;
```

Unsupported optional capabilities and out-of-profile clauses report NA.
Exceptions inside required checks report FAIL. Do not present NA as proof of a
behavior the adapter cannot support.

## Connect a Python shim

Implement a shim around a Rust CLI or library and call the harness directly. Once
an application-owned `my_kernel_adapter` module supplies `MyKernelAdapter`:

```python
import json
from deponent.conformance import run_conformance
from my_kernel_adapter import MyKernelAdapter  # supplied by your integration

receipt = run_conformance(MyKernelAdapter())
print(json.dumps(receipt.to_dict(), indent=2))
raise SystemExit(0 if receipt.conformant else 1)
```

The stock CLI's `--kernel` choices come from
`deponent.adapters.BUILTIN_ADAPTERS`, which currently contains only `deponent`.
There is no entry-point discovery or CLI external-adapter loader. Dropping a shim
into a directory does not register it. A source integration needing a new CLI name
must explicitly register its adapter and test that distribution. Direct
`run_conformance()` use needs no registry change.

## Native Rust harness

A native implementation can port the clauses and receipt semantics. Pin the
reference revision, reproduce profile/capability filtering and error behavior,
and compare correct and deliberately broken kernels. No Rust implementation or
cross-language equivalence is verified by this document.

## Receipts and reference code

`ConformanceReceipt.to_dict()` returns `kernel`, `profile`, `conformant`, `counts`,
and `clauses`. Each clause has `id`, `profile`, `status`, and `detail`. Counts come
from actual results. When all applicable probes pass, the current built-in adapter
returns 10 PASS, 0 FAIL, and 3 NA. This is self-assessed conformance, not external
certification or proof that a target machine's jail has been tested.

- [Protocol](../deponent/adapters/contract.py)
- [Built-in action-gate adapter](../deponent/adapters/deponent.py)
- [Clause definitions](../deponent/conformance.py)
- [CLI registry](../deponent/adapters/__init__.py)

The source Sworn wrappers are legacy, excluded from distribution, and not current
built-in validators.
