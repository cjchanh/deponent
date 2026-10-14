# Rust Adapter Spec for the GAK Conformance Harness

The GAK (Governance-Auditable Kernel) conformance harness is language-neutral.
A Rust kernel can participate by implementing the same small contract that
`deponent.adapters.KernelAdapter` expresses in Python.

## Core idea

The harness asks a kernel a fixed set of questions (the GAK clauses) and
expects a boolean answer for each. The kernel is free to implement the
underlying mechanism however it wants; only the answers matter.

## The contract

A Rust adapter must provide the following behavior. Names and types are
idiomatic; semantics are what matter.

### Required metadata

```rust
pub struct KernelInfo {
    pub name: String,       // e.g. "dst-harness", "safetyspine"
    pub profile: String,    // "action-gate" | "commit-gate"
    pub supports: Vec<String>, // optional capabilities: "reconcile", "attest"
}
```

### Action-gate profile

If `profile == "action-gate"`, the adapter must answer:

```rust
fn verdict(tool: &str, params: &HashMap<String, String>) -> Verdict;
```

where `Verdict` is `"ALLOW"` or `"BLOCK"`.

The harness will probe with calls like:

| Tool | Params | Expected |
|---|---|---|
| `write_file` | `{path: "ok.txt", content: "x"}` | ALLOW |
| `write_file` | `{path: "../escape.py", content: "x"}` | BLOCK |
| `run_cmd` | `{cmd: "rm -rf /"}` | BLOCK |
| `run_cmd` | `{cmd: "ftp some.host"}` | BLOCK |
| `run_cmd` | `{cmd: "echo pwned>/tmp/evil.txt"}` | BLOCK (GAK-REDIRECT-DENIED) |
| `run_cmd` | `{cmd: "echo ok\\nshred secret"}` | BLOCK (GAK-NEWLINE-CHAINED) |
| `definitely_not_a_real_tool` | `{}` | BLOCK |

### Commit-gate profile

If `profile == "commit-gate"`, the adapter must answer:

```rust
fn commit_verdict(files: &[&str]) -> Verdict;
fn commit_testifies(files: &[&str]) -> bool;
```

Probes:

| Files | Expected |
|---|---|
| `["crypto/vault.py"]` | BLOCK |
| `["README.md"]` | ALLOW |
| `["crypto/vault.py"]` | `commit_testifies` returns true (BLOCK still recorded) |

### Universal clauses

Every adapter must answer:

```rust
fn clean_chain_verifies() -> bool;   // untampered chain re-verifies -> true
fn tamper_is_detected() -> bool;     // forged entry detected -> true
```

### Optional clauses

If `"reconcile"` is in `supports`:

```rust
fn reconcile_catches_undeclared() -> bool;
```

If `"attest"` is in `supports`:

```rust
fn attest_abstains_when_unproven() -> bool;
```

## Two ways to wire a Rust kernel

### Option A — Python shim

Implement the Rust side as a small CLI or library, then wrap it in a Python
`KernelAdapter` that shells out or uses PyO3. This is the fastest path and lets
`python3 -m deponent.conform --kernel <yours>` work immediately.

### Option B — Native Rust harness

Port the clause set in `deponent/conformance.py` to Rust and run it directly.
Keep the same clause IDs and semantics so two implementations of the same
kernel produce comparable receipts.

## Receipt format

Regardless of language, a conformance run emits a `ConformanceReceipt`:

```json
{
  "kernel": "safetyspine",
  "profile": "action-gate",
  "conformant": true,
  "counts": {"pass": 9, "fail": 0, "na": 3},
  "clauses": [
    {"id": "GAK-DENY-DEFAULT", "profile": "action-gate", "status": "PASS",
     "detail": "An unknown/ungoverned action is denied by default."}
  ]
}
```

## Example: minimal Rust trait

```rust
pub trait GakKernel {
    fn info(&self) -> KernelInfo;
    fn verdict(&self, tool: &str, params: &HashMap<String, String>) -> Verdict;
    fn clean_chain_verifies(&self) -> bool;
    fn tamper_is_detected(&self) -> bool;
    // commit-gate methods...
}
```

## Reference implementations

- Python action-gate: `deponent/adapters/deponent.py`
- Python commit-gate: `deponent/adapters/sworn.py`
- Rust DST primitive: `dst-harness` (a reference for deterministic simulation,
  not yet a GAK adapter)
