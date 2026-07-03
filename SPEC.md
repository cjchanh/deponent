# Deponent — Governance Contract & Threat Model (SPEC.md)

> It doesn't answer. It testifies.

Deponent is a small, model-agnostic governance layer that sits under a local AI
agent's tool calls and turns "trust me, it ran fine" into a record you can check.
The core is ~735 lines of pure Python, standard-library only, no third-party
dependencies (`deponent/{gate,jail,ledger,receipts,cell,__init__}.py`). Version
`0.1.0`. License: Apache-2.0.

This document is the contract an engineer needs to decide whether to put Deponent
in their stack, and the threat model a security reviewer needs to audit it. It is
deliberately explicit about what is **not** covered. Those limits are the product,
not a disclaimer.

---

## 1. Protected output and the core invariant

**Protected output: the host** — the filesystem outside the sandbox directory, the
network, the user's privileges, and any state an agent's action could reach that is
irreversible or out-of-bounds.

**Core invariant:**

> Nothing irreversible or out-of-sandbox executes without a recorded ALLOW. The
> agent saying "done" is never the evidence.

Two halves enforce this:

- **No silent execution.** Every action routes through one `Cell.act()` call
  (`cell.py:62`). It is gated *before* it runs and recorded *after*. A BLOCK is
  recorded too — the testimony includes what was refused (`test_cell.py:25`,
  `cell.py:65`).
- **No self-reported closure.** Closure is not the agent's claim. It is
  `Ledger.verify()` recomputing the hash chain (`ledger.py:85`) and, at write
  time, the receipt verifier recomputing both the chain and the receipt signature
  (`receipts.py:121`). Both *recompute*; neither trusts a stored boolean. This is
  the rule the whole project is built on: **self-reported health is never the
  evidence** (`receipts.py:18`).

The reference agent team (`examples/governed_team.py`) shows the invariant in
practice: when the Builder model says "done," the harness re-runs pytest
out-of-band and pushes back if it isn't actually green (`governed_team.py:91-105`);
certification anchors only on deterministic signals — out-of-band test pass, intact
chain, rogue action proven blocked — with the LLM Reviewer explicitly **advisory,
recorded but not gating** (`governed_team.py:214-219`).

---

## 2. The five pillars

| Pillar | Where | What it means here |
|---|---|---|
| **Deny-by-default** | `gate.py:96-113` | An unrecognized tool returns `BLOCK / unknown-tool`. Nothing is permitted unless a policy branch explicitly allows it (`test_gate.py:63`, `test_cell.py:33`). |
| **Fail-closed** | `gate.py`, `jail.py:81`, `cell.py:109` | Unknown tool, unparsable command, path escape → BLOCK. Off macOS, `run_cmd` **refuses to execute un-jailed** rather than degrade to a bare run. |
| **Dry-run / gate-before-destructive** | `cell.py:62-79` | The gate classifies blast radius *before* any execution. Destructive/irreversible signatures (`rm -rf`, `mkfs`, `dd`, `sudo`, …) never reach the shell (`gate.py:48-57`, `test_gate.py:34`). |
| **Independent audit** | `ledger.py` | Every decision + a hash of its outcome is appended to a tamper-evident chain, verifiable after the fact by re-linking from genesis — a path independent of the agent's own status signal. |
| **Bounded execution** | `jail.py` | Seatbelt jail: no network, writes confined to the sandbox, CPU/file-size rlimits, plus RSS-polling and wall-clock watchdogs that kill runaways (`jail.py:108-149`). |

### Deny-by-default gate (`gate.py`)

The gate governs the **shell + path surface**: which programs may run, which paths
may be touched, and whether a command chains or substitutes its way out of policy.
It blocks, in order:

- **Unknown tool** — any tool with no policy branch (`gate.py:113`).
- **Path escape, read and write** — a path that resolves outside the sandbox
  (`gate.py:99-106`); absolute paths and `../` traversal are rejected
  (`test_gate.py:39-46`). Containment uses `Path.resolve()` and a prefix check,
  and rejects embedded NULs (`gate.py:85-93`).
- **Destructive / out-of-scope commands** — substring denylist covering
  irreversible (`rm -rf`, `rmdir`, `mkfs`, `dd if=/of=`, fork bombs, `shutdown`),
  network (`curl`, `wget`, `ssh`, `scp`, `nc`, `telnet`, `nmap`), privilege/system
  writes (`sudo`, `chmod`, `chown`, `/etc/`, `/usr/`, `launchctl`, `systemctl`),
  package installs, and home/parent references (`gate.py:48-57`).
- **Command substitution** — `$(...)`, backticks, `${...}` are rejected outright
  (`gate.py:65,122`, `test_gate.py:55`).
- **Shell chaining to a denied segment** — the command is split on `&&`, `||`, `;`,
  `|`, and **every** segment's program head must be in the allowlist, with every
  path-like argument contained in the sandbox (`gate.py:124-144`,
  `test_gate.py:59`).

It allows only an allowlist of coding programs — `python`, `python3`, `pytest`,
`ruff`, `black`, `mypy`, `ls`, `cat`, `grep`, `diff`, etc. (`gate.py:59-63`) — with
in-sandbox path arguments. The policy (`deny`, `allow_heads`) is module-level and
**overridable per `Gate` instance** (`gate.py:77-82`); the defaults are a sane
coding-agent sandbox, not a universal security policy.

### Bounded execution — the jail (`jail.py`)

The gate constrains the shell and paths; it does **not** constrain arbitrary code
*inside* an allowed command (an ALLOWed `python -c` can still run arbitrary Python
in the sandbox). The jail closes that gap. See §5.

---

## 3. Threat model

Honest surface-by-surface. "Covered" means there is code plus a passing test that
demonstrates the block; "Not covered" means out of scope for this reference layer.

| Surface | Status | Notes |
|---|---|---|
| Unknown / unmodeled tool | **Covered** | Deny-by-default BLOCK (`gate.py:113`, `test_gate.py:63`). |
| Path traversal out of sandbox (read + write) | **Covered** | `../`, absolute paths, NUL-injected paths rejected (`gate.py:85-106`, `test_gate.py:39-46`). |
| Destructive / irreversible shell commands | **Covered** | Denylist + tests (`gate.py:48-57`, `test_gate.py:34`). |
| Network egress via shell command | **Covered (gate)** | `curl`/`wget`/`ssh`/`nc`… blocked (`gate.py:51`). |
| Network egress from *inside* an allowed program | **Covered (jail, macOS)** | `(deny network*)` — sockets/urlopen fail (`jail.py:48`, `test_jail.py:44-50`). |
| Privilege escalation / system-dir writes | **Covered** | `sudo`, `chmod`, `/etc/`, `/usr/`, `launchctl`… blocked (`gate.py:54-55`, `test_gate.py:52`). |
| Command substitution / shell expansion | **Covered** | `$()`, backticks, `${}` rejected (`gate.py:122`, `test_gate.py:55`). |
| Chaining to a denied segment | **Covered** | Per-segment allowlist (`gate.py:124-144`, `test_gate.py:59`). |
| Arbitrary code inside an allowed program writing outside the sandbox | **Covered (jail, macOS)** | `(deny file-write*)` minus the sandbox subpath (`jail.py:48-53`, `test_jail.py:52-72`). |
| Child process escaping the sandbox | **Covered (jail, macOS)** | Children inherit the profile (`test_jail.py:66`). |
| Memory / fork bomb, wall-clock runaway | **Covered (jail, macOS)** | RSS watchdog + wall-clock kill, proven live (`jail.py:108-149`, `test_jail.py:86-100`). |
| Ledger tamper / reorder after the fact | **Covered (evident, not prevented)** | Detected on `verify()`; see §4 (`ledger.py:72-87`, `test_ledger.py:26-43`). |
| Receipt metadata tamper | **Covered (evident)** | Signature recomputed over canonical body (`receipts.py:139-142`, `test_receipts.py:58`). |
| Arbitrary code inside an allowed program on **Linux/Windows** | **Not covered** | The in-language jail is macOS-only; supply your own (firejail/nsjail/container). The gate refuses to run un-jailed off macOS. See §5. |
| An attacker who can rewrite the whole ledger file from genesis | **Not covered** | sha256 is tamper-evident, not signed; there is no authorship proof. See §4. |
| In-language exfiltration in **gate-only mode** (`use_jail=False`) | **Not covered** | No network/write confinement; use only where another sandbox wraps the process (`cell.py:114-119`). |
| Side channels, timing, supply-chain of the Python runtime itself | **Not covered** | Out of scope for a reference primitive. |
| Universal/production security policy | **Not covered** | Defaults are a coding-agent sandbox, overridable; this is a reference primitive, not a hardened production sandbox. |

**Continuously-verified vs. historical red-team.** The macOS jail tests that run on
every test run cover network egress, write-out, child-process containment,
memory-bomb kill, and wall-clock kill live, against the real `sandbox-exec`
(`test_jail.py:44-100`). Separately, a documented development red-team recorded 0 of
9 escape attempts succeeding against the jail, including the two real Seatbelt
bypasses — `osascript 'do shell script'` (the spawned shell stays sandboxed) and
`launchctl submit` (no stray job left) — plus loopback `/dev/tcp` egress, DNS, and
symlink/hardlink/rename writes-out. Those nine are a development record, not a
continuously-run suite; the live coverage above is what runs in CI.

---

## 4. The ledger's exact guarantee

The ledger (`ledger.py`) is an **append-only sha256 hash chain**. Each entry stores
who/what/the verdict/a sha256 of the outcome, plus `prev_hash` and `entry_hash`;
`entry_hash = sha256(prev_hash + "\n" + canonical_json(payload))`, genesis-anchored
(`ledger.py:41-63`). The outcome is stored as a hash, not verbatim, so the ledger
testifies that a specific output occurred without becoming a data-exfiltration sink
(`ledger.py:46-59`).

**The precise claim — and its bound:**

- It is **tamper-evident**, not tamper-proof. Mutating or reordering any entry
  breaks the re-link, and `verify()` returns `(False, location)` naming the first
  broken entry (`ledger.py:72-83`, `test_ledger.py:26-43`).
- It proves **internal consistency** — no entry was altered or reordered — **not
  authorship**. It does not prove *who* wrote the chain.
- It is **sha256-only. There is no key material anywhere in the project.** Do not
  describe it as "cryptographically signed," "unforgeable," or "tamper-proof." The
  correct words are **tamper-evident** and **hash-chained**. An attacker who can
  rewrite the entire file from genesis can produce an internally-consistent forged
  chain; sha256 evidence does not stop that, and the source says so explicitly
  (`ledger.py:11-18`).
- Asymmetric signing (e.g. ed25519) is a **deliberate non-goal** of this layer. It
  would introduce key handling — a separate, heavier security surface — and is
  intentionally excluded to keep the primitive small and key-free.

**Recompute-not-trust verifier contract.** Both verifiers recompute; neither
returns a stored boolean:

- `Ledger.verify_entries(entries, genesis)` re-links a chain from a list of stored
  entries with no live chain needed, so a third party can verify a persisted log
  (`ledger.py:71-83`).
- `receipts.verify(receipt_id)` (1) re-links the chain and (2) recomputes the
  receipt's content-hash signature over the canonical body; **any** mutated chain
  entry or mutated metadata returns `False`, fail-closed, as do missing or
  unparseable receipts (`receipts.py:121-142`, `test_receipts.py:46-65`). Note: the
  "signature" is a content hash, not an authorship signature — see the sha256 bound
  above (`receipts.py:20-23,99`).
- `receipts.persist()` runs that real verifier as a **write-time round-trip and
  RAISES on failure** — a corrupt write can never be reported as success — and
  refuses outright to persist a chain that is already broken
  (`receipts.py:74-77,112-114`, `test_receipts.py:67-71`).

Receipts are written atomically (temp file → `os.replace`) into a per-producer
directory with an append-only `index.jsonl` and a `LATEST` pointer, so a downstream
gate (CI, a release check) can ask one question — "did this run testify cleanly?" —
and get a fail-closed answer (`receipts.py:100-117`).

---

## 5. The jail profile, the macOS-only caveat, the Linux substitution

The jail (`jail.py`) uses the native macOS primitive `sandbox-exec` (Seatbelt).
There is no seccomp and no Docker assumption.

**Profile** (`jail.py:46-55`) — allow-by-default minus the two things that matter
for blast radius:

- `(deny network*)` — no exfil, no callback, no download.
- `(deny file-write*)` then allow only the sandbox subpath, a sandbox-local
  `TMPDIR`, and the `/dev` nulls — cannot tamper with or persist outside.
- file-read stays allowed (read alone is inert once the network is gone).

**Resource limits** (`jail.py:57-59,108-149`):

- CPU 60s, max file size 256MB via `ulimit`.
- `RLIMIT_NPROC` is intentionally **not** capped — it is per-UID on macOS, so a
  low cap false-fails legitimate forks. Fork bombs are bounded instead by the
  wall-clock + CPU caps.
- `ulimit -v` (RLIMIT_AS) is **ignored on macOS** (verified — a 4GB alloc succeeds
  under a 2GB cap), so memory is bounded by an external **RSS-polling watchdog**
  that kills the process group when resident memory crosses the cap
  (mmap-agnostic), alongside a **wall-clock** cap. Both kills are proven live
  (`test_jail.py:86-100`). Output goes to a file, not a pipe, so a chatty child
  cannot deadlock the watchdog (`jail.py:122-124`).

**Fail-closed off macOS.** `jail_available()` checks for the Seatbelt binary
(`jail.py:62-64`). If it is absent, `jail_command()` **raises** rather than build an
un-jailed command (`jail.py:81-82`), `run_jailed()` returns `killed="no-jail"`
without executing (`jail.py:116-117`, `test_jail.py:119-129`), and `Cell._run_cmd`
refuses with an explicit fail-closed error (`cell.py:109-110`). Callers must never
execute un-jailed on a false.

**Linux substitution note.** The in-language jail is **macOS-only**. On Linux, swap
this one module for `firejail`, `nsjail`, or a container — the contract is the same
(deny network, confine writes, bound resources, fail closed). **The Gate and Ledger
above it are platform-independent** and run everywhere; only `jail.py` is
OS-specific (`jail.py:27-30`). Gate-only mode (`use_jail=False`) is available for
platforms where another sandbox already wraps the process, with the explicit
understanding that it provides no network/write confinement (`cell.py:114-119`).

---

## 6. Failure modes

Every failure path halts (fail-closed). There are **no fail-open paths**.

| Failure | Behavior |
|---|---|
| Unknown tool | **Halt** — BLOCK `unknown-tool` (`gate.py:113`). |
| Empty / non-string command | **Halt** — BLOCK `empty-command` (`gate.py:116`). |
| Unparsable command (bad shlex) | **Halt** — BLOCK `unparsable-command` (`gate.py:131`). |
| Path escapes sandbox (read/write/arg) | **Halt** — BLOCK out-of-sandbox (`gate.py:99-106,143`). |
| Destructive / network / privilege command | **Halt** — BLOCK `destructive-or-out-of-scope` (`gate.py:119-121`). |
| Command substitution | **Halt** — BLOCK `command-substitution` (`gate.py:122`). |
| Program not in allowlist | **Halt** — BLOCK `program-not-allowlisted` (`gate.py:136`). |
| `sandbox-exec` unavailable (off macOS) | **Halt** — refuse to run un-jailed; raise / `no-jail` / explicit error (`jail.py:81`, `cell.py:109`). |
| Memory cap exceeded | **Halt** — process group killed, `killed="memory>NMB"` (`jail.py:133-134`). |
| Wall-clock cap exceeded | **Halt** — process group killed, `killed="wallclock>Ns"` (`jail.py:135-136`). |
| Ledger entry mutated / reordered | **Halt** — `verify()` → `(False, location)` (`ledger.py:78-81`). |
| Receipt chain or metadata tampered | **Halt** — `verify()` → `False` (`receipts.py:135-142`). |
| Receipt missing / unparseable | **Halt** — `verify()` → `False` (`receipts.py:125-130`). |
| Broken chain at persist time | **Halt** — `persist()` raises `ValueError` (`receipts.py:76-77`). |
| Receipt fails round-trip verify after write | **Halt** — `persist()` raises `RuntimeError` (`receipts.py:113-114`). |
| Malformed tool *parameters* (e.g. wrong arg name) | **Fail-soft execution, fail-closed policy** — the error is fed back to the agent so it can self-correct; the loop never crashes; the gate verdict still stands and is recorded. **The policy never fails open** (`cell.py:69-79`, `test_cell.py:50`). |

The last row is the only "continue," and it is deliberate: a malformed call is an
*agent* error, not a *policy* failure. Execution fails soft (returns a corrective
message instead of raising) so the agent loop survives; the gate decision is
unaffected and is recorded either way. No path lets a denied action through.

---

## 7. Verification status

44 tests pass on system Python 3 (pytest 9.0.2): gate 13, ledger 4, jail 14,
receipts 7, cell 6. The jail tests invoke the **real** macOS `sandbox-exec` live
(not mocked) and skip automatically off macOS (`test_jail.py:19`). Reproduce:

```
python -m pytest -q
```

What the tests prove, not just that they run: deny-by-default on unknown tools,
path-escape BLOCK on read and write, destructive/network/substitution/chaining
BLOCKs, a positive ALLOW path, live network/write/child-process containment in the
jail, memory-bomb and wall-clock kills, fail-closed-when-unavailable, hash-chain
tamper and reorder detection, and a fail-closed receipt round-trip.

---

## 8. Versioning and stability

- **Version `0.1.0`** (`deponent/__init__.py:34`, `pyproject.toml`). Development
  Status: 4 — Beta (`pyproject.toml:16`).
- **`deponent-receipt/v1`** is the receipt schema (`receipts.py:40`). Receipt
  body fields, the canonical-body signature definition, and the genesis-anchored
  chain hash are the on-disk contract; a breaking change to any of them is intended
  to bump the schema string. Multi-schema verification (verifying an old receipt
  under its own schema version) is a forward commitment, **not yet implemented** —
  the current `verify()` validates one schema and does not dispatch on the schema
  field (`receipts.py:121-142`).
- **Public API** (`__init__.__all__`): `Cell`, `ActResult`, `Gate`, `GateDecision`,
  `DENY_SUBSTR`, `ALLOW_HEADS`, `Ledger`, `jail_available`, `jail_command`,
  `run_jailed`, `persist`, `verify`, `write_operator_receipt`.
- **Stability posture.** Pre-1.0: the API may change. The *guarantees* are intended
  to be stable from here — deny-by-default, fail-closed, recompute-not-trust
  verification, tamper-evident (not signed) ledger. If a future version weakens any
  of those, it is a breaking change and will be called one.
- **Dependencies.** The core kernel is standard-library only, zero third-party
  dependencies. Only the `examples/` agent team needs a model runtime (`mlx-vlm`
  for the local MLX backend, or a running Ollama daemon via stdlib `urllib`); the
  kernel does not.

---

## Scope boundary — what is the kernel vs. the example

The **kernel** is `deponent/{gate,jail,ledger,receipts,cell}.py` plus
`__init__.py`. That is the governed surface this spec covers.

The **reference backend and agent team live in `examples/` and are NOT the
kernel.** `examples/governed_team.py` runs an Architect → gated Builder → advisory
Reviewer over one shared local model, made model-agnostic by `examples/backends.py`
(MLX or Ollama; add your own). The reference local model is North Mini Code 1.0
(Cohere, 30B MoE / 3B active, Apache-2.0) on Apple Silicon via `mlx-vlm`.

Numbers about the example are about the example, not the kernel:

- **Capability bench: directional, not statistically significant** (n ≈ 17). North
  Mini Code scored 0.749 vs `qwen3-coder:30b` 0.686, winning 6 of 9 tasks. State
  "directional / not statistically significant" whenever citing this.
- **Reliability of the example team** (not the kernel): across sweeps it produced
  correct code ~90% of the time and, critically, **zero buggy-but-accepted modules
  across 32 runs** — it fails loud (no module, or won't compile), never silently
  wrong. After decoupling the stochastic advisory Reviewer from the hard gate,
  pipeline certification rose from 25% to 83% and tracked correctness in that
  sweep. The point is not a benchmark win: **governance turns a flaky local model
  into a worker that fails visibly.**

---

## Open-core boundary

The reference kernel (`gate`/`ledger`/`jail`/`receipts`/`cell`/`examples`/canaries)
is open, Apache-2.0. The productionized, certified, supported safety kernel
(SafetySpine / Governor Console) stays commercial. Deponent is the smallest
version of that same idea — deny-by-default, fail-closed, audited, bounded — given
away as the primitive beneath the products, not as bait. Apache-2.0 is recommended
because it matches North Mini Code's license and carries a patent grant.

This is a reference governance primitive. The limits above are the contract, not
fine print: it does not promise to be a hardened production sandbox, it does not
sign, it does not run its jail off macOS, and it never reports a self-claim as
evidence.