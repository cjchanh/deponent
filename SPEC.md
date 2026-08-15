# Deponent — Governance Contract & Threat Model (SPEC.md)

> It doesn't answer. It testifies.

Deponent is a small, model-agnostic governance layer that sits under a local AI
agent's tool calls and turns "trust me, it ran fine" into a record you can check.
The five-pillar kernel (`deponent/{gate,jail,ledger,receipts,cell}.py` plus
`__init__.py`) is standard-library only: **zero third-party runtime
dependencies.** Version `0.1.1`. License: Apache-2.0. Additional public modules
(claims, profiles, reach, reconcile, badge, conformance, playground, selfgate)
sit on that core. `operator_attest.py` is an optional extra (`deponent[attest]`),
not part of the keyless execution path. Do not trust a frozen line-count slogan;
measure with `wc -l` if you need a number.

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
  (`cell.py:84`). It is gated *before* it runs and recorded *after*. A BLOCK is
  recorded too — the testimony includes what was refused (`test_cell.py:26-32`,
  `cell.py:87-92`).
- **No self-reported closure.** Closure is not the agent's claim. It is
  `Ledger.verify()` recomputing the hash chain (`ledger.py:102-104`) and, at write
  time, the receipt verifier recomputing both the chain and the receipt signature
  (`receipts.py:121-142`). Both *recompute*; neither trusts a stored boolean. This is
  the rule the whole project is built on: **self-reported health is never the
  evidence** (`receipts.py:18`).

The reference agent team (`examples/governed_team.py`) shows the invariant in
practice: when the Builder model says "done," the harness re-runs pytest
out-of-band and pushes back if it isn't actually green (`governed_team.py:119-143`);
certification anchors only on deterministic signals — out-of-band test pass, intact
chain, rogue action proven blocked — with the LLM Reviewer explicitly **advisory,
recorded but not gating** (`governed_team.py:277-279`).

---

## 2. The five pillars

| Pillar | Where | What it means here |
|---|---|---|
| **Deny-by-default** | `gate.py:134-135` | An unrecognized tool returns `BLOCK / unknown-tool`. Nothing is permitted unless a policy branch explicitly allows it (`test_gate.py:63`, `test_cell.py:55`). |
| **Fail-closed** | `gate.py`, `jail.py:108-109`, `cell.py:158-159` | Unknown tool, unparsable command, path escape → BLOCK. When no confinement backend is available, `run_cmd` **refuses to execute un-jailed** rather than degrade to a bare run. |
| **Dry-run / gate-before-destructive** | `cell.py:84-92` | The gate classifies blast radius *before* any execution. Destructive/irreversible signatures (`rm -rf`, `mkfs`, `dd`, `sudo`, …) never reach the shell (`gate.py:52-61`, `test_gate.py:34`). |
| **Independent audit** | `ledger.py` | Every decision + a hash of its outcome is appended to a tamper-evident chain, verifiable after the fact by re-linking from genesis — a path independent of the agent's own status signal. |
| **Bounded execution** | `jail.py` | Live-verified Seatbelt jail (macOS): no network, writes confined to the sandbox, CPU/file-size rlimits, plus RSS-polling and wall-clock watchdogs that kill runaways (`jail.py:118-147`). A Docker backend exists in the same module and is marked **DRAFT**, not live-verified. |

### Deny-by-default gate (`gate.py`)

The gate governs the **shell + path surface**: which programs may run, which paths
may be touched, and whether a command chains or substitutes its way out of policy.
It blocks, in order:

- **Unknown tool** — any tool with no policy branch (`gate.py:134-135`).
- **Path escape, read and write** — a path that resolves outside the sandbox
  (`gate.py:117-129`); absolute paths and `../` traversal are rejected
  (`test_gate.py:39-46`). Containment uses `Path.resolve()` and a prefix check,
  and rejects embedded NULs (`gate.py:105-113`).
- **Destructive / out-of-scope commands** — substring denylist covering
  irreversible (`rm -rf`, `rmdir`, `mkfs`, `dd if=/of=`, fork bombs, `shutdown`),
  network (`curl`, `wget`, `ssh`, `scp`, `nc`, `telnet`, `nmap`), privilege/system
  writes (`sudo`, `chmod`, `chown`, `/etc/`, `/usr/`, `launchctl`, `systemctl`),
  package installs, and home/parent references (`gate.py:52-61`).
- **Command substitution** — `$(...)`, backticks, `${...}` are rejected outright
  (`gate.py:71,144-145`, `test_gate.py:55`).
- **Shell redirects** — `>` and `<` (including glued forms such as `x>>/etc/p`)
  are rejected outright (`gate.py:72-78,146-148`, `test_gate.py:75-84`).
- **Shell chaining to a denied segment** — the command is split on `&&`, `||`, `;`,
  `|`, newline, and CR, and **every** segment's program head must be in the allowlist,
  with every path-like argument contained in the sandbox (`gate.py:149-170`,
  `test_gate.py:59`, `test_gate.py:90`).

It allows only an allowlist of coding programs — `python`, `python3`, `pytest`,
`ruff`, `black`, `mypy`, `ls`, `cat`, `grep`, `diff`, etc. (`gate.py:63-67`) — with
in-sandbox path arguments. The policy (`deny`, `allow_heads`) is module-level and
**overridable per `Gate` instance** (`gate.py:89-102`); the defaults are a sane
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
| Unknown / unmodeled tool | **Covered** | Deny-by-default BLOCK (`gate.py:134-135`, `test_gate.py:63`). |
| Path traversal out of sandbox (read + write) | **Covered** | `../`, absolute paths, NUL-injected paths rejected (`gate.py:105-129`, `test_gate.py:39-46`). |
| Destructive / irreversible shell commands | **Covered** | Denylist + tests (`gate.py:52-61`, `test_gate.py:34`). |
| Network egress via shell command | **Covered (gate)** | `curl`/`wget`/`ssh`/`nc`… blocked (`gate.py:55`). |
| Network egress from *inside* an allowed program | **Covered (jail, macOS Seatbelt)** | `(deny network*)` — sockets/urlopen fail (`jail.py:55-64`, `test_jail.py`). |
| Privilege escalation / system-dir writes | **Covered** | `sudo`, `chmod`, `/etc/`, `/usr/`, `launchctl`… blocked (`gate.py:52-61`, `test_gate.py:52`). |
| Command substitution / shell expansion | **Covered** | `$()`, backticks, `${}` rejected (`gate.py:144-145`, `test_gate.py:55`). |
| Shell redirects | **Covered** | `>`/`<` including glued forms (`gate.py:146-148`, `test_gate.py:75-84`). |
| Chaining / newline-separated second command | **Covered** | Per-segment allowlist including newline/CR (`gate.py:70,149-170`, `test_gate.py:59,90`). |
| Arbitrary code inside an allowed program writing outside the sandbox | **Covered (jail, macOS Seatbelt)** | `(deny file-write*)` minus the sandbox subpath (`jail.py:55-64`, `test_jail.py`). |
| Child process escaping the sandbox | **Covered (jail, macOS Seatbelt)** | Children inherit the profile (`test_jail.py`). |
| Memory / fork bomb, wall-clock runaway | **Covered (jail, macOS Seatbelt)** | RSS watchdog + wall-clock kill, proven live (`jail.py:118-147`, `test_jail.py`). |
| Ledger tamper / reorder after the fact | **Covered (evident, not prevented)** | Detected on `verify()`; see §4 (`ledger.py:81-104`, `test_ledger.py`). |
| Receipt metadata tamper | **Covered (evident)** | Signature recomputed over canonical body (`receipts.py:139-142`, `test_receipts.py`). |
| Arbitrary code inside an allowed program on **Linux/Windows without a live-verified backend** | **Not covered as live-verified** | Seatbelt tests skip without `sandbox-exec`. `jail.py` contains a **DRAFT** Docker backend; `tests/test_jail_backends.py` gates those tests. Do not read DRAFT as proven. See §5. |
| An attacker who can rewrite the whole ledger file from genesis | **Not covered** | sha256 is tamper-evident, not signed; there is no authorship proof. See §4. |
| Ledger tail truncation without an external length anchor | **Not covered by `verify()` alone** | A shorter prefix still re-links. Catch it with a receipt head or `verify_entries(..., expected_len=N)` (`ledger.py:20-27,81-91`). |
| In-language exfiltration in **gate-only mode** (`use_jail=False`) | **Not covered** | No network/write confinement; use only where another sandbox wraps the process (`cell.py:163-168`). |
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
(`ledger.py:50-73`). The outcome is stored as a hash, not verbatim, so the ledger
testifies that a specific output occurred without becoming a data-exfiltration sink
(`ledger.py:55-69`).

**The precise claim — and its bound:**

- It is **tamper-evident**, not tamper-proof. Mutating or reordering any entry
  breaks the re-link, and `verify()` returns `(False, location)` naming the first
  broken entry (`ledger.py:81-104`, `test_ledger.py`).
- It proves **internal consistency** — no entry was altered or reordered — **not
  authorship**. It does not prove *who* wrote the chain.
- The **ledger core is keyless sha256.** Do not describe it as "cryptographically
  signed," "unforgeable," or "tamper-proof." The correct words are **tamper-evident**
  and **hash-chained**. An attacker who can rewrite the entire file from genesis can
  produce an internally-consistent forged chain; sha256 evidence does not stop that,
  and the source says so explicitly (`ledger.py:12-18`).
- Asymmetric signing is a **deliberate non-goal of the ledger/receipt path.** An
  optional, verification-only ed25519 overlay lives in `operator_attest.py` (extra
  `deponent[attest]`). It verifies an operator's out-of-band signature over a run; it
  signs nothing the agent does. The core stays keyless on purpose.
- `verify()` on its own does **not** detect tail truncation. A shorter prefix still
  re-links. Use a sealed receipt or `verify_entries(..., expected_len=N)`
  (`ledger.py:20-27,81-91`).

**Recompute-not-trust verifier contract.** Both verifiers recompute; neither
returns a stored boolean:

- `Ledger.verify_entries(entries, genesis)` re-links a chain from a list of stored
  entries with no live chain needed, so a third party can verify a persisted log
  (`ledger.py:81-100`).
- `receipts.verify(receipt_id)` (1) re-links the chain and (2) recomputes the
  receipt's content-hash signature over the canonical body; **any** mutated chain
  entry or mutated metadata returns `False`, fail-closed, as do missing or
  unparseable receipts (`receipts.py:121-142`, `test_receipts.py`). Note: the
  "signature" is a content hash, not an authorship signature — see the sha256 bound
  above (`receipts.py:20-23,99`).
- `receipts.persist()` runs that real verifier as a **write-time round-trip and
  RAISES on failure** — a corrupt write can never be reported as success — and
  refuses outright to persist a chain that is already broken
  (`receipts.py:75-77,113-114`, `test_receipts.py`).

Receipts are written atomically (temp file → `os.replace`) into a per-producer
directory with an append-only `index.jsonl` and a `LATEST` pointer, so a downstream
gate (CI, a release check) can ask one question — "did this run testify cleanly?" —
and get a fail-closed answer (`receipts.py:100-117`).

---

## 5. The jail profile, the macOS Seatbelt path, the DRAFT Docker backend

The live-verified in-language jail is macOS `sandbox-exec` (Seatbelt). There is no
seccomp. `jail.py` also contains a **DRAFT** Docker backend; that backend is not
claimed as live-verified. `jail_available()` is **not** a Seatbelt-only check: it
returns True iff `select_backend()` finds a backend that answers
(`jail.py:264-266`). On Darwin the candidate list is Seatbelt only
(`jail.py:246-247`). On Linux the candidate is Docker (`jail.py:248-249`).

**Seatbelt profile** (`jail.py:55-64`) — allow-by-default minus the two things that
matter for blast radius:

- `(deny network*)` — no exfil, no callback, no download.
- `(deny file-write*)` then allow only the sandbox subpath, a sandbox-local
  `TMPDIR`, and the `/dev` nulls — cannot tamper with or persist outside.
- file-read stays allowed (read alone is inert once the network is gone).

**Resource limits** (`jail.py:66-68,118-147`):

- CPU 60s, max file size 256MB via `ulimit`.
- `RLIMIT_NPROC` is intentionally **not** capped — it is per-UID on macOS, so a
  low cap false-fails legitimate forks. Fork bombs are bounded instead by the
  wall-clock + CPU caps.
- `ulimit -v` (RLIMIT_AS) is **ignored on macOS** (verified — a 4GB alloc succeeds
  under a 2GB cap), so memory is bounded by an external **RSS-polling watchdog**
  that kills the process group when resident memory crosses the cap
  (mmap-agnostic), alongside a **wall-clock** cap. Both kills are proven live in
  `tests/test_jail.py`. Output goes to a file, not a pipe, so a chatty child
  cannot deadlock the watchdog (`jail.py:126-127`).

**Fail-closed when no backend is available.** `jail_command()` is Seatbelt-specific
and **raises** rather than build an un-jailed command if `sandbox-exec` is missing
(`jail.py:108-109`). `run_jailed()` returns `killed="no-jail"` without executing
when `select_backend()` is None (`jail.py:278-282`). `Cell._run_cmd` refuses with an
explicit fail-closed error when `use_jail=True` and `jail_available()` is False
(`cell.py:158-159`). Callers must never execute un-jailed on a false.

**Linux / Docker note.** The **live-verified** in-language jail is **macOS
Seatbelt**. The Docker backend in `jail.py` is labeled DRAFT in source
(`jail.py:170-185`) and its tests are gated. Do not treat a present Docker CLI as
proven confinement. Gate-only mode (`use_jail=False`) is available where another
sandbox already wraps the process, with no network/write confinement from Deponent
(`cell.py:163-168`). **The Gate and Ledger above the jail are platform-independent.**

---

## 6. Failure modes

Every failure path halts (fail-closed). There are **no fail-open paths**.

| Failure | Behavior |
|---|---|
| Unknown tool | **Halt** — BLOCK `unknown-tool` (`gate.py:134-135`). |
| Empty / non-string command | **Halt** — BLOCK `empty-command` (`gate.py:137-139`). |
| Unparsable command (bad shlex) | **Halt** — BLOCK `unparsable-command` (`gate.py:156-157`). |
| Path escapes sandbox (read/write/arg) | **Halt** — BLOCK out-of-sandbox (`gate.py:117-129,168-169`). |
| Destructive / network / privilege command | **Halt** — BLOCK `destructive-or-out-of-scope` (`gate.py:141-143`). |
| Command substitution | **Halt** — BLOCK `command-substitution` (`gate.py:144-145`). |
| Shell redirect | **Halt** — BLOCK `shell-redirect` (`gate.py:146-148`). |
| Program not in allowlist | **Halt** — BLOCK `program-not-allowlisted` (`gate.py:161-162`). |
| No confinement backend (`use_jail=True`) | **Halt** — refuse to run un-jailed; raise / `no-jail` / explicit error (`jail.py:108-109,278-282`, `cell.py:158-159`). |
| Memory cap exceeded | **Halt** — process group killed, `killed="memory>NMB"` (`jail.py:137-138`). |
| Wall-clock cap exceeded | **Halt** — process group killed, `killed="wallclock>Ns"` (`jail.py:139-140`). |
| Ledger entry mutated / reordered | **Halt** — `verify()` → `(False, location)` (`ledger.py:93-98`). |
| Receipt chain or metadata tampered | **Halt** — `verify()` → `False` (`receipts.py:135-142`). |
| Receipt missing / unparseable | **Halt** — `verify()` → `False` (`receipts.py:125-130`). |
| Broken chain at persist time | **Halt** — `persist()` raises `ValueError` (`receipts.py:75-77`). |
| Receipt fails round-trip verify after write | **Halt** — `persist()` raises `RuntimeError` (`receipts.py:113-114`). |
| Malformed tool *parameters* (e.g. wrong arg name) | **Fail-soft execution, fail-closed policy** — the error is fed back to the agent so it can self-correct; the loop never crashes; the gate verdict still stands and is recorded. **The policy never fails open** (`cell.py:94-101`, `test_cell.py:72`). |

The last row is the only "continue," and it is deliberate: a malformed call is an
*agent* error, not a *policy* failure. Execution fails soft (returns a corrective
message instead of raising) so the agent loop survives; the gate decision is
unaffected and is recorded either way. No path lets a denied action through.

---

## 7. Verification status

Do not trust a frozen pass count. The suite lives in `tests/` (gate, jail,
jail_backends, ledger, receipts, cell, claims, conformance, badge, playground,
profiles, reach, reconcile, operator_attest, selfgate). Seatbelt tests skip when
`sandbox-exec` is absent. Docker-backend tests are gated. Reproduce on this host:

```
python -m pytest -q
```

`python -m pytest --collect-only -q` reports the collected set independently of
host skips. What the tests prove, not just that they run: deny-by-default on
unknown tools, path-escape BLOCK on read and write, destructive/network/substitution/
chaining/redirect/newline BLOCKs, a positive ALLOW path, disposable-relative-target
BLOCK with unchanged sentinel bytes (`test_cell.py`), live network/write/child-process
containment in the Seatbelt jail when present, memory-bomb and wall-clock kills,
fail-closed-when-unavailable, hash-chain tamper and reorder detection, and a
fail-closed receipt round-trip.

---

## 8. Versioning and stability

- **Version `0.1.1`** (`deponent/__init__.py`, `pyproject.toml`). Development
  Status: 4 — Beta (`pyproject.toml`).
- **`deponent-receipt/v1`** is the receipt schema (`receipts.py:40`). Receipt
  body fields, the canonical-body signature definition, and the genesis-anchored
  chain hash are the on-disk contract; a breaking change to any of them is intended
  to bump the schema string. Multi-schema verification (verifying an old receipt
  under its own schema version) is a forward commitment, **not yet implemented** —
  the current `verify()` validates one schema and does not dispatch on the schema
  field (`receipts.py:121-142`).
- **Public API** (`__init__.__all__`): `Cell`, `ActResult`, `Gate`, `GateDecision`,
  `DENY_SUBSTR`, `ALLOW_HEADS`, `build_gate`, `build_cell`, `Ledger`, `Claim`,
  `ClaimSet`, `attest`, `jail_available`, `jail_command`, `run_jailed`, `persist`,
  `verify`, `write_operator_receipt`, `__version__`.
- **Stability posture.** Pre-1.0: the API may change. The *guarantees* are intended
  to be stable from here — deny-by-default, fail-closed, recompute-not-trust
  verification, tamper-evident (not signed) ledger. If a future version weakens any
  of those, it is a breaking change and will be called one.
- **Dependencies.** The core kernel is standard-library only, zero third-party
  dependencies. Optional extra `deponent[attest]` pulls `cryptography` for the
  operator overlay only. Only the `examples/` agent team needs a model runtime
  (`mlx-vlm` for the local MLX backend, or a running Ollama daemon via stdlib
  `urllib`); the kernel does not.

---

## Scope boundary — what is the kernel vs. the example

The **five-pillar kernel** is `deponent/{gate,jail,ledger,receipts,cell}.py` plus
`__init__.py`. That is the governed surface this spec centers on. The public
package also ships claims, profiles, reach, reconcile, badge, conformance,
playground, and selfgate; those are additional modules, not a substitute for the
pillars. `deponent/adapters/sworn.py` is hatch-excluded legacy source and is not a current built-in.

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
is open, Apache-2.0. Deponent is a small governance primitive: deny-by-default,
fail-closed, audited, and bounded. Apache-2.0 is recommended because it matches
North Mini Code's license and carries a patent grant.

This is a reference governance primitive. The limits above are the contract, not
fine print: it does not promise to be a hardened production sandbox, the ledger
core does not sign, the live-verified jail is macOS Seatbelt (Docker in `jail.py`
is DRAFT), and it never reports a self-claim as evidence.
