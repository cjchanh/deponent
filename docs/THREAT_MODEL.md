# Deponent — Threat Model

> It doesn't answer. It testifies. This document is held to the same rule: every
> mechanism below names the file and line that implements it, and every line
> citation here was read and verified against the working tree, not inherited.

## Precedence — read this first

[`SPEC.md`](../SPEC.md) is the **normative governance contract**. Where this
document and `SPEC.md` disagree about what the kernel promises, `SPEC.md` wins and
the disagreement is a defect worth filing.

This document is the **adversary-centric companion**: who is attacking, what they
want, which boundary they must cross, and what is left standing after the kernel
does its job. `SPEC.md` §3 already carries the surface-by-surface coverage table
and is not restated here.

**Scope of this document:** the kernel — `deponent/{gate,jail,ledger,receipts,cell}.py`
plus `__init__.py`. `examples/` is not the kernel and is not covered.

---

## 1. Assets — what is actually being protected

Ordered by what an attacker gains by taking it.

| # | Asset | Where it lives | Loss looks like |
|---|---|---|---|
| **A1** | **The host outside the sandbox** | Filesystem, network, privileges, any irreversible state | An agent deletes, exfiltrates, escalates, or installs — irreversibly |
| **A2** | **The integrity of the record** | `Ledger` chain; persisted receipts | The run's history says something that did not happen, and it is believed |
| **A3** | **The gate's decision authority** | `Gate.evaluate()` | An action executes without a recorded classification — the invariant's actual break |
| **A4** | **The confidentiality of the audit log** | Persisted ledger entries | The log becomes the thing worth stealing (it recorded what it governed) |
| **A5** | **Bounded resource consumption** | Jail rlimits + watchdogs | A runaway agent takes the machine down without ever leaving the sandbox |

A2 deserves emphasis because it is easy to state backwards. The asset is not
"the log file." A destroyed log is a visible, honest failure. The asset is
**belief in the log** — a forged record that verifies is strictly worse than no
record, and the kernel's guarantee is precisely bounded here (§4, §6).

---

## 2. Adversaries — capability, not vibes

| ID | Adversary | Capability assumed | In scope? |
|---|---|---|---|
| **ADV-1** | **Careless / misaligned agent** | Proposes arbitrary tool calls through `Cell.act()`. No goal of evading the gate; simply wrong. | **Yes — primary** |
| **ADV-2** | **Prompt-injected agent** | Same API reach as ADV-1, but goal-directed: actively tries to phrase an action to pass the gate. Steered by hostile content the agent read. | **Yes — primary** |
| **ADV-3** | **Hostile code inside an allowed program** | Arbitrary code execution *inside* an ALLOWed `python`/`pytest` invocation. Cannot choose which tool was allowed; can do anything once running. | **Yes — jail's whole purpose** |
| **ADV-4** | **Post-hoc record falsifier** | Read/write access to the ledger file *after* the run. Wants the record to read differently. | **Partial — evident, not prevented** |
| **ADV-5** | **Host-privileged attacker** | Root, or write access to the kernel's own source, or control of the Python runtime. | **No — out of scope** |
| **ADV-6** | **Network / supply-chain attacker** | MITM, malicious dependency. | **No — core has zero third-party dependencies** (`pyproject.toml:34`) |

ADV-5 is the honest ceiling. Anyone who can edit `gate.py` has already won, and no
amount of in-process governance changes that. The kernel is a **policy boundary
inside a cooperating process**, not a privilege boundary against its own host.

---

## 3. Trust boundaries

```
   ADV-1 / ADV-2  ─── proposes tool call
          │
 ═════════▼═══════════════════  B1: the ONLY sanctioned entry point
    Cell.act()                  cell.py:84
          │
 ═════════▼═══════════════════  B2: policy boundary (shell + path surface)
    Gate.evaluate()             gate.py:116     deny-by-default -> gate.py:135
          │ ALLOW only
 ═════════▼═══════════════════  B3: OS confinement boundary  ── ADV-3 stops here
    run_jailed()                jail.py:269     fail-closed -> jail.py:278-282
          │ output
 ═════════▼═══════════════════  B4: durability / evidence boundary
    Ledger.record()             ledger.py:70    hash-linked -> ledger.py:62-64
          │
 ═════════▼═══════════════════  B5: OUTSIDE the model ── ADV-4 operates here,
    persisted file / receipt        ADV-5 owns everything
```

**B1 is a convention, not an enforced boundary.** Nothing stops a caller from
importing `subprocess` and bypassing the Cell entirely. The kernel governs the
agent's *tool surface*; it does not confine the Python process it lives in. This is
the single most important thing to understand before deploying it.

**B3 exists because B2 cannot see inside an allowed program.** The gate approves
`python3 script.py` on the shell/path surface; only the jail constrains what that
Python then does (`gate.py:23-26` states this gap explicitly).

---

## 4. Mechanisms as implemented

Verified against the working tree. Every line number below was confirmed by
reading the file.

### 4.1 Deny-by-default (B2)

`Gate.evaluate()` (`gate.py:116-135`) dispatches on exactly three known tools —
`read_file`, `write_file`, `run_cmd`. Anything else falls through to an
unconditional block:

```python
# gate.py:135
return GateDecision("BLOCK", "unknown-tool", f"no policy for tool {tool!r} (deny-by-default)")
```

This is a real default, not a documented intention: the deny is the function's
fall-through return, so a tool cannot be permitted by omission. Proven by
`tests/test_gate.py:63`.

**Path containment** (`gate.py:105-113`) resolves the candidate path and requires it
to equal the sandbox root or start with `root + os.sep`, rejecting non-strings and
embedded NULs. Because it uses `Path.resolve()`, `../` traversal and symlinks are
normalized before the prefix check.

**Command classification** (`gate.py:137-170`), in order — each returns BLOCK:

| Order | Check | Line | Blast class |
|---|---|---|---|
| 1 | Empty / non-string | `gate.py:138-139` | `empty-command` |
| 2 | Substring denylist (53 patterns) | `gate.py:52-61`, `141-143` | `destructive-or-out-of-scope` |
| 3 | Substitution `$(`, `` ` ``, `${` | `gate.py:71`, `144-145` | `command-substitution` |
| 4 | Redirects `>` `<` (whole class) | `gate.py:77`, `146-148` | `shell-redirect` |
| 5 | Per-segment program allowlist | `gate.py:70`, `150-162` | `program-not-allowlisted` |
| 6 | Per-argument path containment | `gate.py:163-169` | `arg-path-escape` |

Check 5 is the anti-ADV-2 control: the command is split on `&&`, `||`, `;`, `|`,
**and newline/CR** (`gate.py:70`), so a second *line* cannot smuggle a
non-allowlisted program past a first allowlisted one. Check 4 blocks the redirect
class wholesale rather than trying to extract a target from the token stream — the
comment at `gate.py:72-76` explains the specific evasion (`x>>/etc/p` tokenizes as
one relative-looking argument). Both are the correct fail-closed shape: refuse the
class you cannot parse reliably.

**Reach-gated writes** (`gate.py:173-192`) are opt-in. When an enforcing policy is
set, an *unresolvable* blast radius is treated as exceeding the ceiling, never as
safe (`gate.py:180-183`). Reach can only make the gate stricter — with
`reach=None` behaviour is identical to the substring gate.

### 4.2 Confinement (B3)

macOS Seatbelt profile (`jail.py:55-64`) is allow-by-default minus the two things
that carry blast radius: `(deny network*)` at `jail.py:57`, `(deny file-write*)` at
`jail.py:58` with writes re-allowed only under the sandbox subpath and the `/dev`
nulls. Resource caps: `ulimit -t 60`, `ulimit -f 524288` (`jail.py:68`), an
RSS-polling watchdog that kills the process group (`jail.py:137-138`) and a
wall-clock kill (`jail.py:139-140`). Output is written to a file rather than a pipe
so a chatty child cannot deadlock the watchdog (`jail.py:128-130`).

**Fail-closed dispatch is real.** `jail_command()` raises rather than build an
un-jailed command when the Seatbelt binary is absent (`jail.py:108-109`);
`run_jailed()` returns `killed="no-jail"` without executing when no backend is
available (`jail.py:278-282`); `Cell._run_cmd` refuses with an explicit error
(`cell.py:158-159`). Three independent refusals, no shared flag between them.
Proven by `tests/test_jail.py:171`.

### 4.3 Tamper-evidence (B4)

`entry_hash = sha256(prev_hash + "\n" + canonical_json(payload))`, genesis-anchored
(`ledger.py:62-64`, `ledger.py:102-104`). `verify_entries()` (`ledger.py:111-131`)
re-links from genesis and returns the index of the first break — it recomputes and
never reads a stored boolean. Detection of mutation and reorder is proven by
`tests/test_ledger.py:26` and `:36`.

The outcome is stored as `outcome_sha256`, not verbatim (`ledger.py:87`), so the
ledger testifies that a specific output occurred without becoming an exfiltration
sink. Opt-in **content-blind mode** (`ledger.py:89-96`) extends this to the request
itself — `params_sha256` + `reason_sha256` replace the plaintext — which is the A4
control. Proven by `tests/test_ledger.py:86`.

### 4.4 Recompute-not-trust receipts (B4)

`receipts.verify()` (`receipts.py:121-142`) does two independent recomputations: the
chain re-link (`receipts.py:135-138`) and the receipt's content hash over its
canonical body (`receipts.py:139-142`). `persist()` refuses to write a chain that is
already broken (`receipts.py:75-77`), writes atomically via temp-file + `os.replace`
(`receipts.py:101-105`), and then runs the real verifier as a **write-time
round-trip that raises** (`receipts.py:112-114`). A corrupt write cannot be reported
as success.

The `signature` field (`receipts.py:99`) is a **content hash, not an authorship
signature**. The source says so at the assignment site. See §6.

---

## 5. Explicitly out of scope

Named so they are decisions, not gaps.

1. **Anything ADV-5 can do.** Root, source edits, a patched Python runtime. The
   kernel governs a cooperating process; it does not defend against its own host.
2. **Bypassing `Cell.act()`.** A caller that shells out directly is not governed.
   B1 is a convention.
3. **The read surface.** The jail restricts **writes, not reads**. A jailed process
   can read `~/.ssh` or `~/.aws` and return the contents on stdout to the un-jailed
   caller, which may have network. `jail.py:21-27` states this in the module
   docstring. **The jail is not an exfiltration boundary** — it stops the sandboxed
   process from *calling out*, not from *reading a secret and handing it back*.
4. **Authorship of the record.** sha256 only; no key material in the core.
   Asymmetric signing is a deliberate non-goal (`ledger.py:12-18`). The optional
   `operator_attest.py` overlay is verification-only and signs nothing the agent does.
5. **A universal security policy.** `DENY_SUBSTR` / `ALLOW_HEADS` are a
   coding-agent sandbox, overridable per instance (`gate.py:89-93`). They are not
   claimed to be complete for another tool surface.
6. **Side channels, timing, runtime supply chain.**
7. **Denial of service against the host by an ALLOWed workload** beyond the
   configured memory and wall-clock caps.

---

## 6. Residual risks

What is still standing after the kernel does everything it claims. Ordered by the
gap between how dangerous it is and how likely a reader is to miss it.

### R1 — The README quickstart runs with **no confinement** *(highest practical risk)*

The quickstart, and `examples/minimal.py:19`, construct the Cell with
`use_jail=False`. In that mode `Cell._run_cmd` executes
`subprocess.run(cmd, shell=True, ...)` (`cell.py:166-168`) — the gate's shell/path
policy still holds, but there is **no network confinement and no write confinement**.
`SPEC.md:121` correctly lists in-language exfiltration in gate-only mode as **not
covered**.

This is a documented, deliberate mode, and the demo needs it to run off-macOS. The
residual risk is one of **defaults-by-example**: the first code a new user copies
is the un-jailed one, and ADV-3 is entirely unconstrained there. Anyone running
untrusted agent output should set `use_jail=True` and check `jail_available()`.

### R2 — Substring denylists are deny-known-bad inside a deny-by-default gate

`DENY_SUBSTR` (`gate.py:52-61`) is enumerated. The *program allowlist* (check 5) is
the real deny-by-default control and is what bounds ADV-2; the substring list is a
second layer that, by construction, only catches patterns someone thought of.
Do not reason about the gate as though the denylist were exhaustive — reason about
it as: **only these 20 program heads run at all** (`gate.py:63-67`), and the
denylist trims the space further. A gap in the denylist is a gap only if it is also
reachable through an allowlisted head.

### R3 — Tail truncation is invisible to the chain alone

A hash chain has no length commitment. Dropping the most recent N entries leaves a
shorter chain that **still re-links cleanly from genesis and verifies as intact.**
The project is honest about this: `ledger.py:20-27` documents it, and
`tests/test_ledger.py:59` (`test_truncation_passes_verify_alone`) pins the limit as
a *passing* test rather than hiding it.

The mitigation exists but is **caller-supplied**: `verify_entries(..., expected_len=N)`
(`ledger.py:121-122`) catches it only when the caller already knows the count, or
when a sealed receipt anchors the head. A run that persists no receipt and records
no count has no truncation detection. ADV-4's cheapest attack is not editing an
entry — it is deleting the last few.

### R4 — Tamper-evidence is not attribution

An ADV-4 who can rewrite the file **from genesis** produces an internally consistent
chain that verifies `True`. sha256 proves internal consistency, not authorship, and
the receipt's `signature` is a content hash (`receipts.py:99`) — it proves the body
was not altered after writing, not who wrote it. Correct words: **tamper-evident**,
**hash-chained**. Never "signed," "unforgeable," or "tamper-proof."

### R5 — Off-macOS confinement is materially weaker than on-macOS, and the repo contradicts itself about how weak

The in-language jail is Seatbelt on macOS (`jail.py:246-247`); every other platform
dispatches to `DockerBackend` (`jail.py:248-250`), which requires a live daemon
(`jail.py:193-203`) — absent one, `jail_available()` is False and the kernel
correctly refuses to run rather than degrade.

**Unresolved documentation conflict, recorded rather than adjudicated.** The repo
makes two incompatible statements about the Docker backend's verification status:

- `jail.py:33-37` (module docstring) — "Docker: **LIVE-VERIFIED** … Last verified
  2026-07-03 against Docker 29.4.1: 10/10 escape-proofs green."
- `jail.py:184-186` (the `DockerBackend` class docstring, same file) — "**DRAFT** —
  must pass `tests/test_jail_backends.py::TestDockerBackend` against a live daemon
  before its confinement is claimed."
- `README.md:127` and `README.md:205`, and `SPEC.md:267` — DRAFT, **not** live-verified.

Three of four surfaces say DRAFT. Treat non-macOS confinement as **unverified on
your host until you run it there**: the escape-proofs are opt-in behind
`DEPONENT_TEST_DOCKER=1` (`tests/test_jail_backends.py:73,77`) and therefore do
**not** run in the default suite or in CI. A green `make test` on Linux says nothing
about Docker confinement.

### R6 — Reconcile is optional and silently absent

`cell.py:36-45` imports `reconcile` in a `try/except ImportError` and sets
`_RECONCILE_AVAILABLE = False` on failure. The two-plane observed-vs-declared check
then simply does not run. This is handled honestly — the claim-set reports it
absent rather than faking it — but a deployment that lost the module gets less
checking with no error at import time.

### R7 — Execution errors fail soft by design

`cell.py:96-101` catches every exception from `_execute` and feeds the message back
to the agent instead of raising, so an agent loop survives a malformed call. The
**policy** never fails open — the gate verdict already stands and is recorded
either way — but a reader skimming for `try/except` should know this one is
deliberate and is the only "continue" in the kernel (`SPEC.md:253`).

---

## 7. How this document was verified

Self-reported health is not evidence, so here is the evidence for this document.

| Check | Command | Result |
|---|---|---|
| Suite green | `python3 -m pytest -q` | **exit 0** — 174 passed, 7 skipped |
| Test count claim | `python3 -m pytest --collect-only` | **181 collected**, matching `README.md:121` and `SPEC.md:264` |
| Quickstart output claim | `python3 examples/minimal.py` | **exit 0**, output matches `README.md:43-52` exactly, including `chain intact (4 entries)` |
| Every line citation above | `grep -n` against each cited symbol | Confirmed against the working tree |

Skips are host-dependent by design: live Seatbelt tests skip when `sandbox_apply`
is refused by an outer confinement, and the DRAFT Docker escape-proofs are opt-in.

**Known defect found during verification, not fixed here.** `SPEC.md`'s line
citations have drifted from the code — it cites `cell.py:62` for `Cell.act()`
(actually `cell.py:84`), `gate.py:113` for the deny-by-default return (actually
`gate.py:135`), `ledger.py:85` for `verify()` (actually `ledger.py:133`), and
`jail.py:62-64` for `jail_available()` (actually `jail.py:264-266`). The *claims*
in `SPEC.md` are accurate; only the line anchors are stale. Citations in **this**
document were re-derived from the working tree. Correcting `SPEC.md` was outside
this change's scope and is recorded here rather than silently patched.
