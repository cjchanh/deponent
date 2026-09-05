# Deponent

[![deponent: GAK self-evaluated](docs/deponent-badge.svg)](#proven) &nbsp;·&nbsp; [![CI](https://github.com/cjchanh/deponent/actions/workflows/ci.yml/badge.svg)](https://github.com/cjchanh/deponent/actions/workflows/ci.yml) &nbsp;·&nbsp; **Apache-2.0** &nbsp;·&nbsp; verify the mark yourself: `python3 -m deponent.badge verify --kernel deponent`

**A governed sovereign agent kernel. It doesn't answer. It testifies.**

![Deponent blocks a destructive action and an unknown tool, then detects a forged audit record](docs/demo.gif)

A local AI agent runs on your machine. It edits files, runs commands, touches your system — and when it finishes, all you have is its word that it behaved, and a failed step reports success as readily as a real one. Deponent replaces the word with a record you can verify yourself.

It is a small, model-agnostic governance layer that sits under any agent's tool calls:

```
deny-by-default gate  ->  Seatbelt jail  ->  tamper-evident ledger  ->  verifiable receipt
```

**Containment boundary:** the live-verified jail is macOS Seatbelt (OS confinement) only. `Cell()` defaults to `use_jail=True`; when the jail is unavailable it fail-closes (records ALLOW, refuses execution) rather than silently switching to gate-only. On other hosts you supply confinement or opt into gate-only (`use_jail=False`): the deny-by-default gate and the ledger still run, but there is no OS confinement; argument paths are containment-checked whether spaced, glued to a flag (`-o/tmp/x`, `--output=/tmp/x`), or reached through a symlink that already exists inside the sandbox. In gate-only mode only a small safe set of heads runs by default; other heads need `allow_unjailed_heads` on both the Cell and its Gate (the Cell heads kwarg alone does not opt in a foreign gate). Interpreters need both knobs: membership in `allow_unjailed_heads` and `allow_unjailed_interpreters=True` on both the Cell and its Gate (the Cell interpreter kwarg alone does not opt in a foreign gate, and an interpreter listed only in `allow_unjailed_heads` is still refused), and gate-only commands run without a shell, one command at a time. Playground `ClassifyCell` is gate-only, so a chain such as `echo a && echo b` is `chain-unjailed` BLOCK (jail-mode would ALLOW). Gate-only runs are policy evidence, not sandbox evidence. The ledger is tamper-evident for edits, deletions and reordering; truncation and re-chaining are caught only against a head published outside the ledger (`Ledger.head()` / receipt `ledger_head`).

The core is pure Python and standard-library only: **zero third-party runtime dependencies.** Install it with `pip install deponent`.

---

## Quickstart

```python
import tempfile
from deponent import Cell

cell = Cell(tempfile.mkdtemp(), use_jail=False)   # a sovereign, local sandbox
                                                  # use_jail=True on macOS adds the Seatbelt jail
print(cell.act("write_file", {"path": "notes.txt", "content": "hello"}).output)  # ALLOW
print(cell.act("read_file",  {"path": "notes.txt"}).output)                      # ALLOW
print(cell.act("run_cmd",    {"cmd": "rm -rf ./blocked-example"}).output)        # BLOCK (destructive)
print(cell.act("exfiltrate", {"to": "evil.example"}).output)                     # BLOCK (deny-by-default)

ok, msg = cell.verify()                           # recompute the chain — don't trust it
print(f"testimony intact: {ok} — {msg}")
```

That is exactly `examples/minimal.py`. Run it (`python3 examples/minimal.py`) and it prints:

```text
wrote 5 bytes -> notes.txt
hello
BLOCKED [destructive-or-out-of-scope]: matched deny pattern 'rm -rf'
BLOCKED [unknown-tool]: no policy for tool 'exfiltrate' (deny-by-default)

testimony intact: True — chain intact (4 entries)
  ALLOW write_file  [reversible-local-write]
  ALLOW read_file   [reversible-local-read]
  BLOCK run_cmd     [destructive-or-out-of-scope]
  BLOCK exfiltrate  [unknown-tool]
```

No model needed for the demo. No network. No install required to run it from the repo.

---

## Why this exists

Local agents are useful precisely because they act on your machine. That is also the risk: you are trusting they only did what they said they did.

A self-report is not evidence. Every system has two surfaces — what it says about itself and what it actually did — and they drift. Agents are no exception: "tests pass," "done," "cleaned up" is a claim, not a fact.

Deponent replaces the trust with a record. Every action an agent proposes is gated before it runs, jailed while it runs, and recorded after it runs into a hash-chained ledger you can re-verify from scratch. At the end you can **prove what happened** — or prove the record was altered. There is no third option.

---

## How it works

One object, `Cell`, is the whole architecture. Each action goes through `.act()`:

```
agent proposes an action
        │
        ▼
   ┌─────────┐   deny-by-default. unknown tool / path escape /
   │  GATE   │   destructive cmd / network / privilege  ->  BLOCK
   └────┬────┘
        │ ALLOW
        ▼
   ┌─────────┐   macOS Seatbelt: no network, writes confined to
   │  JAIL   │   the sandbox, CPU + memory + wall-clock bounded
   └────┬────┘
        │ output
        ▼
   ┌─────────┐   append-only sha256 hash chain. every decision +
   │ LEDGER  │   a hash of its outcome, link-locked to the prior
   └────┬────┘
        │
        ▼
   ┌─────────┐   recompute the chain AND the content hash.
   │ RECEIPT │   verify() is real — there is no return-True stub
   └─────────┘
```

- **The Gate** governs the shell + path surface — which programs may run, which paths may be touched, whether a command chains or substitutes its way out of policy. Deny-by-default and fail-closed: anything it cannot classify is blocked. It can also gate on real blast radius: wire a `ReachOracle` (opt-in) and a write is gated on its **reverse-dependency closure** — what the action can reach, not just what string it contains. The default policy is the substring + path gate; the reach closure is opt-in.
- **The Jail** closes the gap the gate cannot see: the *code inside* an allowed command. On macOS the native primitive is `sandbox-exec` (Seatbelt) — no Docker assumed.
- **The Ledger** is the testimony: an append-only, hash-chained record where mutating or reordering any past entry breaks the re-link.
- **The Receipt** is the closure artifact. Its verifier recomputes the chain from genesis *and* recomputes the receipt's own content hash. `persist()` runs that verifier as a write-time round-trip and **raises on failure**, so a corrupt write can never be reported as success.

The Cell is the keystone, and it composes at every scale: one tool call, one agent, or a whole team sharing one ledger. The kernel does not change when the model does. Subclass `Cell` and override `_execute` to govern your own tool surface — the gate + jail + ledger wrapping is inherited unchanged.

---

## What it does NOT do

This section is the trust anchor. Read it before you build on this.

- **It is a reference governance primitive, not a hardened production sandbox.** It is the smallest honest version of the idea — clear enough to read end-to-end, strong enough to be useful, not a certified security product.
- **The live-verified jail is macOS Seatbelt (OS confinement).** `jail.py` also contains a **DRAFT** Docker backend; do not read DRAFT as proven. On other hosts you supply confinement or opt into gate-only (`use_jail=False`). In gate-only mode only a small safe set of heads runs by default; other heads need `allow_unjailed_heads` on both the Cell and its Gate (the Cell heads kwarg alone does not opt in a foreign gate). Interpreters need both knobs: membership in `allow_unjailed_heads` and `allow_unjailed_interpreters=True` on both the Cell and its Gate (the Cell interpreter kwarg alone does not opt in a foreign gate, and an interpreter listed only in `allow_unjailed_heads` is still refused), and gate-only commands run without a shell, one command at a time. Playground `ClassifyCell` is gate-only, so a chain such as `echo a && echo b` is `chain-unjailed` BLOCK (jail-mode would ALLOW). The gate and ledger are platform-independent.
- **It is tamper-EVIDENT, not tamper-PROOF.** The ledger core is a **keyless sha256 hash chain** — nothing in the agent's execution path is signed. It proves *internal consistency* — that no entry was altered or reordered — **not authorship.** An attacker who can rewrite the entire file from genesis can produce a consistent chain. The core ledger is **not cryptographic signatures.** There is an **optional, verification-only ed25519 operator-attestation overlay** (`operator_attest.py`, opt-in via `deponent[attest]`) that verifies an operator's out-of-band signature over a run; it signs nothing the agent does. The core stays keyless on purpose — asymmetric signing in the execution path is a deliberate non-goal.
- **The default gate policy is a sane coding-agent sandbox, not a universal security policy.** It is overridable per instance (`deny=`, `allow_heads=`). Tune it for your tool surface.

State the limits, or the guarantees mean nothing.

---

## Proven

The suite exercises the gate, live macOS Seatbelt confinement, ledger integrity,
receipts, reconciliation, claims, build profiles, the public playground, and the
conformance harness. Platform- or optional-capability checks skip explicitly when
their real backend is unavailable; they are never replaced with a passing mock.

Run `python3 -m pytest -q` to get the current count and host-specific skip set.
`make self-gate-live` drives a real local build through the same gate, jail, and
ledger path and emits receipts for inspection.

**The `GAK-conformant` mark (self-evaluated).** The mark is **self-evaluated against GAK v0.x**: `deponent.badge certify` scores the kernel against a standard its own author wrote, and it stays self-evaluated until a second, independent implementer passes the same harness. `python3 -m deponent.badge certify --kernel deponent` emits a self-contained badge (the SVG above), a markdown snippet, and a JSON receipt carrying a sha256 `clauses_digest` over the per-clause results — so the badge maps to a specific, reproducible outcome. Re-derive it yourself, fail-closed:

```sh
python3 -m deponent.badge verify --kernel deponent   # exit 0 only when the mark is earned
```

Any kernel that implements the small adapter and passes the clause set earns the same mark; a kernel that fails gets a red "not conformant" badge and a non-zero exit. The badge is generated locally — no shields.io, no network — because a sovereignty product shouldn't phone home to prove it passed.

**Seatbelt escape-proofs — two kinds, kept separate so the claim is exactly as strong as the evidence.** (1) **Committed live canaries** (`canaries/CANARIES.md`, J1–J8): network exfil, raw-socket egress, writes outside the sandbox, child-process escape, memory-bomb, and wall-clock runaway — each a real test run against the live macOS sandbox, 0 through; if a canary stops holding, the suite goes red. (2) **Manual development red-team** — during development I hand-ran Seatbelt bypasses (`osascript 'do shell script'`, `launchctl submit`, loopback `/dev/tcp`, DNS, symlink/hardlink/rename writes-out), all blocked; these **shaped the gate denylist and the Seatbelt profile but are not committed tests** — take them as reported, not reproducible from the repo.

**Recompute-not-trust receipts:** the verifier does not read a stored boolean. It re-links the chain from genesis and recomputes the receipt's content hash over its canonical body. `persist()` runs that verifier on write and raises on failure. This is the project's core rule made mechanical: *self-reported health is never the evidence.*

---

## Governed agent team example

`examples/governed_team.py` shows an Architect, a gated Builder, and an advisory
Reviewer sharing one ledger. The example is model-agnostic through
`examples/backends.py`; use an Ollama or MLX backend, or add your own. Closure is
an out-of-band test run plus an intact ledger—not the Builder saying “done.”

```bash
# Ollama (any tool-capable coder)
python3 examples/governed_team.py --backend ollama --model qwen3-coder:30b \
  --goal "Implement reverse_words(s): reverse word order, collapse runs of spaces."

# Local MLX North Mini Code (Apple Silicon)
DEPONENT_MLX_MODEL=mlx-community/North-Mini-Code-1.0-4bit \
  python3 examples/governed_team.py --backend mlx --goal "..."
```

---

## Install + run the tests

```bash
git clone <repo> deponent && cd deponent
python3 -m pip install -e .        # or just run from the repo — the core needs no install

make test                          # current suite; real-backend skips are host-dependent
make demo                          # the minimal testify demo, no model needed
```

The kernel has **zero third-party dependencies.** Only the example team needs a model runtime; the kernel does not.

### Run it in Docker (any platform)

```bash
docker build -t deponent .
docker run --rm deponent             # scores the kernel against its own GAK standard -> CONFORMANT
docker run --rm deponent make test   # run the suite in-container
```

The gate, ledger, and receipts are platform-independent. Live-verified OS confinement is macOS Seatbelt. The Docker backend in `jail.py` is **DRAFT**; `tests/test_jail_backends.py` gates those tests. Do not read DRAFT as proven.

---

## Stewardship

Deponent is an open-source project from
[Centennial Defense Systems](https://centennialdefense.systems), maintained by
Christopher “CJ” Chanhnourack. The repository is the complete public reference
kernel; its claims are limited to behavior you can reproduce from the source.

---

## Support

Report vulnerabilities through [SECURITY.md](SECURITY.md). General support and
contributions are best-effort; no response-time SLA is offered.

---

## License

Apache-2.0 — including the patent grant.

The license applies to the public source and includes the Apache 2.0 patent grant.
