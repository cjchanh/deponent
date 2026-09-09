# Deponent

[![deponent: GAK self-evaluated](docs/deponent-badge.svg)](#proven) &nbsp;·&nbsp; [![CI](https://github.com/cjchanh/deponent/actions/workflows/ci.yml/badge.svg)](https://github.com/cjchanh/deponent/actions/workflows/ci.yml) &nbsp;·&nbsp; **Apache-2.0** &nbsp;·&nbsp; check the mark yourself: `python3 -m deponent.badge verify --kernel deponent`

A deny-by-default gate, macOS Seatbelt jail, and tamper-evident ledger for local agent tool calls. Standard-library only: **zero third-party runtime dependencies.**

**Install:** `pip install deponent`

```python
import tempfile
from deponent import Cell

cell = Cell(tempfile.mkdtemp(), use_jail=False)
print(cell.act("write_file", {"path": "notes.txt", "content": "hello"}).output)
print(cell.act("run_cmd", {"cmd": "rm -rf ./blocked-example"}).output)
print(cell.act("exfiltrate", {"to": "evil.example"}).output)
```

**Refuses:** unknown tools, out-of-sandbox paths, destructive commands; in gate-only mode, interpreters and command chains unless you opt them in.

Why it exists: [docs/WHY.md](docs/WHY.md). Limits: [docs/BOUNDARIES.md](docs/BOUNDARIES.md).

---

## Quickstart

```python
import tempfile
from deponent import Cell

cell = Cell(tempfile.mkdtemp(), use_jail=False)   # use_jail=True on macOS adds the Seatbelt jail
print(cell.act("write_file", {"path": "notes.txt", "content": "hello"}).output)  # ALLOW
print(cell.act("read_file",  {"path": "notes.txt"}).output)                      # ALLOW
print(cell.act("run_cmd",    {"cmd": "rm -rf ./blocked-example"}).output)        # BLOCK (destructive)
print(cell.act("exfiltrate", {"to": "evil.example"}).output)                     # BLOCK (deny-by-default)

ok, msg = cell.verify()
print(f"chain intact: {ok} — {msg}")
```

That is `examples/minimal.py`. Run it (`python3 examples/minimal.py`). No model. No network.

---

## Containment

**Containment boundary:** the live-verified jail is macOS Seatbelt (OS confinement) only. `Cell()` defaults to `use_jail=True`; when the jail is unavailable it fail-closes (records ALLOW, refuses execution) rather than silently switching to gate-only. On other hosts you supply confinement or opt into gate-only (`use_jail=False`): the deny-by-default gate and the ledger still run, but there is no OS confinement; argument paths are containment-checked whether spaced, glued to a flag (`-o/tmp/x`, `--output=/tmp/x`), dash-prefixed after `--` (`cat -- -secret`), or reached through a symlink that already exists inside the sandbox. In gate-only mode only a small safe set of heads runs by default; other heads need `allow_unjailed_heads` on both the Cell and its Gate (the Cell heads kwarg alone does not opt in a foreign gate). Interpreters need both knobs: membership in `allow_unjailed_heads` and `allow_unjailed_interpreters=True` on both the Cell and its Gate (the Cell interpreter kwarg alone does not opt in a foreign gate, and an interpreter listed only in `allow_unjailed_heads` is still refused), and gate-only commands run without a shell, one command at a time. Playground `ClassifyCell` is gate-only, so a chain such as `echo a && echo b` is `chain-unjailed` BLOCK (jail-mode would ALLOW). Gate-only runs are policy evidence, not sandbox evidence. The ledger is tamper-evident for edits, deletions and reordering; truncation and re-chaining are caught only against a head published outside the ledger (`Ledger.head()` / receipt `ledger_head`).

```
deny-by-default gate  ->  Seatbelt jail  ->  tamper-evident ledger  ->  verifiable evidence record
```

- **The Gate** checks which programs may run, which paths may be touched, and whether a command chains or substitutes its way out of policy. Deny-by-default and fail-closed. Optional `ReachOracle`: a write can be checked on its reverse-dependency closure.
- **The Jail** confines the code inside an allowed command. On macOS the native primitive is `sandbox-exec` (Seatbelt).
- **The Ledger** is an append-only sha256 hash chain. Mutating or reordering any past entry breaks the re-link.
- **The evidence record** (`deponent.receipts`) recomputes the chain from genesis *and* recomputes its own content hash. `persist()` runs that check as a write-time round-trip and **raises on failure**.

Subclass `Cell` and override `_execute` to wrap your own tool surface — gate + jail + ledger wrapping is inherited.

---

## What it does NOT do

Full text: [docs/BOUNDARIES.md](docs/BOUNDARIES.md).

- **Reference kernel, not a certified security product.**
- **Live-verified jail is macOS Seatbelt only.** Docker in `jail.py` is **DRAFT**.
- **Tamper-evident, not tamper-proof.** Keyless sha256 chain; optional verification-only ed25519 overlay (`operator_attest.py`, extra `deponent[attest]`) checks a maintainer's out-of-band signature over a run and signs nothing the agent does.
- **Default policy is a coding-agent sandbox.** Override with `deny=` / `allow_heads=`.

---

## Proven

The suite exercises the gate, live macOS Seatbelt confinement, ledger integrity,
evidence records, reconciliation, claims, build profiles, the public playground, and the
conformance harness. Platform- or optional-capability checks skip explicitly when
their real backend is unavailable; they are never replaced with a passing mock.

Run `python3 -m pytest -q` to get the current count and host-specific skip set.
`make self-gate-live` drives a real local build through the same gate, jail, and
ledger path and emits evidence records for inspection.

**The `GAK-conformant (self-assessed)` mark.** The mark is **self-assessed against GAK v0.x**: `deponent.badge certify` scores the kernel against a standard its own author wrote, and it stays self-assessed until a second, independent implementer passes the same harness. The certification JSON carries `self_assessed: true` and `third_party_verified: false`; the bare mark `GAK-conformant` is reserved for an independent run. `python3 -m deponent.badge certify --kernel deponent` emits a self-contained badge (the SVG above), a markdown snippet, and a JSON record carrying a sha256 `clauses_digest` over the per-clause results. Re-derive it yourself, fail-closed:

```sh
python3 -m deponent.badge verify --kernel deponent   # exit 0 only when the mark is earned
```

Any kernel that implements the small adapter and passes the clause set earns the same mark; a kernel that fails gets a red "not conformant" badge and a non-zero exit. The badge is generated locally — no shields.io, no network.

**Seatbelt escape-proofs — two kinds, kept separate so the claim is exactly as strong as the evidence.** (1) **Committed live canaries** (`canaries/CANARIES.md`, J1–J8): network exfil, raw-socket egress, writes outside the sandbox, child-process escape, memory-bomb, and wall-clock runaway — each a real test run against the live macOS sandbox, 0 through; if a canary stops holding, the suite goes red. (2) **Manual development review** — during development Seatbelt bypasses (`osascript 'do shell script'`, `launchctl submit`, loopback `/dev/tcp`, DNS, symlink/hardlink/rename writes-out) were hand-run and blocked; these **shaped the gate denylist and the Seatbelt profile but are not committed tests** — take them as reported, not reproducible from the repo.

**Recompute-not-trust evidence records:** the verifier does not read a stored boolean. It re-links the chain from genesis and recomputes the record's content hash over its canonical body. `persist()` runs that verifier on write and raises on failure. Self-reported health is never the evidence.

---

## Example agent team

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
make demo                          # the minimal demo, no model needed
```

The kernel has **zero third-party dependencies.** Only the example team needs a model runtime; the kernel does not.

### Run it in Docker (any platform)

```bash
docker build -t deponent .
docker run --rm deponent             # scores the kernel against its own GAK standard -> GAK-conformant (self-assessed)
docker run --rm deponent make test   # run the suite in-container
```

The gate, ledger, and evidence records are platform-independent. Live-verified OS confinement is macOS Seatbelt. The Docker backend in `jail.py` is **DRAFT**; `tests/test_jail_backends.py` gates those tests. Do not read DRAFT as proven.

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
