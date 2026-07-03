# Security Policy

Deponent is a security tool, and it is held to the standard it asks of agents:
it tells you exactly what it does and does not protect, and it invites you to
break it.

## Honest scope (read this first)

Deponent is a **reference governance primitive**, not a hardened production
sandbox. It is designed to make a local agent's actions *testify* — gated
deny-by-default, jailed, and recorded to a tamper-evident chain — not to be an
impenetrable container. Read [SPEC.md](SPEC.md) for the full threat model and the
explicit non-goals. In particular:

- The in-language jail is **macOS-only** (Seatbelt / `sandbox-exec`). Off macOS,
  `run_cmd` fails closed and you must supply your own sandbox (firejail, nsjail,
  a container). The gate and the ledger are platform-independent.
- The ledger is **tamper-evident** (sha256 hash chain), **not** cryptographically
  signed. It proves a record was not altered or reordered; it does **not** prove
  authorship. There is no key material in this project. Do not rely on it for
  attribution against an attacker who can rewrite the whole log from genesis.

These are deliberate boundaries, not undiscovered gaps. If you find a way the gate
or jail fails *within its stated scope* — a sandbox escape, a deny-bypass, a
tamper that `verify()` misses — that is a real vulnerability and we want it.

## Reporting a vulnerability

Email **cj@centennialsystems.com** with a description and, ideally, a reproducing
test in the style of `tests/`. Please do not open a public issue for an unpatched
escape or bypass.

We aim to acknowledge reports promptly and to credit reporters (with permission)
once a fix lands.

## Supported versions

`0.x` is pre-1.0; fixes land on `main`. Pin a tag for reproducibility.
