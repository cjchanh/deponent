# Changelog

## 0.1.3

Credential shield, and ledger verification that fails closed on missing, empty or forked testimony. Callers that used to get a success on these ledger inputs now get a refusal.

- **Credential shield** (`python3 -m deponent shield` / `python3 -m deponent shield-verify`): runs an agent process tree under a deny-by-default macOS Seatbelt profile — reads inside `HOME` are denied by default, with the workspace, any declared `--state-dir` or `--allow-read` path, and the agent's own declared key as the carve-outs; writes are confined to the workspace; inherited `*_API_KEY`/`*_TOKEN`/`*_SECRET` env vars are scrubbed to an allowlist; the parent (outside the sandbox) writes an externally anchored, hash-chained, recomputable receipt (`python3 -m deponent shield-verify` returns `ANCHORED_OK` / `MISSING` / `TAMPERED` / `UNANCHORED`, never a false "intact"). Composes with [Agent Safehouse](https://github.com/eugene1g/agent-safehouse) via `--with-safehouse` (Safehouse contains, Deponent records and proves on top). Fail-closed: an invalid path, a missing `sandbox-exec`, or any other unmet precondition means REFUSE — no unsandboxed fallback. Known-not-stopped residuals (workspace hardlinks, cross-process signalling, `sysctl(KERN_PROCARGS2)` env/argv reads, and others): docs/SHIELD.md.
- `Ledger.load(path).verify()` no longer reports a missing or empty ledger file as intact. It returns `(False, "no testimony: …")` unless you pass an external anchor that commits to an empty chain (`expected_head=Ledger.GENESIS` or `expected_length=0`, e.g. a receipt's `ledger_head` / `ledger_length` for a run that recorded nothing). A ledger that has only recorded in-process is unaffected.
- `receipts.persist()` raises `ValueError` for such a ledger (one loaded from a missing or empty file) and writes nothing: no receipt, no index line, no `LATEST`. A live ledger that recorded nothing first-hand is not affected: `persist()` still mints its receipt, with `ledger_length` 0 and `ledger_head` GENESIS, and C-CHAIN-INTACT abstains for that run.
- `claims.attest()` / `Cell.attest()`, claim `C-CHAIN-INTACT`:
  - REFUTED (the run is not sound) for a ledger loaded from a missing or empty file;
  - ABSTAIN instead of ATTESTED for a run that recorded no actions, because an empty chain proves nothing;
  - REFUTED when the run has actions but the ledger holds no entries.
- `Ledger(path)` raises `LedgerForkError` (a subclass of `FileExistsError`) when `path` already holds a chain, instead of appending a second chain that left the file unverifiable. So do `Cell(..., ledger_path=<file with entries>)`, `playground.run_agent(..., sandbox=<directory reused from an earlier run>)` and `selfgate.governed_self_build(<reused directory>)`. Use a new path per run, or continue the chain explicitly with `Ledger.load(path)`.
- Every append to a ledger file first checks that the file still ends where this ledger left it: the same byte length and the same last entry hash. A second writer on the same file, for example two `Ledger.load(path)` instances, now gets `LedgerForkError` and nothing is written, instead of forking the chain from a stale head. The in-memory chain advances only after the write lands. With no OS lock, two processes that pass the check at the same instant can still fork the file; either one's next append then refuses, and `verify()` reports the break.
- Ledger files whose records contain U+2028, U+2029 or U+0085 (for example in a tool parameter) now load. Before, `Ledger.load()` split them with `str.splitlines()` and raised `JSONDecodeError`, so an agent could make its own testimony unloadable. Records are now split on `"\n"` only, like the writer writes them. A stray separator, or other non-JSON whitespace between records, now fails closed instead of being skipped. Files from earlier writers, including CRLF line endings from text mode on Windows, still load.
- `SPEC.md` `file:line` citations now point at the current source.

## 0.1.2 — 2026-09-08

Gate and ledger hardening since 0.1.1. Not uploaded to PyPI from this tree.

- `353f91b` — gate-only mode is deny-by-default: only `GATE_ONLY_SAFE_HEADS` run unjailed; interpreters need both opt-in knobs (C1).
- `b18ff68` — argument paths glued to flags (`-o/tmp/x`, `--output=/tmp/x`) are containment-checked like spaced paths (red-team D-1).
- `e1a2bf1` — `Ledger.head()` / `verify(expected_head, expected_length)`; write/read refuse outside-pointing symlinks.
- `16e8603` — every `run_cmd` argv token is resolved for containment, so a pre-planted sandbox symlink that points outside cannot be read through a bare name (red-team D-2).
- `7a3d13e` — lock the D-2 escape-shape matrix (relative chain, symlink-to-symlink, dangling, directory, nested, flag values).
- `c1f399e` — dash-prefixed operand after `--` is resolved as itself; execute path re-checks argv for direct subclass calls.
- this tree — macOS CI fails if `tests/test_jail.py` skips (C4); lock `python3 -c 'a; b'` as data not a chain (C2); register pass on README / PyPI description / `docs/`.

## 0.1.1

Public kernel as released. Predates the gate-hardening commits above.
