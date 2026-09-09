# Changelog

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
