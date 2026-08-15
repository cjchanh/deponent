# UPGRADE_REPORT — deponent-public-es06

Writer lane: local Cursor on this checkout only. No Codex, no push, no other repos.

This is not a score. It is a list of facts about this tree after one local upgrade.

## Purpose of this checkout

Public ES-06: isolated public Deponent source. Runtime built-in is Deponent only. Public executable demos use disposable relative targets. Do not describe Sworn as current. Do not advertise private brands. Do not claim more jail/key guarantee than the code has. `deponent/gate.py`, `deponent/jail.py`, and `deponent/operator_attest.py` were not edited.

## What changed

Honesty tests in `tests/test_conformance.py` (red first, then green):

- SPEC version is `0.1.1` and lists every `__all__` name.
- SPEC does not freeze "44 tests pass".
- `deponent/conformance.py` does not call the clause set "seven-primitive" (there are 13 clauses).
- SPEC / SECURITY / `canaries/CANARIES.md` do not claim the whole project has no key material.
- README / SECURITY / canaries do not mention Sworn; SPEC may mention `deponent/adapters/sworn.py` only as hatch-excluded and not a current built-in.
- Package docstring uses `tempfile` + `use_jail=False`, not `Cell("/tmp/agent-workdir")`.
- README does not call the Docker jail live-verified.
- Canaries catalog the disposable-relative-target cell proof and the redirect/newline gate proofs.

Docs/code aligned to those tests:

- `SPEC.md`: version `0.1.1`, current `__all__`, current line citations, shell-redirect and newline coverage, ledger truncation bound, optional `operator_attest` overlay, `jail_available()` as backend dispatch, Docker backend labeled DRAFT.
- `SECURITY.md` and `canaries/CANARIES.md`: core is keyless; optional attest extra exists; no frozen 44-pass slogan; C7 disposable-target row; G10/G11 redirect/newline rows.
- `README.md`: live-verified jail is Seatbelt; Docker backend is DRAFT.
- `deponent/__init__.py` docstring matches the README gate-only disposable quickstart.
- `deponent/conformance.py`: drops "seven-primitive".
- `AGENTS.md`: "Present tree" facts only. Not a completion mark.

Protected files were not touched: `deponent/gate.py`, `deponent/jail.py`, `deponent/operator_attest.py`.

## What is still false or unfinished

- This is still a reference primitive, not a hardened production sandbox.
- The ledger is still tamper-evident, not signed, not authorship-proof. An attacker who rewrites the file from genesis can make a consistent chain.
- `verify()` still does not detect tail truncation by itself. Receipt `expected_len` / sealed head is required for that.
- Multi-schema receipt verification is still not implemented (`SPEC.md` §8).
- Live-verified OS confinement is still macOS Seatbelt only. The Docker backend in `jail.py` is still DRAFT. `tests/test_jail_backends.py` is still gated.
- `deponent/adapters/sworn.py` and `deponent/sworn_adapter.py` still exist in source as hatch-excluded legacy. They are importable from a source checkout. They are not in `BUILTIN_ADAPTERS`.
- Full-tree Ruff/format debt named in `AGENTS.md` (14 findings / 43 files, including the three protected files) was not cleaned. Changed Python paths were checked; the rest was not relabeled as passing.
- SPEC line numbers will go stale again if those files move. They were corrected against this tree, not guaranteed forever.
- Example-team bench numbers in SPEC (n ≈ 17, 0.749 vs 0.686, 32-run anecdote) were not re-run. They remain historical claims about the example, not the kernel.
- Wheel / sdist / twine checks from `AGENTS.md` were not run. This lane stayed in-repo and did not write an external Codex `work/` dist dir.
- `AGENTS.md` still says this repository contract does not authorize commits. The operator query for this turn asked for a local commit. No push.

## How a reviewer should check

From this checkout, unsandboxed (Seatbelt `sandbox_apply` fails when nested under another sandbox):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest --collect-only -q -p no:cacheprovider
PYTHONDONTWRITEBYTECODE=1 python3 -m deponent.badge verify --kernel deponent
python3 examples/minimal.py
ruff check --no-cache --select E9,F63,F7,F82 .
ruff check --no-cache tests/test_conformance.py deponent/conformance.py deponent/__init__.py
ruff format --check --no-cache tests/test_conformance.py deponent/conformance.py deponent/__init__.py
```

Honesty subset:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests/test_conformance.py::TestPublicDistributionTruth
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests/test_cell.py::TestCell::test_disposable_relative_target_is_blocked_unchanged_and_testified
```

Confirm protected files are unchanged:

```sh
git diff -- deponent/gate.py deponent/jail.py deponent/operator_attest.py
```

That diff must be empty.

What this writer actually ran:

- `TestPublicDistributionTruth`: 12 passed.
- Suite excluding `tests/test_jail.py` and `tests/test_jail_backends.py`: exit 0 (1 skip). Nested-sandbox full suite: 6 Seatbelt failures, all `sandbox_apply: Operation not permitted`. Those are the outer sandbox, not a kernel change.
- Collected tests after this change: 166 (was 159). Added 7 honesty tests.
- `python3 -m deponent.badge verify --kernel deponent`: `EARNED: deponent is GAK-conformant (10 pass / 3 na, action-gate); digest de6b7089f894`.
- `python3 examples/minimal.py`: BLOCK on `rm -rf ./blocked-example` and `exfiltrate`; chain intact (4 entries).
- Ruff syntax + changed-path check/format: pass.

Do not treat that as a host-independent pass count. Run the unsandboxed suite on the review host and record that host's skip set.
