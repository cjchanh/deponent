# Deponent Repository Rules

## Purpose and authority

This checkout is the isolated public-source remediation lane for Deponent.
Global Codex governance remains active. This file adds repository-specific
enforcement and does not authorize commits or outward actions.

Source identity and scope are frozen in the ES-06 cross-reference:
`/Users/cj/Documents/Codex/2026-08-11/files-mentioned-by-the-user-you/outputs/release/evidence/20260811_public_entity_search_master/items/ES-06/ACTIVE_DEPONENT_CROSS_REFERENCE.md`.

## Source boundaries

- Use only this public checkout and its public Git history.
- Never import from `/Users/cj/Workspace/active/deponent` or any private origin.
- Require public `main` to remain at the reviewed base before applying ES-06.
- Preserve Apache-2.0, Python `>=3.10`, and `project.dependencies = []`.
- Keep the core standard-library-only; optional dependencies remain opt-in.

## Safety and product truth

- Public executable demos use disposable relative targets, never filesystem-root
  or home-directory targets.
- Hostile root/home strings are allowed only in explicitly reviewed,
  non-executing policy tests and canary documentation.
- Frozen-base runtime still registers Sworn as a built-in validator. ES-06 must
  make Deponent the sole current built-in and must not describe Sworn as current.
- Remove private-infrastructure names and non-current product promotion from
  public package, example, and rendered-documentation surfaces.
- Do not edit `deponent/gate.py`, `deponent/jail.py`, or
  `deponent/operator_attest.py` without a new independently verified security
  finding and fresh `OPERATOR COMMIT:` authority.

## Present tree (facts, not a score)

This checkout currently:

- Registers only `"deponent"` in `BUILTIN_ADAPTERS`.
- Keeps `deponent/adapters/sworn.py` and `deponent/sworn_adapter.py` in source as
  hatch-excluded legacy wrappers, labeled not-current built-in.
- Uses disposable relative `rm -rf ./blocked-example` targets on public executable
  demos.
- Proves that disposable target with `use_jail=False`: BLOCK, unchanged sentinel
  bytes, valid refusal ledger entry
  (`tests/test_cell.py::test_disposable_relative_target_is_blocked_unchanged_and_testified`).

These are observations about this tree. They are not a completion mark.

## Required method

- Use red-green TDD: capture a failing regression before production edits.
- Test the real disposable-target behavior with `use_jail=False`; prove BLOCK,
  unchanged sentinel bytes, and a valid refusal ledger entry.
- Scan source, rendered docs, wheel, and sdist for prohibited targets, brands,
  private residue, stale contact data, and unexpected dependencies.
- Build and install artifacts in isolated external directories; do not rely on
  source-tree imports for artifact verification.

## Verification

- Tests: `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider`
- Collection: `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest --collect-only -q -p no:cacheprovider`
- Repository syntax lint: `ruff check --no-cache --select E9,F63,F7,F82 .`
- Authorized Python-path lint: `ruff check` over every changed Python path in
  the reviewed ES-06 scope plus the authorized 2026-08-12 generic
  `examples/safety_action_governor.py` rename, always with `--no-cache`.
- Authorized Python-path format: `ruff format --check` over every changed
  Python path in the reviewed ES-06 scope plus the authorized 2026-08-12 generic
  `examples/safety_action_governor.py` rename, always with `--no-cache`.
- Build: `PYTHONDONTWRITEBYTECODE=1 python3 -m build --sdist --wheel --outdir
  /Users/cj/Documents/Codex/2026-08-11/files-mentioned-by-the-user-you/work/es06-dist .`
- Metadata: run `python -m twine check` from an isolated ES-06 tool venv outside
  the repository against
  `/Users/cj/Documents/Codex/2026-08-11/files-mentioned-by-the-user-you/work/es06-dist/*`.
  Bootstrap that venv under the external `work/` directory with pinned `build`,
  `twine`, `ruff`, `pytest`, and `cryptography` versions; record `pip freeze` in
  evidence.
- Conformance: `PYTHONDONTWRITEBYTECODE=1 python3 -m deponent.badge verify --kernel deponent`

The frozen base has 14 full-tree Ruff findings and 43 files that the current
formatter would rewrite, including all three protected files. Preserve that
baseline explicitly: final full-tree debt may not increase, every changed
authorized Python path must pass full Ruff and format checks, repository syntax
lint must pass, and the three protected SHA-256 values in the cross-reference
must remain exact. Do not relabel the pre-existing full-tree debt as passing.

Final test/collection counts must meet or exceed the registered baseline. Any
required gate, package-content, provenance, source-identity, protected-hash, or
baseline-ratchet failure halts.

## 2026-08-12 residue closure extension

The current operator-authorized local closure also permits `SPEC.md`,
`canaries/CANARIES.md`, and the rename of
`examples/safetyspine_action_governor.py` to
`examples/safety_action_governor.py`. The change must remove retired product
promotion while retaining a generic executable safety-governance example. The
authority record is
`/Users/cj/Documents/Codex/2026-08-11/files-mentioned-by-the-user-you/outputs/release/evidence/20260811_public_entity_search_master/items/ES-06/SCOPE_EXTENSION_20260812.md`.

## Outward boundary

No commit, push, publication, release, PyPI upload, GitHub mutation, deployment,
outreach, repository deletion, or checkout-session creation is authorized by
this repository contract.
