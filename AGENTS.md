# Deponent — agent contract

This is a public kernel. Agents **do the work**. A brick is not a governor.

## Allow (do this without waiting)

- Read, edit, test, lint, and local-commit on a feature branch.
- Open a pull request with command receipts (pytest / ruff / python3 -m deponent.badge verify --kernel deponent).
- Fix docs, examples, CI, leaked private paths, and claim-language drift.
- Use disposable relative targets in executable demos. Never / or $HOME.

## Block (irreversible floor)

- PyPI upload, tags, GitHub Releases, new remotes, history rewrite, sudo, network exfil.
- Real CUI / PII / customer evidence / private Archivist corpus.
- Edits to deponent/gate.py, deponent/jail.py, or deponent/operator_attest.py unless there is a new independently verified security finding.

## Product truth

- Deponent is the current public built-in kernel. Do not describe Sworn as the current validator path.
- Tamper-evident, not tamper-proof. Research prototype, not an accreditation.
- Do not put private host paths (/Users/cj/..., Codex evidence dirs, Workspace checkouts) in public files.
- Core stays standard-library-only. project.dependencies stays empty.

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

## Verification (receipts, not vibes)

    PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
    ruff check --no-cache --select E9,F63,F7,F82 .
    python3 -m deponent.badge verify --kernel deponent

If a check cannot complete, report the exact command and output. Then fix it or skip-honest. Do not halt the whole job because a reversible edit lacked a ceremonial OPERATOR COMMIT line.

## Outward boundary

Do not publish, tag, or PyPI-upload from this contract. Do not delete the repository. Everything else that is local and reversible is in-bounds.
