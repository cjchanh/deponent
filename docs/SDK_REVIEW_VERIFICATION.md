# SDK documentation repair — verification record

Date: 2026-10-11 UTC (2026-10-10 America/Denver).

Scope: the documentation introduced by [PR #5](https://github.com/cjchanh/deponent/pull/5).
The repair was prepared from commit `0df679c89c269f4343afe2525a5f4ef54b79db43`.
All 77 source blobs were checked against their Git blob hashes; the reconstructed
base tree was `ca6540af045910e3269f26ce40ba4872c9b08145`.
No kernel, test, dependency, or workflow file is changed by this repair.

## Fresh local checks

Host: Linux, Python 3.12. These are local documentation checks, not live macOS or
Docker confinement evidence.

| Check | Observed result |
|---|---|
| Execute each Python block in `README_SDK.md` and `API_SURFACE.md` in a fresh process | All four blocks passed, including actual file write, deletion refusal, unchanged sentinel, custom-tool ALLOW/BLOCK, and ledger verification |
| Import every symbol in the API module table | 67 symbol checks passed, including optional attestation with installed cryptography |
| `python3 -S -c "import deponent; from deponent.claims import Claim, ClaimSet, attest"` | Exit 0; core imports with site packages disabled |
| `python3 -m deponent.badge verify --kernel deponent` | Exit 0; EARNED, self-assessed, 10 PASS / 3 NA; digest `de6b7089f894` |
| `run_conformance(DeponentAdapter()).to_dict()` | Conformant; 10 PASS, 0 FAIL, 3 NA; 13 clauses |
| Record a non-sensitive write and inspect its ledger entry | Plaintext request and reason present; no content-blind replacement fields |
| Parse all source/test Python modules with `ast.parse` | Passed |
| Relative-link and public-content checks | Passed; no private host paths or root-deletion demo targets in changed guides |
| `git diff --check` | Exit 0 |

The custom Rust shim example depends on an application-owned adapter. It was not
executed as a Rust integration and is not represented as one.

## Required commands unavailable on this host

- `PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider`
  returned exit 1: `No module named pytest`.
- Installing the development tools in an isolated environment failed:
  `No matching distribution found for pytest`.
- `ruff check --no-cache --select E9,F63,F7,F82 .` returned exit 127:
  `ruff: command not found`.
- A standard-library `unittest discover -s tests -q` attempt was **not a full-suite
  pass**: 315 discovered entries, 58 skips, and four module-import errors because
  those modules require pytest. It does not replace the required pytest gate.

No stale 181-test or 174-pass baseline is retained as fresh evidence.

## Existing upstream CI, separately scoped

The source commit's [CI run 37268186831](https://github.com/cjchanh/deponent/actions/runs/37268186831)
completed successfully on October 5, 2026. All eight Ubuntu/macOS and Python
3.10–3.13 jobs were retrieved and reported success. The macOS jobs also reported
successful no-skip containment/shield steps. Those are **upstream commit receipts**,
not a fresh run on the documentation repair or on a consumer's machine.

The repair PR's checks must be assessed against its actual commit. This record
does not predeclare those checks successful. Ruff remains unverified unless a
separate receipt is produced; the existing CI workflow does not run Ruff.

## Review finding disposition

All rows refer to the original review on PR #5. They describe repairs proposed
here, not reviewer approval or resolution of the original threads.

| Original comment ID | Finding | Repair |
|---|---|---|
| 4180856635 | Custom tool lacks custom Gate | Runnable Gate + Cell example with positive and negative outcomes |
| 4180856644 | Untested conformance claims | Explicit 13-clause scope; redirect/newline excluded from conformance claims |
| 4180856651 | Missing jail contract method | Required `jail_fails_closed()` and failure semantics documented |
| 4180856656 | Shim incorrectly promises CLI discovery | Direct harness path and explicit registry requirement |
| 4180856662 | Nonexistent content-blind mode | Plaintext request/reason disclosure and confidentiality limits |
| 4180856670 | Obsolete gate-only execution description | `shell=False`, one segment, explicit opt-ins |
| 4180856676 | Legacy Sworn listed as public built-in | Source-only, excluded, not-current qualification |
| 4180856680 | Root-deletion quickstart | Temporary disposable target, sentinel, verified refusal |
| 4180856683 | Stale test receipts | Fresh checks and unavailable gates separated from upstream CI |
| 4180856685 | Wrong claims module | `deponent.claims` separated from optional operator-attestation module |
| 4180856686 | Nonexistent reach function | `ImportGraphReach` and actual reach exports |
| 4180856689 | Rebinding constants presented as policy change | Explicit per-instance `deny=` / `allow_heads=` configuration |
| 4180856695 | Incorrect non-macOS availability | Docker CLI/daemon selection and DRAFT/live-test limits |
| 4180856698 | Nonexistent backend module | Actual backend classes in `deponent.jail` |
| 4180856703 | Protocol import path does not export it | `deponent.adapters.contract.KernelAdapter` |

The import check also found four claimed trace-helper functions absent from
`deponent.claims`; the table now lists only that module's real exports. The threat
model removes stale line anchors and retains the separate Cell/jail control-file
issue described by PR #4. This change does not fix or close that security issue.
