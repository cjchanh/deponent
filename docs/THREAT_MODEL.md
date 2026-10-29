# Deponent — threat model

This document describes the 0.2.0 source tree, its mechanisms, and their limits.
It is a source review, not an independent security certification or a live-host
containment test. References use symbols instead of drifting line numbers.

## Contract and scope

[SPEC.md](../SPEC.md) is the normative governance contract. A disagreement between
that contract and the implementation is a defect, not evidence that the promised
behavior exists. This companion covers Gate, Cell, jail, ledger, and receipts.
The credential shield has a separate surface in [SHIELD.md](SHIELD.md).

The kernel mediates a cooperating caller's tool API. It does not confine the Python
process that imports it. A caller can bypass `Cell.act()` and invoke host APIs
directly. Custom tools need their own execution and confinement design.

## Assets and adversaries

| Asset | Relevant loss |
|---|---|
| Host filesystem, network, and privileges | Allowed execution reaches outside its intended scope |
| Decision authority | An action executes without the intended policy checks |
| Record integrity | Modified or incomplete history is accepted as original |
| Audit confidentiality | Request text or metadata in the record exposes sensitive data |
| Host capacity | An allowed process exhausts resources |

The intended callers include mistaken agents and agents influenced by hostile
content. Arbitrary code inside an allowed program presents a different threat:
command classification cannot inspect all of its effects. Backend confinement
must be assessed separately, including the unresolved Cell/jail risks below.

Host administrators, a modified kernel/runtime, malicious installed executables,
and supply-chain compromise are outside the core's protection. Having no
third-party Python dependencies does not remove runtime or executable trust.

## Boundaries

1. `Cell.act()` receives a proposed action from a cooperating caller.
2. `Gate.evaluate()` classifies it. Cell adds path and gate-only execution checks.
3. An allowed tool executes. Only the built-in command path invokes the selected
   jail when `use_jail=True`; custom execution is not automatically jailed.
4. Cell records the decision and output hash in a ledger, then returns a result.
5. A caller may persist and verify a receipt. External custody and authenticity
   require controls outside the core hash chain.

Execution and durable recording are not one atomic transaction. A process failure
or ledger-write error after execution can leave effects without the expected
record. A valid ledger alone does not establish complete coverage of host activity.

## Mechanisms present in this tree

### Gate and execution checks

[`Gate.evaluate()`](../deponent/gate.py) recognizes `read_file`, `write_file`, and
`run_cmd`; unknown tools return BLOCK. File paths are resolved and checked against
the sandbox root. Command classification checks deny patterns, substitutions,
redirection, tokenized program heads, and argument paths. Physical newline and
carriage-return separators are handled by `tokenize_command()`.

Policy defaults are per-instance configuration, not a universal security policy.
`DENY_SUBSTR` is a tuple and `ALLOW_HEADS` is a frozenset. Rebinding these names
does not change captured constructor defaults; pass `deny=` and `allow_heads=`.
Optional reach checks can impose an additional restriction on writes.

[`Cell._gate_only_guard()` and `_run_cmd()`](../deponent/cell.py) require exactly
one tokenized command segment in gate-only mode and execute its argv with
`shell=False`. Interpreters require explicit permission from both Cell and Gate;
extra heads require membership in both opt-in sets. These checks reduce the
reachable command surface but provide no OS confinement. Binary identity, runtime
behavior, and filesystem races remain outside a string classifier's guarantee.

File tools also recheck and resolve their paths in `_checked_sandbox_path()`.
They subsequently use path-based opens; this is not a descriptor-based guarantee
against concurrent replacement of path components.

### Jail selection and availability

[`_candidate_backends()`](../deponent/jail.py) selects Seatbelt on macOS and
Docker on other platforms. `jail_available()` reports whether a selected backend
answers its availability check. For Docker that means a CLI and a responding
daemon; it does not prove that an image can execute or that live escape tests pass.
Without a backend, `run_jailed()` returns `killed="no-jail"` and does not run the
command. `jail_command()` is a Seatbelt-specific helper, not the portable dispatcher.

The Seatbelt profile denies network and filesystem writes except its configured
workspace/device exceptions. It does not deny general host reads. CPU/file limits
and RSS/wall-clock monitoring bound some workloads; this is not comprehensive
protection against all resource exhaustion.

The Docker command requests no network, a read-only root filesystem, a writable
workspace bind mount and temporary filesystem, memory/process/CPU limits, dropped
capabilities, and no-new-privileges. Actual backend behavior must be tested on the
target host. Docker's class and opt-in tests say DRAFT, while the module-level
text retains a historical LIVE-VERIFIED claim. This documentation repair does not
resolve that implementation-history conflict or promote the backend's status.

### Ledger integrity and confidentiality

[`Ledger.record()`](../deponent/ledger.py) hashes each payload together with the
previous entry hash. Verification recomputes links from genesis. Changes that do
not consistently recompute the chain are detected. The output is stored as
`outcome_sha256`, but **request data is not content-blind**:

- `params` values are converted to strings and truncated to 200 characters each.
- `reason` is stored as plaintext without that truncation.
- Other metadata, such as agent and tool names, is also stored in the payload.
- There are no `params_sha256` / `reason_sha256` replacement fields or selectable
  content-blind mode in this implementation.

Protect the ledger as potentially sensitive data. Hashing output neither encrypts
requests nor prevents low-entropy output hashes from being guessed. Do not send
secrets through the API under an assumption that its audit record hides them.

New ledgers refuse an existing nonempty chain. Appends check the previously seen
file size and tail hash; stale writers raise `LedgerForkError`. These checks are
not a claim of an atomic multiprocess append protocol or protection from a
host-privileged writer.

### Persisted receipts

[`persist()`](../deponent/receipts.py) verifies the ledger, includes its head and
length, writes the receipt through a temporary file and rename, and runs a
verification round trip before updating `LATEST`. `verify()` recomputes the chain
and the receipt's content hash.

The field named `signature` is a SHA-256 content hash, **not an authorship
signature**. An attacker able to rewrite a whole receipt can also replace the
chain, head, length, and hash. To detect that replacement, the verifier needs an
independently retained anchor or an appropriate trusted signing system.

## Residual risks

### Gate-only mode is constrained but unjailed

The SDK quickstart opts into `use_jail=False` for a portable demonstration. Its
command path uses `shell=False`, rejects multi-segment commands, and refuses
interpreters by default. The previous claim that it directly executes a shell
string with `shell=True` was obsolete.

Opting interpreters or additional executables into gate-only mode gives those
programs the host process's permissions. Even the constrained default is not an
OS sandbox. Do not infer hostile-code containment from a successful quickstart.

### Cell/jail control files are inside the writable workspace

The current Seatbelt helper writes `.jail.sb` under the workspace and the trusted
parent opens `.run_out` there. Workspace-controlled file contents and path
replacement can therefore affect control files or parent-side writes. Resolving a
path before opening it does not make all later path components immutable.

The narrower direct-process Seatbelt checks do not establish protection against
these indirect paths. This issue is also described in
[the separate containment-scope PR](https://github.com/cjchanh/deponent/pull/4).
Do not treat `use_jail=True` or a green conformance mark as closure of this issue.
This documentation repair changes no containment implementation.

### Reads and returned output are not a confidentiality boundary

The Seatbelt profile permits host reads. An allowed program can return sensitive
read results to its unjailed caller, which may have network access. The separate
credential shield has a different profile; its properties must not be attributed
to the Cell/jail path. Request data can also enter the plaintext audit log.

### Tail truncation and complete rewrites need external anchors

Removing a nonempty chain's tail can leave an internally valid shorter chain.
`expected_head` and `expected_length` detect a mismatch only when the verifier
retains the expected values independently. `verify_entries()` also accepts the
legacy `expected_len` parameter. A receipt stored beside an attacker-rewritable
ledger is not, by itself, independent custody.

`Ledger.load(path).verify()` refuses a missing or empty file without an explicit
empty-chain anchor. A fresh in-memory empty ledger and a bare empty list have
different provenance and should not be confused with a missing recorded run.

### Reconciliation observes a limited surface

[`snapshot()` and `reconcile_action()`](../deponent/reconcile.py) compare workspace
files. Reconciliation is optional, ignores hidden bookkeeping paths, and does not
observe every host or network effect. A `run_cmd` can make changes without those
being classified as an undeclared file-tool write. An unavailable optional module
must not become a claim that reconciliation ran.

### Permission is not successful execution

Cell catches exceptions from `_execute()` and includes the error in the output;
the original ALLOW verdict can remain. `ActResult.allowed` therefore does not
mean the action completed or its output is correct. A hash chain proves internal
record consistency, not the truth of every recorded assertion or task completion.

## Verification and claim limits

See [SDK_REVIEW_VERIFICATION.md](SDK_REVIEW_VERIFICATION.md) for commands, observed
results, and unavailable checks for this documentation repair. No historical test
count is presented here as a fresh run.

The conformance harness currently has 13 clauses. For the built-in adapter, 10
apply and three are NA. Its jail clause exercises unavailable-backend refusal; it
does not run the full live containment suite. Redirect and newline regressions
are separate gate tests, not conformance clauses.

Live Seatbelt/shield tests require macOS. Docker escape tests are opt-in through
`DEPONENT_TEST_DOCKER=1` and require a usable daemon and image. A Linux default-suite
pass cannot establish either target-host containment result. Neither a skipped
check nor a self-assessed conformance mark is an independent security review.
