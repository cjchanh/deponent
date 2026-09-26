# Deponent Credential Shield

Run an untrusted coding agent as a whole process tree under a macOS Seatbelt
profile whose **reads are deny-by-default inside HOME**, while the parent process
(outside the sandbox) writes **hash-chained, externally anchored, recomputable
receipts** of what the agent attempted and what was denied.

> **This is a defense-in-depth _proof_ layer, not a credential-theft prevention
> system.** Read the boundaries below before you rely on it. Every protection
> claim maps to a named canary in `tests/test_shield_live.py`; every honest limit
> is pinned by a `KNOWN-NOT-STOPPED` canary so it cannot silently change.

    python3 -m deponent shield \
      --workspace ./project --own-key ~/.ssh/agent_ed25519 \
      --own-env ANTHROPIC_API_KEY \
      -- my-agent --do-the-thing

    python3 -m deponent shield-verify ~/.deponent/shield-receipts/<id>.jsonl

## Prior art — the shield is the proof layer

Containment for local coding agents **already exists**, and is good. The shield
does not reinvent it; it adds an audit trail on top of it.

- **Agent Safehouse** (`github.com/eugene1g/agent-safehouse`, Apache-2.0) — a
  macOS deny-first `sandbox-exec` launcher for Claude Code, Codex, OpenCode,
  Cursor, Aider, Gemini CLI and others. Denies `~/.ssh`, `~/.aws` and much more by
  default. **The shield composes with it** (see below) rather than competing.
- **Codex CLI** (v0.125+) — opt-in deny-read glob policies and `--log-denials` on
  macOS.
- **Anthropic sandbox-runtime (`srt`)** — a sandboxing runtime for agent tools.

**What the shield adds that these do not:** the containment and the *record* of
what the agent tried are separated. The parent, outside the sandbox, writes a
hash-chained receipt with **bracketed positive controls** and an **external
anchor the agent cannot write**, and `shield-verify` **recomputes** it — it never
returns "intact" for a missing, empty, truncated or re-chained receipt. Plus a set
of **side-channel denies** turned on by default (keychain mach-lookup, AppleEvents,
LaunchServices, process-info) and **env scrubbing** with names-only receipts.

Contribution → canary map:

| Contribution | Canary |
|---|---|
| Anchored, recomputable receipt; verify is honest | `C11_verify_end_to_end`, `TestReceiptVerify::*` |
| Reach capture with bracketed controls, self-reports UNAVAILABLE | `C9_receipt_reach_is_events_or_unavailable` |
| Keychain mach-lookup denied by default | (profile) `test_keychain_and_side_channel_denies` + empirical §Empirical notes |
| AppleEvents / LaunchServices / process-info denied | `test_keychain_and_side_channel_denies`, `C12_parent_env_not_readable` |
| Env scrubbed to an allowlist, names-only receipt | `C6_env_secret_scrubbed`, `TestEnvScrub::*` |

## What it stops (each maps to a canary)

| Protection | Canary |
|---|---|
| The agent's **own declared key** stays readable | `C1_own_key_readable` |
| **Another agent's** credential (`~/.codex`, …) is denied | `C2_other_agent_key_denied` |
| `~/.ssh` denied via `cat`, `python open()`, **and** a workspace symlink | `C3_ssh_denied_three_ways` |
| Writes are confined to the workspace (outside denied) | `C5_writes_confined` |
| Inherited env secrets (`*_API_KEY`/`*_TOKEN`/`*_SECRET`) dropped unless declared | `C6_env_secret_scrubbed` |
| `osascript` / `open` / `launchctl` / `security` exec denied | `C7_exec_denied` |
| Keychain mach-lookup (`com.apple.SecurityServer`) denied by default | §Empirical notes; profile test |
| Parent/other-process env not readable via `process-info` | `C12_parent_env_not_readable` (see note) |
| Child does not inherit parent file descriptors (`close_fds`) | `FD_not_inherited` |
| Reach recorded, or **UNAVAILABLE** — never empty-and-OK | `C9_receipt_reach_is_events_or_unavailable` |
| Receipt is anchored and recomputable; tamper/truncate/re-chain caught | `C11_verify_end_to_end`, `TestReceiptVerify::*` |
| Fail-closed: invalid path or missing `sandbox-exec` ⇒ REFUSE, child never starts | `C10_refuse_invalid_path`, `C10_refuse_missing_sandbox_exec` |

## What it does NOT stop (KNOWN-NOT-STOPPED — pinned by canaries)

These are **design residuals**, not bugs. Each is pinned so it cannot be
over-claimed or silently regress.

| Residual | Canary |
|---|---|
| A **pre-existing workspace hardlink** to a protected file is READABLE (Seatbelt keys on the path). Mitigation: preflight refuses `st_nlink>1` unless `--allow-hardlinks`. | `C4_workspace_hardlink_is_readable_KNOWN_NOT_STOPPED` |
| **Signalling a process outside the sandbox** is NOT blocked on macOS 27 (`(deny signal (target others))` is ineffective here). | `C8_signal_parent_KNOWN_NOT_STOPPED` |
| The agent's **own declared key can still be exfiltrated over the network** — it can read it (by design) and it needs the network for its model. Read-deny protects *other* secrets, not the one you hand it. | (design; see below) |
| **Keychain beyond the default mach-lookup deny** — the deny flips a probe's `OSStatus -25300 → -50`, but this is not a proof that all keychain access paths are closed. | §Empirical notes |
| Anything the base `(allow default)` permits, and any secret **outside HOME** or in a path re-opened via `--allow-read`. | design |

**We do not claim, anywhere:** "prevents credential theft", "stops malicious
agents", "escape-proof", "protects the Keychain" (beyond the tested default
mach-lookup deny), "prevents exfiltration", or "works everywhere". The shield
raises the cost and **produces evidence**; it is one layer.

## Using with Agent Safehouse (`--with-safehouse`)

**Safehouse contains; Deponent records and proves.**

    python3 -m deponent shield --with-safehouse \
      --workspace ./project --own-key ~/.ssh/agent_ed25519 \
      -- my-agent

In this mode Deponent runs `safehouse --stdout --append-profile=<overlay>
--workdir=<ws>` to obtain the **full assembled policy text** (policy mode makes no
network calls), records its real sha256 in the receipt, then launches
`sandbox-exec -p <policy> -- CMD` itself — keeping env scrubbing, `close_fds`, the
bracketed reach controls and the anchored receipt. The Deponent overlay is
appended **last**, so its denies (the always-deny credential catalog minus your
`--own-key` carve-outs, and the side-channel denies) narrow Safehouse's allows.
Credit and thanks to Agent Safehouse for the base policy.

Live compose canaries: `TestSafehouseCompose::*` (skipped unless `safehouse` is on
PATH). They prove: workspace read/write, catalog key denied, own-key carve-out
survives composition, the overlay's side-channel denies take effect, and the
receipt verifies `ANCHORED_OK`.

## Receipts and verification

The parent writes an append-only, genesis-anchored **hash-chained JSONL**
(`session_start` → `reach_event`* → `session_end`), always, including on child
crash (`try/finally`). The `session_start` records argv, the profile sha256, the
`--own-key` declarations, the **dropped env NAMES only** (never values), and the
catalog size. The head hash + length are written to an **anchor dir the profile
denies the agent from writing** (default `~/.deponent/shield-anchors/`).

`shield-verify` recomputes and returns exactly one of:

- **ANCHORED_OK** — chain re-links and head+length match the external anchor.
- **MISSING** — file absent or empty (never reported as intact).
- **TAMPERED** — an edited record, a truncated tail, a full re-chain, an
  unparseable line, or an anchor that should exist but is gone.
- **UNANCHORED** — chain re-links but the receipt was written `--no-anchor`
  (truncation cannot be detected without an external anchor).

Residual, kept honest: an attacker who can write **both** the receipt and the
anchor (i.e. already has parent-level access) can produce a consistent pair. The
anchor defeats an in-sandbox agent, not a host-level compromise.

## Reach capture — why it usually says UNAVAILABLE

Reach events are denied catalog reads pulled from the macOS unified log. Before
**and** after the agent runs, the shield triggers a known-denied read of a
shield-owned sentinel under the *same* profile (bracketed positive controls). If
**either** control deny is not observed in the log, the receipt records
`reach_events: "UNAVAILABLE"` — **never "none"**.

On macOS 27, `sandbox-exec` custom-profile denies are **not reliably emitted** to
the unified log (system App-Sandbox denies are; short-lived `sandbox-exec` child
denies are not), so the honest value on this host is `UNAVAILABLE`. `log show`
itself works without root. The kernel still enforces every deny regardless of
whether it is logged; reach capture is an *audit* signal, not the control.

## Empirical notes (macOS 27, verified by the tests above)

- **SBPL is last-match-wins.** The profile relies on it: `(allow default)` →
  `(deny (subpath HOME))` → allow workspace/state/allow-read → **deny catalog**
  (so `--allow-read` cannot re-open a catalog path) → **allow own-key** last (so
  `--own-key` overrides both the HOME deny and the catalog deny).
- **Symlinks are resolved** to their target before the profile applies (a
  workspace symlink to `~/.ssh` is denied).
- **Pre-existing workspace hardlinks are readable**; a *new* hardlink to a denied
  file created from inside the sandbox is blocked. Hence the `st_nlink>1`
  preflight refusal.
- **Keychain:** denying `com.apple.SecurityServer` (mach-lookup) flips a
  `SecItemCopyMatching` probe from `-25300` to `-50`. `com.apple.secd` /
  `com.apple.securityd` denies are inert.
- **`(deny signal (target others))` does not block a real signal** to an outside
  process on this host.
- **`(deny sysctl-read)` breaks normal tools** (e.g. `python3`), so it is **not**
  used; `(deny process-info* (target others))` alone covers the process-info path
  without breaking the child.
- **Children inherit the sandbox** (Seatbelt applies to the whole process tree).

## Strategic risk

`sandbox-exec` is **deprecated by Apple**. It works today and Agent Safehouse,
Codex and others rely on it, but a future macOS could remove or further restrict
it. Treat the Seatbelt backend as replaceable; the receipt/anchor/verify layer is
independent of it and would carry over to a successor confinement primitive.

## Fail-closed contract

Non-macOS host, missing `sandbox-exec`, an SBPL-unsafe path (quote / backslash /
control char), a profile error, a missing `--own-key` (unless
`--allow-missing-own-key`), a workspace hardlink (unless `--allow-hardlinks`), or
an unwritable anchor dir (unless `--no-anchor`) all mean **REFUSE, and the child
never starts.** There is no unsandboxed fallback, ever.
