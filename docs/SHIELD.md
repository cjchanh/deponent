# Deponent Credential Shield

Run an untrusted coding agent as a whole process tree under a macOS Seatbelt
profile whose **reads are deny-by-default inside HOME**, while the parent process
(outside the sandbox) writes a **hash-chained, externally anchored, recomputable
receipt**. Every receipt records the launch (argv, the profile sha256, the
`--own-key`/`--own-env` declarations, the **dropped env NAMES only**, and the
catalog size) and the outcome (the child's exit status, always, including on
crash). Attempted **denied reads** are captured only where the OS logs them; on
macOS 27 that is usually **`UNAVAILABLE`** (see *Reach capture* below) — the
kernel still enforces every deny, whether or not it is logged.

> **This is a defense-in-depth _proof_ layer, not a credential-theft prevention
> system.** Read the boundaries below before you rely on it. Every protection
> claim maps to a named test. Of the limits we know about, three are pinned by
> `KNOWN-NOT-STOPPED` canaries so they cannot silently change; the rest are
> design residuals documented below **without** a canary. Treat those as not stopped.

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
| Keychain mach-lookup denied by default (live probe: `-25300 → -50`) | `C13_keychain_securityserver_deny_flips_status`, (profile) `test_keychain_and_side_channel_denies` |
| AppleEvents / LaunchServices / process-info deny **rules emitted** | `test_keychain_and_side_channel_denies` (see the process-info residual under "What it does NOT stop") |
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
| Keychain mach-lookup (`com.apple.SecurityServer`) denied by default; a live `SecItemCopyMatching` probe flips `-25300 → -50` | `C13_keychain_securityserver_deny_flips_status` |
| The setuid-root `/bin/ps` fails to **exec** under the sandbox — a platform restriction on setuid exec, **not** a shield rule (`EXEC_DENY` does not list `ps`), so it leaks nothing; but a non-setuid tool that reads process info directly is **not** stopped (see the sysctl residual below) | `C12_parent_env_readable_via_sysctl_KNOWN_NOT_STOPPED` (secondary assertion) |
| Child does not inherit parent file descriptors (`close_fds`) | `FD_not_inherited` |
| Reach recorded, or **UNAVAILABLE** — never empty-and-OK | `C9_receipt_reach_is_events_or_unavailable` |
| Receipt is anchored and recomputable; tamper/truncate/re-chain caught | `C11_verify_end_to_end`, `TestReceiptVerify::*` |
| Fail-closed: invalid path or missing `sandbox-exec` ⇒ REFUSE, child never starts | `C10_refuse_invalid_path`, `C10_refuse_missing_sandbox_exec` |
| A read surface (workspace, `--state-dir`, `--allow-read`) that is HOME or an ancestor of HOME, **including `/`** ⇒ REFUSE | `test_refuses_workspace_root`, `test_refuses_allow_read_root`, `test_refuses_state_dir_ancestor_of_home` |
| Receipt and anchor dirs are **read- and write-denied** to the agent (last rule, so no allow re-opens them); overlap with anything the agent can reach ⇒ REFUSE | `A1_audit_files_unreadable_by_child`, `TestAuditSurfaceOrdering::*`, `test_refuses_receipt_dir_inside_workspace`, `test_refuses_anchor_dir_containing_workspace`, `test_refuses_own_key_inside_anchor_dir` |

## What it does NOT stop

These are **design residuals**, not bugs. **Only the first three are pinned by
canaries**; the others are documented here with no canary. Treat every row as
not stopped.

| Residual | Canary |
|---|---|
| A **pre-existing workspace hardlink** to a protected file is READABLE (Seatbelt keys on the path). Mitigation: preflight refuses `st_nlink>1` unless `--allow-hardlinks`. | `C4_workspace_hardlink_is_readable_KNOWN_NOT_STOPPED` |
| **Signalling a process outside the sandbox** is NOT blocked on macOS 27 (`(deny signal (target others))` is ineffective here). | `C8_signal_parent_KNOWN_NOT_STOPPED` |
| **Another same-uid process's exec-time environment AND argv are READABLE via `sysctl(KERN_PROCARGS2)`.** `(deny process-info* (target others))` does not block it, a `(deny sysctl-read (sysctl-name "kern.procargs2"))` filter does not block it, and a blanket `(deny sysctl-read)` breaks the child. An agent can therefore read the environment (including inherited secrets) and command line of other processes owned by the same user. Do not rely on the shield to hide secrets held in any same-uid process's environment; scrub them before launch. | `C12_parent_env_readable_via_sysctl_KNOWN_NOT_STOPPED` |
| The agent's **own declared key can still be exfiltrated over the network** — it can read it (by design) and it needs the network for its model. Read-deny protects *other* secrets, not the one you hand it. | (design; see below) |
| **Keychain beyond the default mach-lookup deny** — the deny flips a probe's `OSStatus -25300 → -50`, but this is not a proof that all keychain access paths are closed. | §Empirical notes |
| Anything the base `(allow default)` permits, and any secret **outside HOME**, including external volumes and `/Users/Shared`, or in a path re-opened via `--allow-read`. | design |
| Declaring an agent socket (e.g. `--own-env SSH_AUTH_SOCK`) grants key **use** without key **read**: the agent can sign with every key that socket holds. | design |
| The exec denies on `osascript` / `open` / `launchctl` / `security` match **literal paths only**, so they are speed bumps. The controls that matter are the mach-lookup and AppleEvent denies. Processes started on the agent's behalf by system services run outside the sandbox. | design (no canary) |

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

Live compose canaries: `TestSafehouseCompose::*` (run when `safehouse` is on PATH;
safehouse 0.12.0 is present here). They prove: workspace read/write, the catalog
key denied under the composed policy, the own-key carve-out surviving composition,
and the receipt verifying `ANCHORED_OK`. The overlay's side-channel denies (keychain
mach-lookup, AppleEvents, LaunchServices, process-info) are proven **present** in
the composed overlay by the profile test `TestSafehouseOverlay::test_overlay_has_side_channel_denies`;
their runtime effect is the same as in standalone mode (e.g. the keychain flip in
`C13`).

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
**either** control deny is not observed in the log — **or** the controls are seen
but no catalog denial is matched in the window — the receipt records
`reach_events: "UNAVAILABLE"` — **never "none"** and never an empty set reported as
`OBSERVED`. When the value is `OBSERVED` it is always backed by `reach_event`
records (pinned by `C9_receipt_reach_is_events_or_unavailable`).

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
  used. `(deny process-info* (target others))` is emitted, but it does **not** stop
  a direct `sysctl(KERN_PROCARGS2, pid)` read of another same-uid process's
  exec-time environment and argv, and neither does a `(sysctl-name "kern.procargs2")`
  filter. (The setuid-root `/bin/ps` also fails here, but that is the platform
  refusing to *exec* a setuid binary under the sandbox — not this rule, and not a
  path the agent needs.) That leak is a documented residual (see "What it does NOT
  stop"): scrub secrets from any same-uid process's environment before launch rather
  than relying on the shield to hide them.
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
