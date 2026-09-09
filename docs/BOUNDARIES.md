# Boundaries

This is the trust anchor. Read it before you build on Deponent.

- **It is a reference kernel, not a hardened production sandbox.** Small enough
  to read end-to-end, strong enough to be useful, not a certified security product.
- **The live-verified jail is macOS Seatbelt (OS confinement).** `jail.py` also
  contains a **DRAFT** Docker backend; do not read DRAFT as proven. On other hosts
  you supply confinement or opt into gate-only (`use_jail=False`).
- **It is tamper-evident, not tamper-proof.** The ledger core is a keyless sha256
  hash chain — nothing in the agent's execution path is signed. It proves internal
  consistency (no entry altered or reordered), not authorship. An attacker who can
  rewrite the entire file from genesis can produce a consistent chain. An optional
  verification-only ed25519 overlay (`operator_attest.py`, extra `deponent[attest]`)
  can check a maintainer's out-of-band signature over a run; it signs nothing the
  agent does. Asymmetric signing in the execution path is a deliberate non-goal.
- **The default gate policy is a coding-agent sandbox, not a universal security
  policy.** Override per instance (`deny=`, `allow_heads=`).
- **Gate-only is policy evidence, not sandbox evidence.** `Cell()` defaults to
  `use_jail=True` and fail-closes when the jail is missing rather than silently
  switching. Gate-only runs the deny-by-default gate and the ledger with no OS
  confinement.

State the limits, or the guarantees mean nothing.
