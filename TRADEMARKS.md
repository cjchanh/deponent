# Trademarks & Naming Policy

Apache-2.0 grants copyright and patent rights but **explicitly does not grant
trademark rights** (Apache-2.0 §6). This file states how the project name and the
conformance mark may and may not be used. There are two distinct things here — the
*kernel name* and the *conformance standard* — and they are not the same.

## Two marks, two purposes

**1. "Deponent" — the project / kernel name.** "Deponent", any associated logo, and
**Centennial Defense Systems / CDS** are marks of Centennial Defense Systems. The
software is licensed under Apache-2.0; the *name* is reserved (Apache-2.0 §6). It
identifies this specific kernel and its origin.

**2. "GAK-conformant" / the GAK conformance standard — an earnable, vendor-neutral
mark.** This is a property of the *standard*, not of the Deponent name. Any kernel
that implements the adapter and passes the GAK conformance harness
(`gak-conformance/v1`) earns the right to describe itself as **GAK-conformant** —
including kernels that are not Deponent, not from CDS, and not forks of this code.
The mark attaches to the test result, not to this project. Deponent is the reference
implementation of the standard, not the owner of the adjective.

## You may

- Describe your software, factually, as **GAK-conformant** when it actually passes
  the harness (`python3 -m deponent.badge verify --kernel <yours>` exits 0). This is
  vendor-neutral and open to anyone — it is a claim about the standard, not about
  Deponent.
- State, factually, that your software *uses* or *is built on* Deponent
  (e.g. "powered by Deponent", "built on the Deponent kernel") — nominative use.
- Fork the code and redistribute under Apache-2.0, **keeping** the `NOTICE` file and
  existing attribution.

## You may not

- Name your fork, product, service, or company **"Deponent"**, or any name
  confusingly similar, in a way that implies it is the official project or is
  endorsed by Centennial Defense Systems.
- Claim a kernel is **GAK-conformant** when it does not pass the harness. The mark is
  earned by a reproducible result, not asserted; the `verify` CLI fails closed.
- Remove or alter attribution and then redistribute under a confusingly similar name
  (Apache-2.0 §4 NOTICE / changed-file obligations still bind).

## Forks

Forks are welcome under Apache-2.0. If your fork diverges materially, **rename it** so
users can tell the projects apart; upstream attribution must be retained per the
license. A renamed fork may still earn and claim the **GAK-conformant** mark — that
mark belongs to the standard, not to the Deponent name.

Questions about permitted use: contact Centennial Defense Systems.
