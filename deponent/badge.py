#!/usr/bin/env python3
"""
badge.py — the "GAK-conformant" mark, EARNED by passing the harness.

A category is owned when others can EARN a mark in it. This turns the GAK
conformance harness (conformance.py) into infrastructure: any kernel that passes
the clause set gets a verifiable "GAK-conformant" badge (SVG + a markdown
snippet) and a fail-closed verify CLI that re-derives the result. The badge is the
category-ownership lever. The mark it grants is "GAK-conformant" — the vendor-neutral
GAK conformance standard (`gak-conformance/v1`), EARNED by passing the harness. Per
TRADEMARKS.md the mark is a property of the standard, NOT a use of the "Deponent"
name: any kernel that passes the clause set may claim it, including kernels that are
not Deponent and not from CDS.

HONESTY (a badge that can be faked is worthless):
  - The green "conformant" badge is emitted ONLY when run_conformance actually
    passes. A non-conformant kernel gets a RED "not conformant" badge — never a
    green one. The mark is earned, not asserted.
  - The certification carries a `clauses_digest` (sha256 of the per-clause id+status
    set), so a consumer can VERIFY the badge corresponds to a specific, reproducible
    clause outcome — not a hand-edited image.
  - `verify` re-runs the harness and fails closed: not conformant -> non-zero exit.
  - The claim is bounded: "passes the conformance harness", never "is secure". The
    harness proves the GAK clauses under test, not adversarial security.

SECURITY POSTURE: no key material. The badge is sha256 content-addressed, not signed
(authorship binding is the separate operator-attestation overlay, not this layer).
The SVG is self-contained and offline (system fonts only — no web font, no network).
Verification: tests/test_badge.py.
"""
from __future__ import annotations

import hashlib
import html
import json
import sys
from dataclasses import dataclass
from pathlib import Path

HARNESS_VERSION = "gak-conformance/v1"
SCHEMA_VERSION = "gak-certification/v1"

_GREEN = "#3fb950"
_RED = "#e5534b"
_GRAY = "#555"


# --------------------------------------------------------------------------- #
# Certification
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Certification:
    """The result of running the GAK harness against a kernel, as an earnable mark."""
    kernel: str
    profile: str
    conformant: bool
    counts: dict          # {pass, fail, na}
    clauses_digest: str   # sha256 over the sorted (id, status) pairs — reproducible
    clauses: tuple        # the per-clause results (id, status)

    @property
    def mark(self) -> str:
        return "GAK-conformant" if self.conformant else "not-conformant"

    @property
    def message(self) -> str:
        return "conformant" if self.conformant else "not conformant"

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "harness_version": HARNESS_VERSION,
            "kernel": self.kernel,
            "profile": self.profile,
            "conformant": self.conformant,
            "mark": self.mark,
            "counts": self.counts,
            "clauses_digest": self.clauses_digest,
            "clauses": [{"id": cid, "status": st} for cid, st in self.clauses],
        }


def _resolve_adapter(kernel):
    """Accept a kernel NAME (looked up in the registry) or an adapter instance/class."""
    from .adapters import BUILTIN_ADAPTERS
    if isinstance(kernel, str):
        if kernel not in BUILTIN_ADAPTERS:
            raise ValueError(f"unknown kernel {kernel!r}; known: {sorted(BUILTIN_ADAPTERS)}")
        return BUILTIN_ADAPTERS[kernel]()
    return kernel() if isinstance(kernel, type) else kernel


def certify(kernel="deponent") -> Certification:
    """Run the GAK harness against a kernel and produce an earnable certification.

    The digest is over the per-clause (id, status) pairs ONLY — no timestamp — so two
    runs of the same kernel produce the same digest (the mark is reproducible)."""
    from .conformance import run_conformance
    receipt = run_conformance(_resolve_adapter(kernel)).to_dict()
    pairs = tuple(sorted((c["id"], c["status"]) for c in receipt["clauses"]))
    body = json.dumps({"kernel": receipt["kernel"], "harness": HARNESS_VERSION,
                       "clauses": [list(p) for p in pairs]}, sort_keys=True)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return Certification(
        kernel=receipt["kernel"], profile=receipt["profile"],
        conformant=receipt["conformant"], counts=receipt["counts"],
        clauses_digest=digest, clauses=pairs,
    )


def _verdict_line(cert: Certification) -> tuple[bool, str]:
    if cert.conformant:
        return True, (f"{cert.kernel} is GAK-conformant "
                      f"({cert.counts['pass']} pass / {cert.counts['na']} na, {cert.profile}); "
                      f"digest {cert.clauses_digest[:12]}")
    return False, (f"{cert.kernel} is NOT conformant "
                   f"({cert.counts['fail']} clause(s) failed) — mark not earned (fail-closed)")


def verify(kernel="deponent") -> tuple[bool, str]:
    """Re-derive the certification and return (earned, message). Fail-closed: a kernel
    that is not conformant does NOT earn the mark."""
    return _verdict_line(certify(kernel))


# --------------------------------------------------------------------------- #
# Renderers — self-contained, offline (system fonts only, no network)
# --------------------------------------------------------------------------- #
def _text_width(s: str) -> int:
    # approx advance width at 11px Verdana/DejaVu; good enough for a flat badge.
    return int(len(s) * 6.5) + 10


def render_svg(cert: Certification, *, label: str = "deponent") -> str:
    """A flat 'deponent | conformant' badge as a fully self-contained SVG.

    Uses generic SYSTEM font families (Verdana/DejaVu/sans-serif) — these resolve on
    the viewer's machine; there is NO @font-face, NO url(), NO network fetch. Green
    only when earned; red otherwise."""
    msg = cert.message
    color = _GREEN if cert.conformant else _RED
    lw, mw = _text_width(label), _text_width(msg)
    w = lw + mw
    lx, mx = lw / 2, lw + mw / 2
    el, em = html.escape(label), html.escape(msg)
    aria = html.escape(f"{label}: {msg}")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" '
        f'role="img" aria-label="{aria}">'
        f'<title>{aria}</title>'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{lw}" height="20" fill="{_GRAY}"/>'
        f'<rect x="{lw}" width="{mw}" height="20" fill="{color}"/>'
        f'<rect width="{w}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,DejaVu Sans,Geneva,sans-serif" font-size="11">'
        f'<text x="{lx:.0f}" y="15" fill="#010101" fill-opacity=".3">{el}</text>'
        f'<text x="{lx:.0f}" y="14">{el}</text>'
        f'<text x="{mx:.0f}" y="15" fill="#010101" fill-opacity=".3">{em}</text>'
        f'<text x="{mx:.0f}" y="14">{em}</text></g></svg>'
    )


def render_markdown(cert: Certification, *, svg_path: str = "deponent-badge.svg",
                    project_url: str = "https://github.com/cjchanh/deponent") -> str:
    """A copy-paste markdown snippet — the badge image + a BOUNDED factual claim + the
    local verify command. The claim never overreaches ('passes the harness', not 'secure')."""
    alt = html.escape(f"deponent: {cert.message}")
    if cert.conformant:
        claim = (f"`{cert.kernel}` passes the deponent conformance harness "
                 f"({cert.counts['pass']} required clauses, {cert.profile} profile). "
                 f"It does not certify adversarial security — only the GAK clauses under test.")
    else:
        claim = (f"`{cert.kernel}` does NOT currently pass the deponent conformance harness "
                 f"({cert.counts['fail']} clause(s) failed). The mark is not earned.")
    return (
        f"[![{alt}]({svg_path})]({project_url})\n\n"
        f"{claim}\n\n"
        f"Verify locally (re-derives the result, fail-closed):\n\n"
        f"    python3 -m deponent.badge verify --kernel {cert.kernel}\n\n"
        f"certification digest: `{cert.clauses_digest[:16]}` ({HARNESS_VERSION})\n"
    )


def render_text(cert: Certification) -> str:
    head = "EARNED" if cert.conformant else "NOT EARNED (fail-closed)"
    lines = [f"DEPONENT CERTIFICATION — {cert.kernel} ({cert.profile}): {head}",
             "=" * 60,
             f"  mark      : {cert.mark}",
             f"  conformant: {cert.conformant}  "
             f"[{cert.counts['pass']} pass / {cert.counts['fail']} fail / {cert.counts['na']} na]",
             f"  digest    : {cert.clauses_digest}",
             f"  harness   : {HARNESS_VERSION}"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="deponent.badge",
        description="Earn (or verify) the 'GAK-conformant' mark by passing the GAK harness.")
    ap.add_argument("mode", nargs="?", default="certify", choices=["certify", "verify"],
                    help="certify (emit badge/markdown) or verify (fail-closed exit code)")
    ap.add_argument("--kernel", default="deponent", help="kernel adapter to certify")
    ap.add_argument("--svg", type=Path, default=None, help="write the SVG badge here")
    ap.add_argument("--markdown", action="store_true", help="print the markdown snippet")
    ap.add_argument("--json", dest="json_out", type=Path, default=None,
                    help="write the certification receipt JSON here")
    args = ap.parse_args(argv)

    try:
        cert = certify(args.kernel)
    except ValueError as e:
        print(f"badge error: {e}", file=sys.stderr)
        return 2

    if args.mode == "verify":
        ok, msg = _verdict_line(cert)
        print(f"{'EARNED' if ok else 'NOT EARNED'}: {msg}")
        if args.json_out is not None:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(cert.to_dict(), indent=2), encoding="utf-8")
        return 0 if ok else 1

    # certify mode
    print(render_text(cert))
    svg = render_svg(cert)
    if args.svg is not None:
        args.svg.parent.mkdir(parents=True, exist_ok=True)
        args.svg.write_text(svg, encoding="utf-8")
        print(f"\nsvg badge -> {args.svg}")
    if args.markdown:
        svg_ref = str(args.svg) if args.svg is not None else "deponent-badge.svg"
        print("\n--- markdown ---\n" + render_markdown(cert, svg_path=svg_ref))
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(cert.to_dict(), indent=2), encoding="utf-8")
        print(f"json receipt -> {args.json_out}")
    # certify mode exits 0 even when not conformant — it reports the (red) badge honestly.
    return 0


__all__ = [
    "Certification", "certify", "verify",
    "render_svg", "render_markdown", "render_text",
    "HARNESS_VERSION", "SCHEMA_VERSION", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
