#!/usr/bin/env python3
"""Top-level subcommand dispatcher so the shield can be invoked as the audit
spec writes it:

    python3 -m deponent shield [opts] -- CMD ARGS...
    python3 -m deponent shield-verify RECEIPT [--anchor-dir DIR]

Other kernel CLIs keep their existing module-style entry points
(`python3 -m deponent.badge`, `.conform`, `.playground`, `.selfgate`); this
dispatcher is additive and only wires the shield subcommands.
"""
from __future__ import annotations

import sys

_USAGE = (
    "usage: python3 -m deponent <subcommand> ...\n"
    "  shield [opts] -- CMD ARGS   run CMD under the credential shield\n"
    "  shield-verify RECEIPT       verify a shield receipt against its anchor\n"
    "\n"
    "other CLIs: python3 -m deponent.badge | .conform | .playground | .selfgate\n"
)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        sys.stdout.write(_USAGE)
        return 0
    sub, rest = argv[0], argv[1:]
    from . import shield
    if sub == "shield":
        return shield.cmd_shield(rest)
    if sub == "shield-verify":
        return shield.cmd_verify(rest)
    sys.stderr.write(f"unknown subcommand {sub!r}\n\n{_USAGE}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
