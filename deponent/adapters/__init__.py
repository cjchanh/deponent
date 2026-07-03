"""deponent.adapters — GAK conformance adapters for different kernels.

Drop a new adapter here to make `python3 -m deponent.conform --kernel <name>`
work against a new governed system.
"""
from __future__ import annotations

from .deponent import DeponentAdapter
from .sworn import SwornAdapter

__all__ = ["DeponentAdapter", "SwornAdapter"]

BUILTIN_ADAPTERS: dict[str, type] = {
    "deponent": DeponentAdapter,
    "sworn": SwornAdapter,
}

# Optional assurance-lane adapter: the Rust kernel (provenant-rs) via a fail-closed
# shim. Present only in the dev tree (it shells to a sibling Rust build) and excluded
# from the public package — so register tolerantly: if the module is absent, the
# public package still imports and `provenant-rs` simply isn't a --kernel choice.
try:
    from .provenant_rs import ProvenantRsAdapter

    BUILTIN_ADAPTERS["provenant-rs"] = ProvenantRsAdapter
    __all__.append("ProvenantRsAdapter")
except Exception:
    pass
