"""deponent.adapters — GAK conformance adapters for different kernels.

Drop a new adapter here to make `python3 -m deponent.conform --kernel <name>`
work against a new governed system.
"""

from __future__ import annotations

from .deponent import DeponentAdapter

__all__ = ["DeponentAdapter"]

BUILTIN_ADAPTERS: dict[str, type] = {
    "deponent": DeponentAdapter,
}
