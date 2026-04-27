"""Multi-fork dispatch layer for leanSpec consensus specification."""

from .lstar.containers.state import State
from .lstar.spec import LstarSpec
from .lstar.store import AttestationSignatureEntry, Store
from .protocol import ForkProtocol, SpecStateType, SpecStoreType
from .registry import ForkRegistry

FORK_SEQUENCE: list[ForkProtocol] = [LstarSpec()]
"""Ordered oldest to newest. ForkRegistry enforces strictly increasing VERSION."""

DEFAULT_REGISTRY: ForkRegistry = ForkRegistry(FORK_SEQUENCE)
"""Shared registry over the registered forks. Convenient for top-level callers."""

__all__ = [
    "AttestationSignatureEntry",
    "DEFAULT_REGISTRY",
    "FORK_SEQUENCE",
    "ForkProtocol",
    "ForkRegistry",
    "LstarSpec",
    "SpecStateType",
    "SpecStoreType",
    "State",
    "Store",
]
