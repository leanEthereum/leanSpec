"""SSZ (Simple Serialize) implementation."""

from lean_spec.types import ZERO_HASH

from .hash import hash_tree_root

__all__ = [
    "hash_tree_root",
    "ZERO_HASH",
]
