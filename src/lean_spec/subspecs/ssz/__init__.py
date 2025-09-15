"""SSZ (Simple Serialize) implementation."""

from .constants import ZERO_HASH
from .hash import HashTreeRoot, hash_tree_root

__all__ = [
    "HashTreeRoot",
    "hash_tree_root",
    "ZERO_HASH",
]
