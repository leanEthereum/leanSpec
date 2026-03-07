"""
Forkchoice algorithm implementation.

This module implements the LMD GHOST forkchoice algorithm for Ethereum,
providing the core functionality for determining the canonical chain head.
"""

from .store import GossipSignatureEntry, Store

__all__ = [
    "GossipSignatureEntry",
    "Store",
]
