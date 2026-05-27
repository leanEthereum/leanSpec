"""Merkleization primitives for SSZ.

Builds a binary Merkle tree over a chunk sequence, with SSZ padding rules.
The leaf width is the SHA-256 digest size, so leaves and inner nodes are interchangeable.
"""

from __future__ import annotations

from collections.abc import Sequence
from hashlib import sha256
from typing import Final

from lean_spec.types import ZERO_HASH
from lean_spec.types.byte_arrays import Bytes32


def _next_pow2(x: int) -> int:
    """Smallest power of two greater than or equal to x.

    Returns 1 when x is 0 or 1.
    """
    if x <= 1:
        return 1
    return 1 << (x - 1).bit_length()


_MAX_ZERO_HASH_DEPTH: Final = 64
"""Depth covered by the pre-computed zero-subtree cache.

Trees up to 2 to the 64 leaves are covered directly.
That is well past any chunk count the protocol uses."""


def _precompute_zero_hashes() -> tuple[Bytes32, ...]:
    """Compute the all-zero subtree root at every depth up to the cache limit."""
    hashes: list[Bytes32] = [ZERO_HASH]
    for _ in range(_MAX_ZERO_HASH_DEPTH):
        prev = hashes[-1]
        hashes.append(Bytes32(sha256(prev + prev).digest()))
    return tuple(hashes)


_ZERO_HASHES: tuple[Bytes32, ...] = _precompute_zero_hashes()
"""Roots of perfect zero subtrees, indexed by depth.

Index 0 holds the all-zero leaf.
Index d holds the root of a perfect binary tree of 2 to the d leaves."""


def _zero_tree_root(width: int) -> Bytes32:
    """Root of an all-zero perfect binary tree with the given leaf count.

    The width must be a power of two.
    Trees beyond the cache extend by hashing the last cached root with itself.
    """
    if width <= 1:
        return ZERO_HASH
    depth = (width - 1).bit_length()
    if depth < len(_ZERO_HASHES):
        return _ZERO_HASHES[depth]
    h = _ZERO_HASHES[-1]
    for _ in range(depth - len(_ZERO_HASHES) + 1):
        h = Bytes32(sha256(h + h).digest())
    return h


def merkleize(chunks: Sequence[Bytes32], limit: int | None = None) -> Bytes32:
    r"""Compute the SSZ Merkle root over a chunk sequence.

    Tree layout for three leaves with no limit:

        leaves   :  c0     c1     c2     ZERO     (padded to next power of two)
                     \____/        \______/
                      h01           h(c2, ZERO)
                       \______________/
                              root

    When a limit is provided, the tree width is the next power of two of that limit.
    Missing leaves contribute pre-computed zero subtree roots instead of
    materialized zero chunks, so allocation stays proportional to actual data.

    Args:
        chunks: Leaf chunks, each exactly 32 bytes wide.
        limit: Optional leaf-count capacity; tree width is rounded up to the next power of two.

    Returns:
        The Merkle root.

    Raises:
        ValueError: If the chunk count exceeds the limit.
    """
    n = len(chunks)
    if n == 0:
        return _zero_tree_root(_next_pow2(limit)) if limit is not None else ZERO_HASH
    if limit is None:
        width = _next_pow2(n)
    elif limit < n:
        raise ValueError("merkleize: input exceeds limit")
    else:
        width = _next_pow2(limit)
    if width == 1:
        return chunks[0]

    # Walk one tree layer per outer iteration.
    # A missing right sibling pulls the all-zero subtree of the current size from the cache,
    # so unused zero leaves are never allocated.
    level: list[Bytes32] = list(chunks)
    subtree_size = 1
    while subtree_size < width:
        next_level: list[Bytes32] = []
        i = 0
        while i < len(level):
            left = level[i]
            i += 1
            if i < len(level):
                right = level[i]
                i += 1
            else:
                right = _zero_tree_root(subtree_size)
            next_level.append(Bytes32(sha256(left + right).digest()))
        level = next_level
        subtree_size *= 2

    # Invariant: width is the next power of two of the leaf count or capacity,
    # so the loop above halves the level count down to exactly one root.
    assert len(level) == 1
    return level[0]


def mix_in_length(root: Bytes32, length: int) -> Bytes32:
    """Mix a length into a Merkle root via the SSZ uint256 little-endian encoding.

    Variable-length types append their declared length to disambiguate roots.
    Two lists with identical elements but different lengths must produce different roots.

    Args:
        root: Merkle root over the data chunks.
        length: Non-negative count to mix in.

    Returns:
        The length-mixed root.

    Raises:
        ValueError: If the length is negative.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    return Bytes32(sha256(root + length.to_bytes(32, "little")).digest())
