"""Merkleization utilities per SSZ."""

from __future__ import annotations

from typing import Sequence

from lean_spec.subspecs.ssz.utils import get_power_of_two_ceil, hash_nodes
from lean_spec.types import ZERO_HASH
from lean_spec.types.byte_arrays import Bytes32

_MAX_ZERO_HASH_DEPTH: int = 64
"""Maximum depth of pre-computed zero hashes (supports trees up to 2^64 leaves)."""

_ZERO_HASHES: list[Bytes32] = []
"""Pre-computed zero hash roots at each depth level.

Index i contains the root of a full zero tree with 2^i leaves:

- Index 0: ZERO_HASH (single leaf)
- Index 1: hash(ZERO_HASH || ZERO_HASH) (2 leaves)
- Index 2: hash of two index-1 hashes (4 leaves)
- And so on...
"""


def _precompute_zero_hashes() -> None:
    """Pre-compute zero hashes at module load time for O(1) lookup."""
    global _ZERO_HASHES
    _ZERO_HASHES = [ZERO_HASH]
    for _ in range(_MAX_ZERO_HASH_DEPTH):
        prev = _ZERO_HASHES[-1]
        _ZERO_HASHES.append(hash_nodes(prev, prev))


_precompute_zero_hashes()


def _zero_tree_root(width_pow2: int) -> Bytes32:
    """Return the Merkle root of a full zero tree with `width_pow2` leaves.

    Uses pre-computed zero hashes for O(1) lookup.
    Falls back to computation for extremely large trees beyond the cache.
    """
    if width_pow2 <= 1:
        return ZERO_HASH
    depth = (width_pow2 - 1).bit_length()
    if depth < len(_ZERO_HASHES):
        return _ZERO_HASHES[depth]
    # Fallback for extremely large trees beyond pre-computed depth
    h = _ZERO_HASHES[-1]
    for _ in range(depth - len(_ZERO_HASHES) + 1):
        h = hash_nodes(h, h)
    return h


def merkleize(chunks: Sequence[Bytes32], limit: int | None = None) -> Bytes32:
    """Compute the Merkle root of chunks.

    Padding rules:

    - No limit: pad to next power of two of len(chunks)
    - With limit >= len(chunks): pad to next power of two of limit
    - limit < len(chunks): raises ValueError
    - Empty chunks: returns ZERO_HASH (or zero-subtree root if limit provided)

    Uses pre-computed zero subtree roots for efficient padding.
    Avoids materializing large zero-filled arrays.
    """
    n = len(chunks)
    if n == 0:
        # If a limit is provided, return the zero-subtree root of that width
        return _zero_tree_root(get_power_of_two_ceil(limit)) if limit is not None else ZERO_HASH

    # Determine the width of the bottom layer after padding/limiting
    if limit is None:
        width = get_power_of_two_ceil(n)
    else:
        if limit < n:
            raise ValueError("merkleize: input exceeds limit")
        width = get_power_of_two_ceil(limit)

    # Width of 1: the single chunk is the root
    if width == 1:
        return chunks[0]

    # Use efficient algorithm that avoids materializing zero-filled arrays.
    #
    # The idea: instead of padding with ZERO_HASH and hashing pairwise,
    # we use pre-computed zero subtree roots for missing sections.
    return _merkleize_efficient(list(chunks), width)


def _merkleize_efficient(chunks: list[Bytes32], width: int) -> Bytes32:
    """Efficient merkleization using pre-computed zero subtree roots.

    Instead of materializing width-n zero hashes and hashing them all,
    this algorithm only processes actual data and uses pre-computed
    zero subtree roots for padding.

    Time complexity: O(n * log(width)) instead of O(width * log(width))
    Space complexity: O(n) instead of O(width)
    """
    # Current level of nodes (starts with the input chunks)
    level = chunks
    # Current subtree size (starts at 1, doubles each level)
    subtree_size = 1

    while subtree_size < width:
        next_level: list[Bytes32] = []
        i = 0

        while i < len(level):
            left = level[i]
            i += 1

            if i < len(level):
                # We have a right sibling from actual data
                right = level[i]
                i += 1
            else:
                # No right sibling - use zero subtree of current size
                right = _zero_tree_root(subtree_size)

            next_level.append(hash_nodes(left, right))

        # If we have fewer nodes than needed for this level,
        # the remaining pairs are all zeros - but we only add
        # nodes that will eventually be paired with real data.
        level = next_level
        subtree_size *= 2

    # After the loop, we should have exactly one root
    if len(level) == 1:
        return level[0]

    # If still more than one, continue pairing with zero subtrees
    while len(level) > 1:
        next_level = []
        for j in range(0, len(level), 2):
            left = level[j]
            right = level[j + 1] if j + 1 < len(level) else _zero_tree_root(subtree_size)
            next_level.append(hash_nodes(left, right))
        level = next_level
        subtree_size *= 2

    return level[0] if level else _zero_tree_root(width)


def merkleize_progressive(chunks: Sequence[Bytes32], num_leaves: int = 1) -> Bytes32:
    """Progressive Merkleization (per spec).

    Rare in practice; provided for completeness. Splits on `num_leaves`:
    - right: merkleize the first up-to-`num_leaves` chunks using a fixed-width tree
    - left: recurse on the remaining chunks, quadrupling the right's width at each step
    """
    if len(chunks) == 0:
        return ZERO_HASH

    # Right branch: fixed-width merkleization of the first `num_leaves` chunks
    right = merkleize(chunks[:num_leaves], num_leaves)

    # Left branch: recursively collapse everything beyond `num_leaves`
    left = (
        merkleize_progressive(chunks[num_leaves:], num_leaves * 4)
        if len(chunks) > num_leaves
        else ZERO_HASH
    )

    # Combine branches
    return hash_nodes(left, right)


def mix_in_length(root: Bytes32, length: int) -> Bytes32:
    """Mix the length (as uint256 little-endian) into a Merkle root."""
    if length < 0:
        raise ValueError("length must be non-negative")
    # The "mix" is `hash(root + length_uint256_le)`
    return hash_nodes(root, Bytes32(length.to_bytes(32, "little")))


def mix_in_selector(root: Bytes32, selector: int) -> Bytes32:
    """Mix the union selector (as uint256 little-endian) into a Merkle root."""
    if selector < 0:
        raise ValueError("selector must be non-negative")
    # The "mix" is `hash(root + selector_uint256_le)`
    return hash_nodes(root, Bytes32(selector.to_bytes(32, "little")))
