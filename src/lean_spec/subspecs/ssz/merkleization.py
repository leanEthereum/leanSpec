"""Merkleization utilities per SSZ."""

from __future__ import annotations

from typing import Sequence

from lean_spec.subspecs.ssz.utils import get_power_of_two_ceil, hash_nodes
from lean_spec.types import ZERO_HASH
from lean_spec.types.byte_arrays import Bytes32


def _zero_tree_root(width_pow2: int) -> Bytes32:
    """
    Return the Merkle root of a full zero tree with `width_pow2` leaves.

    Power of two >= 1.
    """
    if width_pow2 <= 1:
        return ZERO_HASH
    # Build tree from bottom up: hash ZERO_HASH with itself repeatedly
    h, w = ZERO_HASH, width_pow2
    while w > 1:
        h, w = hash_nodes(h, h), w // 2
    return h


def merkleize(chunks: Sequence[Bytes32], limit: int | None = None) -> Bytes32:
    """Compute the Merkle root of `chunks`.

    Behavior
    --------
    - If `limit` is None: pad to next power of two of len(chunks).
    - If `limit` is provided and >= len(chunks): pad to next power of two of `limit`.
    - If `limit` < len(chunks): raise (exceeds limit).
    - If no chunks: return ZERO_HASH.
      *Exception when `limit` is provided:* return the zero-subtree root for the padded width.

    This matches the SSZ spec's padding/limiting rules.
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

    # Start with the leaf layer: provided chunks + ZERO padding
    level: list[Bytes32] = list(chunks) + [ZERO_HASH] * (width - n)

    # Reduce bottom-up: pairwise hash until a single root remains
    while len(level) > 1:
        it = iter(level)
        # Pair up elements: hash each (a, b) pair
        level = [
            hash_nodes(a, next(it, ZERO_HASH)) for a in it
        ]  # Safe: even-length implied by padding
    return level[0]


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
