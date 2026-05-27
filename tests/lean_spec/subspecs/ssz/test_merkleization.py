"""Unit tests for SSZ Merkleization primitives."""

from __future__ import annotations

from hashlib import sha256

import pytest

from lean_spec.subspecs.ssz.merkleization import (
    _ZERO_HASHES,
    _next_pow2,
    _zero_tree_root,
    merkleize,
    mix_in_length,
)
from lean_spec.types import ZERO_HASH, Bytes32


def h(a: Bytes32, b: Bytes32) -> Bytes32:
    """Pairwise SHA-256 of two 32-byte nodes; used to build expected roots."""
    return Bytes32(sha256(a + b).digest())


# Sample chunks for testing, c[i] = bytes32(i)
c = [Bytes32(i.to_bytes(32, "little")) for i in range(16)]

# Pre-calculate zero-tree roots for assertions
# Z[0] = ZERO_HASH, Z[1] = h(Z[0], Z[0]), Z[2] = h(Z[1], Z[1]), etc.
Z = [ZERO_HASH]
for _ in range(10):
    Z.append(h(Z[-1], Z[-1]))


@pytest.mark.parametrize(
    "x, expected",
    [
        (0, 1),  # Edge case: 0 should result in 1
        (1, 1),  # A power of two
        (2, 2),  # A power of two
        (3, 4),  # A number between powers of two
        (4, 4),  # A power of two
        (5, 8),
        (7, 8),
        (8, 8),
        (9, 16),
        (1023, 1024),
        (1024, 1024),  # A larger power of two
    ],
)
def test_next_pow2(x: int, expected: int) -> None:
    """Returns the smallest power of two at or above the input, with 1 for 0 and 1."""
    assert _next_pow2(x) == expected


def test_merkleize_empty_no_limit() -> None:
    """Merkleizing an empty list with no limit returns the all-zero leaf."""
    assert merkleize([]) == ZERO_HASH


@pytest.mark.parametrize(
    "limit, expected_width, expected_zero_root",
    [
        (0, 1, Z[0]),  # limit=0 -> width=1 -> root is Z[0]
        (1, 1, Z[0]),  # limit=1 -> width=1 -> root is Z[0]
        (2, 2, Z[1]),  # limit=2 -> width=2 -> root is Z[1]
        (3, 4, Z[2]),  # limit=3 -> width=4 -> root is Z[2]
        (7, 8, Z[3]),  # limit=7 -> width=8 -> root is Z[3]
        (8, 8, Z[3]),
    ],
)
def test_merkleize_empty_with_limit(
    limit: int, expected_width: int, expected_zero_root: Bytes32
) -> None:
    """Empty input with a limit yields the zero-subtree root at the rounded-up width."""
    assert merkleize([], limit=limit) == expected_zero_root


def test_merkleize_single_chunk() -> None:
    """The root of a single chunk is the chunk itself."""
    assert merkleize([c[1]]) == c[1]


def test_merkleize_power_of_two_chunks() -> None:
    """A power-of-two leaf count needs no padding."""
    # Test with 2 chunks
    assert merkleize([c[0], c[1]]) == h(c[0], c[1])
    # Test with 4 chunks
    root_4 = h(h(c[0], c[1]), h(c[2], c[3]))
    assert merkleize(c[0:4]) == root_4


def test_merkleize_non_power_of_two_chunks() -> None:
    """A non-power-of-two leaf count pads to the next power of two."""
    # Test with 3 chunks (pads to 4)
    expected = h(h(c[0], c[1]), h(c[2], Z[0]))
    assert merkleize(c[0:3]) == expected
    # Test with 5 chunks (pads to 8)
    h01 = h(c[0], c[1])
    h23 = h(c[2], c[3])
    h4z = h(c[4], Z[0])
    # The remaining leaves are zero, so their parent is h(Z[0], Z[0]) = Z[1]
    expected = h(h(h01, h23), h(h4z, Z[1]))
    assert merkleize(c[0:5]) == expected


def test_merkleize_with_limit_padding() -> None:
    """A limit larger than the leaf count widens the tree to the next power of two of the limit."""
    # 3 chunks, but limit is 8 (pads to width 8)
    h01 = h(c[0], c[1])
    h2z = h(c[2], Z[0])
    # The parent of h01 and h2z
    left_branch = h(h01, h2z)
    # The right branch is a zero-tree of width 4, so its root is Z[2].
    right_branch = Z[2]
    expected = h(left_branch, right_branch)
    assert merkleize(c[0:3], limit=8) == expected


def test_merkleize_error_on_exceeding_limit() -> None:
    """Raises when the chunk count exceeds the limit."""
    with pytest.raises(ValueError, match="input exceeds limit"):
        merkleize(c[0:5], limit=4)


def test_mix_in_length() -> None:
    """Mixes the length encoded as little-endian uint256 into the root."""
    root = c[0]
    length = 12345
    length_bytes = Bytes32(length.to_bytes(32, "little"))
    expected = h(root, length_bytes)
    assert mix_in_length(root, length) == expected


def test_mix_in_length_zero() -> None:
    """Zero is a valid length."""
    root = c[0]
    length = 0
    length_bytes = Bytes32(length.to_bytes(32, "little"))
    expected = h(root, length_bytes)
    assert mix_in_length(root, length) == expected


def test_mix_in_length_error_on_negative() -> None:
    """Rejects negative lengths."""
    with pytest.raises(ValueError):
        mix_in_length(c[0], -1)


def test_zero_tree_root_internal() -> None:
    """Returns the cached zero-subtree root at depths within the cache."""
    assert _zero_tree_root(1) == Z[0]
    assert _zero_tree_root(2) == Z[1]
    assert _zero_tree_root(4) == Z[2]
    assert _zero_tree_root(8) == Z[3]
    assert _zero_tree_root(16) == Z[4]


def test_zero_tree_root_fallback_beyond_precomputed_depth() -> None:
    """Trees one step beyond the cache fall back to a single extra hash step."""
    # _ZERO_HASHES has 65 entries (indices 0..64).
    # width = 2**65 gives depth = 65, which equals len(_ZERO_HASHES),
    # triggering the fallback that hashes upward from _ZERO_HASHES[-1].
    width = 2**65
    result = _zero_tree_root(width)

    # The fallback computes one extra hash step beyond the last cached value.
    # depth=65, len(_ZERO_HASHES)=65, so range(65 - 65 + 1) = range(1) -> one iteration.
    expected = h(_ZERO_HASHES[-1], _ZERO_HASHES[-1])
    assert result == expected


def test_zero_tree_root_fallback_two_steps_beyond_cache() -> None:
    """Trees two steps beyond the cache fall back to two hash steps."""
    # width = 2**66 gives depth = 66, requiring two hash steps beyond cache.
    width = 2**66
    result = _zero_tree_root(width)

    step1 = h(_ZERO_HASHES[-1], _ZERO_HASHES[-1])
    expected = h(step1, step1)
    assert result == expected
