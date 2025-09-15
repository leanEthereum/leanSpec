"""Unit tests for SSZ Merkleization utilities."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.ssz.constants import ZERO_HASH
from lean_spec.subspecs.ssz.merkleization import Merkle
from lean_spec.subspecs.ssz.utils import hash_nodes
from lean_spec.types.byte_arrays import Bytes32


def h(a: Bytes32, b: Bytes32) -> Bytes32:
    """A concise alias for hash_nodes for building expected roots."""
    return hash_nodes(a, b)


# Create some sample chunks for testing, c[i] = bytes32(i)
c = [Bytes32(i.to_bytes(32, "little")) for i in range(16)]

# Pre-calculate zero-tree roots for assertions
# Z[0] = ZERO_HASH, Z[1] = h(Z[0], Z[0]), Z[2] = h(Z[1], Z[1]), etc.
Z = [ZERO_HASH]
for _ in range(10):
    Z.append(h(Z[-1], Z[-1]))


def test_merkleize_empty_no_limit() -> None:
    """Tests that merkleizing an empty list with no limit returns the ZERO_HASH."""
    assert Merkle.merkleize([]) == ZERO_HASH


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
    """
    Tests that merkleizing an empty list with a limit returns the correct
    pre-computed root for a tree of zero hashes of the specified width.
    """
    assert Merkle.merkleize([], limit=limit) == expected_zero_root


def test_merkleize_single_chunk() -> None:
    """Tests that the root of a single chunk is the chunk itself."""
    assert Merkle.merkleize([c[1]]) == c[1]


def test_merkleize_power_of_two_chunks() -> None:
    """Tests merkleization with a number of chunks that is a power of two (no padding needed)."""
    # Test with 2 chunks
    assert Merkle.merkleize([c[0], c[1]]) == h(c[0], c[1])
    # Test with 4 chunks
    root_4 = h(h(c[0], c[1]), h(c[2], c[3]))
    assert Merkle.merkleize(c[0:4]) == root_4


def test_merkleize_non_power_of_two_chunks() -> None:
    """Tests merkleization with a number of chunks that requires padding."""
    # Test with 3 chunks (pads to 4)
    expected = h(h(c[0], c[1]), h(c[2], Z[0]))
    assert Merkle.merkleize(c[0:3]) == expected
    # Test with 5 chunks (pads to 8)
    h01 = h(c[0], c[1])
    h23 = h(c[2], c[3])
    h4z = h(c[4], Z[0])
    # The remaining leaves are zero, so their parent is h(Z[0], Z[0]) = Z[1]
    expected = h(h(h01, h23), h(h4z, Z[1]))
    assert Merkle.merkleize(c[0:5]) == expected


def test_merkleize_with_limit_padding() -> None:
    """Tests that a limit correctly enforces a larger tree width than the number of chunks."""
    # 3 chunks, but limit is 8 (pads to width 8)
    h01 = h(c[0], c[1])
    h2z = h(c[2], Z[0])
    # The parent of h01 and h2z
    left_branch = h(h01, h2z)
    # The right branch is a zero-tree of width 4, so its root is Z[2].
    right_branch = Z[2]
    expected = h(left_branch, right_branch)
    assert Merkle.merkleize(c[0:3], limit=8) == expected


def test_merkleize_error_on_exceeding_limit() -> None:
    """Tests that merkleize raises a ValueError if the chunk count exceeds the limit."""
    with pytest.raises(ValueError, match="input exceeds limit"):
        Merkle.merkleize(c[0:5], limit=4)


def test_mix_in_length() -> None:
    """Tests mixing a length into a root."""
    root = c[0]
    length = 12345
    length_bytes = Bytes32(length.to_bytes(32, "little"))
    expected = h(root, length_bytes)
    assert Merkle.mix_in_length(root, length) == expected


def test_mix_in_length_zero() -> None:
    """Tests mixing a length of 0."""
    root = c[0]
    length = 0
    length_bytes = Bytes32(length.to_bytes(32, "little"))
    expected = h(root, length_bytes)
    assert Merkle.mix_in_length(root, length) == expected


def test_mix_in_length_error_on_negative() -> None:
    """Tests that mixing in a negative length raises a ValueError."""
    with pytest.raises(ValueError):
        Merkle.mix_in_length(c[0], -1)


def test_mix_in_selector() -> None:
    """Tests mixing a selector into a root."""
    root = c[1]
    selector = 42
    selector_bytes = Bytes32(selector.to_bytes(32, "little"))
    expected = h(root, selector_bytes)
    assert Merkle.mix_in_selector(root, selector) == expected


def test_mix_in_selector_error_on_negative() -> None:
    """Tests that mixing in a negative selector raises a ValueError."""
    with pytest.raises(ValueError):
        Merkle.mix_in_selector(c[1], -1)


def test_zero_tree_root_internal() -> None:
    """Tests the internal helper for calculating the root of an all-zero tree."""
    assert Merkle._zero_tree_root(1) == Z[0]
    assert Merkle._zero_tree_root(2) == Z[1]
    assert Merkle._zero_tree_root(4) == Z[2]
    assert Merkle._zero_tree_root(8) == Z[3]
    assert Merkle._zero_tree_root(16) == Z[4]


def test_merkleize_progressive_empty() -> None:
    """Tests progressive merkleization of an empty list."""
    assert Merkle.merkleize_progressive([]) == ZERO_HASH


def test_merkleize_progressive_single_chunk() -> None:
    """Tests progressive merkleization of a single chunk."""
    # right = merkleize([c[0]], 1) -> c[0]
    # left = ZERO_HASH
    expected = h(ZERO_HASH, c[0])
    assert Merkle.merkleize_progressive([c[0]], num_leaves=1) == expected


def test_merkleize_progressive_five_chunks() -> None:
    """
    Tests progressive merkleization with multiple recursive steps.
    Calculates the expected root manually by tracing the spec's logic.
    """
    chunks = c[0:5]

    # Manually trace the recursion for `merkleize_progressive(chunks, 1)`:
    # Step 1 (num_leaves=1):
    # right1 = merkleize([c0], 1) -> c0
    # left1 = merkleize_progressive([c1, c2, c3, c4], 4)
    #
    #   To calculate left1, recurse...
    #   Step 2 (num_leaves=4):
    #   right2 = merkleize([c1, c2, c3, c4], 4) -> h(h(c1,c2), h(c3,c4))
    #   left2 = ZERO_HASH (no more chunks)
    #   So, left1 = h(left2, right2) = h(Z[0], right2)
    #
    # Final result is h(left1, right1)
    right2 = h(h(c[1], c[2]), h(c[3], c[4]))
    left1 = h(Z[0], right2)
    right1 = c[0]
    expected = h(left1, right1)

    assert Merkle.merkleize_progressive(chunks, num_leaves=1) == expected
