"""Tests for the build_merkle_tree function."""

import os

import pytest
from typing_extensions import List

from lean_spec.subspecs.ssz.merkle_proof.tree import build_merkle_tree
from lean_spec.subspecs.ssz.utils import hash_nodes
from lean_spec.types import ZERO_HASH
from lean_spec.types.byte_arrays import Bytes32

# Create some deterministic leaves for predictable results
LEAF_A = Bytes32(b"\xaa" * 32)
LEAF_B = Bytes32(b"\xbb" * 32)
LEAF_C = Bytes32(b"\xcc" * 32)
LEAF_D = Bytes32(b"\xdd" * 32)


def test_build_merkle_tree_empty() -> None:
    """
    Tests that building a tree with no leaves returns two zero hashes.

    This corresponds to a tree with a single zero leaf, resulting in a zero root.
    """
    expected_tree = [ZERO_HASH, ZERO_HASH]
    assert build_merkle_tree([]) == expected_tree


def test_build_merkle_tree_single_leaf() -> None:
    """
    Tests that a tree with a single leaf has the leaf as its root.
    Note: The 0-index is a placeholder.
    """
    # Assuming the placeholder at index 0 is ZERO_HASH, not Bytes32.zero()
    expected_tree = [ZERO_HASH, LEAF_A]
    assert build_merkle_tree([LEAF_A]) == expected_tree


def test_build_merkle_tree_two_leaves() -> None:
    """
    Tests a perfectly balanced tree with two leaves (a power of 2).
    """
    root = hash_nodes(LEAF_A, LEAF_B)
    expected_tree = [
        ZERO_HASH,  # Placeholder at index 0
        root,  # Root at index 1
        LEAF_A,  # Leaf at index 2
        LEAF_B,  # Leaf at index 3
    ]
    assert build_merkle_tree([LEAF_A, LEAF_B]) == expected_tree


def test_build_merkle_tree_three_leaves() -> None:
    """
    Tests a tree with a number of leaves that is not a power of 2,
    requiring padding with a ZERO_HASH.
    """
    # Bottom layer: [LEAF_A, LEAF_B, LEAF_C, ZERO_HASH]
    parent_ab = hash_nodes(LEAF_A, LEAF_B)
    parent_c_zero = hash_nodes(LEAF_C, ZERO_HASH)
    root = hash_nodes(parent_ab, parent_c_zero)

    expected_tree = [
        ZERO_HASH,  # Placeholder at index 0
        root,  # Root at index 1
        parent_ab,  # Parent at index 2
        parent_c_zero,  # Parent at index 3
        LEAF_A,
        LEAF_B,
        LEAF_C,
        ZERO_HASH,  # Padding at index 7
    ]
    assert build_merkle_tree([LEAF_A, LEAF_B, LEAF_C]) == expected_tree


@pytest.mark.parametrize("num_leaves", [5, 11, 16])
def test_build_merkle_tree_larger_trees(num_leaves: int) -> None:
    """
    Tests larger trees by verifying the root and structure without
    checking every intermediate node by hand.
    """
    leaves = [Bytes32(os.urandom(32)) for _ in range(num_leaves)]
    tree = build_merkle_tree(leaves)

    # Check tree length
    #
    # A full tree is twice the size of its padded bottom layer.
    expected_bottom_size = 1
    while expected_bottom_size < num_leaves:
        expected_bottom_size *= 2
    assert len(tree) == expected_bottom_size * 2

    # Check that the original leaves are correctly placed
    assert tree[expected_bottom_size : expected_bottom_size + num_leaves] == leaves

    # Manually re-calculate and verify the root
    #
    # This ensures the hashing logic is correct throughout the tree.
    layer = list(leaves) + [ZERO_HASH] * (expected_bottom_size - num_leaves)
    while len(layer) > 1:
        new_layer: List[Bytes32] = []
        for i in range(0, len(layer), 2):
            new_layer.append(hash_nodes(layer[i], layer[i + 1]))
        layer = new_layer

    expected_root = layer[0]
    assert tree[1] == expected_root
