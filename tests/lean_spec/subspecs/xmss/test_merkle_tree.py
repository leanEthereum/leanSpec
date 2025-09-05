"""Tests for the sparse Merkle tree implementation."""

import pytest

from lean_spec.subspecs.xmss.containers import HashDigest
from lean_spec.subspecs.xmss.merkle_tree import (
    PROD_MERKLE_TREE,
    MerkleTree,
)
from lean_spec.subspecs.xmss.tweak_hash import (
    TreeTweak,
)


def _run_commit_open_verify_roundtrip(
    merkle_tree: MerkleTree,
    num_leaves: int,
    depth: int,
    start_index: int,
    leaf_parts_len: int,
) -> None:
    """
    A helper function to perform a full Merkle tree roundtrip test.

    The process is as follows:
    1.  Generate random leaf data.
    2.  Hash the leaves to create layer 0 of the tree.
    3.  Build the full Merkle tree and get its root (commit).
    4.  For each leaf, generate an authentication path (open).
    5.  Verify that each path is valid for its corresponding leaf and root.

    Args:
        num_leaves: The number of active leaves in the tree.
        start_index: The starting index of the first active leaf.
        leaf_parts_len: The number of digests that constitute a single leaf.
    """
    # SETUP: Generate a random parameter and the raw leaf data.
    parameter = merkle_tree.rand.parameter()
    leaves: list[list[HashDigest]] = [
        [merkle_tree.rand.domain() for _ in range(leaf_parts_len)] for _ in range(num_leaves)
    ]

    # HASH LEAVES: Compute the layer 0 nodes by hashing the leaf parts.
    leaf_hashes: list[HashDigest] = [
        merkle_tree.hasher.apply(
            parameter,
            TreeTweak(level=0, index=start_index + i),
            leaf_parts,
        )
        for i, leaf_parts in enumerate(leaves)
    ]

    # COMMIT: Build the Merkle tree from the leaf hashes.
    tree = merkle_tree.build(depth, start_index, parameter, leaf_hashes)
    root = merkle_tree.root(tree)

    # OPEN & VERIFY: For each leaf, generate and verify its path.
    for i, leaf_parts in enumerate(leaves):
        position = start_index + i
        opening = merkle_tree.path(tree, position)
        is_valid = merkle_tree.verify_path(parameter, root, position, leaf_parts, opening)
        assert is_valid, f"Verification failed for leaf at position {position}"


@pytest.mark.parametrize(
    "num_leaves, depth, start_index, leaf_parts_len, description",
    [
        (16, 4, 0, 3, "Full tree (depth 4)"),
        (12, 5, 0, 5, "Half tree, left-aligned (depth 5)"),
        (16, 5, 16, 2, "Half tree, right-aligned (depth 5)"),
        (22, 6, 13, 3, "Sparse, non-aligned tree (depth 6)"),
        (2, 2, 2, 6, "Half tree, right-aligned (small)"),
        (1, 1, 0, 1, "Tree with a single leaf at the start"),
        (1, 1, 1, 1, "Tree with a single leaf at an odd index"),
        (16, 5, 7, 2, "Small sparse tree starting at an odd index"),
    ],
)
def test_commit_open_verify_roundtrip(
    num_leaves: int,
    depth: int,
    start_index: int,
    leaf_parts_len: int,
    description: str,
) -> None:
    """Tests the Merkle tree logic for various configurations."""
    # Ensure the test case parameters are valid for the specified tree depth.
    assert start_index + num_leaves <= (1 << depth)

    _run_commit_open_verify_roundtrip(
        PROD_MERKLE_TREE, num_leaves, depth, start_index, leaf_parts_len
    )
