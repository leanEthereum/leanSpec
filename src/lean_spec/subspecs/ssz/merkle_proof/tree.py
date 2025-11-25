"""Merkle tree building logic."""

from typing import List, Sequence

from lean_spec.subspecs.ssz.utils import get_power_of_two_ceil, hash_nodes
from lean_spec.types import ZERO_HASH
from lean_spec.types.byte_arrays import Bytes32


def build_merkle_tree(leaves: Sequence[Bytes32]) -> List[Bytes32]:
    r"""
    Builds a full Merkle tree and returns it as a flat list.

    The tree is represented as a list where the node at a generalized
    index `i` is located at `tree[i]`. The 0-index is a placeholder.
    """
    # Handle the edge case of no leaves.
    if not leaves:
        # Per the spec, a tree of an empty list is a single ZERO_HASH.
        #
        # The flat list format includes a placeholder at index 0.
        return [ZERO_HASH] * 2

    # Calculate the required size of the bottom layer (must be a power of two).
    bottom_layer_size = get_power_of_two_ceil(len(leaves))

    # Create the complete, padded leaf layer.
    padded_leaves = list(leaves) + [ZERO_HASH] * (bottom_layer_size - len(leaves))

    # Initialize the tree with placeholders for parent nodes and the padded leaves.
    #
    # The first half of the list will store the calculated parent nodes.
    tree = [ZERO_HASH] * bottom_layer_size + padded_leaves

    # Iterate backwards from the last parent node up to the root.
    #
    # This calculates the tree from the bottom up.
    for i in range(bottom_layer_size - 1, 0, -1):
        # A parent at index `i` is the hash of its two children at `2*i` and `2*i+1`.
        tree[i] = hash_nodes(tree[i * 2], tree[i * 2 + 1])

    # Return the fully constructed tree.
    return tree
