"""
Implements the sparse Merkle tree used in the Generalized XMSS scheme.

This module provides the data structures and algorithms for building a Merkle
tree over a contiguous subset of leaves, computing authentication paths, and
verifying those paths.

The key features are:
1.  **Sparsity**: The tree can represent a massive address space (e.g., 2^32
    leaves) while only storing the nodes relevant to a smaller, active range of
    leaves (e.g., 2^20 leaves).
2.  **Random Padding**: To simplify the logic for pairing sibling nodes, the
    active layers are padded with random hash values to ensure they always
    start at an even index and end at an odd index.
"""

from __future__ import annotations

from typing import List

from lean_spec.subspecs.xmss.constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)

from .structures import (
    HashDigest,
    HashTree,
    HashTreeLayer,
    HashTreeOpening,
    Parameter,
)
from .tweak_hash import (
    PROD_TWEAK_HASHER,
    TEST_TWEAK_HASHER,
    TreeTweak,
    TweakHasher,
)
from .utils import PROD_RAND, TEST_RAND, Rand


class MerkleTree:
    """An instance of the Merkle Tree handler for a given config."""

    def __init__(self, config: XmssConfig, hasher: TweakHasher, rand: Rand):
        """Initializes with a config, a hasher, and a random generator."""
        self.config = config
        self.hasher = hasher
        self.rand = rand

    def _get_padded_layer(
        self, nodes: List[HashDigest], start_index: int
    ) -> HashTreeLayer:
        """
        Pads a layer to ensure its nodes can always be paired up.

        This helper function adds random padding to the start and/or end of
        a list of nodes to enforce an invariant: every layer must start at an
        even index and end at an odd index. This guarantees that every node has
        a sibling, simplifying the construction of the next layer up.

        Args:
            nodes: The list of active nodes for the current layer.
            start_index: The starting index of the first node in `nodes`.

        Returns:
            A new `HashTreeLayer` with padding applied.
        """
        nodes_with_padding: List[HashDigest] = []
        end_index = start_index + len(nodes) - 1

        # Prepend random padding if the layer starts at an odd index.
        if start_index % 2 == 1:
            nodes_with_padding.append(self.rand.domain())

        # The actual start index of the padded layer is always the even
        # number at or immediately before the original start_index.
        actual_start_index = start_index - (start_index % 2)

        # Add the actual node content.
        nodes_with_padding.extend(nodes)

        # Append random padding if the layer ends at an even index.
        if end_index % 2 == 0:
            nodes_with_padding.append(self.rand.domain())

        return HashTreeLayer(
            start_index=actual_start_index, nodes=nodes_with_padding
        )

    def build(
        self,
        depth: int,
        start_index: int,
        parameter: Parameter,
        leaf_hashes: List[HashDigest],
    ) -> HashTree:
        """
        Builds a new sparse Merkle tree from a list of leaf hashes.

        The construction proceeds bottom-up, from the leaf layer to the root.
        At each level, pairs of sibling nodes are hashed to create
        their parents for the next level up.

        Args:
            depth: The depth of the tree (e.g., 32 for a 2^32 leaf space).
            start_index: The index of the first leaf in `leaf_hashes`.
            parameter: The public parameter `P` for the hash function.
            leaf_hashes: The list of pre-hashed leaf nodes to
            build the tree on.

        Returns:
            The fully constructed `HashTree` object.
        """
        # Start with the leaf hashes and apply the initial padding.
        layers: List[HashTreeLayer] = []
        current_layer = self._get_padded_layer(leaf_hashes, start_index)
        layers.append(current_layer)

        # Iterate from the leaf layer (level 0) up to the root.
        for level in range(depth):
            parents: List[HashDigest] = []
            # Group the current layer's nodes into pairs of siblings.
            for i, children in enumerate(
                zip(
                    current_layer.nodes[0::2],
                    current_layer.nodes[1::2],
                    strict=False,
                )
            ):
                # Calculate the position of the parent node in the
                # next level up.
                parent_index = (current_layer.start_index // 2) + i
                # Create the tweak for hashing these two children.
                tweak = TreeTweak(level=level + 1, index=parent_index)
                # Hash the left and right children to get their parent.
                parent_node = self.hasher.apply(
                    parameter, tweak, list(children)
                )
                parents.append(parent_node)

            # Pad the new list of parents to prepare for the next iteration.
            new_start_index = current_layer.start_index // 2
            current_layer = self._get_padded_layer(parents, new_start_index)
            layers.append(current_layer)

        return HashTree(depth=depth, layers=layers)

    def get_root(self, tree: HashTree) -> HashDigest:
        """Extracts the root digest from a constructed Merkle tree."""
        # The root is the single node in the final layer.
        return tree.layers[-1].nodes[0]

    def get_path(self, tree: HashTree, position: int) -> HashTreeOpening:
        """
        Computes the Merkle authentication path for a leaf at a given position.

        The path consists of the list of sibling nodes required to reconstruct
        the root, starting from the leaf's sibling and going up the tree.

        Args:
            tree: The `HashTree` from which to extract the path.
            position: The absolute index of the leaf for which to
            generate path.

        Returns:
            A `HashTreeOpening` object containing the co-path.
        """
        co_path: List[HashDigest] = []
        current_position = position

        # Iterate from the bottom layer (level 0) up to the layer
        # below the root.
        for level in range(tree.depth):
            # Determine the sibling's position using an XOR operation.
            sibling_position = current_position ^ 1
            # Find the sibling's index within the sparse `nodes` vector.
            layer = tree.layers[level]
            sibling_index_in_vec = sibling_position - layer.start_index
            # Add the sibling's hash to the co-path.
            co_path.append(layer.nodes[sibling_index_in_vec])
            # Move up to the parent's position for the next iteration.
            current_position //= 2

        return HashTreeOpening(siblings=co_path)

    def verify_path(
        self,
        parameter: Parameter,
        root: HashDigest,
        position: int,
        leaf_parts: List[HashDigest],
        opening: HashTreeOpening,
    ) -> bool:
        """
        Verifies a Merkle authentication path.

        This function reconstructs a candidate root by starting with the leaf
        node and repeatedly hashing it with the sibling nodes provided
        in the opening path.

        The verification succeeds if the candidate root matches the true root.

        Args:
            parameter: The public parameter `P` for the hash function.
            root: The known, trusted Merkle root.
            position: The absolute index of the leaf being verified.
            leaf_parts: The list of digests that constitute the original leaf.
            opening: The `HashTreeOpening` object containing the sibling path.

        Returns:
            `True` if the path is valid, `False` otherwise.
        """
        # The first step is to hash the constituent parts of the leaf to get
        # the actual node at layer 0 of the tree.
        leaf_tweak = TreeTweak(level=0, index=position)
        current_node = self.hasher.apply(parameter, leaf_tweak, leaf_parts)

        # Iterate up the tree, hashing the current node with its sibling from
        # the path at each level.
        current_position = position
        for level, sibling_node in enumerate(opening.siblings):
            # Determine if the current node is a left or right child.
            if current_position % 2 == 0:
                # Current node is a left child; sibling is on the right.
                children = [current_node, sibling_node]
            else:
                # Current node is a right child; sibling is on the left.
                children = [sibling_node, current_node]

            # Move up to the parent's position for the next iteration.
            current_position //= 2
            # Create the tweak for the parent's level and position.
            parent_tweak = TreeTweak(level=level + 1, index=current_position)
            # Hash the children to compute the parent node.
            current_node = self.hasher.apply(parameter, parent_tweak, children)

        # After iterating through the entire path, the final computed node
        # should be the root of the tree.
        return current_node == root


PROD_MERKLE_TREE = MerkleTree(PROD_CONFIG, PROD_TWEAK_HASHER, PROD_RAND)
"""An instance configured for production-level parameters."""

TEST_MERKLE_TREE = MerkleTree(TEST_CONFIG, TEST_TWEAK_HASHER, TEST_RAND)
"""A lightweight instance for test environments."""
