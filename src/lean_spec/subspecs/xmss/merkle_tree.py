"""
Implements the sparse Merkle tree used in the Generalized XMSS scheme.

### Usage of Merkle Trees in XMSS scheme: Aggregating Keys

A Merkle tree is a cryptographic data structure that allows for the efficient
aggregation and verification of large sets of data. In XMSS, its role is to
aggregate **one-time public keys** (the leaves of the tree) into a single,
compact **master public key** (the root of the tree).

A verifier who knows only the root can be given a small proof (an "authentication
path") to efficiently verify that a specific one-time public key is a legitimate
part of the overall scheme.

### Key Optimizations for XMSS

This implementation includes two important features tailored for this use case:

1.  **Sparsity**: A key pair might have a massive theoretical lifetime (e.g., 2^32 epochs),
    but in practice, a signer only needs to generate and store the keys for a
    much smaller, active range (e.g., 2^20 epochs). This implementation builds a
    "sparse" tree, only computing and storing the nodes and branches relevant to
    this active range of leaves, leading to enormous savings in computation and memory.

2.  **Random Padding**: To simplify the algorithm that builds the tree, each active
    layer is padded with random hash values. This ensures that every node can
    always be paired with a sibling, eliminating complex edge-case logic for
    "orphan" nodes at the boundaries of the sparse region.
"""

from __future__ import annotations

from typing import List

from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from .containers import (
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

    def _get_padded_layer(self, nodes: List[HashDigest], start_index: int) -> HashTreeLayer:
        """
        Pads a layer of nodes with random hashes to simplify tree construction.

        This helper enforces a crucial invariant: every active layer must start at an
        even index and end at an odd index. This guarantees that every node within
        the layer can be neatly paired with a sibling (a left child with a right
        child), which dramatically simplifies the parent generation logic by
        removing the need to handle edge cases.

        Args:
            nodes: The list of active nodes for the current layer.
            start_index: The starting index of the first node in `nodes`.

        Returns:
            A new `HashTreeLayer` with the necessary padding applied.
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

        return HashTreeLayer(start_index=actual_start_index, nodes=nodes_with_padding)

    def build(
        self,
        depth: int,
        start_index: int,
        parameter: Parameter,
        leaf_hashes: List[HashDigest],
    ) -> HashTree:
        """
        Builds a new sparse Merkle tree from a contiguous range of leaf hashes.

        ### Construction Algorithm

        1.  **Initialization**: The process starts with the provided `leaf_hashes`
            at the bottom of the tree (level 0). This layer is padded.

        2.  **Bottom-Up Iteration**: The tree is built level by level, from the
            leaves towards the root.

        3.  **Parent Generation**: In each level, the current layer's nodes are
            grouped into pairs (left child, right child). Each pair is then
            hashed together (using a level- and index-specific tweak) to create
            a parent node in the level above.

        4.  **Padding**: The new list of parent nodes is padded to prepare for the
            next iteration, ensuring the sibling-pairing logic remains simple.

        5.  **Termination**: This process repeats until a layer with a single
            node is produced. This final node is the tree's root.

        Args:
            depth: The total depth of the tree (e.g., 32 for a 2^32 leaf space).
            start_index: The absolute index of the first leaf in `leaf_hashes`.
            parameter: The public parameter `P` for the hash function.
            leaf_hashes: The list of pre-hashed leaf nodes.

        Returns:
            The fully constructed `HashTree` object containing all computed layers.
        """
        # Check there is enough space for the leafs in the tree.
        if start_index + len(leaf_hashes) > 2**depth:
            raise ValueError("Not enough space for leafs in the tree.")

        # Start with the leaf hashes and apply the initial padding.
        layers: List[HashTreeLayer] = []
        current_layer = self._get_padded_layer(leaf_hashes, start_index)
        layers.append(current_layer)

        # Iterate from the leaf layer (level 0) up to the root.
        for level in range(depth):
            parents: List[HashDigest] = []
            # Group the current layer's nodes into pairs of (left, right) siblings.
            #
            # The padding guarantees this works perfectly without leaving orphan nodes.
            for i, children in enumerate(
                zip(
                    current_layer.nodes[0::2],
                    current_layer.nodes[1::2],
                    strict=False,
                )
            ):
                # Calculate the position of the parent node in the next level up.
                parent_index = (current_layer.start_index // 2) + i
                # Create the tweak for hashing these two children.
                tweak = TreeTweak(level=level + 1, index=parent_index)
                # Hash the left and right children to get their parent.
                parent_node = self.hasher.apply(parameter, tweak, list(children))
                parents.append(parent_node)

            # Pad the new list of parents to prepare for the next iteration.
            new_start_index = current_layer.start_index // 2
            current_layer = self._get_padded_layer(parents, new_start_index)
            layers.append(current_layer)

        # Return the completed tree containing all computed layers.
        return HashTree(depth=depth, layers=layers)

    def root(self, tree: HashTree) -> HashDigest:
        """
        Extracts the root digest from a constructed Merkle tree.

        The root is the single node in the final, highest layer of the `HashTree`
        and serves as the primary component of the master public key.
        """
        # The root is the single node in the final layer.
        return tree.layers[-1].nodes[0]

    def path(self, tree: HashTree, position: int) -> HashTreeOpening:
        """
        Computes the authentication path for a leaf.

        The path is the minimal set of sibling nodes a verifier needs to reconstruct
        the root from a given leaf. This `O(log N)` proof is what makes Merkle
        tree verification highly efficient.

        ### Path Generation Algorithm
        The algorithm "climbs" the tree from the leaf level to the root. At each
        level, it identifies the sibling of the current node on the path and adds
        it to the `co_path`. It then moves up to the parent's position for the
        next level.

        Args:
            tree: The `HashTree` from which to extract the path.
            position: The absolute index of the leaf whose path is needed.

        Returns:
            A `HashTreeOpening` object containing the list of sibling hashes.
        """
        # Check that there is at least one layer in the tree.
        if len(tree.layers) == 0:
            raise ValueError("Cannot generate path for empty tree.")

        # Check that the position is within the tree's range.
        if position < tree.layers[0].start_index:
            raise ValueError("Position (before start) is invalid.")

        if position >= tree.layers[0].start_index + len(tree.layers[0].nodes):
            raise ValueError("Position (after end) is invalid.")

        co_path: List[HashDigest] = []
        current_position = position

        # Iterate from the leaf layer (level 0) up to the layer below the root.
        for level in range(tree.depth):
            # Determine the sibling's position by flipping the last bit (XOR with 1).
            sibling_position = current_position ^ 1
            # Find the sibling's index within our sparsely stored `nodes` vector.
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
        Verifies a Merkle authentication path against a known, trusted root.

        This function is the final check in signature verification. It proves that the
        one-time public key used for the signature (represented by `leaf_parts`) is a
        legitimate member of the set committed to by the Merkle `root`.

        ### Verification Algorithm

        1.  **Leaf Computation**: The process begins at the bottom. The verifier first
            hashes the `leaf_parts` to compute the actual leaf digest. This becomes the
            starting `current_node` for the climb up the tree.

        2.  **Bottom-Up Reconstruction**: The verifier iterates through the `opening.siblings`
            path. At each `level`, it takes the `current_node` and the `sibling_node`
            from the path.

        3.  **Parent Calculation**: It determines if the `current_node` is a left or
            right child based on its `position`. The two nodes are placed in the
            correct `(left, right)` order and hashed (with the correct `TreeTweak`)
            to compute the parent. This parent becomes the `current_node` for the
            next level.

        4.  **Final Comparison**: After all siblings are used, the final `current_node`
            is the candidate root. The path is valid if and only if it matches the trusted `root`.

        Args:
            parameter: The public parameter `P` for the hash function.
            root: The known, trusted Merkle root from the public key.
            position: The absolute index of the leaf being verified.
            leaf_parts: The list of digests that constitute the original leaf.
            opening: The `HashTreeOpening` object containing the sibling path.

        Returns:
            `True` if the path is valid and reconstructs the root, `False` otherwise.
        """
        # Compute the depth
        depth = len(opening.siblings)
        # Compute the number of leafs in the tree
        num_leafs = 2**depth
        # Check that the tree depth is at most 32.
        if len(opening.siblings) > 32:
            raise ValueError("Tree depth must be at most 32.")
        # Check that the position and path length match.
        if position >= num_leafs:
            raise ValueError("Position and path length do not match.")

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
