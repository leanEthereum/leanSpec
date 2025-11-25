"""
Subtree construction and manipulation for top-bottom Merkle tree traversal.

This module contains the `HashSubTree` type and its associated construction methods,
implementing the memory-efficient top-bottom tree traversal approach.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List

from lean_spec.types import StrictBaseModel, Uint64

from .containers import HashDigest, HashTreeLayer, HashTreeOpening, Parameter
from .tweak_hash import TreeTweak

if TYPE_CHECKING:
    from .rand import Rand
    from .tweak_hash import TweakHasher


def _get_padded_layer(rand: Rand, nodes: List[HashDigest], start_index: int) -> HashTreeLayer:
    """
    Pads a layer of nodes with random hashes to simplify tree construction.

    This helper enforces a crucial invariant: every active layer must start at an
    even index and end at an odd index. This guarantees that every node within
    the layer can be neatly paired with a sibling (a left child with a right
    child), which dramatically simplifies the parent generation logic by
    removing the need to handle edge cases.

    Args:
        rand: Random generator for padding values.
        nodes: The list of active nodes for the current layer.
        start_index: The starting index of the first node in `nodes`.

    Returns:
        A new `HashTreeLayer` with the necessary padding applied.
    """
    nodes_with_padding: List[HashDigest] = []
    end_index = start_index + len(nodes) - 1

    # Prepend random padding if the layer starts at an odd index.
    if start_index % 2 == 1:
        nodes_with_padding.append(rand.domain())

    # The actual start index of the padded layer is always the even
    # number at or immediately before the original start_index.
    actual_start_index = start_index - (start_index % 2)

    # Add the actual node content.
    nodes_with_padding.extend(nodes)

    # Append random padding if the layer ends at an even index.
    if end_index % 2 == 0:
        nodes_with_padding.append(rand.domain())

    return HashTreeLayer(start_index=actual_start_index, nodes=nodes_with_padding)


class HashSubTree(StrictBaseModel):
    """
    Represents a subtree of a sparse Merkle tree.

    This is the building block for the top-bottom tree traversal approach,
    which splits a large Merkle tree into:
    - **One top tree**: Contains the root and the top `LOG_LIFETIME/2` layers
    - **Multiple bottom trees**: Each contains `sqrt(LIFETIME)` leaves

    A subtree can represent either a complete tree (from layer 0) or a partial tree
    starting from a higher layer (like a top tree starting from layer `LOG_LIFETIME/2`).

    The layers are stored from `lowest_layer` up to the root, with padding applied
    to ensure even alignment for efficient parent computation.

    Memory Efficiency
    -----------------
    For a key with lifetime 2^32:
    - Traditional approach: O(2^32) = requires hundreds of GiB
    - Top-bottom approach: O(sqrt(2^32)) = O(2^16) ≈ much less memory

    The secret key maintains:
    - The full top tree (sparse, only active roots)
    - Two consecutive bottom trees (sliding window)
    """

    depth: int
    """
    The total depth of the full tree (e.g., 32 for a 2^32 leaf space).

    This represents the depth of the complete Merkle tree, not just this subtree.
    A subtree starting from layer `k` will have `depth - k` layers stored.
    """

    lowest_layer: int
    """
    The lowest layer included in this subtree.

    - For bottom trees: `lowest_layer = 0` (includes leaves)
    - For top trees: `lowest_layer = LOG_LIFETIME/2` (starts from middle)

    Example: For LOG_LIFETIME=32, top tree has lowest_layer=16, containing
    layers 16 through 32 (the root).
    """

    layers: List[HashTreeLayer]
    """
    The layers of this subtree, from `lowest_layer` to the root.

    - `layers[0]` corresponds to layer `lowest_layer` in the full tree
    - `layers[-1]` corresponds to the highest layer in this subtree
    - For bottom trees: the last layer contains a single root
    - For top trees: the last layer contains the global root

    Each layer maintains the padding invariant: start index is even,
    end index is odd (except for single-node layers).
    """

    @classmethod
    def new(
        cls,
        hasher: TweakHasher,
        rand: Rand,
        lowest_layer: int,
        depth: int,
        start_index: int,
        parameter: Parameter,
        lowest_layer_nodes: List[HashDigest],
    ) -> HashSubTree:
        """
        Builds a new sparse Merkle subtree starting from a specified layer.

        This is the general constructor for subtrees and is used internally by
        `new_top_tree()` and `new_bottom_tree()`. A subtree can start from any
        layer, not just layer 0 (leaves).

        ### Construction Algorithm

        1.  **Initialization**: Start with the provided nodes at `lowest_layer`,
            apply padding to ensure even alignment.

        2.  **Bottom-Up Iteration**: Build the tree layer by layer, from the
            lowest layer towards the root.

        3.  **Parent Generation**: At each level, group nodes into pairs
            (left, right) and hash them to create parent nodes.

        4.  **Padding**: Apply padding to each new layer to maintain the
            even-alignment invariant.

        5.  **Termination**: Continue until reaching the root or the desired
            highest layer.

        Args:
            hasher: The tweakable hash instance for computing parent nodes.
            rand: Random generator for padding values.
            lowest_layer: The starting layer for this subtree (0 for full trees).
            depth: The total depth of the full tree (e.g., 32 for 2^32 leaves).
            start_index: The absolute index at `lowest_layer` where this subtree begins.
            parameter: The public parameter `P` for the hash function.
            lowest_layer_nodes: The hash nodes at `lowest_layer` to build from.

        Returns:
            A `HashSubTree` containing all computed layers from `lowest_layer` to root.
        """
        # Validate that we have enough space in the tree for these nodes.
        # At layer `lowest_layer`, there are 2^(depth - lowest_layer) possible positions.
        max_index_at_layer = 1 << (depth - lowest_layer)
        if start_index + len(lowest_layer_nodes) > max_index_at_layer:
            raise ValueError(
                f"Not enough space at layer {lowest_layer}: "
                f"start_index={start_index}, nodes={len(lowest_layer_nodes)}, "
                f"max={max_index_at_layer}"
            )

        # Start with the lowest layer nodes and apply initial padding.
        layers: List[HashTreeLayer] = []
        current_layer = _get_padded_layer(rand, lowest_layer_nodes, start_index)
        layers.append(current_layer)

        # Build the tree layer by layer from lowest_layer up to the root.
        for level in range(lowest_layer, depth):
            parents: List[HashDigest] = []

            # Group current layer's nodes into pairs of (left, right) siblings.
            # The padding guarantees this works perfectly without orphan nodes.
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
                parent_node = hasher.apply(parameter, tweak, list(children))
                parents.append(parent_node)

            # Pad the new list of parents to prepare for the next iteration.
            new_start_index = current_layer.start_index // 2
            current_layer = _get_padded_layer(rand, parents, new_start_index)
            layers.append(current_layer)

        # Return the completed subtree.
        return cls(depth=depth, lowest_layer=lowest_layer, layers=layers)

    @classmethod
    def new_top_tree(
        cls,
        hasher: TweakHasher,
        rand: Rand,
        depth: int,
        start_bottom_tree_index: int,
        parameter: Parameter,
        bottom_tree_roots: List[HashDigest],
    ) -> HashSubTree:
        """
        Constructs a top tree from the roots of bottom trees.

        For top-bottom tree traversal, the full Merkle tree is split into:
        - **Top tree**: Contains root and top `LOG_LIFETIME/2` layers
        - **Bottom trees**: Each contains `sqrt(LIFETIME)` leaves

        The top tree's lowest layer contains the roots of all bottom trees,
        and it is built upward from there to the global root.

        ### Algorithm

        1.  **Determine lowest layer**: For a tree of depth `d`, the top tree
            starts at layer `d/2` (the middle of the tree).

        2.  **Build upward**: Use `new()` to build from the bottom tree
            roots up to the global root.

        Args:
            hasher: The tweakable hash instance for computing parent nodes.
            rand: Random generator for padding values.
            depth: The total depth of the full tree (must be even for top-bottom split).
            start_bottom_tree_index: The index of the first bottom tree in the range.
            parameter: The public parameter `P` for the hash function.
            bottom_tree_roots: The list of roots from all bottom trees in order.

        Returns:
            A `HashSubTree` representing the top tree with `lowest_layer = depth/2`.

        Raises:
            ValueError: If depth is odd (top-bottom split requires even depth).
        """
        if depth % 2 != 0:
            raise ValueError(
                f"Top-bottom tree split requires even depth, got {depth}. "
                f"The top tree must start at depth/2, which must be an integer."
            )

        # The top tree starts at the middle layer.
        lowest_layer = depth // 2

        # Build the top tree using the bottom tree roots as the lowest layer.
        return cls.new(
            hasher=hasher,
            rand=rand,
            lowest_layer=lowest_layer,
            depth=depth,
            start_index=start_bottom_tree_index,
            parameter=parameter,
            lowest_layer_nodes=bottom_tree_roots,
        )

    @classmethod
    def new_bottom_tree(
        cls,
        hasher: TweakHasher,
        rand: Rand,
        depth: int,
        bottom_tree_index: int,
        parameter: Parameter,
        leaves: List[HashDigest],
    ) -> HashSubTree:
        """
        Constructs a single bottom tree from leaf hashes.

        A bottom tree covers `sqrt(LIFETIME)` consecutive epochs. For a tree with
        `LOG_LIFETIME = 32`, each bottom tree covers 2^16 = 65536 epochs.

        Bottom trees are numbered 0, 1, 2, ... where tree `i` covers epochs
        `[i * sqrt(LIFETIME), (i+1) * sqrt(LIFETIME))`.

        ### Algorithm

        1.  **Build full tree**: First, build a complete subtree from layer 0
            using the provided leaves.

        2.  **Truncate incompatible top layers**: The full tree computation adds
            padding nodes in upper layers that would be incompatible with other
            bottom trees. We remove these layers.

        3.  **Replace with standalone root**: Extract the root at layer `depth/2`
            and make it the highest layer of this bottom tree.

        Args:
            hasher: The tweakable hash instance for computing parent nodes.
            rand: Random generator for padding values.
            depth: The total depth of the full tree (must be even).
            bottom_tree_index: The index of this bottom tree (0, 1, 2, ...).
            parameter: The public parameter `P` for the hash function.
            leaves: The pre-hashed leaf nodes (one-time public keys).

        Returns:
            A `HashSubTree` with layers 0 through `depth/2`, where the highest
            layer contains only the bottom tree's root.

        Raises:
            ValueError: If depth is odd or leaves count doesn't match `sqrt(LIFETIME)`.
        """
        if depth % 2 != 0:
            raise ValueError(
                f"Top-bottom tree split requires even depth, got {depth}. "
                f"Bottom trees must span exactly depth/2 layers."
            )

        leafs_per_bottom_tree = 1 << (depth // 2)
        if len(leaves) != leafs_per_bottom_tree:
            raise ValueError(
                f"Bottom tree must have exactly {leafs_per_bottom_tree} leaves "
                f"(sqrt(LIFETIME) for depth={depth}), got {len(leaves)}"
            )

        # Calculate the starting index for this bottom tree's leaves.
        start_index = bottom_tree_index * leafs_per_bottom_tree

        # Build a full subtree from layer 0 using the leaves.
        full_tree = cls.new(
            hasher=hasher,
            rand=rand,
            lowest_layer=0,
            depth=depth,
            start_index=start_index,
            parameter=parameter,
            lowest_layer_nodes=leaves,
        )

        # Truncate to remove upper layers that would be incompatible with the top tree.
        # We keep layers 0 through depth/2 (inclusive).
        #
        # Extract the root at layer depth/2. The root's index in that layer is either
        # the bottom_tree_index (if it's the left child of its parent in the top tree)
        # or bottom_tree_index (if it's the right child). Since we're at layer depth/2,
        # the position is simply bottom_tree_index.
        middle_layer = full_tree.layers[depth // 2]

        # The root is at position (start_index >> (depth // 2)) = bottom_tree_index
        # within the middle layer. We need to find it in the stored nodes.
        root_position_in_layer = bottom_tree_index - middle_layer.start_index
        root = middle_layer.nodes[root_position_in_layer]

        # Truncate layers to keep only 0 through depth/2 - 1.
        truncated_layers = full_tree.layers[: (depth // 2)]

        # Add a final layer containing just the root.
        truncated_layers.append(HashTreeLayer(start_index=bottom_tree_index, nodes=[root]))

        return cls(depth=depth, lowest_layer=0, layers=truncated_layers)

    def root(self) -> HashDigest:
        """
        Extracts the root digest from this subtree.

        For top-bottom tree traversal, a subtree's root is the single node
        in its highest layer.

        Returns:
            The root hash digest of the subtree.

        Raises:
            ValueError: If the subtree has no layers or the highest layer is empty.
        """
        if len(self.layers) == 0:
            raise ValueError("Cannot get root of empty subtree.")

        highest_layer = self.layers[-1]
        if len(highest_layer.nodes) == 0:
            raise ValueError("Highest layer of subtree is empty.")

        # The root is the only node in the highest layer for proper subtrees.
        # For top trees and bottom trees, the highest layer should have exactly one node.
        return highest_layer.nodes[0]

    def path(self, position: Uint64) -> HashTreeOpening:
        """
        Computes the authentication path for a leaf within this subtree.

        This is similar to full tree path computation but works with subtrees that may
        not start from layer 0. The path is computed from the specified position up to
        (but not including) the subtree's root.

        For a subtree covering layers L through H (where H is the highest/root layer),
        this generates H - L siblings: one for each layer from L to H-1.

        Args:
            position: The absolute index of the leaf in the full tree coordinate system.

        Returns:
            A `HashTreeOpening` containing the sibling hashes for the path.

        Raises:
            ValueError: If the subtree is empty or the position is out of bounds.
        """
        if len(self.layers) == 0:
            raise ValueError("Cannot generate path for empty subtree.")

        lowest_layer = self.layers[0]
        if int(position) < lowest_layer.start_index:
            raise ValueError("Position is before the subtree's start index.")

        if int(position) >= lowest_layer.start_index + len(lowest_layer.nodes):
            raise ValueError("Position is beyond the subtree's range.")

        co_path: List[HashDigest] = []
        current_position = int(position)

        # Iterate through layers from lowest to highest, EXCLUDING the final root layer.
        # The root layer doesn't contribute a sibling to the authentication path.
        # self.layers[:-1] gives all layers except the last (root) layer.
        for layer in self.layers[:-1]:
            # Determine the sibling's position by flipping the last bit.
            sibling_position = current_position ^ 1
            sibling_index = sibling_position - layer.start_index

            # Ensure the sibling exists in this layer
            if sibling_index < 0 or sibling_index >= len(layer.nodes):
                raise ValueError(
                    f"Sibling index {sibling_index} out of bounds for layer "
                    f"with {len(layer.nodes)} nodes"
                )

            # Add the sibling's hash to the co-path.
            co_path.append(layer.nodes[sibling_index])

            # Move to the parent's position for the next iteration.
            current_position //= 2

        return HashTreeOpening(siblings=co_path)


def combined_path(
    top_tree: HashSubTree, bottom_tree: HashSubTree, position: Uint64
) -> HashTreeOpening:
    """
    Generates a combined authentication path spanning top and bottom trees.

    For top-bottom tree traversal, a signature's authentication path must prove
    that a leaf is part of the global Merkle root. This requires two proofs:

    1.  **Bottom tree path**: Proves the leaf is part of its bottom tree's root
    2.  **Top tree path**: Proves the bottom tree's root is part of the global root

    This function combines both paths into a single `HashTreeOpening` that can
    be used for verification.

    ### Algorithm

    1.  **Determine which bottom tree**: Calculate which bottom tree contains
        the specified position.

    2.  **Get bottom tree path**: Extract the authentication path from the leaf
        up to the bottom tree's root (depth/2 siblings).

    3.  **Get top tree path**: Extract the authentication path from the bottom
        tree's root up to the global root (depth/2 siblings).

    4.  **Concatenate**: Combine both paths into a single path with `depth` siblings.

    Args:
        top_tree: The top tree containing the global root.
        bottom_tree: The bottom tree containing the specified position.
        position: The absolute epoch/leaf index to generate a path for.

    Returns:
        A `HashTreeOpening` with `depth` siblings that authenticates the leaf
        against the global root.

    Raises:
        ValueError: If trees have mismatched depths, odd depth, or position is
                   out of bounds for the bottom tree.
    """
    # Validate that both trees have the same depth.
    if top_tree.depth != bottom_tree.depth:
        raise ValueError(
            f"Top and bottom trees must have same depth: "
            f"top={top_tree.depth}, bottom={bottom_tree.depth}"
        )

    depth = top_tree.depth

    # Validate even depth (required for top-bottom split).
    if depth % 2 != 0:
        raise ValueError(
            f"Top-bottom tree traversal requires even depth, got {depth}. "
            f"Cannot split tree into equal top and bottom halves."
        )

    # Calculate parameters for bottom trees.
    leafs_per_bottom_tree = 1 << (depth // 2)

    # Determine which bottom tree this position belongs to.
    #
    # Bottom tree index = floor(position / sqrt(LIFETIME))
    bottom_tree_index = int(position) // leafs_per_bottom_tree

    # Verify that the provided bottom_tree actually corresponds to this position.
    # The bottom tree's lowest layer starts at bottom_tree_index * leafs_per_bottom_tree.
    expected_start = bottom_tree_index * leafs_per_bottom_tree
    actual_start = bottom_tree.layers[0].start_index

    if actual_start != expected_start:
        raise ValueError(
            f"Bottom tree mismatch: position {position} belongs to "
            f"bottom tree {bottom_tree_index} (should start at {expected_start}), "
            f"but provided bottom tree starts at {actual_start}"
        )

    # Get the authentication path within the bottom tree (from leaf to bottom tree root).
    bottom_path = bottom_tree.path(position)

    # Get the authentication path within the top tree (from bottom tree root to global root).
    # The bottom tree's root is at position `bottom_tree_index` in the top tree's lowest layer.
    top_path = top_tree.path(Uint64(bottom_tree_index))

    # Concatenate the two paths: bottom siblings first, then top siblings.
    # This creates a complete path from leaf to global root.
    combined_siblings = bottom_path.siblings + top_path.siblings

    return HashTreeOpening(siblings=combined_siblings)
