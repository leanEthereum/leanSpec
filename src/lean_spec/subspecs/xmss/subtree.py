"""
Subtree construction and manipulation for top-bottom Merkle tree traversal.

This module contains the `HashSubTree` type and its associated construction methods,
implementing the memory-efficient top-bottom tree traversal approach.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.types import Uint64
from lean_spec.types.container import Container

from .tweak_hash import TreeTweak
from .types import (
    HashDigestList,
    HashDigestVector,
    HashTreeLayer,
    HashTreeLayers,
    HashTreeOpening,
    Parameter,
    PRFKey,
)
from .utils import get_padded_layer

if TYPE_CHECKING:
    from .constants import XmssConfig
    from .prf import Prf
    from .rand import Rand
    from .tweak_hash import TweakHasher


class HashSubTree(Container):
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

    SSZ Container with fields:
    - depth: uint64
    - lowest_layer: uint64
    - layers: List[HashTreeLayer, LAYERS_LIMIT]

    Serialization is handled automatically by SSZ.
    """

    depth: Uint64
    """
    The total depth of the full tree (e.g., 32 for a 2^32 leaf space).

    This represents the depth of the complete Merkle tree, not just this subtree.
    A subtree starting from layer `k` will have `depth - k` layers stored.
    """

    lowest_layer: Uint64
    """
    The lowest layer included in this subtree.

    - For bottom trees: `lowest_layer = 0` (includes leaves)
    - For top trees: `lowest_layer = LOG_LIFETIME/2` (starts from middle)

    Example: For LOG_LIFETIME=32, top tree has lowest_layer=16, containing
    layers 16 through 32 (the root).
    """

    layers: HashTreeLayers
    """
    The layers of this subtree, from `lowest_layer` to the root.

    SSZ notation: `List[HashTreeLayer, LAYERS_LIMIT]`

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
        start_index: Uint64,
        parameter: Parameter,
        lowest_layer_nodes: list[HashDigestVector],
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
        # Validate: nodes must fit in available positions at this layer.
        max_positions = 1 << (depth - lowest_layer)
        if int(start_index) + len(lowest_layer_nodes) > max_positions:
            raise ValueError(
                f"Overflow at layer {lowest_layer}: "
                f"start={start_index}, count={len(lowest_layer_nodes)}, max={max_positions}"
            )

        # Initialize with padded input layer.
        layers: list[HashTreeLayer] = []
        current = get_padded_layer(rand, lowest_layer_nodes, start_index)
        layers.append(current)

        # Build upward: hash pairs of children to create parents.
        for level in range(lowest_layer, depth):
            parent_start = current.start_index // Uint64(2)

            # Hash each pair of siblings into their parent using zip for cleaner indexing.
            parent_start_int = int(parent_start)
            node_pairs = zip(current.nodes[::2], current.nodes[1::2], strict=True)
            parents = [
                hasher.apply(
                    parameter,
                    TreeTweak(level=level + 1, index=Uint64(parent_start_int + i)),
                    [left, right],
                )
                for i, (left, right) in enumerate(node_pairs)
            ]

            # Pad and store the new layer.
            current = get_padded_layer(rand, parents, parent_start)
            layers.append(current)

        return cls(
            depth=Uint64(depth),
            lowest_layer=Uint64(lowest_layer),
            layers=HashTreeLayers(data=layers),
        )

    @classmethod
    def new_top_tree(
        cls,
        hasher: TweakHasher,
        rand: Rand,
        depth: int,
        start_bottom_tree_index: Uint64,
        parameter: Parameter,
        bottom_tree_roots: list[HashDigestVector],
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
            raise ValueError(f"Depth must be even for top-bottom split, got {depth}.")

        # Build from middle layer using bottom tree roots as leaves.
        return cls.new(
            hasher=hasher,
            rand=rand,
            lowest_layer=depth // 2,
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
        bottom_tree_index: Uint64,
        parameter: Parameter,
        leaves: list[HashDigestVector],
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
            raise ValueError(f"Depth must be even for top-bottom split, got {depth}.")

        # Each bottom tree has exactly sqrt(LIFETIME) leaves.
        leafs_per_tree = 1 << (depth // 2)
        if len(leaves) != leafs_per_tree:
            raise ValueError(
                f"Expected {leafs_per_tree} leaves for depth={depth}, got {len(leaves)}."
            )

        # Build full tree from leaves.
        full_tree = cls.new(
            hasher=hasher,
            rand=rand,
            lowest_layer=0,
            depth=depth,
            start_index=bottom_tree_index * Uint64(leafs_per_tree),
            parameter=parameter,
            lowest_layer_nodes=leaves,
        )

        # Extract root from middle layer.
        middle = full_tree.layers[depth // 2]
        root_idx = int(bottom_tree_index - middle.start_index)
        root_layer = HashTreeLayer(
            start_index=bottom_tree_index,
            nodes=HashDigestList(data=[middle.nodes[root_idx]]),
        )

        # Keep bottom half + single root node.
        truncated = [full_tree.layers[i] for i in range(depth // 2)]
        return cls(
            depth=Uint64(depth),
            lowest_layer=Uint64(0),
            layers=HashTreeLayers(data=truncated + [root_layer]),
        )

    @classmethod
    def from_prf_key(
        cls,
        prf: "Prf",
        hasher: "TweakHasher",
        rand: "Rand",
        config: "XmssConfig",
        prf_key: PRFKey,
        bottom_tree_index: Uint64,
        parameter: Parameter,
    ) -> "HashSubTree":
        """
        Generates a single bottom tree on-demand from the PRF key.

        This is a key component of the top-bottom tree approach: instead of storing all
        one-time secret keys, we regenerate them on-demand using the PRF. This enables
        O(sqrt(LIFETIME)) memory usage.

        ### Algorithm

        1.  **Determine epoch range**: Bottom tree `i` covers epochs
            `[i * sqrt(LIFETIME), (i+1) * sqrt(LIFETIME))`

        2.  **Generate leaves**: For each epoch in parallel:
            - For each chain (0 to DIMENSION-1):
              - Derive secret start: `PRF(prf_key, epoch, chain_index)`
              - Compute public end: hash chain for `BASE - 1` steps
            - Hash all chain ends to get the leaf

        3.  **Build bottom tree**: Construct the bottom tree from the leaves

        Args:
            prf: The PRF instance for key derivation.
            hasher: The tweakable hash instance.
            rand: Random generator for padding values.
            config: The XMSS configuration.
            prf_key: The master PRF secret key.
            bottom_tree_index: The index of the bottom tree to generate (0, 1, 2, ...).
            parameter: The public parameter `P` for the hash function.

        Returns:
            A `HashSubTree` representing the requested bottom tree.
        """
        # Calculate the number of leaves per bottom tree: sqrt(LIFETIME).
        leafs_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)

        # Determine the epoch range for this bottom tree.
        start_epoch = bottom_tree_index * Uint64(leafs_per_bottom_tree)
        end_epoch = start_epoch + Uint64(leafs_per_bottom_tree)

        # Generate leaf hashes for all epochs in this bottom tree.
        leaf_hashes: list[HashDigestVector] = []

        for epoch in range(int(start_epoch), int(end_epoch)):
            # For each epoch, compute the one-time public key (chain endpoints).
            chain_ends: list[HashDigestVector] = []

            for chain_index in range(config.DIMENSION):
                # Derive the secret start of the chain from the PRF key.
                start_digest = prf.apply(prf_key, Uint64(epoch), Uint64(chain_index))

                # Compute the public end by hashing BASE - 1 times.
                end_digest = hasher.hash_chain(
                    parameter=parameter,
                    epoch=Uint64(epoch),
                    chain_index=chain_index,
                    start_step=0,
                    num_steps=config.BASE - 1,
                    start_digest=start_digest,
                )
                chain_ends.append(end_digest)

            # Hash the chain ends to get the leaf for this epoch.
            leaf_tweak = TreeTweak(level=0, index=Uint64(epoch))
            leaf_hash = hasher.apply(parameter, leaf_tweak, chain_ends)
            leaf_hashes.append(leaf_hash)

        # Build the bottom tree from the leaf hashes.
        return cls.new_bottom_tree(
            hasher=hasher,
            rand=rand,
            depth=config.LOG_LIFETIME,
            bottom_tree_index=bottom_tree_index,
            parameter=parameter,
            leaves=leaf_hashes,
        )

    def root(self) -> HashDigestVector:
        """
        Extracts the root digest from this subtree.

        For top-bottom tree traversal, a subtree's root is the single node
        in its highest layer.

        Returns:
            The root hash digest of the subtree.

        Raises:
            ValueError: If the subtree has no layers or the highest layer is empty.
        """
        if not self.layers:
            raise ValueError("Empty subtree has no root.")
        if not self.layers[-1].nodes:
            raise ValueError("Top layer is empty.")
        return self.layers[-1].nodes[0]

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
        if not self.layers:
            raise ValueError("Empty subtree.")

        # Check bounds.
        first = self.layers[0]
        if not (first.start_index <= position < first.start_index + Uint64(len(first.nodes))):
            raise ValueError(f"Position {position} out of bounds.")

        # Collect sibling at each layer (except root).
        siblings: list[HashDigestVector] = []
        pos = position

        # Iterate over all layers except the last (root).
        num_layers = len(self.layers)
        for i in range(num_layers - 1):
            layer = self.layers[i]
            # Sibling index: flip last bit of position, adjust for layer offset.
            sibling_idx = int((pos ^ Uint64(1)) - layer.start_index)
            if not (0 <= sibling_idx < len(layer.nodes)):
                raise ValueError(f"Sibling index {sibling_idx} out of bounds.")

            siblings.append(layer.nodes[sibling_idx])
            pos = pos // Uint64(2)  # Move to parent position.

        return HashTreeOpening(siblings=HashDigestList(data=siblings))


def combined_path(
    top_tree: HashSubTree,
    bottom_tree: HashSubTree,
    position: Uint64,
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
    # Validate matching depths.
    if top_tree.depth != bottom_tree.depth:
        raise ValueError(f"Depth mismatch: top={top_tree.depth}, bottom={bottom_tree.depth}.")

    depth = int(top_tree.depth)
    if depth % 2 != 0:
        raise ValueError(f"Depth must be even, got {depth}.")

    # Validate bottom tree matches position.
    leafs_per_tree = Uint64(1 << (depth // 2))
    expected_start = (position // leafs_per_tree) * leafs_per_tree
    if bottom_tree.layers[0].start_index != expected_start:
        raise ValueError(
            f"Wrong bottom tree: position {position} needs start {expected_start}, "
            f"got {bottom_tree.layers[0].start_index}."
        )

    # Concatenate: bottom path + top path.
    bottom_path = bottom_tree.path(position)
    top_path = top_tree.path(position // leafs_per_tree)
    combined = tuple(bottom_path.siblings.data) + tuple(top_path.siblings.data)

    return HashTreeOpening(siblings=HashDigestList(data=combined))


def verify_path(
    hasher: "TweakHasher",
    parameter: Parameter,
    root: HashDigestVector,
    position: Uint64,
    leaf_parts: list[HashDigestVector],
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
        hasher: The tweakable hash instance for computing parent nodes.
        parameter: The public parameter `P` for the hash function.
        root: The known, trusted Merkle root from the public key.
        position: The absolute index of the leaf being verified.
        leaf_parts: The list of digests that constitute the original leaf.
        opening: The `HashTreeOpening` object containing the sibling path.

    Returns:
        `True` if the path is valid and reconstructs the root, `False` otherwise.

    Raises:
        ValueError: If the tree depth exceeds 32 or position doesn't match path length.
    """
    # Compute the depth
    depth = len(opening.siblings)
    if depth > 32:
        raise ValueError("Depth exceeds maximum of 32.")
    if int(position) >= (1 << depth):
        raise ValueError("Position exceeds tree capacity.")

    # Start: hash leaf parts to get leaf node.
    current = hasher.apply(
        parameter,
        TreeTweak(level=0, index=Uint64(position)),
        leaf_parts,
    )
    pos = int(position)

    # Walk up: hash current with each sibling.
    for level, sibling in enumerate(opening.siblings):
        # Left child has even position, right child has odd.
        left, right = (current, sibling) if pos % 2 == 0 else (sibling, current)
        pos //= 2  # Parent position.
        current = hasher.apply(
            parameter,
            TreeTweak(level=level + 1, index=Uint64(pos)),
            [left, right],
        )

    # Valid if we reconstructed the expected root.
    return current == root
