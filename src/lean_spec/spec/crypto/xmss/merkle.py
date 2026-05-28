r"""
Sparse Merkle subtrees for the top-bottom traversal of an XMSS key.

# Overview

The long-lived public key of an XMSS signature is the root of one Merkle tree.
That tree commits to one one-time public key per slot of the key's lifetime.
A signature opens the leaf for its slot with a path of sibling hashes up to the root.

A full lifetime tree has one leaf per slot.
For a lifetime of 2^32 slots, holding every node in memory is infeasible.

# The top-bottom split

The tree is cut into one top tree sitting above many bottom trees.
Each bottom tree covers a contiguous run of leaves, the square root of the lifetime of them.
There are that many bottom trees, and their roots are exactly the leaves of the top tree.

The signer keeps the whole top tree resident, plus the bottom trees around the active slot.
As the active slot advances, stale bottom trees are dropped and fresh ones regenerated on demand.
Resident memory stays near the square root of the lifetime instead of the full lifetime.

# Sparse layers

Only a window of leaves is resident, so a stored layer holds a contiguous slice, not a full level.
Each layer records the absolute index of its first node, keeping positions in full-tree coordinates.
"""

from itertools import batched
from typing import Self

from lean_spec.spec.ssz import Uint64
from lean_spec.spec.ssz.collections import SSZList
from lean_spec.spec.ssz.container import Container

from .constants import TARGET_CONFIG, XmssConfig
from .field import random_domain
from .poseidon import PoseidonXmss
from .prf import PRFKey
from .types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    TreeTweak,
)


class HashTreeLayer(Container):
    """
    A single horizontal slice of a sparse Merkle subtree.

    The tree is sparse, so a layer stores only the nodes computed for the active leaf range.
    """

    start_index: Uint64
    """Absolute index of the first stored node within its level."""

    nodes: HashDigestList
    """Stored hash digests for this layer, ordered left to right."""

    @classmethod
    def padded(
        cls,
        config: XmssConfig,
        nodes: list[HashDigestVector],
        start_index: Uint64,
    ) -> Self:
        """
        Build a layer whose nodes can all be paired at the next level up.

        # Why pad

        The level above pairs nodes two at a time, then hashes each pair.
        - A run starting on an odd index lacks a left neighbor for its first node.
        - A run ending on an even index lacks a right neighbor for its last node.

        Padding either gap with a fresh random digest lets every node pair.

        # Invariant

        The result starts on an even index and ends on an odd index.
        A single-node layer is the sole exception, since it is a subtree root.

        # Layout

            indices 5, 6, 7   ->   [pad]  5  6  7      starts 4, ends 7
            indices 4, 5, 6   ->    4  5  6  [pad]     starts 4, ends 7

        Args:
            config: Active XMSS configuration.
            nodes: Active nodes at this layer, in ascending index order.
            start_index: Absolute index of the first active node.

        Returns:
            A layer satisfying the alignment invariant above.
        """
        nodes_with_padding: list[HashDigestVector] = []
        end_index = start_index + Uint64(len(nodes)) - Uint64(1)

        # Prepend one random sibling when the layer begins on an odd index.
        if start_index % Uint64(2) == Uint64(1):
            nodes_with_padding.append(random_domain(config))

        # The padded layer always starts on the even index at or before start_index.
        actual_start_index = start_index - (start_index % Uint64(2))

        nodes_with_padding.extend(nodes)

        # Append one random sibling when the layer ends on an even index.
        if end_index % Uint64(2) == Uint64(0):
            nodes_with_padding.append(random_domain(config))

        return cls(
            start_index=actual_start_index,
            nodes=HashDigestList(data=nodes_with_padding),
        )


class HashTreeLayers(SSZList[HashTreeLayer]):
    """
    The layers of a subtree, ordered from the lowest layer up to the root.

    A bottom tree and a top tree each cover half the depth.
    The cap admits the full lifetime tree.
    """

    LIMIT = TARGET_CONFIG.LOG_LIFETIME + 1
    """Layers run from level zero, the leaves, up to the lifetime depth, the root, inclusive."""


class HashSubTree(Container):
    """
    A contiguous slice of an XMSS lifetime tree, stored layer by layer.

    # Overview

    A subtree holds every node from its lowest layer up to a single root node.
    Two shapes exist, told apart by where the lowest layer sits.

    - A bottom tree starts at layer zero and covers a window of leaves.
    - A top tree starts at the split layer and covers the bottom-tree roots.

    # Invariant

    Every stored layer starts on an even index and ends on an odd index.
    The exception is the top layer, which holds the single subtree root.
    """

    depth: Uint64
    """Depth of the full lifetime tree this subtree belongs to.

    A subtree starting at layer k stores depth - k layers.
    """

    lowest_layer: Uint64
    """Lowest layer included in this subtree:
    - Zero for bottom trees,
    - LOG_LIFETIME/2 for top trees.
    """

    layers: HashTreeLayers
    """Layers stored from lowest_layer up to the subtree root.

    The last entry holds a single node, the subtree root.
    """

    @classmethod
    def new(
        cls,
        poseidon: PoseidonXmss,
        config: XmssConfig,
        lowest_layer: Uint64,
        depth: Uint64,
        start_index: Uint64,
        parameter: Parameter,
        lowest_layer_nodes: list[HashDigestVector],
        highest_layer: Uint64 | None = None,
    ) -> Self:
        """
        Build a subtree from its lowest layer up to a bounding layer.

        # Overview

        Each layer is hashed pairwise into the layer above, climbing one level per step.
        Padding keeps every intermediate layer aligned so sibling pairs form cleanly.
        Building stops at the bounding layer, which defaults to the global root.

        Args:
            poseidon: Cached Poseidon engine.
            config: Active XMSS configuration.
            lowest_layer: Starting layer for this subtree.
            depth: Total depth of the full lifetime tree.
            start_index: Absolute index of the first input node.
            parameter: Public parameter for the hash function.
            lowest_layer_nodes: Active nodes at the lowest layer.
            highest_layer: Layer to stop building at, defaulting to the full depth.

        Returns:
            A subtree holding every layer from the lowest layer up to the bounding layer.

        Raises:
            ValueError: When the input nodes do not fit the level they start in.
        """
        # Build to the global root unless a lower bounding layer is requested.
        highest_layer = depth if highest_layer is None else highest_layer

        # The input nodes must fit in the layer they belong to.
        max_positions = 1 << int(depth - lowest_layer)
        if int(start_index) + len(lowest_layer_nodes) > max_positions:
            raise ValueError(
                f"Overflow at layer {lowest_layer}: "
                f"start={start_index}, count={len(lowest_layer_nodes)}, max={max_positions}"
            )

        # Phase 1: pad the input layer.
        layers: list[HashTreeLayer] = []
        current = HashTreeLayer.padded(config, lowest_layer_nodes, start_index)
        layers.append(current)

        # Phases 2 + 3: hash sibling pairs, pad, repeat.
        for level in range(lowest_layer, highest_layer):
            parent_start = current.start_index // Uint64(2)
            parents = [
                poseidon.tweak_hash(
                    config,
                    parameter,
                    TreeTweak(level=level + 1, index=parent_start + Uint64(i)),
                    [left, right],
                )
                for i, (left, right) in enumerate(batched(current.nodes, 2))
            ]
            current = HashTreeLayer.padded(config, parents, parent_start)
            layers.append(current)

        return cls(
            depth=depth,
            lowest_layer=lowest_layer,
            layers=HashTreeLayers(data=layers),
        )

    @classmethod
    def new_top_tree(
        cls,
        poseidon: PoseidonXmss,
        config: XmssConfig,
        depth: int,
        start_bottom_tree_index: Uint64,
        parameter: Parameter,
        bottom_tree_roots: list[HashDigestVector],
    ) -> Self:
        """Build the top tree from bottom-tree roots up to the global root.

        The top tree starts at layer depth/2 and treats bottom-tree roots as its leaves.

        Args:
            poseidon: Cached Poseidon engine.
            config: Active XMSS configuration.
            depth: Total depth of the full lifetime tree.
            start_bottom_tree_index: Index of the first bottom tree in the range.
            parameter: Public parameter for the hash function.
            bottom_tree_roots: Roots of all bottom trees in the range, in order.

        Returns:
            A top tree whose root is the global Merkle root.

        Raises:
            ValueError: When depth is odd.
        """
        # Top-bottom split requires an even depth.
        if depth % 2 != 0:
            raise ValueError(f"Depth must be even for top-bottom split, got {depth}.")

        return cls.new(
            poseidon=poseidon,
            config=config,
            lowest_layer=Uint64(depth // 2),
            depth=Uint64(depth),
            start_index=start_bottom_tree_index,
            parameter=parameter,
            lowest_layer_nodes=bottom_tree_roots,
        )

    @classmethod
    def new_bottom_tree(
        cls,
        poseidon: PoseidonXmss,
        config: XmssConfig,
        depth: int,
        bottom_tree_index: Uint64,
        parameter: Parameter,
        leaves: list[HashDigestVector],
    ) -> Self:
        """
        Build one bottom tree from its leaf hashes up to its standalone root.

        # Overview

        A bottom tree spans the lower half of the lifetime tree for one window of slots.
        Its root is later placed as a single leaf of the top tree.

        Args:
            poseidon: Cached Poseidon engine.
            config: Active XMSS configuration.
            depth: Total depth of the full lifetime tree.
            bottom_tree_index: Index of this bottom tree.
            parameter: Public parameter for the hash function.
            leaves: Pre-hashed one-time public keys for this bottom tree's slots.

        Returns:
            A subtree spanning the lower half of the tree, ending in the bottom-tree root.

        Raises:
            ValueError: When the depth is odd, or the leaf count is not the square
                root of the lifetime.
        """
        if depth % 2 != 0:
            raise ValueError(f"Depth must be even for top-bottom split, got {depth}.")

        # Each bottom tree spans exactly sqrt(LIFETIME) leaves.
        leaves_per_tree = 1 << (depth // 2)
        if len(leaves) != leaves_per_tree:
            raise ValueError(
                f"Expected {leaves_per_tree} leaves for depth={depth}, got {len(leaves)}."
            )

        # Phase 1: build only layers 0 through depth/2, the bottom tree's own height.
        subtree = cls.new(
            poseidon=poseidon,
            config=config,
            lowest_layer=Uint64(0),
            depth=Uint64(depth),
            start_index=bottom_tree_index * Uint64(leaves_per_tree),
            parameter=parameter,
            lowest_layer_nodes=leaves,
            highest_layer=Uint64(depth // 2),
        )

        # Phase 2: the top built layer is padded to a sibling pair.
        # The real root is the node at this tree's index, not always position zero.
        # An odd index leaves a random pad at position zero, so select by absolute index.
        top = subtree.layers[-1]
        root_idx = int(bottom_tree_index - top.start_index)
        root_layer = HashTreeLayer(
            start_index=bottom_tree_index,
            nodes=HashDigestList(data=[top.nodes[root_idx]]),
        )
        return cls(
            depth=Uint64(depth),
            lowest_layer=Uint64(0),
            layers=HashTreeLayers(data=list(subtree.layers[:-1]) + [root_layer]),
        )

    @classmethod
    def from_prf_key(
        cls,
        poseidon: PoseidonXmss,
        config: XmssConfig,
        prf_key: PRFKey,
        bottom_tree_index: Uint64,
        parameter: Parameter,
    ) -> Self:
        """
        Regenerate one bottom tree on demand from the master secret seed.

        # Overview

        The secret key is not stored slot by slot.
        One short master seed deterministically expands into every chain start.
        This lets the signer keep only a sliding window resident and rebuild the rest on demand.

        # What a leaf is

        Each slot owns one one-time signature made of many independent hash chains.
        Walking a chain from its secret start to its far end yields one public chain end.
        Hashing all of a slot's chain ends together produces the leaf committed at that slot.

        Args:
            poseidon: Cached Poseidon engine.
            config: Active XMSS configuration.
            prf_key: Master secret seed.
            bottom_tree_index: Index of the bottom tree to regenerate.
            parameter: Public parameter for the hash function.

        Returns:
            The requested bottom tree.
        """
        # Each bottom tree covers sqrt(LIFETIME) consecutive epochs.
        leaves_per_bottom_tree = config.LEAVES_PER_BOTTOM_TREE
        start_epoch = bottom_tree_index * Uint64(leaves_per_bottom_tree)
        end_epoch = start_epoch + Uint64(leaves_per_bottom_tree)

        leaf_hashes: list[HashDigestVector] = []
        for epoch in range(start_epoch, end_epoch):
            # Derive each chain start from the seed, then walk it to its public end.
            # The far end is the chain start hashed forward the full length minus one.
            chain_ends: list[HashDigestVector] = []
            for chain_index in range(config.DIMENSION):
                start_digest = prf_key.derive_chain_start(
                    config, Uint64(epoch), Uint64(chain_index)
                )
                end_digest = poseidon.hash_chain(
                    config=config,
                    parameter=parameter,
                    epoch=Uint64(epoch),
                    chain_index=chain_index,
                    start_step=0,
                    num_steps=config.BASE - 1,
                    start_digest=start_digest,
                )
                chain_ends.append(end_digest)

            # The leaf for this slot is the hash of all its chain ends together.
            leaf_tweak = TreeTweak(level=0, index=Uint64(epoch))
            leaf_hash = poseidon.tweak_hash(config, parameter, leaf_tweak, chain_ends)
            leaf_hashes.append(leaf_hash)

        return cls.new_bottom_tree(
            poseidon=poseidon,
            config=config,
            depth=config.LOG_LIFETIME,
            bottom_tree_index=bottom_tree_index,
            parameter=parameter,
            leaves=leaf_hashes,
        )

    def root(self) -> HashDigestVector:
        """Return the single node in the highest stored layer.

        Raises:
            ValueError: When the subtree is empty or the highest layer has no nodes.
        """
        if not self.layers:
            raise ValueError("Empty subtree has no root.")
        if not self.layers[-1].nodes:
            raise ValueError("Top layer is empty.")
        return self.layers[-1].nodes[0]

    def path(self, position: Uint64) -> HashTreeOpening:
        """
        Collect the sibling hashes that connect one leaf to the subtree root.

        # Overview

        At each level the node has exactly one sibling, the node sharing its parent.
        That sibling sits at the current position with its lowest bit flipped.
        Recording one sibling per level, then halving the position to climb, yields the full path.
        The root has no sibling, so the walk stops one level below it.

        # Layout

            climbing from leaf position 5 in a three-level subtree:

                position 5  ->  sibling 4   (flip low bit),  then halve to 2
                position 2  ->  sibling 3   (flip low bit),  then halve to 1
                position 1  ->  root, no sibling, stop

        Args:
            position: Absolute index of the leaf in full-tree coordinates.

        Returns:
            An opening of sibling hashes ordered from the leaf upward.

        Raises:
            ValueError: When the subtree is empty or the position is out of bounds.
        """
        if not self.layers:
            raise ValueError("Empty subtree.")

        first = self.layers[0]
        if not (first.start_index <= position < first.start_index + Uint64(len(first.nodes))):
            raise ValueError(f"Position {position} out of bounds.")

        siblings: list[HashDigestVector] = []
        pos = int(position)

        # Stop one short of the root layer.
        # The root has no sibling.
        for layer in self.layers[:-1]:
            # The sibling sits at the position with the last bit flipped, then we
            # rebase by the layer's start_index because the layer is sparse.
            sibling_idx = (pos ^ 1) - int(layer.start_index)
            if not (0 <= sibling_idx < len(layer.nodes)):
                raise ValueError(f"Sibling index {sibling_idx} out of bounds.")
            siblings.append(layer.nodes[sibling_idx])
            pos //= 2

        return HashTreeOpening(siblings=HashDigestList(data=siblings))


def combined_path(
    top_tree: HashSubTree,
    bottom_tree: HashSubTree,
    position: Uint64,
) -> HashTreeOpening:
    """
    Stitch a bottom-tree opening and a top-tree opening into one full path.

    # Overview

    A signature authenticates its leaf all the way up to the global root.
    No single resident subtree spans that whole distance, so two openings are joined.

    # Proof flow

        bottom opening : proves the leaf sits under its bottom-tree root.
        top opening    : proves that bottom-tree root sits under the global root.

    Args:
        top_tree: The top tree containing the global root.
        bottom_tree: The bottom tree containing the leaf.
        position: Absolute index of the leaf.

    Returns:
        One opening that authenticates the leaf against the global root.

    Raises:
        ValueError: When the tree depths disagree, the depth is odd, or the position
            does not belong to the supplied bottom tree.
    """
    if top_tree.depth != bottom_tree.depth:
        raise ValueError(f"Depth mismatch: top={top_tree.depth}, bottom={bottom_tree.depth}.")

    depth = int(top_tree.depth)
    if depth % 2 != 0:
        raise ValueError(f"Depth must be even, got {depth}.")

    # The position must belong to the supplied bottom tree, not a sibling one.
    leaves_per_tree = Uint64(1 << (depth // 2))
    expected_start = (position // leaves_per_tree) * leaves_per_tree
    if bottom_tree.layers[0].start_index != expected_start:
        raise ValueError(
            f"Wrong bottom tree: position {position} needs start {expected_start}, "
            f"got {bottom_tree.layers[0].start_index}."
        )

    # The opening climbs from leaf to root, so bottom siblings come before top siblings.
    bottom_path = bottom_tree.path(position)
    top_path = top_tree.path(position // leaves_per_tree)
    combined = tuple(bottom_path.siblings.data) + tuple(top_path.siblings.data)

    return HashTreeOpening(siblings=HashDigestList(data=combined))


def verify_path(
    poseidon: PoseidonXmss,
    config: XmssConfig,
    parameter: Parameter,
    root: HashDigestVector,
    position: Uint64,
    leaf_parts: list[HashDigestVector],
    opening: HashTreeOpening,
) -> bool:
    """
    Recompute a root from a leaf and its opening, then compare against a trusted root.

    # Overview

    Verification mirrors construction in reverse.
    The leaf is hashed, then folded with each sibling while climbing one level per step.
    The walk succeeds when the recomputed root equals the trusted root.

    # Why return false instead of raising

    The opening arrives inside an untrusted signature.
    A malformed opening must be a quiet verification failure, never a crash.
    So out-of-range input returns false rather than raising.

    Args:
        poseidon: Cached Poseidon engine.
        config: Active XMSS configuration.
        parameter: Public parameter for the hash function.
        root: Trusted root taken from the public key.
        position: Absolute index of the leaf being verified.
        leaf_parts: Digests that constitute the original leaf.
        opening: Sibling path from leaf to root.

    Returns:
        True when the path reconstructs the trusted root, false otherwise.
    """
    # Guard against malformed openings.
    # The opening list caps at 32 entries.
    # A depth greater than 32 would overflow the position bound check below.
    depth = len(opening.siblings)
    if depth > 32:
        return False
    if int(position) >= (1 << depth):
        return False

    # Phase 1: hash the leaf parts to derive the starting node.
    current = poseidon.tweak_hash(
        config,
        parameter,
        TreeTweak(level=0, index=Uint64(position)),
        leaf_parts,
    )
    pos = int(position)

    # Phase 2: hash with each sibling, climbing one layer per iteration.
    for level, sibling in enumerate(opening.siblings):
        # The current node sits on the left when its position is even.
        left, right = (current, sibling) if pos % 2 == 0 else (sibling, current)
        pos //= 2
        current = poseidon.tweak_hash(
            config,
            parameter,
            TreeTweak(level=level + 1, index=Uint64(pos)),
            [left, right],
        )

    # Phase 3: compare against the trusted root.
    return current == root
