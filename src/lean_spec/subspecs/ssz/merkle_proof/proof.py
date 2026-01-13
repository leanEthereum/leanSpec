"""Merkle proofs for SSZ."""

from __future__ import annotations

from typing import Sequence

from pydantic import Field, model_validator

from lean_spec.types import ZERO_HASH, StrictBaseModel
from lean_spec.types.byte_arrays import Bytes32

from ..utils import hash_nodes
from .gindex import GeneralizedIndex

Root = Bytes32
"""The type of a Merkle tree root."""
Proof = Sequence[Bytes32]
"""The type of a Merkle proof."""
ProofHashes = Sequence[Bytes32]
"""The type of a Merkle proof's helper nodes."""


class MerkleProof(StrictBaseModel):
    """
    Represents a Merkle multiproof, encapsulating its data and verification logic.

    This object is immutable; once created, its contents cannot be changed.
    """

    leaves: Sequence[Bytes32] = Field(..., description="The leaf data being proven.")

    indices: Sequence[GeneralizedIndex] = Field(
        ..., description="The generalized indices of the leaves."
    )

    proof_hashes: ProofHashes = Field(..., description="The helper nodes required for the proof.")

    @model_validator(mode="after")
    def check_leaves_and_indices_length(self) -> MerkleProof:
        """Ensures the number of leaves matches the number of indices."""
        if len(self.leaves) != len(self.indices):
            raise ValueError("The number of leaves must match the number of indices.")
        return self

    @classmethod
    def from_single_leaf(
        cls, leaf: Bytes32, proof_hashes: ProofHashes, index: GeneralizedIndex
    ) -> MerkleProof:
        """Creates a MerkleProof object from a traditional single-item proof."""
        return cls(leaves=[leaf], proof_hashes=proof_hashes, indices=[index])

    def _get_helper_indices(self) -> list[GeneralizedIndex]:
        """
        Calculates the generalized indices of all "helper" nodes needed to prove the leaves.

        This is an internal helper method.
        """
        all_helper_indices: set[GeneralizedIndex] = set()
        all_path_indices: set[GeneralizedIndex] = set()

        for index in self.indices:
            all_helper_indices.update(index.get_branch_indices())
            all_path_indices.update(index.get_path_indices())

        return sorted(all_helper_indices - all_path_indices, key=lambda g: g.value, reverse=True)

    def calculate_root(self) -> Root:
        """
        Calculates the Merkle root from the proof's leaves and helper nodes.

        Handles both single and multi-leaf proofs seamlessly.
        """
        # For a single leaf proof, use the more direct calculation.
        if len(self.indices) == 1:
            index = self.indices[0]
            leaf = self.leaves[0]
            if len(self.proof_hashes) != index.depth:
                raise ValueError("Proof length must match the depth of the index.")

            root = leaf
            for i, branch_node in enumerate(self.proof_hashes):
                if index.get_bit(i):
                    root = hash_nodes(branch_node, root)
                else:
                    root = hash_nodes(root, branch_node)
            return root

        # For multi-leaf proofs, perform tree reconstruction.
        helper_indices = self._get_helper_indices()
        if len(self.proof_hashes) != len(helper_indices):
            raise ValueError("Proof length does not match the required number of helper nodes.")

        # 1. Start with the known nodes (leaves and proof hashes).
        tree: dict[int, Bytes32] = {
            **{index.value: node for index, node in zip(self.indices, self.leaves, strict=False)},
            **{
                index.value: node
                for index, node in zip(helper_indices, self.proof_hashes, strict=False)
            },
        }

        # 2. Process nodes from deepest to shallowest.
        #    The list of keys will grow as we create new parent nodes.
        keys = sorted(tree.keys(), reverse=True)
        pos = 0
        while pos < len(keys):
            key = keys[pos]
            sibling_key = key ^ 1

            # 3. If a node's sibling is also in the tree, we can create their parent.
            if sibling_key in tree:
                parent_key = key // 2

                # Ensure we don't re-calculate a parent we already have.
                if parent_key not in tree:
                    # The order of hashing depends on which key is smaller.
                    if key < sibling_key:
                        tree[parent_key] = hash_nodes(tree[key], tree[sibling_key])
                    else:
                        tree[parent_key] = hash_nodes(tree[sibling_key], tree[key])
                    keys.append(parent_key)
            pos += 1

        # 4. After processing all nodes, the root must be at index 1.
        if 1 not in tree:
            # This can happen if the proof is incomplete or for an empty leaf set.
            return ZERO_HASH

        return tree[1]

    def verify(self, root: Root) -> bool:
        """Verifies the Merkle proof against a known root."""
        try:
            return self.calculate_root() == root
        except ValueError:
            return False
