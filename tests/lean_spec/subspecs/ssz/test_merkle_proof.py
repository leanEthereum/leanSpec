"""Tests for the SSZ merkle proofs."""

import os
from typing import Dict

import pytest
from typing_extensions import Any

from lean_spec.subspecs.ssz.merkle_proof.gindex import GeneralizedIndex
from lean_spec.subspecs.ssz.merkle_proof.proof import MerkleProof, ProofHashes
from lean_spec.subspecs.ssz.merkle_proof.tree import build_merkle_tree
from lean_spec.subspecs.ssz.utils import get_power_of_two_ceil
from lean_spec.types.byte_arrays import Bytes32


@pytest.fixture
def sample_tree_data() -> Dict[str, Any]:
    """Provides a pre-computed Merkle tree and its components."""
    leaves = [Bytes32(os.urandom(32)) for _ in range(11)]
    tree = build_merkle_tree(leaves)
    root = tree[1]
    bottom_layer_start_index = get_power_of_two_ceil(len(leaves))

    return {
        "leaves": leaves,
        "tree": tree,
        "root": root,
        "bottom_layer_start_index": bottom_layer_start_index,
    }


def test_merkle_proof_instantiation_valid(sample_tree_data: Dict[str, Any]) -> None:
    """Tests that a MerkleProof can be created with valid data."""
    leaf = sample_tree_data["leaves"][0]
    index = GeneralizedIndex(value=sample_tree_data["bottom_layer_start_index"])
    proof = MerkleProof(leaves=[leaf], indices=[index], proof_hashes=[])
    assert proof.leaves == [leaf]


def test_merkle_proof_instantiation_mismatched_lengths() -> None:
    """Tests that instantiation fails if leaves and indices have different lengths."""
    leaf = Bytes32(os.urandom(32))
    index1 = GeneralizedIndex(value=8)
    index2 = GeneralizedIndex(value=9)
    with pytest.raises(ValueError, match="The number of leaves must match the number of indices."):
        MerkleProof(leaves=[leaf], indices=[index1, index2], proof_hashes=[])


def test_from_single_leaf_factory(sample_tree_data: Dict[str, Any]) -> None:
    """Tests the `from_single_leaf` class method factory."""
    leaf = sample_tree_data["leaves"][0]
    index = GeneralizedIndex(value=sample_tree_data["bottom_layer_start_index"])
    proof_hashes = [Bytes32(os.urandom(32))] * index.depth

    proof = MerkleProof.from_single_leaf(leaf, proof_hashes, index)
    assert proof.leaves == [leaf]
    assert proof.indices == [index]
    assert proof.proof_hashes == proof_hashes


@pytest.mark.parametrize("leaf_index_to_test", [0, 3, 10])
def test_single_leaf_proof_verification(
    sample_tree_data: Dict[str, Any], leaf_index_to_test: int
) -> None:
    """Tests calculation and verification of a valid single-leaf proof."""
    tree = sample_tree_data["tree"]
    root = sample_tree_data["root"]
    gindex = GeneralizedIndex(
        value=sample_tree_data["bottom_layer_start_index"] + leaf_index_to_test
    )
    leaf = sample_tree_data["leaves"][leaf_index_to_test]

    branch_indices = gindex.get_branch_indices()
    proof_hashes = [tree[i.value] for i in branch_indices]

    proof = MerkleProof.from_single_leaf(leaf, proof_hashes, gindex)

    assert proof.calculate_root() == root
    assert proof.verify(root) is True
    assert proof.verify(Bytes32(os.urandom(32))) is False


def test_single_leaf_invalid_proof_length(sample_tree_data: Dict[str, Any]) -> None:
    """Tests that verification fails for a proof with an incorrect length."""
    root = sample_tree_data["root"]
    gindex = GeneralizedIndex(value=sample_tree_data["bottom_layer_start_index"] + 2)
    leaf = sample_tree_data["leaves"][2]

    # Create a proof that is too short
    proof_hashes = [Bytes32(os.urandom(32))] * (gindex.depth - 1)
    proof = MerkleProof.from_single_leaf(leaf, proof_hashes, gindex)

    assert proof.verify(root) is False
    with pytest.raises(ValueError, match="Proof length must match the depth of the index."):
        proof.calculate_root()


@pytest.mark.parametrize(
    "leaf_indices_to_test",
    [
        [2, 3],  # Siblings
        [5, 6],  # Adjacent cousins
        [0, 7],  # Distant cousins
        [1, 5, 10],  # Three distant leaves
    ],
)
def test_multi_leaf_proof_verification(
    sample_tree_data: Dict[str, Any], leaf_indices_to_test: list[int]
) -> None:
    """Tests calculation and verification of valid multi-leaf proofs."""
    tree = sample_tree_data["tree"]
    root = sample_tree_data["root"]
    leaves = [sample_tree_data["leaves"][i] for i in leaf_indices_to_test]
    indices = [
        GeneralizedIndex(value=sample_tree_data["bottom_layer_start_index"] + i)
        for i in leaf_indices_to_test
    ]

    # Create a temporary proof object just to calculate the helper indices
    temp_proof = MerkleProof(leaves=leaves, indices=indices, proof_hashes=[])
    helper_indices = temp_proof._get_helper_indices()
    proof_hashes = [tree[i.value] for i in helper_indices]

    # Create the final, valid proof object
    proof = MerkleProof(leaves=leaves, indices=indices, proof_hashes=proof_hashes)

    assert proof.calculate_root() == root
    assert proof.verify(root) is True
    assert proof.verify(Bytes32(os.urandom(32))) is False


def test_multi_leaf_invalid_proof_length(sample_tree_data: Dict[str, Any]) -> None:
    """Tests that multi-proof verification fails if the number of proof hashes is wrong."""
    root = sample_tree_data["root"]
    leaves = [sample_tree_data["leaves"][i] for i in [2, 3]]
    indices = [
        GeneralizedIndex(value=sample_tree_data["bottom_layer_start_index"] + i) for i in [2, 3]
    ]

    # Provide a proof with one too few hashes
    proof_hashes: ProofHashes = []
    proof = MerkleProof(leaves=leaves, indices=indices, proof_hashes=proof_hashes)

    assert proof.verify(root) is False
    with pytest.raises(
        ValueError, match="Proof length does not match the required number of helper nodes."
    ):
        proof.calculate_root()
