"""Tests for Store.compute_block_weights."""

from __future__ import annotations

from lean_spec.subspecs.containers.attestation import AggregationBits, AttestationData
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, SignatureKey
from lean_spec.types.byte_arrays import ByteListMiB
from tests.lean_spec.helpers import make_bytes32, make_signed_block


def _make_empty_proof(participants: list[ValidatorIndex]) -> AggregatedSignatureProof:
    """Create an aggregated proof with empty proof data for testing."""
    return AggregatedSignatureProof(
        participants=AggregationBits.from_validator_indices(ValidatorIndices(data=participants)),
        proof_data=ByteListMiB(data=b""),
    )


def test_genesis_only_store_returns_empty_weights(base_store: Store) -> None:
    """A genesis-only store with no attestations has no block weights."""
    assert base_store.compute_block_weights() == {}


def test_linear_chain_weight_accumulates_upward(base_store: Store) -> None:
    """Weights walk up from the attested head through all ancestors above finalized slot."""
    genesis_root = base_store.head

    block1 = make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=genesis_root,
        state_root=make_bytes32(10),
    )
    block1_root = hash_tree_root(block1.message.block)

    block2 = make_signed_block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(1),
        parent_root=block1_root,
        state_root=make_bytes32(20),
    )
    block2_root = hash_tree_root(block2.message.block)

    new_blocks = dict(base_store.blocks)
    new_blocks[block1_root] = block1.message.block
    new_blocks[block2_root] = block2.message.block

    new_states = dict(base_store.states)
    genesis_state = base_store.states[genesis_root]
    new_states[block1_root] = genesis_state
    new_states[block2_root] = genesis_state

    att_data = AttestationData(
        slot=Slot(2),
        head=Checkpoint(root=block2_root, slot=Slot(2)),
        target=Checkpoint(root=block2_root, slot=Slot(2)),
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )
    data_root = att_data.data_root_bytes()

    proof = _make_empty_proof([ValidatorIndex(0)])
    aggregated_payloads = {
        SignatureKey(ValidatorIndex(0), data_root): [proof],
    }

    store = base_store.model_copy(
        update={
            "blocks": new_blocks,
            "states": new_states,
            "head": block2_root,
            "latest_known_aggregated_payloads": aggregated_payloads,
            "attestation_data_by_root": {data_root: att_data},
        }
    )

    weights = store.compute_block_weights()

    # Validator 0 attests to block2 as head.
    # Walking up: block2 (slot 2 > 0) gets +1, block1 (slot 1 > 0) gets +1.
    # Genesis (slot 0) is at finalized_slot so it does NOT get weight.
    assert weights == {block2_root: 1, block1_root: 1}


def test_multiple_attestations_accumulate(base_store: Store) -> None:
    """Multiple validators attesting to the same head accumulate weight."""
    genesis_root = base_store.head

    block1 = make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=genesis_root,
        state_root=make_bytes32(10),
    )
    block1_root = hash_tree_root(block1.message.block)

    new_blocks = dict(base_store.blocks)
    new_blocks[block1_root] = block1.message.block

    new_states = dict(base_store.states)
    new_states[block1_root] = base_store.states[genesis_root]

    att_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=block1_root, slot=Slot(1)),
        target=Checkpoint(root=block1_root, slot=Slot(1)),
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )
    data_root = att_data.data_root_bytes()

    proof = _make_empty_proof([ValidatorIndex(0), ValidatorIndex(1)])
    aggregated_payloads = {
        SignatureKey(ValidatorIndex(0), data_root): [proof],
        SignatureKey(ValidatorIndex(1), data_root): [proof],
    }

    store = base_store.model_copy(
        update={
            "blocks": new_blocks,
            "states": new_states,
            "head": block1_root,
            "latest_known_aggregated_payloads": aggregated_payloads,
            "attestation_data_by_root": {data_root: att_data},
        }
    )

    weights = store.compute_block_weights()

    # Both validators contribute weight to block1
    assert weights == {block1_root: 2}
