"""Tests for Store attestation handling."""

from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT
from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.block import (
    Block,
    BlockBody,
    BlockSignatures,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator, ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import SignatureKey
from lean_spec.types import Bytes32, Bytes52, Uint64
from tests.lean_spec.helpers import TEST_VALIDATOR_ID


def test_on_block_processes_multi_validator_aggregations() -> None:
    """Ensure Store.on_block handles aggregated attestations with many validators."""
    key_manager = XmssKeyManager(max_slot=Slot(10))
    validators = Validators(
        data=[
            Validator(
                pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                index=ValidatorIndex(i),
            )
            for i in range(3)
        ]
    )
    genesis_state = State.generate_genesis(genesis_time=Uint64(0), validators=validators)
    genesis_block = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    base_store = Store.get_forkchoice_store(
        genesis_state,
        genesis_block,
        validator_id=TEST_VALIDATOR_ID,
    )
    consumer_store = base_store

    # Producer view knows about attestations from validators 1 and 2
    attestation_slot = Slot(1)
    attestation_data = base_store.produce_attestation_data(attestation_slot)

    # Store attestation data in latest_known_attestations
    attestation_data_map = {
        validator_id: attestation_data for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
    }

    # Aggregate signatures manually for aggregated_payloads
    data_root = attestation_data.data_root_bytes()
    signatures_list = [
        key_manager.sign_attestation_data(vid, attestation_data)
        for vid in (ValidatorIndex(1), ValidatorIndex(2))
    ]
    participants = [ValidatorIndex(1), ValidatorIndex(2)]
    
    from lean_spec.subspecs.containers.attestation import AggregationBits
    from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof

    proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices(participants),
        public_keys=[key_manager.get_public_key(vid) for vid in participants],
        signatures=signatures_list,
        message=data_root,
        epoch=attestation_data.slot,
    )

    aggregated_payloads = {
        SignatureKey(vid, data_root): [proof] 
        for vid in participants
    }

    producer_store = base_store.model_copy(
        update={
            "latest_known_attestations": attestation_data_map,
            # No gossip signatures needed for block production now
            "aggregated_payloads": aggregated_payloads,
        }
    )

    # For slot 1 with 3 validators: 1 % 3 == 1, so validator 1 is the proposer
    proposer_index = ValidatorIndex(1)
    _, block, _ = producer_store.produce_block_with_signatures(
        attestation_slot,
        proposer_index,
    )

    block_root = hash_tree_root(block)
    parent_state = producer_store.states[block.parent_root]
    proposer_attestation = Attestation(
        validator_id=proposer_index,
        data=AttestationData(
            slot=attestation_slot,
            head=Checkpoint(root=block_root, slot=attestation_slot),
            target=Checkpoint(root=block_root, slot=attestation_slot),
            source=Checkpoint(root=block.parent_root, slot=parent_state.latest_block_header.slot),
        ),
    )
    proposer_signature = key_manager.sign_attestation_data(
        proposer_attestation.validator_id,
        proposer_attestation.data,
    )

    attestation_signatures = key_manager.build_attestation_signatures(block.body.attestations)

    signed_block = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=block,
            proposer_attestation=proposer_attestation,
        ),
        signature=BlockSignatures(
            attestation_signatures=attestation_signatures,
            proposer_signature=proposer_signature,
        ),
    )

    # Advance consumer store time to block's slot before processing
    block_time = consumer_store.config.genesis_time + block.slot * Uint64(SECONDS_PER_SLOT)
    consumer_store = consumer_store.on_tick(block_time, has_proposal=True)

    updated_store = consumer_store.on_block(signed_block)

    assert ValidatorIndex(1) in updated_store.latest_known_attestations
    assert ValidatorIndex(2) in updated_store.latest_known_attestations
    assert updated_store.latest_known_attestations[ValidatorIndex(1)] == attestation_data
    assert updated_store.latest_known_attestations[ValidatorIndex(2)] == attestation_data


def test_on_block_preserves_immutability_of_aggregated_payloads() -> None:
    """Verify that Store.on_block doesn't mutate previous store's aggregated_payloads."""
    key_manager = XmssKeyManager(max_slot=Slot(10))
    validators = Validators(
        data=[
            Validator(
                pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                index=ValidatorIndex(i),
            )
            for i in range(3)
        ]
    )
    genesis_state = State.generate_genesis(genesis_time=Uint64(0), validators=validators)
    genesis_block = Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    base_store = Store.get_forkchoice_store(
        genesis_state,
        genesis_block,
        validator_id=TEST_VALIDATOR_ID,
    )

    # First block: create and process a block with attestations to populate
    # `aggregated_payloads`.
    attestation_slot_1 = Slot(1)
    attestation_data_1 = base_store.produce_attestation_data(attestation_slot_1)
    data_root_1 = attestation_data_1.data_root_bytes()

    attestation_data_map_1 = {
        validator_id: attestation_data_1 for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
    }
    gossip_sigs_1 = {
        SignatureKey(validator_id, data_root_1): key_manager.sign_attestation_data(
            validator_id, attestation_data_1
        )
        for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
    }

    producer_store_1 = base_store.model_copy(
        update={
            "latest_known_attestations": attestation_data_map_1,
            "gossip_signatures": gossip_sigs_1,
        }
    )

    proposer_index_1 = ValidatorIndex(1)
    _, block_1, _ = producer_store_1.produce_block_with_signatures(
        attestation_slot_1,
        proposer_index_1,
    )

    block_root_1 = hash_tree_root(block_1)
    parent_state_1 = producer_store_1.states[block_1.parent_root]
    proposer_attestation_1 = Attestation(
        validator_id=proposer_index_1,
        data=AttestationData(
            slot=attestation_slot_1,
            head=Checkpoint(root=block_root_1, slot=attestation_slot_1),
            target=Checkpoint(root=block_root_1, slot=attestation_slot_1),
            source=Checkpoint(
                root=block_1.parent_root,
                slot=parent_state_1.latest_block_header.slot,
            ),
        ),
    )
    proposer_signature_1 = key_manager.sign_attestation_data(
        proposer_attestation_1.validator_id,
        proposer_attestation_1.data,
    )

    attestation_signatures_1 = key_manager.build_attestation_signatures(block_1.body.attestations)

    signed_block_1 = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=block_1,
            proposer_attestation=proposer_attestation_1,
        ),
        signature=BlockSignatures(
            attestation_signatures=attestation_signatures_1,
            proposer_signature=proposer_signature_1,
        ),
    )

    # Process first block
    block_time_1 = base_store.config.genesis_time + block_1.slot * Uint64(SECONDS_PER_SLOT)
    consumer_store = base_store.on_tick(block_time_1, has_proposal=True)
    store_after_block_1 = consumer_store.on_block(signed_block_1)

    # Now process a second block that includes attestations for the SAME validators
    # This tests the case where we append to existing lists in aggregated_payloads
    attestation_slot_2 = Slot(2)
    attestation_data_2 = store_after_block_1.produce_attestation_data(attestation_slot_2)
    data_root_2 = attestation_data_2.data_root_bytes()

    attestation_data_map_2 = {
        validator_id: attestation_data_2 for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
    }
    gossip_sigs_2 = {
        SignatureKey(validator_id, data_root_2): key_manager.sign_attestation_data(
            validator_id, attestation_data_2
        )
        for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
    }

    producer_store_2 = store_after_block_1.model_copy(
        update={
            "latest_known_attestations": attestation_data_map_2,
            "gossip_signatures": gossip_sigs_2,
        }
    )

    proposer_index_2 = ValidatorIndex(2)
    _, block_2, _ = producer_store_2.produce_block_with_signatures(
        attestation_slot_2,
        proposer_index_2,
    )

    block_root_2 = hash_tree_root(block_2)
    parent_state_2 = producer_store_2.states[block_2.parent_root]
    proposer_attestation_2 = Attestation(
        validator_id=proposer_index_2,
        data=AttestationData(
            slot=attestation_slot_2,
            head=Checkpoint(root=block_root_2, slot=attestation_slot_2),
            target=Checkpoint(root=block_root_2, slot=attestation_slot_2),
            source=Checkpoint(
                root=block_2.parent_root,
                slot=parent_state_2.latest_block_header.slot,
            ),
        ),
    )
    proposer_signature_2 = key_manager.sign_attestation_data(
        proposer_attestation_2.validator_id,
        proposer_attestation_2.data,
    )

    attestation_signatures_2 = key_manager.build_attestation_signatures(block_2.body.attestations)

    signed_block_2 = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=block_2,
            proposer_attestation=proposer_attestation_2,
        ),
        signature=BlockSignatures(
            attestation_signatures=attestation_signatures_2,
            proposer_signature=proposer_signature_2,
        ),
    )

    # Advance time and capture state before processing second block
    block_time_2 = store_after_block_1.config.genesis_time + block_2.slot * Uint64(SECONDS_PER_SLOT)
    store_before_block_2 = store_after_block_1.on_tick(block_time_2, has_proposal=True)

    # Capture the original list lengths for keys that already exist
    original_sig_lengths = {k: len(v) for k, v in store_before_block_2.aggregated_payloads.items()}

    # Process the second block
    store_after_block_2 = store_before_block_2.on_block(signed_block_2)

    # Verify immutability: the list lengths in store_before_block_2 should not have changed
    for key, original_length in original_sig_lengths.items():
        current_length = len(store_before_block_2.aggregated_payloads[key])
        assert current_length == original_length, (
            f"Immutability violated: list for key {key} grew from {original_length} to "
            f"{current_length}"
        )

    # Verify that the updated store has new keys (different attestation data in block 2)
    # The key point is that store_before_block_2 wasn't mutated
    assert len(store_after_block_2.aggregated_payloads) >= len(
        store_before_block_2.aggregated_payloads
    )
