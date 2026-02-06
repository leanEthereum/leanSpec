"""Tests for Store attestation handling."""

from __future__ import annotations

from unittest import mock

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT, SECONDS_PER_SLOT
from lean_spec.subspecs.containers.attestation import (
    AggregationBits,
    Attestation,
    AttestationData,
    SignedAggregatedAttestation,
    SignedAttestation,
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
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, SignatureKey
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

    # Aggregate signatures manually for aggregated_payloads
    data_root = attestation_data.data_root_bytes()
    signatures_list = [
        key_manager.sign_attestation_data(vid, attestation_data)
        for vid in (ValidatorIndex(1), ValidatorIndex(2))
    ]
    participants = [ValidatorIndex(1), ValidatorIndex(2)]

    proof = AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices(participants),
        public_keys=[key_manager.get_public_key(vid) for vid in participants],
        signatures=signatures_list,
        message=data_root,
        epoch=attestation_data.slot,
    )

    aggregated_payloads = {SignatureKey(vid, data_root): [proof] for vid in participants}

    producer_store = base_store.model_copy(
        update={
            # Store attestation data for later extraction
            "attestation_data_by_root": {data_root: attestation_data},
            # No gossip signatures needed for block production now
            "latest_known_aggregated_payloads": aggregated_payloads,
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
    slot_duration_seconds = block.slot * SECONDS_PER_SLOT
    block_time = consumer_store.config.genesis_time + slot_duration_seconds
    consumer_store = consumer_store.on_tick(block_time, has_proposal=True)

    updated_store = consumer_store.on_block(signed_block)

    # Verify attestations can be extracted from aggregated payloads
    extracted_attestations = updated_store._extract_attestations_from_aggregated_payloads(
        updated_store.latest_known_aggregated_payloads
    )
    assert ValidatorIndex(1) in extracted_attestations
    assert ValidatorIndex(2) in extracted_attestations
    assert extracted_attestations[ValidatorIndex(1)] == attestation_data
    assert extracted_attestations[ValidatorIndex(2)] == attestation_data


def test_on_block_preserves_immutability_of_aggregated_payloads() -> None:
    """Verify that Store.on_block doesn't mutate previous store's latest_new_aggregated_payloads."""
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
    # `latest_new_aggregated_payloads`.
    attestation_slot_1 = Slot(1)
    attestation_data_1 = base_store.produce_attestation_data(attestation_slot_1)
    data_root_1 = attestation_data_1.data_root_bytes()

    attestation_data_map_1 = {data_root_1: attestation_data_1}
    gossip_sigs_1 = {
        SignatureKey(validator_id, data_root_1): key_manager.sign_attestation_data(
            validator_id, attestation_data_1
        )
        for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
    }

    producer_store_1 = base_store.model_copy(
        update={
            "attestation_data_by_root": attestation_data_map_1,
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
    slot_duration_seconds_1 = block_1.slot * SECONDS_PER_SLOT
    block_time_1 = base_store.config.genesis_time + slot_duration_seconds_1
    consumer_store = base_store.on_tick(block_time_1, has_proposal=True)
    store_after_block_1 = consumer_store.on_block(signed_block_1)

    # Now process a second block that includes attestations for the SAME validators
    # This tests the case where we append to existing lists in latest_new_aggregated_payloads
    attestation_slot_2 = Slot(2)
    attestation_data_2 = store_after_block_1.produce_attestation_data(attestation_slot_2)
    data_root_2 = attestation_data_2.data_root_bytes()

    attestation_data_map_2 = {data_root_2: attestation_data_2}
    gossip_sigs_2 = {
        SignatureKey(validator_id, data_root_2): key_manager.sign_attestation_data(
            validator_id, attestation_data_2
        )
        for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
    }

    producer_store_2 = store_after_block_1.model_copy(
        update={
            "attestation_data_by_root": attestation_data_map_2,
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
    slot_duration_seconds_2 = block_2.slot * SECONDS_PER_SLOT
    block_time_2 = store_after_block_1.config.genesis_time + slot_duration_seconds_2
    store_before_block_2 = store_after_block_1.on_tick(block_time_2, has_proposal=True)

    # Capture the original list lengths for keys that already exist
    original_sig_lengths = {
        k: len(v) for k, v in store_before_block_2.latest_new_aggregated_payloads.items()
    }

    # Process the second block
    store_after_block_2 = store_before_block_2.on_block(signed_block_2)

    # Verify immutability: the list lengths in store_before_block_2 should not have changed
    for key, original_length in original_sig_lengths.items():
        current_length = len(store_before_block_2.latest_new_aggregated_payloads[key])
        assert current_length == original_length, (
            f"Immutability violated: list for key {key} grew from {original_length} to "
            f"{current_length}"
        )

    # Verify that the updated store has new keys (different attestation data in block 2)
    # The key point is that store_before_block_2 wasn't mutated
    assert len(store_after_block_2.latest_new_aggregated_payloads) >= len(
        store_before_block_2.latest_new_aggregated_payloads
    )


def _create_store_with_validators(
    key_manager: XmssKeyManager,
    num_validators: int,
    current_validator_id: ValidatorIndex,
) -> tuple[Store, State, Block, AttestationData]:
    """
    Create a Store with validators and produce attestation data for testing.

    Returns a tuple of (store, genesis_state, genesis_block, attestation_data).
    """
    validators = Validators(
        data=[
            Validator(
                pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                index=ValidatorIndex(i),
            )
            for i in range(num_validators)
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

    store = Store.get_forkchoice_store(
        genesis_state,
        genesis_block,
        validator_id=current_validator_id,
    )

    attestation_data = store.produce_attestation_data(Slot(1))
    return store, genesis_state, genesis_block, attestation_data


class TestOnGossipAttestationSubnetFiltering:
    """
    Unit tests for on_gossip_attestation with is_aggregator=True.

    Tests subnet ID computation and cross-subnet filtering logic.
    When is_aggregator=True, signatures should only be stored if the
    attesting validator is in the same subnet as the current validator.
    """

    def test_same_subnet_stores_signature(self) -> None:
        """
        Aggregator stores signature when attester is in same subnet.

        With ATTESTATION_COMMITTEE_COUNT=4:
        - Validator 0 is in subnet 0 (0 % 4 = 0)
        - Validator 4 is in subnet 0 (4 % 4 = 0)
        - Current validator (0) should store signature from validator 4.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(4)

        store, _, _, attestation_data = _create_store_with_validators(
            key_manager, num_validators=8, current_validator_id=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_id=attester_validator,
            message=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        # Verify signature does NOT exist before calling the method
        data_root = attestation_data.data_root_bytes()
        sig_key = SignatureKey(attester_validator, data_root)
        assert sig_key not in store.gossip_signatures, (
            "Precondition: signature should not exist before calling method"
        )

        # Patch ATTESTATION_COMMITTEE_COUNT to 4 so we can test subnet filtering
        with mock.patch(
            "lean_spec.subspecs.forkchoice.store.ATTESTATION_COMMITTEE_COUNT", Uint64(4)
        ):
            updated_store = store.on_gossip_attestation(
                signed_attestation,
                is_aggregator=True,
            )

        # Verify signature NOW exists after calling the method
        assert sig_key in updated_store.gossip_signatures, (
            "Signature from same-subnet validator should be stored"
        )

    def test_cross_subnet_ignores_signature(self) -> None:
        """
        Aggregator ignores signature when attester is in different subnet.

        With ATTESTATION_COMMITTEE_COUNT=4:
        - Validator 0 is in subnet 0 (0 % 4 = 0)
        - Validator 1 is in subnet 1 (1 % 4 = 1)
        - Current validator (0) should NOT store signature from validator 1.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(1)

        store, _, _, attestation_data = _create_store_with_validators(
            key_manager, num_validators=8, current_validator_id=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_id=attester_validator,
            message=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        with mock.patch(
            "lean_spec.subspecs.forkchoice.store.ATTESTATION_COMMITTEE_COUNT", Uint64(4)
        ):
            updated_store = store.on_gossip_attestation(
                signed_attestation,
                is_aggregator=True,
            )

        # Verify signature was NOT stored
        data_root = attestation_data.data_root_bytes()
        sig_key = SignatureKey(attester_validator, data_root)
        assert sig_key not in updated_store.gossip_signatures, (
            "Signature from different-subnet validator should NOT be stored"
        )

    def test_non_aggregator_never_stores_signature(self) -> None:
        """
        Non-aggregator nodes never store gossip signatures.

        When is_aggregator=False, the signature storage path is skipped
        regardless of subnet membership.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(4)  # Same subnet

        store, _, _, attestation_data = _create_store_with_validators(
            key_manager, num_validators=8, current_validator_id=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_id=attester_validator,
            message=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        with mock.patch(
            "lean_spec.subspecs.forkchoice.store.ATTESTATION_COMMITTEE_COUNT", Uint64(4)
        ):
            updated_store = store.on_gossip_attestation(
                signed_attestation,
                is_aggregator=False,  # Not an aggregator
            )

        # Verify signature was NOT stored even though same subnet
        data_root = attestation_data.data_root_bytes()
        sig_key = SignatureKey(attester_validator, data_root)
        assert sig_key not in updated_store.gossip_signatures, (
            "Non-aggregator should never store gossip signatures"
        )

    def test_attestation_data_always_stored(self) -> None:
        """
        Attestation data is stored regardless of aggregator status or subnet.

        The attestation_data_by_root map is always updated for later reference,
        even when the signature itself is filtered out.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(1)  # Different subnet

        store, _, _, attestation_data = _create_store_with_validators(
            key_manager, num_validators=8, current_validator_id=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_id=attester_validator,
            message=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        with mock.patch(
            "lean_spec.subspecs.forkchoice.store.ATTESTATION_COMMITTEE_COUNT", Uint64(4)
        ):
            updated_store = store.on_gossip_attestation(
                signed_attestation,
                is_aggregator=True,
            )

        # Verify signature was NOT stored (cross-subnet filtered)
        data_root = attestation_data.data_root_bytes()
        sig_key = SignatureKey(attester_validator, data_root)
        assert sig_key not in updated_store.gossip_signatures, (
            "Signature should NOT be stored for cross-subnet validator"
        )

        # Verify attestation data WAS stored even though signature wasn't
        assert data_root in updated_store.attestation_data_by_root, (
            "Attestation data should always be stored"
        )
        assert updated_store.attestation_data_by_root[data_root] == attestation_data


class TestOnGossipAggregatedAttestation:
    """
    Unit tests for on_gossip_aggregated_attestation.

    Tests aggregated proof verification and storage in latest_new_aggregated_payloads.
    """

    def test_valid_proof_stored_correctly(self) -> None:
        """
        Valid aggregated attestation is verified and stored.

        The proof should be stored in latest_new_aggregated_payloads
        keyed by each participating validator's SignatureKey.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        participants = [ValidatorIndex(1), ValidatorIndex(2)]

        store, _, _, attestation_data = _create_store_with_validators(
            key_manager, num_validators=4, current_validator_id=ValidatorIndex(0)
        )

        data_root = attestation_data.data_root_bytes()

        # Create valid aggregated proof
        proof = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(participants),
            public_keys=[key_manager.get_public_key(vid) for vid in participants],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in participants
            ],
            message=data_root,
            epoch=attestation_data.slot,
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=proof,
        )

        updated_store = store.on_gossip_aggregated_attestation(signed_aggregated)

        # Verify proof is stored for each participant
        for vid in participants:
            sig_key = SignatureKey(vid, data_root)
            assert sig_key in updated_store.latest_new_aggregated_payloads, (
                f"Proof should be stored for validator {vid}"
            )
            proofs = updated_store.latest_new_aggregated_payloads[sig_key]
            assert len(proofs) == 1
            assert proofs[0] == proof

    def test_attestation_data_stored_by_root(self) -> None:
        """
        Attestation data is stored in attestation_data_by_root.

        This allows later reconstruction of attestations from proofs.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        participants = [ValidatorIndex(1)]

        store, _, _, attestation_data = _create_store_with_validators(
            key_manager, num_validators=4, current_validator_id=ValidatorIndex(0)
        )

        data_root = attestation_data.data_root_bytes()

        proof = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(participants),
            public_keys=[key_manager.get_public_key(vid) for vid in participants],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in participants
            ],
            message=data_root,
            epoch=attestation_data.slot,
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=proof,
        )

        updated_store = store.on_gossip_aggregated_attestation(signed_aggregated)

        assert data_root in updated_store.attestation_data_by_root
        assert updated_store.attestation_data_by_root[data_root] == attestation_data

    def test_invalid_proof_rejected(self) -> None:
        """
        Invalid aggregated proof is rejected with AssertionError.

        A proof signed by different validators than claimed should fail verification.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        claimed_participants = [ValidatorIndex(1), ValidatorIndex(2)]
        actual_signers = [ValidatorIndex(1), ValidatorIndex(3)]  # Different!

        store, _, _, attestation_data = _create_store_with_validators(
            key_manager, num_validators=4, current_validator_id=ValidatorIndex(0)
        )

        data_root = attestation_data.data_root_bytes()

        # Create proof with WRONG signers (validator 3 signs instead of 2)
        proof = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(claimed_participants),
            public_keys=[key_manager.get_public_key(vid) for vid in actual_signers],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in actual_signers
            ],
            message=data_root,
            epoch=attestation_data.slot,
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=proof,
        )

        with pytest.raises(AssertionError, match="signature verification failed"):
            store.on_gossip_aggregated_attestation(signed_aggregated)

    def test_multiple_proofs_accumulate(self) -> None:
        """
        Multiple aggregated proofs for same validator accumulate.

        When a validator appears in multiple aggregated attestations,
        all proofs should be stored in the list.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))

        store, _, _, attestation_data = _create_store_with_validators(
            key_manager, num_validators=4, current_validator_id=ValidatorIndex(0)
        )

        data_root = attestation_data.data_root_bytes()

        # First proof: validators 1 and 2
        participants_1 = [ValidatorIndex(1), ValidatorIndex(2)]
        proof_1 = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(participants_1),
            public_keys=[key_manager.get_public_key(vid) for vid in participants_1],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in participants_1
            ],
            message=data_root,
            epoch=attestation_data.slot,
        )

        # Second proof: validators 1 and 3 (validator 1 overlaps)
        participants_2 = [ValidatorIndex(1), ValidatorIndex(3)]
        proof_2 = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(participants_2),
            public_keys=[key_manager.get_public_key(vid) for vid in participants_2],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in participants_2
            ],
            message=data_root,
            epoch=attestation_data.slot,
        )

        store = store.on_gossip_aggregated_attestation(
            SignedAggregatedAttestation(data=attestation_data, proof=proof_1)
        )
        store = store.on_gossip_aggregated_attestation(
            SignedAggregatedAttestation(data=attestation_data, proof=proof_2)
        )

        # Validator 1 should have BOTH proofs
        sig_key = SignatureKey(ValidatorIndex(1), data_root)
        stored_proofs = store.latest_new_aggregated_payloads[sig_key]
        assert len(stored_proofs) == 2
        assert proof_1 in stored_proofs, "First proof should be stored"
        assert proof_2 in stored_proofs, "Second proof should be stored"


def _create_store_with_gossip_signatures(
    key_manager: XmssKeyManager,
    num_validators: int,
    current_validator_id: ValidatorIndex,
    attesting_validators: list[ValidatorIndex],
) -> tuple[Store, AttestationData]:
    """
    Create a Store pre-populated with gossip signatures for testing aggregation.

    Returns (store_with_signatures, attestation_data).
    """
    validators = Validators(
        data=[
            Validator(
                pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                index=ValidatorIndex(i),
            )
            for i in range(num_validators)
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
        validator_id=current_validator_id,
    )

    attestation_data = base_store.produce_attestation_data(Slot(1))
    data_root = attestation_data.data_root_bytes()

    # Build gossip signatures for attesting validators
    gossip_signatures = {
        SignatureKey(vid, data_root): key_manager.sign_attestation_data(vid, attestation_data)
        for vid in attesting_validators
    }

    # Populate attestation_data_by_root so aggregation can reconstruct attestations
    attestation_data_by_root = {data_root: attestation_data}

    store = base_store.model_copy(
        update={
            "gossip_signatures": gossip_signatures,
            "attestation_data_by_root": attestation_data_by_root,
        }
    )

    return store, attestation_data


class TestAggregateCommitteeSignatures:
    """
    Integration tests for committee signature aggregation.

    Tests that gossip signatures are correctly aggregated into proofs
    and stored for later use.
    """

    def test_aggregates_gossip_signatures_into_proof(self) -> None:
        """
        Aggregation creates proofs from collected gossip signatures.

        Expected behavior:
        1. Extract attestations from stored signatures
        2. Aggregate signatures into a single proof
        3. Store resulting proofs for later use
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = _create_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            current_validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Perform aggregation
        updated_store = store.aggregate_committee_signatures()

        # Verify proofs were created and stored
        data_root = attestation_data.data_root_bytes()
        for vid in attesting_validators:
            sig_key = SignatureKey(vid, data_root)
            assert sig_key in updated_store.latest_new_aggregated_payloads, (
                f"Aggregated proof should be stored for validator {vid}"
            )
            proofs = updated_store.latest_new_aggregated_payloads[sig_key]
            assert len(proofs) >= 1, "At least one proof should exist"

    def test_aggregated_proof_is_valid(self) -> None:
        """
        Created aggregated proof passes verification.

        The proof should be cryptographically valid and verifiable
        against the original public keys.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = _create_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            current_validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        updated_store = store.aggregate_committee_signatures()

        data_root = attestation_data.data_root_bytes()
        sig_key = SignatureKey(ValidatorIndex(1), data_root)
        proof = updated_store.latest_new_aggregated_payloads[sig_key][0]

        # Extract participants from the proof
        participants = proof.participants.to_validator_indices()
        public_keys = [key_manager.get_public_key(vid) for vid in participants]

        # Verify the proof is valid
        proof.verify(
            public_keys=public_keys,
            message=data_root,
            epoch=attestation_data.slot,
        )

    def test_empty_gossip_signatures_produces_no_proofs(self) -> None:
        """
        No proofs created when gossip_signatures is empty.

        This is the expected behavior when no attestations have been received.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))

        store, _ = _create_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            current_validator_id=ValidatorIndex(0),
            attesting_validators=[],  # No attesters
        )

        updated_store = store.aggregate_committee_signatures()

        # Verify no proofs were created
        assert len(updated_store.latest_new_aggregated_payloads) == 0

    def test_multiple_attestation_data_grouped_separately(self) -> None:
        """
        Signatures for different attestation data are aggregated separately.

        Each unique AttestationData should produce its own aggregated proof.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        validators = Validators(
            data=[
                Validator(
                    pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                    index=ValidatorIndex(i),
                )
                for i in range(4)
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
            validator_id=ValidatorIndex(0),
        )

        # Create two different attestation data (different slots)
        att_data_1 = base_store.produce_attestation_data(Slot(1))
        # Create a second attestation data with different head
        att_data_2 = AttestationData(
            slot=Slot(1),
            head=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(1)),
            target=att_data_1.target,
            source=att_data_1.source,
        )

        data_root_1 = att_data_1.data_root_bytes()
        data_root_2 = att_data_2.data_root_bytes()

        # Validators 1 attests to data_1, validator 2 attests to data_2
        gossip_signatures = {
            SignatureKey(ValidatorIndex(1), data_root_1): key_manager.sign_attestation_data(
                ValidatorIndex(1), att_data_1
            ),
            SignatureKey(ValidatorIndex(2), data_root_2): key_manager.sign_attestation_data(
                ValidatorIndex(2), att_data_2
            ),
        }

        attestation_data_by_root = {
            data_root_1: att_data_1,
            data_root_2: att_data_2,
        }

        store = base_store.model_copy(
            update={
                "gossip_signatures": gossip_signatures,
                "attestation_data_by_root": attestation_data_by_root,
            }
        )

        updated_store = store.aggregate_committee_signatures()

        # Verify both validators have separate proofs
        sig_key_1 = SignatureKey(ValidatorIndex(1), data_root_1)
        sig_key_2 = SignatureKey(ValidatorIndex(2), data_root_2)

        assert sig_key_1 in updated_store.latest_new_aggregated_payloads
        assert sig_key_2 in updated_store.latest_new_aggregated_payloads


class TestTickIntervalAggregation:
    """
    Integration tests for interval-triggered aggregation.

    Tests that interval 2 (aggregation interval) correctly triggers
    signature aggregation for aggregator nodes.
    """

    def test_interval_2_triggers_aggregation_for_aggregator(self) -> None:
        """
        Aggregation is triggered at interval 2 when is_aggregator=True.

        At interval 2, aggregator nodes collect and aggregate signatures.
        Non-aggregators skip this step.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = _create_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            current_validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Set time to interval 1 (so next tick goes to interval 2)
        # time % INTERVALS_PER_SLOT determines current interval
        # We want to end up at interval 2 after tick
        store = store.model_copy(update={"time": Uint64(1)})

        # Tick to interval 2 as aggregator
        updated_store = store.tick_interval(has_proposal=False, is_aggregator=True)

        # Verify aggregation was performed
        data_root = attestation_data.data_root_bytes()
        sig_key = SignatureKey(ValidatorIndex(1), data_root)

        assert sig_key in updated_store.latest_new_aggregated_payloads, (
            "Aggregation should occur at interval 2 for aggregators"
        )

    def test_interval_2_skips_aggregation_for_non_aggregator(self) -> None:
        """
        Aggregation is NOT triggered at interval 2 when is_aggregator=False.

        Non-aggregator nodes should not perform aggregation even at interval 2.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = _create_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            current_validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Set time to interval 1
        store = store.model_copy(update={"time": Uint64(1)})

        # Tick to interval 2 as NON-aggregator
        updated_store = store.tick_interval(has_proposal=False, is_aggregator=False)

        # Verify aggregation was NOT performed
        data_root = attestation_data.data_root_bytes()
        sig_key = SignatureKey(ValidatorIndex(1), data_root)

        assert sig_key not in updated_store.latest_new_aggregated_payloads, (
            "Aggregation should NOT occur for non-aggregators"
        )

    def test_other_intervals_do_not_trigger_aggregation(self) -> None:
        """
        Aggregation is NOT triggered at intervals other than 2.

        Only interval 2 should trigger aggregation, even for aggregators.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = _create_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            current_validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        data_root = attestation_data.data_root_bytes()
        sig_key = SignatureKey(ValidatorIndex(1), data_root)

        # Test intervals 0, 1, 3, 4 (skip 2)
        non_aggregation_intervals = [0, 1, 3, 4]

        for target_interval in non_aggregation_intervals:
            # Set time so next tick lands on target_interval
            # After tick, time becomes time+1, and interval = (time+1) % 5
            # So we need time+1 % 5 == target_interval
            # Therefore time = target_interval - 1 (mod 5)
            pre_tick_time = (target_interval - 1) % int(INTERVALS_PER_SLOT)
            test_store = store.model_copy(update={"time": Uint64(pre_tick_time)})

            updated_store = test_store.tick_interval(has_proposal=False, is_aggregator=True)

            assert sig_key not in updated_store.latest_new_aggregated_payloads, (
                f"Aggregation should NOT occur at interval {target_interval}"
            )

    def test_interval_0_accepts_attestations_with_proposal(self) -> None:
        """
        Interval 0 accepts new attestations when has_proposal=True.

        This tests that interval 0 performs its own action (accepting attestations)
        rather than aggregation.
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        validators = Validators(
            data=[
                Validator(
                    pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                    index=ValidatorIndex(i),
                )
                for i in range(4)
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

        store = Store.get_forkchoice_store(
            genesis_state,
            genesis_block,
            validator_id=ValidatorIndex(0),
        )

        # Set time to interval 4 (so next tick wraps to interval 0)
        store = store.model_copy(update={"time": Uint64(4)})

        # Tick to interval 0 with proposal
        updated_store = store.tick_interval(has_proposal=True, is_aggregator=True)

        # Verify time advanced
        assert updated_store.time == Uint64(5)
        # Interval should now be 0
        assert updated_store.time % INTERVALS_PER_SLOT == Uint64(0)


class TestEndToEndAggregationFlow:
    """
    End-to-end test for the complete aggregation flow.

    Tests the full path from gossip attestation reception through
    interval-triggered aggregation to proof storage.
    """

    def test_gossip_to_aggregation_to_storage(self) -> None:
        """
        Complete flow: gossip attestation -> aggregation -> proof storage.

        Simulates:
        1. Validators send signed attestations via gossip
        2. Aggregator receives and stores signatures (same subnet)
        3. At interval 2, aggregator creates aggregated proof
        4. Proof is stored in latest_new_aggregated_payloads
        """
        key_manager = XmssKeyManager(max_slot=Slot(10))
        num_validators = 4

        validators = Validators(
            data=[
                Validator(
                    pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                    index=ValidatorIndex(i),
                )
                for i in range(num_validators)
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

        # Aggregator is validator 0
        aggregator_id = ValidatorIndex(0)
        store = Store.get_forkchoice_store(
            genesis_state,
            genesis_block,
            validator_id=aggregator_id,
        )

        attestation_data = store.produce_attestation_data(Slot(1))
        data_root = attestation_data.data_root_bytes()

        # Step 1: Receive gossip attestations from validators 1 and 2
        # (all in same subnet since ATTESTATION_COMMITTEE_COUNT=1 by default)
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        for vid in attesting_validators:
            signed_attestation = SignedAttestation(
                validator_id=vid,
                message=attestation_data,
                signature=key_manager.sign_attestation_data(vid, attestation_data),
            )
            store = store.on_gossip_attestation(
                signed_attestation,
                is_aggregator=True,
            )

        # Verify signatures were stored
        for vid in attesting_validators:
            sig_key = SignatureKey(vid, data_root)
            assert sig_key in store.gossip_signatures, f"Signature for {vid} should be stored"

        # Step 2: Advance to interval 2 (aggregation interval)
        store = store.model_copy(update={"time": Uint64(1)})
        store = store.tick_interval(has_proposal=False, is_aggregator=True)

        # Step 3: Verify aggregated proofs were created
        for vid in attesting_validators:
            sig_key = SignatureKey(vid, data_root)
            assert sig_key in store.latest_new_aggregated_payloads, (
                f"Aggregated proof for {vid} should exist after interval 2"
            )

        # Step 4: Verify the proof is valid
        proof = store.latest_new_aggregated_payloads[SignatureKey(ValidatorIndex(1), data_root)][0]
        participants = proof.participants.to_validator_indices()
        public_keys = [key_manager.get_public_key(vid) for vid in participants]

        proof.verify(
            public_keys=public_keys,
            message=data_root,
            epoch=attestation_data.slot,
        )
