"""Tests for Store attestation handling."""

from __future__ import annotations

from unittest import mock

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT
from lean_spec.subspecs.containers.attestation import (
    AggregationBits,
    AttestationData,
    SignedAggregatedAttestation,
    SignedAttestation,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.forkchoice import GossipSignatureEntry
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import (
    TEST_VALIDATOR_ID,
    make_aggregated_proof,
    make_signed_block_from_store,
    make_store,
    make_store_with_attestation_data,
    make_store_with_gossip_signatures,
)


def test_on_block_processes_multi_validator_aggregations(key_manager: XmssKeyManager) -> None:
    """Ensure Store.on_block handles aggregated attestations with many validators."""
    base_store = make_store(num_validators=3, key_manager=key_manager)

    # Producer view knows about attestations from validators 1 and 2
    attestation_slot = Slot(1)
    attestation_data = base_store.produce_attestation_data(attestation_slot)

    participants = [ValidatorIndex(1), ValidatorIndex(2)]

    proof = make_aggregated_proof(key_manager, participants, attestation_data)

    aggregated_payloads = {attestation_data: {proof}}

    producer_store = base_store.model_copy(
        update={
            "latest_known_aggregated_payloads": aggregated_payloads,
        }
    )

    proposer_index = ValidatorIndex(1)
    consumer_store, signed_block = make_signed_block_from_store(
        producer_store, key_manager, attestation_slot, proposer_index
    )

    updated_store = consumer_store.on_block(signed_block)

    # Verify attestations can be extracted from aggregated payloads
    extracted_attestations = updated_store.extract_attestations_from_aggregated_payloads(
        updated_store.latest_known_aggregated_payloads
    )
    assert ValidatorIndex(1) in extracted_attestations
    assert ValidatorIndex(2) in extracted_attestations
    assert extracted_attestations[ValidatorIndex(1)] == attestation_data
    assert extracted_attestations[ValidatorIndex(2)] == attestation_data


def test_on_block_preserves_immutability_of_aggregated_payloads(
    key_manager: XmssKeyManager,
) -> None:
    """Verify that Store.on_block doesn't mutate previous store's latest_new_aggregated_payloads."""
    base_store = make_store(
        num_validators=3, key_manager=key_manager, validator_id=TEST_VALIDATOR_ID
    )

    # First block with attestations from validators 1 and 2
    attestation_slot_1 = Slot(1)
    attestation_data_1 = base_store.produce_attestation_data(attestation_slot_1)

    gossip_sigs_1 = {
        attestation_data_1: {
            GossipSignatureEntry(
                validator_id, key_manager.sign_attestation_data(validator_id, attestation_data_1)
            )
            for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
        },
    }

    producer_store_1 = base_store.model_copy(
        update={
            "gossip_signatures": gossip_sigs_1,
        }
    )

    consumer_store_1, signed_block_1 = make_signed_block_from_store(
        producer_store_1, key_manager, attestation_slot_1, ValidatorIndex(1)
    )
    store_after_block_1 = consumer_store_1.on_block(signed_block_1)

    # Second block with attestations for the SAME validators
    attestation_slot_2 = Slot(2)
    attestation_data_2 = store_after_block_1.produce_attestation_data(attestation_slot_2)

    gossip_sigs_2 = {
        attestation_data_2: {
            GossipSignatureEntry(
                validator_id, key_manager.sign_attestation_data(validator_id, attestation_data_2)
            )
            for validator_id in (ValidatorIndex(1), ValidatorIndex(2))
        },
    }

    producer_store_2 = store_after_block_1.model_copy(
        update={
            "gossip_signatures": gossip_sigs_2,
        }
    )

    store_before_block_2, signed_block_2 = make_signed_block_from_store(
        producer_store_2, key_manager, attestation_slot_2, ValidatorIndex(2)
    )

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


class TestOnGossipAttestationSubnetFiltering:
    """
    Unit tests for on_gossip_attestation with is_aggregator=True.

    Tests subnet ID computation and cross-subnet filtering logic.
    When is_aggregator=True, signatures should only be stored if the
    attesting validator is in the same subnet as the current validator.
    """

    def test_same_subnet_stores_signature(self, key_manager: XmssKeyManager) -> None:
        """
        Aggregator stores signature when attester is in same subnet.

        With ATTESTATION_COMMITTEE_COUNT=4:
        - Validator 0 is in subnet 0 (0 % 4 = 0)
        - Validator 4 is in subnet 0 (4 % 4 = 0)
        - Current validator (0) should store signature from validator 4.
        """
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(4)

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=8, validator_id=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_id=attester_validator,
            data=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        # Verify signature does NOT exist before calling the method
        assert attestation_data not in store.gossip_signatures, (
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
        sigs = updated_store.gossip_signatures.get(attestation_data, set())
        assert any(entry.validator_id == attester_validator for entry in sigs), (
            "Signature from same-subnet validator should be stored"
        )

    def test_cross_subnet_ignores_signature(self, key_manager: XmssKeyManager) -> None:
        """
        Aggregator ignores signature when attester is in different subnet.

        With ATTESTATION_COMMITTEE_COUNT=4:
        - Validator 0 is in subnet 0 (0 % 4 = 0)
        - Validator 1 is in subnet 1 (1 % 4 = 1)
        - Current validator (0) should NOT store signature from validator 1.
        """
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(1)

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=8, validator_id=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_id=attester_validator,
            data=attestation_data,
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
        sigs = updated_store.gossip_signatures.get(attestation_data, set())
        assert not any(entry.validator_id == attester_validator for entry in sigs), (
            "Signature from different-subnet validator should NOT be stored"
        )

    def test_non_aggregator_never_stores_signature(self, key_manager: XmssKeyManager) -> None:
        """
        Non-aggregator nodes never store gossip signatures.

        When is_aggregator=False, the signature storage path is skipped
        regardless of subnet membership.
        """
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(4)  # Same subnet

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=8, validator_id=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_id=attester_validator,
            data=attestation_data,
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
        sigs = updated_store.gossip_signatures.get(attestation_data, set())
        assert not any(entry.validator_id == attester_validator for entry in sigs), (
            "Non-aggregator should never store gossip signatures"
        )

    def test_cross_subnet_does_not_create_gossip_entry(self, key_manager: XmssKeyManager) -> None:
        """
        Cross-subnet attestation does not create a gossip_signatures entry.

        When the attester is in a different subnet, no entry is created
        for that attestation data in gossip_signatures.
        """
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(1)  # Different subnet

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=8, validator_id=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_id=attester_validator,
            data=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        with mock.patch(
            "lean_spec.subspecs.forkchoice.store.ATTESTATION_COMMITTEE_COUNT", Uint64(4)
        ):
            updated_store = store.on_gossip_attestation(
                signed_attestation,
                is_aggregator=True,
            )

        # Verify no gossip entry was created for this attestation data
        assert attestation_data not in updated_store.gossip_signatures, (
            "Cross-subnet attestation should not create a gossip_signatures entry"
        )


class TestOnGossipAggregatedAttestation:
    """
    Unit tests for on_gossip_aggregated_attestation.

    Tests aggregated proof verification and storage in latest_new_aggregated_payloads.
    """

    def test_valid_proof_stored_correctly(self, key_manager: XmssKeyManager) -> None:
        """
        Valid aggregated attestation is verified and stored.

        The proof should be stored in latest_new_aggregated_payloads
        keyed by attestation data.
        """
        participants = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=4, validator_id=ValidatorIndex(0)
        )

        data_root = attestation_data.data_root_bytes()

        # Create valid aggregated proof
        proof = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(
                ValidatorIndices(data=participants)
            ),
            public_keys=[key_manager.get_public_key(vid) for vid in participants],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in participants
            ],
            message=data_root,
            slot=attestation_data.slot,
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=proof,
        )

        updated_store = store.on_gossip_aggregated_attestation(signed_aggregated)

        # Verify proof is stored keyed by attestation data
        assert attestation_data in updated_store.latest_new_aggregated_payloads, (
            "Proof should be stored for this attestation data"
        )
        proofs = updated_store.latest_new_aggregated_payloads[attestation_data]
        assert len(proofs) == 1
        assert proof in proofs

    def test_attestation_data_used_as_key(self, key_manager: XmssKeyManager) -> None:
        """
        Attestation data is used directly as the key in aggregated payloads.

        Proofs are accessible by looking up the attestation data.
        """
        participants = [ValidatorIndex(1)]

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=4, validator_id=ValidatorIndex(0)
        )

        data_root = attestation_data.data_root_bytes()

        proof = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(
                ValidatorIndices(data=participants)
            ),
            public_keys=[key_manager.get_public_key(vid) for vid in participants],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in participants
            ],
            message=data_root,
            slot=attestation_data.slot,
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=proof,
        )

        updated_store = store.on_gossip_aggregated_attestation(signed_aggregated)

        assert attestation_data in updated_store.latest_new_aggregated_payloads
        assert proof in updated_store.latest_new_aggregated_payloads[attestation_data]

    def test_invalid_proof_rejected(self, key_manager: XmssKeyManager) -> None:
        """
        Invalid aggregated proof is rejected with AssertionError.

        A proof signed by different validators than claimed should fail verification.
        """
        claimed_participants = [ValidatorIndex(1), ValidatorIndex(2)]
        actual_signers = [ValidatorIndex(1), ValidatorIndex(3)]  # Different!

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=4, validator_id=ValidatorIndex(0)
        )

        data_root = attestation_data.data_root_bytes()

        # Create proof with WRONG signers (validator 3 signs instead of 2)
        proof = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(
                ValidatorIndices(data=claimed_participants)
            ),
            public_keys=[key_manager.get_public_key(vid) for vid in actual_signers],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in actual_signers
            ],
            message=data_root,
            slot=attestation_data.slot,
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=proof,
        )

        with pytest.raises(AssertionError, match="signature verification failed"):
            store.on_gossip_aggregated_attestation(signed_aggregated)

    def test_multiple_proofs_accumulate(self, key_manager: XmssKeyManager) -> None:
        """
        Multiple aggregated proofs for same validator accumulate.

        When a validator appears in multiple aggregated attestations,
        all proofs should be stored in the list.
        """
        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=4, validator_id=ValidatorIndex(0)
        )

        data_root = attestation_data.data_root_bytes()

        # First proof: validators 1 and 2
        participants_1 = [ValidatorIndex(1), ValidatorIndex(2)]
        proof_1 = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(
                ValidatorIndices(data=participants_1)
            ),
            public_keys=[key_manager.get_public_key(vid) for vid in participants_1],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in participants_1
            ],
            message=data_root,
            slot=attestation_data.slot,
        )

        # Second proof: validators 1 and 3 (validator 1 overlaps)
        participants_2 = [ValidatorIndex(1), ValidatorIndex(3)]
        proof_2 = AggregatedSignatureProof.aggregate(
            participants=AggregationBits.from_validator_indices(
                ValidatorIndices(data=participants_2)
            ),
            public_keys=[key_manager.get_public_key(vid) for vid in participants_2],
            signatures=[
                key_manager.sign_attestation_data(vid, attestation_data) for vid in participants_2
            ],
            message=data_root,
            slot=attestation_data.slot,
        )

        store = store.on_gossip_aggregated_attestation(
            SignedAggregatedAttestation(data=attestation_data, proof=proof_1)
        )
        store = store.on_gossip_aggregated_attestation(
            SignedAggregatedAttestation(data=attestation_data, proof=proof_2)
        )

        # Both proofs should be stored under the same attestation data
        stored_proofs = store.latest_new_aggregated_payloads[attestation_data]
        assert len(stored_proofs) == 2
        assert proof_1 in stored_proofs, "First proof should be stored"
        assert proof_2 in stored_proofs, "Second proof should be stored"


class TestAggregateCommitteeSignatures:
    """
    Integration tests for committee signature aggregation.

    Tests that gossip signatures are correctly aggregated into proofs
    and stored for later use.
    """

    def test_aggregates_gossip_signatures_into_proof(self, key_manager: XmssKeyManager) -> None:
        """
        Aggregation creates proofs from collected gossip signatures.

        Expected behavior:
        1. Extract attestations from stored signatures
        2. Aggregate signatures into a single proof
        3. Store resulting proofs for later use
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Perform aggregation
        updated_store, _ = store.aggregate_committee_signatures()

        # Verify proofs were created and stored keyed by attestation data
        assert attestation_data in updated_store.latest_new_aggregated_payloads, (
            "Aggregated proof should be stored for this attestation data"
        )
        proofs = updated_store.latest_new_aggregated_payloads[attestation_data]
        assert len(proofs) >= 1, "At least one proof should exist"

    def test_aggregated_proof_is_valid(self, key_manager: XmssKeyManager) -> None:
        """
        Created aggregated proof passes verification.

        The proof should be cryptographically valid and verifiable
        against the original public keys.
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        updated_store, _ = store.aggregate_committee_signatures()

        proofs = updated_store.latest_new_aggregated_payloads[attestation_data]
        proof = next(iter(proofs))

        # Extract participants from the proof
        participants = proof.participants.to_validator_indices()
        public_keys = [key_manager.get_public_key(vid) for vid in participants]

        # Verify the proof is valid
        proof.verify(
            public_keys=public_keys,
            message=attestation_data.data_root_bytes(),
            slot=attestation_data.slot,
        )

    def test_empty_gossip_signatures_produces_no_proofs(self, key_manager: XmssKeyManager) -> None:
        """
        No proofs created when gossip_signatures is empty.

        This is the expected behavior when no attestations have been received.
        """
        store, _ = make_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            validator_id=ValidatorIndex(0),
            attesting_validators=[],  # No attesters
        )

        updated_store, _ = store.aggregate_committee_signatures()

        # Verify no proofs were created
        assert len(updated_store.latest_new_aggregated_payloads) == 0

    def test_multiple_attestation_data_grouped_separately(
        self, key_manager: XmssKeyManager
    ) -> None:
        """
        Signatures for different attestation data are aggregated separately.

        Each unique AttestationData should produce its own aggregated proof.
        """
        base_store = make_store(
            num_validators=4, key_manager=key_manager, validator_id=ValidatorIndex(0)
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

        # Validators 1 attests to data_1, validator 2 attests to data_2
        sig_1 = key_manager.sign_attestation_data(ValidatorIndex(1), att_data_1)
        sig_2 = key_manager.sign_attestation_data(ValidatorIndex(2), att_data_2)
        gossip_signatures = {
            att_data_1: {GossipSignatureEntry(ValidatorIndex(1), sig_1)},
            att_data_2: {GossipSignatureEntry(ValidatorIndex(2), sig_2)},
        }

        store = base_store.model_copy(
            update={
                "gossip_signatures": gossip_signatures,
            }
        )

        updated_store, _ = store.aggregate_committee_signatures()

        # Verify both attestation data have separate proofs
        assert att_data_1 in updated_store.latest_new_aggregated_payloads
        assert att_data_2 in updated_store.latest_new_aggregated_payloads


class TestTickIntervalAggregation:
    """
    Integration tests for interval-triggered aggregation.

    Tests that interval 2 (aggregation interval) correctly triggers
    signature aggregation for aggregator nodes.
    """

    def test_interval_2_triggers_aggregation_for_aggregator(
        self, key_manager: XmssKeyManager
    ) -> None:
        """
        Aggregation is triggered at interval 2 when is_aggregator=True.

        At interval 2, aggregator nodes collect and aggregate signatures.
        Non-aggregators skip this step.
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Set time to interval 1 (so next tick goes to interval 2)
        # time % INTERVALS_PER_SLOT determines current interval
        # We want to end up at interval 2 after tick
        store = store.model_copy(update={"time": Uint64(1)})

        # Tick to interval 2 as aggregator
        updated_store, _ = store.tick_interval(has_proposal=False, is_aggregator=True)

        # Verify aggregation was performed
        assert attestation_data in updated_store.latest_new_aggregated_payloads, (
            "Aggregation should occur at interval 2 for aggregators"
        )

    def test_interval_2_skips_aggregation_for_non_aggregator(
        self, key_manager: XmssKeyManager
    ) -> None:
        """
        Aggregation is NOT triggered at interval 2 when is_aggregator=False.

        Non-aggregator nodes should not perform aggregation even at interval 2.
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Set time to interval 1
        store = store.model_copy(update={"time": Uint64(1)})

        # Tick to interval 2 as NON-aggregator
        updated_store, _ = store.tick_interval(has_proposal=False, is_aggregator=False)

        # Verify aggregation was NOT performed
        assert attestation_data not in updated_store.latest_new_aggregated_payloads, (
            "Aggregation should NOT occur for non-aggregators"
        )

    def test_other_intervals_do_not_trigger_aggregation(self, key_manager: XmssKeyManager) -> None:
        """
        Aggregation is NOT triggered at intervals other than 2.

        Only interval 2 should trigger aggregation, even for aggregators.
        """
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_gossip_signatures(
            key_manager,
            num_validators=4,
            validator_id=ValidatorIndex(0),
            attesting_validators=attesting_validators,
        )

        # Test intervals 0, 1, 3, 4 (skip 2)
        non_aggregation_intervals = [0, 1, 3, 4]

        for target_interval in non_aggregation_intervals:
            # Set time so next tick lands on target_interval
            # After tick, time becomes time+1, and interval = (time+1) % 5
            # So we need time+1 % 5 == target_interval
            # Therefore time = target_interval - 1 (mod 5)
            pre_tick_time = (target_interval - 1) % int(INTERVALS_PER_SLOT)
            test_store = store.model_copy(update={"time": Uint64(pre_tick_time)})

            updated_store, _ = test_store.tick_interval(has_proposal=False, is_aggregator=True)

            assert attestation_data not in updated_store.latest_new_aggregated_payloads, (
                f"Aggregation should NOT occur at interval {target_interval}"
            )

    def test_interval_0_accepts_attestations_with_proposal(
        self, key_manager: XmssKeyManager
    ) -> None:
        """
        Interval 0 accepts new attestations when has_proposal=True.

        This tests that interval 0 performs its own action (accepting attestations)
        rather than aggregation.
        """
        store = make_store(
            num_validators=4, key_manager=key_manager, validator_id=ValidatorIndex(0)
        )

        # Set time to interval 4 (so next tick wraps to interval 0)
        store = store.model_copy(update={"time": Uint64(4)})

        # Tick to interval 0 with proposal
        updated_store, _ = store.tick_interval(has_proposal=True, is_aggregator=True)

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

    def test_gossip_to_aggregation_to_storage(self, key_manager: XmssKeyManager) -> None:
        """
        Complete flow: gossip attestation -> aggregation -> proof storage.

        Simulates:
        1. Validators send signed attestations via gossip
        2. Aggregator receives and stores signatures (same subnet)
        3. At interval 2, aggregator creates aggregated proof
        4. Proof is stored in latest_new_aggregated_payloads
        """
        num_validators = 4
        aggregator_id = ValidatorIndex(0)

        store = make_store(
            num_validators=num_validators, key_manager=key_manager, validator_id=aggregator_id
        )

        attestation_data = store.produce_attestation_data(Slot(1))
        data_root = attestation_data.data_root_bytes()

        # Step 1: Receive gossip attestations from validators 1 and 2
        # (all in same subnet since ATTESTATION_COMMITTEE_COUNT=1 by default)
        attesting_validators = [ValidatorIndex(1), ValidatorIndex(2)]

        for vid in attesting_validators:
            signed_attestation = SignedAttestation(
                validator_id=vid,
                data=attestation_data,
                signature=key_manager.sign_attestation_data(vid, attestation_data),
            )
            store = store.on_gossip_attestation(
                signed_attestation,
                is_aggregator=True,
            )

        # Verify signatures were stored
        sigs = store.gossip_signatures.get(attestation_data, set())
        for vid in attesting_validators:
            assert any(entry.validator_id == vid for entry in sigs), (
                f"Signature for {vid} should be stored"
            )

        # Step 2: Advance to interval 2 (aggregation interval)
        store = store.model_copy(update={"time": Uint64(1)})
        store, _ = store.tick_interval(has_proposal=False, is_aggregator=True)

        # Step 3: Verify aggregated proofs were created
        assert attestation_data in store.latest_new_aggregated_payloads, (
            "Aggregated proofs should exist after interval 2"
        )

        # Step 4: Verify the proof is valid
        proof = next(iter(store.latest_new_aggregated_payloads[attestation_data]))
        participants = proof.participants.to_validator_indices()
        public_keys = [key_manager.get_public_key(vid) for vid in participants]

        proof.verify(
            public_keys=public_keys,
            message=data_root,
            slot=attestation_data.slot,
        )
