"""Integration tests for Store aggregation functionality.

Tests the integration between:
- Committee signature aggregation
- Gossip signature processing
- Interval-based aggregation triggers

These tests verify the complete aggregation flow from gossip signature
collection through proof creation and storage.
"""

from __future__ import annotations

from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT
from lean_spec.subspecs.containers.attestation import (
    AttestationData,
    SignedAttestation,
)
from lean_spec.subspecs.containers.block import (
    Block,
    BlockBody,
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


# =============================================================================
# Integration Tests: aggregate_committee_signatures
# =============================================================================


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


# =============================================================================
# Integration Tests: tick_interval aggregation trigger
# =============================================================================


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


# =============================================================================
# End-to-End Integration Test
# =============================================================================


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
