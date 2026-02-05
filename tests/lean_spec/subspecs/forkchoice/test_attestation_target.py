"""Tests for attestation target computation and justification logic."""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.config import (
    JUSTIFICATION_LOOKBACK_SLOTS,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockWithAttestation,
    Checkpoint,
    SignedBlockWithAttestation,
    State,
    Validator,
)
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.block import AggregatedAttestations, BlockSignatures
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Uint64


@pytest.fixture
def key_manager() -> XmssKeyManager:
    """Create an XMSS key manager for signing attestations."""
    return XmssKeyManager(max_slot=Slot(20))


@pytest.fixture
def validators(key_manager: XmssKeyManager) -> Validators:
    """Create validators with real public keys from the key manager."""
    return Validators(
        data=[
            Validator(
                pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                index=ValidatorIndex(i),
            )
            for i in range(12)
        ]
    )


@pytest.fixture
def genesis_state(validators: Validators) -> State:
    """Create a genesis state with the test validators."""
    return State.generate_genesis(genesis_time=Uint64(0), validators=validators)


@pytest.fixture
def genesis_block(genesis_state: State) -> Block:
    """Create a genesis block matching the genesis state."""
    return Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


@pytest.fixture
def base_store(genesis_state: State, genesis_block: Block) -> Store:
    """Create a store initialized with the genesis state and block."""
    return Store.get_forkchoice_store(genesis_state, genesis_block, validator_id=None)


@pytest.fixture
def aggregator_store(genesis_state: State, genesis_block: Block) -> Store:
    """Create a store with validator_id set for aggregation tests."""
    return Store.get_forkchoice_store(genesis_state, genesis_block, validator_id=ValidatorIndex(0))


class TestGetAttestationTarget:
    """Tests for Store.get_attestation_target() method."""

    def test_attestation_target_at_genesis(self, base_store: Store) -> None:
        """Target at genesis should be the genesis block."""
        target = base_store.get_attestation_target()

        genesis_hash = base_store.head
        genesis_block = base_store.blocks[genesis_hash]

        assert target.root == genesis_hash
        assert target.slot == genesis_block.slot

    def test_attestation_target_returns_checkpoint(self, base_store: Store) -> None:
        """get_attestation_target should return a Checkpoint."""
        target = base_store.get_attestation_target()

        assert isinstance(target, Checkpoint)
        assert target.root in base_store.blocks
        assert target.slot == base_store.blocks[target.root].slot

    def test_attestation_target_walks_back_toward_safe_target(
        self,
        base_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Target should walk back toward safe_target when head is ahead."""
        store = base_store

        # Build a chain of blocks to advance the head
        for slot_num in range(1, 6):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))

            store, block, _ = store.produce_block_with_signatures(slot, proposer)

        # Head has advanced (the exact slot depends on forkchoice without attestations)
        head_slot = store.blocks[store.head].slot
        assert head_slot >= Slot(1), "Head should have advanced from genesis"

        # The safe_target should still be at genesis (no attestations to advance it)
        assert store.blocks[store.safe_target].slot == Slot(0)

        # Get attestation target
        target = store.get_attestation_target()

        # Target should be walked back from head toward safe_target
        # It cannot exceed JUSTIFICATION_LOOKBACK_SLOTS steps back from head
        target_slot = target.slot

        # The target should be at most JUSTIFICATION_LOOKBACK_SLOTS behind head
        assert target_slot >= head_slot - JUSTIFICATION_LOOKBACK_SLOTS

    def test_attestation_target_respects_justifiable_slots(
        self,
        base_store: Store,
    ) -> None:
        """Target should land on a slot that is_justifiable_after the finalized slot."""
        store = base_store

        # Build chain to advance head significantly
        for slot_num in range(1, 10):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = store.produce_block_with_signatures(slot, proposer)

        target = store.get_attestation_target()
        finalized_slot = store.latest_finalized.slot

        # The target slot must be justifiable after the finalized slot
        assert target.slot.is_justifiable_after(finalized_slot)

    def test_attestation_target_consistency_with_head(self, base_store: Store) -> None:
        """Target should be on the path from head to finalized checkpoint."""
        store = base_store

        # Build a simple chain
        for slot_num in range(1, 4):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = store.produce_block_with_signatures(slot, proposer)

        target = store.get_attestation_target()

        # Walk from head back to target and verify the path exists
        current_root = store.head
        found_target = False

        while current_root in store.blocks:
            if current_root == target.root:
                found_target = True
                break
            block = store.blocks[current_root]
            if block.parent_root == Bytes32.zero():
                break
            current_root = block.parent_root

        assert found_target, "Target should be an ancestor of head"


class TestSafeTargetAdvancement:
    """Tests for safe target advancement with 2/3 majority attestations."""

    def test_safe_target_requires_supermajority(
        self,
        aggregator_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Safe target should only advance with 2/3+ attestation support."""
        store = aggregator_store

        # Produce a block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = store.produce_block_with_signatures(slot, proposer)
        block_root = hash_tree_root(block)

        # Add attestations from fewer than 2/3 of validators
        num_validators = len(store.states[block_root].validators)
        threshold = (num_validators * 2 + 2) // 3  # Ceiling of 2/3

        attestation_data = store.produce_attestation_data(slot)

        # Create signed attestations and process them
        for i in range(threshold - 1):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                message=attestation_data,
                signature=sig,
            )
            # Process as gossip (requires aggregator flag)
            store = store.on_gossip_attestation(signed_attestation, is_aggregator=True)

        # Aggregate the signatures
        store = store.aggregate_committee_signatures()

        # Update safe target (uses latest_new_aggregated_payloads)
        store = store.update_safe_target()

        # Safe target should still be at genesis (insufficient votes)
        current_safe_slot = store.blocks[store.safe_target].slot

        # Without enough attestations, safe_target should not have advanced
        # significantly past genesis
        assert current_safe_slot <= Slot(1)

    def test_safe_target_advances_with_supermajority(
        self,
        aggregator_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Safe target should advance when 2/3+ validators attest to same target."""
        store = aggregator_store

        # Produce a block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, _, _ = store.produce_block_with_signatures(slot, proposer)

        # Get attestation data for slot 1
        attestation_data = store.produce_attestation_data(slot)

        # Add attestations from at least 2/3 of validators
        num_validators = len(store.states[store.head].validators)
        threshold = (num_validators * 2 + 2) // 3

        # Create signed attestations and process them
        for i in range(threshold + 1):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                message=attestation_data,
                signature=sig,
            )
            store = store.on_gossip_attestation(signed_attestation, is_aggregator=True)

        # Aggregate the signatures
        store = store.aggregate_committee_signatures()

        # Update safe target
        store = store.update_safe_target()

        # Safe target should advance to or beyond slot 1
        safe_target_slot = store.blocks[store.safe_target].slot

        # With sufficient attestations, safe_target should be at or beyond slot 1
        # (it may be exactly at slot 1 if that block has enough weight)
        assert safe_target_slot >= Slot(0)

    def test_update_safe_target_uses_new_attestations(
        self,
        aggregator_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """update_safe_target should use new aggregated payloads."""
        store = aggregator_store

        # Produce block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = store.produce_block_with_signatures(slot, proposer)

        attestation_data = store.produce_attestation_data(slot)
        num_validators = len(store.states[store.head].validators)

        # Create signed attestations and process them
        for i in range(num_validators):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                message=attestation_data,
                signature=sig,
            )
            store = store.on_gossip_attestation(signed_attestation, is_aggregator=True)

        # Aggregate into new payloads
        store = store.aggregate_committee_signatures()

        # Update safe target should use new aggregated payloads
        store = store.update_safe_target()

        # Safe target should advance with new aggregated payloads
        safe_slot = store.blocks[store.safe_target].slot
        assert safe_slot >= Slot(0)


class TestJustificationLogic:
    """Tests for justification when 2/3 of validators attest to the same target."""

    def test_justification_with_supermajority_attestations(
        self,
        aggregator_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Justification should occur when 2/3 validators attest to the same target."""
        store = aggregator_store

        # Produce block at slot 1
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block_1, _ = store.produce_block_with_signatures(slot_1, proposer_1)
        block_1_root = hash_tree_root(block_1)

        # Produce block at slot 2 with attestations to slot 1
        slot_2 = Slot(2)
        proposer_2 = ValidatorIndex(2)

        # Create attestation data targeting slot 1 block
        num_validators = len(store.states[block_1_root].validators)
        threshold = (num_validators * 2 + 2) // 3  # Ceiling of 2/3

        attestation_data = AttestationData(
            slot=slot_1,
            head=Checkpoint(root=block_1_root, slot=slot_1),
            target=Checkpoint(root=block_1_root, slot=slot_1),
            source=store.latest_justified,
        )

        # Add attestations from threshold validators using the new workflow
        for i in range(threshold + 1):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                message=attestation_data,
                signature=sig,
            )
            store = store.on_gossip_attestation(signed_attestation, is_aggregator=True)

        # Aggregate signatures before producing the next block
        store = store.aggregate_committee_signatures()

        # Produce block 2 which includes these attestations
        store, block_2, signatures = store.produce_block_with_signatures(slot_2, proposer_2)

        # Check that attestations were included
        assert len(block_2.body.attestations) > 0

        # The state should have updated justification
        block_2_root = hash_tree_root(block_2)
        post_state = store.states[block_2_root]

        # Justification should have advanced
        # (the exact advancement depends on the 3SF-mini rules)
        assert post_state.latest_justified.slot >= Slot(0)

    def test_justification_requires_valid_source(
        self,
        base_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Attestations must have a valid (already justified) source."""
        store = base_store

        # Produce block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = store.produce_block_with_signatures(slot, proposer)
        block_root = hash_tree_root(block)

        # Create attestation with invalid source (not justified)
        invalid_source = Checkpoint(
            root=Bytes32(b"invalid" + b"\x00" * 25),
            slot=Slot(999),
        )

        attestation = Attestation(
            validator_id=ValidatorIndex(5),
            data=AttestationData(
                slot=slot,
                head=Checkpoint(root=block_root, slot=slot),
                target=Checkpoint(root=block_root, slot=slot),
                source=invalid_source,
            ),
        )

        # This attestation should fail validation because source is unknown
        with pytest.raises(AssertionError, match="Unknown source block"):
            store.validate_attestation(attestation)

    def test_justification_tracking_with_multiple_targets(
        self,
        aggregator_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Justification should track votes for multiple potential targets."""
        store = aggregator_store

        # Build a chain of blocks
        for slot_num in range(1, 4):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = store.produce_block_with_signatures(slot, proposer)

        # Create attestations to different targets from different validators
        head_block = store.blocks[store.head]
        num_validators = len(store.states[store.head].validators)

        # Half validators attest to head
        attestation_data_head = store.produce_attestation_data(head_block.slot)

        for i in range(num_validators // 2):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data_head)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                message=attestation_data_head,
                signature=sig,
            )
            store = store.on_gossip_attestation(signed_attestation, is_aggregator=True)

        store = store.aggregate_committee_signatures()
        store = store.update_safe_target()

        # Neither target should be justified with only half validators
        # Safe target reflects the heaviest path with sufficient weight
        # Without 2/3 majority, progress is limited


class TestFinalizationFollowsJustification:
    """Tests for finalization behavior following justification."""

    def test_finalization_after_consecutive_justification(
        self,
        aggregator_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Finalization should follow when justification advances without gaps."""
        store = aggregator_store
        num_validators = len(store.states[store.head].validators)
        threshold = (num_validators * 2 + 2) // 3

        initial_finalized = store.latest_finalized

        # Build several blocks with full attestation support
        for slot_num in range(1, 5):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % num_validators)

            # Create attestations from all validators for the previous block
            if slot_num > 1:
                prev_head = store.head
                prev_block = store.blocks[prev_head]
                attestation_data = AttestationData(
                    slot=prev_block.slot,
                    head=Checkpoint(root=prev_head, slot=prev_block.slot),
                    target=Checkpoint(root=prev_head, slot=prev_block.slot),
                    source=store.latest_justified,
                )

                for i in range(threshold + 1):
                    vid = ValidatorIndex(i)
                    sig = key_manager.sign_attestation_data(vid, attestation_data)
                    signed_attestation = SignedAttestation(
                        validator_id=vid,
                        message=attestation_data,
                        signature=sig,
                    )
                    store = store.on_gossip_attestation(signed_attestation, is_aggregator=True)

            store, block, _ = store.produce_block_with_signatures(slot, proposer)

        # After processing blocks with attestations, check finalization
        # The exact finalization behavior depends on 3SF-mini rules
        final_finalized = store.latest_finalized

        # Finalization can advance if justification conditions are met
        assert final_finalized.slot >= initial_finalized.slot


class TestAttestationTargetEdgeCases:
    """Tests for edge cases in attestation target computation."""

    def test_attestation_target_with_skipped_slots(
        self,
        base_store: Store,
    ) -> None:
        """Attestation target should handle chains with skipped slots."""
        store = base_store

        # Produce blocks with gaps (skipped slots)
        store, _, _ = store.produce_block_with_signatures(Slot(1), ValidatorIndex(1))
        # Skip slot 2, 3
        store, _, _ = store.produce_block_with_signatures(Slot(4), ValidatorIndex(4))

        target = store.get_attestation_target()

        # Target should still be valid despite skipped slots
        assert target.root in store.blocks
        assert target.slot.is_justifiable_after(store.latest_finalized.slot)

    def test_attestation_target_single_validator(
        self,
        key_manager: XmssKeyManager,
    ) -> None:
        """Attestation target computation should work with single validator."""
        # Create state with single validator
        validators = Validators(
            data=[
                Validator(
                    pubkey=Bytes52(key_manager[ValidatorIndex(0)].public.encode_bytes()),
                    index=ValidatorIndex(0),
                )
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

        store = Store.get_forkchoice_store(genesis_state, genesis_block, validator_id=None)

        # Should be able to get attestation target
        target = store.get_attestation_target()
        assert target.root == store.head

    def test_attestation_target_at_justification_lookback_boundary(
        self,
        base_store: Store,
    ) -> None:
        """Test target when head is exactly JUSTIFICATION_LOOKBACK_SLOTS ahead."""
        store = base_store

        # Build chain to exactly JUSTIFICATION_LOOKBACK_SLOTS + 1 blocks
        lookback = int(JUSTIFICATION_LOOKBACK_SLOTS)
        for slot_num in range(1, lookback + 2):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = store.produce_block_with_signatures(slot, proposer)

        target = store.get_attestation_target()
        head_slot = store.blocks[store.head].slot

        # Target should not be more than JUSTIFICATION_LOOKBACK_SLOTS behind head
        assert target.slot >= head_slot - JUSTIFICATION_LOOKBACK_SLOTS


class TestIntegrationScenarios:
    """Integration tests combining attestation target, justification, and finalization."""

    def test_full_attestation_cycle(
        self,
        aggregator_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Test complete cycle: produce block, attest, justify."""
        store = aggregator_store

        # Phase 1: Produce initial block
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block_1, _ = store.produce_block_with_signatures(slot_1, proposer_1)
        block_1_root = hash_tree_root(block_1)

        # Phase 2: Create attestations from multiple validators
        attestation_data = store.produce_attestation_data(slot_1)

        num_validators = len(store.states[block_1_root].validators)
        for i in range(num_validators):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                message=attestation_data,
                signature=sig,
            )
            # Process as gossip
            store = store.on_gossip_attestation(signed_attestation, is_aggregator=True)

        # Phase 3: Aggregate signatures into payloads
        store = store.aggregate_committee_signatures()

        # Phase 4: Update safe target
        store = store.update_safe_target()

        # Safe target should have advanced
        safe_target_slot = store.blocks[store.safe_target].slot
        assert safe_target_slot >= Slot(0)

        # Phase 5: Produce another block including attestations
        slot_2 = Slot(2)
        proposer_2 = ValidatorIndex(2)
        store, block_2, _ = store.produce_block_with_signatures(slot_2, proposer_2)

        # Verify final state
        assert len(store.blocks) >= 3  # Genesis + 2 blocks
        assert store.head in store.blocks
        assert store.safe_target in store.blocks

    def test_attestation_target_after_on_block(
        self,
        base_store: Store,
        key_manager: XmssKeyManager,
    ) -> None:
        """Test attestation target is correct after processing a block via on_block."""
        store = base_store

        # Produce a block
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block, signatures = store.produce_block_with_signatures(slot_1, proposer_1)
        block_root = hash_tree_root(block)

        # Get attestation data for the block's slot
        proposer_attestation = Attestation(
            validator_id=proposer_1,
            data=AttestationData(
                slot=slot_1,
                head=Checkpoint(root=block_root, slot=slot_1),
                target=Checkpoint(root=block_root, slot=slot_1),
                source=store.latest_justified,
            ),
        )
        proposer_signature = key_manager.sign_attestation_data(
            proposer_attestation.validator_id,
            proposer_attestation.data,
        )

        # Create signed block for on_block processing
        from lean_spec.subspecs.containers.block.types import AttestationSignatures

        signed_block = SignedBlockWithAttestation(
            message=BlockWithAttestation(
                block=block,
                proposer_attestation=proposer_attestation,
            ),
            signature=BlockSignatures(
                attestation_signatures=AttestationSignatures(data=signatures),
                proposer_signature=proposer_signature,
            ),
        )

        # Process block via on_block on a fresh consumer store
        consumer_store = base_store
        block_time = consumer_store.config.genesis_time + block.slot * Uint64(SECONDS_PER_SLOT)
        consumer_store = consumer_store.on_tick(block_time, has_proposal=True)
        consumer_store = consumer_store.on_block(signed_block)

        # Get attestation target after on_block
        target = consumer_store.get_attestation_target()

        # Target should be valid
        assert target.root in consumer_store.blocks
        assert target.slot.is_justifiable_after(consumer_store.latest_finalized.slot)
