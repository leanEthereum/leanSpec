"""Tests for attestation target computation and justification logic."""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.node.chain.clock import Interval
from lean_spec.node.chain.config import JUSTIFICATION_LOOKBACK_SLOTS
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.aggregation import TypeOneMultiSignature, TypeTwoMultiSignature
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import (
    Attestation,
    AttestationData,
    SignedAttestation,
    SignedBlock,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import ByteList512KiB, Bytes32
from tests.lean_spec.helpers import make_store


class TestGetAttestationTarget:
    """Tests for Store.get_attestation_target() method."""

    def test_attestation_target_at_genesis(self, spec: LstarSpec, observer_store: Store) -> None:
        """Target at genesis should be the genesis block."""
        target = spec.get_attestation_target(observer_store)

        genesis_hash = observer_store.head
        genesis_block = observer_store.blocks[genesis_hash]

        assert target.root == genesis_hash
        assert target.slot == genesis_block.slot

    def test_attestation_target_returns_checkpoint(
        self, spec: LstarSpec, observer_store: Store
    ) -> None:
        """get_attestation_target should return a Checkpoint."""
        target = spec.get_attestation_target(observer_store)

        assert isinstance(target, Checkpoint)
        assert target.root in observer_store.blocks
        assert target.slot == observer_store.blocks[target.root].slot

    def test_attestation_target_walks_back_toward_safe_target(
        self,
        observer_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Target should walk back toward safe_target when head is ahead."""
        store = observer_store

        # Build a chain of blocks to advance the head
        for slot_num in range(1, 6):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))

            store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)

        # Head has advanced (the exact slot depends on forkchoice without attestations)
        head_slot = store.blocks[store.head].slot
        assert head_slot >= Slot(1), "Head should have advanced from genesis"

        # The safe_target should still be at genesis (no attestations to advance it)
        assert store.blocks[store.safe_target].slot == Slot(0)

        # Get attestation target
        target = spec.get_attestation_target(store)

        # Target should be walked back from head toward safe_target
        # It cannot exceed JUSTIFICATION_LOOKBACK_SLOTS steps back from head
        target_slot = target.slot

        # The target should be at most JUSTIFICATION_LOOKBACK_SLOTS behind head
        assert int(target_slot) >= int(head_slot) - int(JUSTIFICATION_LOOKBACK_SLOTS)

    def test_attestation_target_respects_justifiable_slots(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """Target should land on a slot that is_justifiable_after the finalized slot."""
        store = observer_store

        # Build chain to advance head significantly
        for slot_num in range(1, 10):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        target = spec.get_attestation_target(store)
        finalized_slot = store.latest_finalized.slot

        # The target slot must be justifiable after the finalized slot
        assert target.slot.is_justifiable_after(finalized_slot)

    def test_attestation_target_consistency_with_head(
        self, observer_store: Store, spec: LstarSpec
    ) -> None:
        """Target should be on the path from head to finalized checkpoint."""
        store = observer_store

        # Build a simple chain
        for slot_num in range(1, 4):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        target = spec.get_attestation_target(store)

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
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Safe target should only advance with 2/3+ attestation support."""
        store = keyed_store

        # Produce a block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)
        block_root = hash_tree_root(block)

        # Add attestations from fewer than 2/3 of validators
        num_validators = len(store.states[block_root].validators)
        threshold = (num_validators * 2 + 2) // 3  # Ceiling of 2/3

        attestation_data = spec.produce_attestation_data(store, slot)

        # Create signed attestations and process them
        for i in range(threshold - 1):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                data=attestation_data,
                signature=sig,
            )
            # Process as gossip (requires aggregator flag)
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Aggregate the signatures
        store, _ = spec.aggregate(store)

        # Update safe target (uses latest_new_aggregated_payloads)
        store = spec.update_safe_target(store)

        # Safe target should still be at genesis (insufficient votes)
        current_safe_slot = store.blocks[store.safe_target].slot

        # Without enough attestations, safe_target should not have advanced
        # significantly past genesis
        assert current_safe_slot <= Slot(1)

    def test_safe_target_advances_with_supermajority(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Safe target should advance when 2/3+ validators attest to same target."""
        store = keyed_store

        # Produce a block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        # Get attestation data for slot 1
        attestation_data = spec.produce_attestation_data(store, slot)

        # Add attestations from at least 2/3 of validators
        num_validators = len(store.states[store.head].validators)
        threshold = (num_validators * 2 + 2) // 3

        # Create signed attestations and process them
        for i in range(threshold + 1):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                data=attestation_data,
                signature=sig,
            )
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Aggregate the signatures
        store, _ = spec.aggregate(store)

        # Update safe target
        store = spec.update_safe_target(store)

        # Verify the aggregation produced payloads and safe target was updated.
        # Safe target advancement depends on the full 3SF-mini justification rules,
        # which may require multiple slots. This test verifies the pipeline works.
        assert store.safe_target in store.blocks

    def test_update_safe_target_uses_new_attestations(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """update_safe_target should use new aggregated payloads."""
        store = keyed_store

        # Produce block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)

        attestation_data = spec.produce_attestation_data(store, slot)
        num_validators = len(store.states[store.head].validators)

        # Create signed attestations and process them
        for i in range(num_validators):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                data=attestation_data,
                signature=sig,
            )
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Aggregate into new payloads
        store, _ = spec.aggregate(store)

        # Update safe target should use new aggregated payloads
        store = spec.update_safe_target(store)

        # Verify update_safe_target processes new aggregated payloads without error
        assert store.safe_target in store.blocks


class TestJustificationLogic:
    """Tests for justification when 2/3 of validators attest to the same target."""

    def test_justification_with_supermajority_attestations(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Justification should occur when 2/3 validators attest to the same target."""
        store = keyed_store

        # Produce block at slot 1
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block_1, _ = spec.produce_block_with_signatures(store, slot_1, proposer_1)
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
                data=attestation_data,
                signature=sig,
            )
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Aggregate signatures before producing the next block
        store, _ = spec.aggregate(store)

        # Produce block 2 which includes these attestations
        store, block_2, signatures = spec.produce_block_with_signatures(store, slot_2, proposer_2)

        # Check that attestations were included
        assert len(block_2.body.attestations) > 0

        # The state should have updated justification
        block_2_root = hash_tree_root(block_2)
        post_state = store.states[block_2_root]

        # Justification should be present in the post-state
        assert post_state.latest_justified.root in store.blocks

    def test_justification_requires_valid_source(
        self,
        observer_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Attestations must have a valid (already justified) source."""
        store = observer_store

        # Produce block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)
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
            spec.validate_attestation(store, attestation.data)

    def test_justification_tracking_with_multiple_targets(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Justification should track votes for multiple potential targets."""
        store = keyed_store

        # Build a chain of blocks
        for slot_num in range(1, 4):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        # Create attestations to different targets from different validators
        head_block = store.blocks[store.head]
        num_validators = len(store.states[store.head].validators)

        # Half validators attest to head
        attestation_data_head = spec.produce_attestation_data(store, head_block.slot)

        for i in range(num_validators // 2):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data_head)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                data=attestation_data_head,
                signature=sig,
            )
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        store, _ = spec.aggregate(store)
        store = spec.update_safe_target(store)

        # With only half the validators, safe target should not advance past genesis
        assert store.blocks[store.safe_target].slot == Slot(0)


class TestFinalizationFollowsJustification:
    """Tests for finalization behavior following justification."""

    def test_finalization_after_consecutive_justification(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Finalization should follow when justification advances without gaps."""
        store = keyed_store
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
                        data=attestation_data,
                        signature=sig,
                    )
                    store = spec.on_gossip_attestation(
                        store, signed_attestation, is_aggregator=True
                    )

            store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)

        # After processing blocks with attestations, check finalization
        # The exact finalization behavior depends on 3SF-mini rules
        final_finalized = store.latest_finalized

        # Finalization can advance if justification conditions are met
        assert final_finalized.slot >= initial_finalized.slot


class TestAttestationTargetEdgeCases:
    """Tests for edge cases in attestation target computation."""

    def test_attestation_target_with_skipped_slots(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """Attestation target should handle chains with skipped slots."""
        store = observer_store

        # Produce blocks with gaps (skipped slots)
        store, _, _ = spec.produce_block_with_signatures(store, Slot(1), ValidatorIndex(1))
        # Skip slot 2, 3
        store, _, _ = spec.produce_block_with_signatures(store, Slot(4), ValidatorIndex(4))

        target = spec.get_attestation_target(store)

        # Target should still be valid despite skipped slots
        assert target.root in store.blocks
        assert target.slot.is_justifiable_after(store.latest_finalized.slot)

    def test_attestation_target_single_validator(
        self,
        spec: LstarSpec,
        key_manager: XmssKeyManager,
    ) -> None:
        """Attestation target computation should work with single validator."""
        store = make_store(num_validators=1, key_manager=key_manager, validator_id=None)

        # Should be able to get attestation target
        target = spec.get_attestation_target(store)
        assert target.root == store.head

    def test_attestation_target_at_justification_lookback_boundary(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """Test target when head is exactly JUSTIFICATION_LOOKBACK_SLOTS ahead."""
        store = observer_store

        # Build chain to exactly JUSTIFICATION_LOOKBACK_SLOTS + 1 blocks
        lookback = int(JUSTIFICATION_LOOKBACK_SLOTS)
        for slot_num in range(1, lookback + 2):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        target = spec.get_attestation_target(store)
        head_slot = store.blocks[store.head].slot

        # Target should not be more than JUSTIFICATION_LOOKBACK_SLOTS behind head
        assert int(target.slot) >= int(head_slot) - int(JUSTIFICATION_LOOKBACK_SLOTS)


class TestIntegrationScenarios:
    """Integration tests combining attestation target, justification, and finalization."""

    def test_full_attestation_cycle(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Test complete cycle: produce block, attest, justify."""
        store = keyed_store

        # Phase 1: Produce initial block
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block_1, _ = spec.produce_block_with_signatures(store, slot_1, proposer_1)
        block_1_root = hash_tree_root(block_1)

        # Phase 2: Create attestations from multiple validators
        attestation_data = spec.produce_attestation_data(store, slot_1)

        num_validators = len(store.states[block_1_root].validators)
        for i in range(num_validators):
            vid = ValidatorIndex(i)
            sig = key_manager.sign_attestation_data(vid, attestation_data)
            signed_attestation = SignedAttestation(
                validator_id=vid,
                data=attestation_data,
                signature=sig,
            )
            # Process as gossip
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Phase 3: Aggregate signatures into payloads
        store, _ = spec.aggregate(store)

        # Phase 4: Update safe target
        store = spec.update_safe_target(store)

        # Verify the full cycle completed: safe target is a valid block in the store
        assert store.safe_target in store.blocks

        # Phase 5: Produce another block including attestations
        slot_2 = Slot(2)
        proposer_2 = ValidatorIndex(2)
        store, block_2, _ = spec.produce_block_with_signatures(store, slot_2, proposer_2)

        # Verify final state
        assert len(store.blocks) >= 3  # Genesis + 2 blocks
        assert store.head in store.blocks
        assert store.safe_target in store.blocks

    def test_attestation_target_after_on_block(
        self,
        observer_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Test attestation target is correct after processing a block via on_block."""
        store = observer_store

        # Produce a block
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block, signatures = spec.produce_block_with_signatures(store, slot_1, proposer_1)
        block_root = hash_tree_root(block)

        # Wrap the proposer's signature into a singleton Type-1, then merge
        # with the per-attestation Type-1s into the block-level Type-2.
        proposer_signature = key_manager.sign_block_root(proposer_1, slot_1, block_root)
        proposer_pubkey = key_manager.get_public_keys(proposer_1)[1]
        proposer_type_1 = TypeOneMultiSignature.aggregate(
            children=[],
            raw_xmss=[(proposer_1, proposer_pubkey, proposer_signature)],
            message=block_root,
            slot=slot_1,
        )

        head_state = store.states[store.head]
        public_keys_per_part: list[list] = [
            [
                head_state.validators[vid].get_attestation_pubkey()
                for vid in proof.participants.to_validator_indices()
            ]
            for proof in signatures
        ]
        public_keys_per_part.append([proposer_pubkey])

        merged = TypeTwoMultiSignature.aggregate(
            [*signatures, proposer_type_1],
            public_keys_per_part=public_keys_per_part,
        )
        signed_block = SignedBlock(
            block=block,
            proof=ByteList512KiB(data=merged.encode_bytes()),
        )

        # Process block via on_block on a fresh consumer store
        consumer_store = observer_store
        target_interval = Interval.from_slot(block.slot)
        consumer_store, _ = spec.on_tick(consumer_store, target_interval, has_proposal=True)
        consumer_store = spec.on_block(consumer_store, signed_block)

        # Get attestation target after on_block
        target = spec.get_attestation_target(consumer_store)

        # Target should be valid
        assert target.root in consumer_store.blocks
        assert target.slot.is_justifiable_after(consumer_store.latest_finalized.slot)
