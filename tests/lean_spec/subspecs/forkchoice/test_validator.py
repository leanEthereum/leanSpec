"""Tests for validator block production and attestation functionality."""

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    Checkpoint,
    Config,
    SignedAttestation,
    ValidatorIndex,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import GossipSignatureEntry, Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import TEST_VALIDATOR_ID, make_aggregated_proof, make_store


class TestBlockProduction:
    """Test validator block production functionality."""

    def test_produce_block_basic(self, sample_store: Store) -> None:
        """Test basic block production by authorized proposer."""
        slot = Slot(1)
        validator_idx = ValidatorIndex(1)  # Proposer for slot 1

        store, block, _signatures = sample_store.produce_block_with_signatures(slot, validator_idx)
        # Verify block structure
        assert block.slot == slot
        assert block.proposer_index == validator_idx
        assert block.parent_root == sample_store.head
        assert isinstance(block.body, BlockBody)
        assert block.state_root != Bytes32.zero()  # Should have computed state root

        # Verify block was added to store
        block_hash = hash_tree_root(block)
        assert block_hash in store.blocks
        assert block_hash in store.states

    def test_produce_block_unauthorized_proposer(self, sample_store: Store) -> None:
        """Test block production fails for unauthorized proposer."""
        slot = Slot(1)
        wrong_validator = ValidatorIndex(2)  # Not proposer for slot 1

        with pytest.raises(AssertionError, match="is not the proposer for slot"):
            sample_store.produce_block_with_signatures(slot, wrong_validator)

    def test_produce_block_with_attestations(
        self, sample_store: Store, key_manager: XmssKeyManager
    ) -> None:
        """Test block production includes available attestations."""
        head_block = sample_store.blocks[sample_store.head]

        # Add some attestations to the store
        head_checkpoint = Checkpoint(root=sample_store.head, slot=head_block.slot)
        data_5 = AttestationData(
            slot=head_block.slot,
            head=head_checkpoint,
            target=sample_store.get_attestation_target(),
            source=sample_store.latest_justified,
        )
        signed_5 = SignedAttestation(
            validator_id=ValidatorIndex(5),
            data=data_5,
            signature=key_manager.sign_attestation_data(ValidatorIndex(5), data_5),
        )
        data_6 = AttestationData(
            slot=head_block.slot,
            head=head_checkpoint,
            target=sample_store.get_attestation_target(),
            source=sample_store.latest_justified,
        )
        signed_6 = SignedAttestation(
            validator_id=ValidatorIndex(6),
            data=data_6,
            signature=key_manager.sign_attestation_data(ValidatorIndex(6), data_6),
        )

        proof_5 = make_aggregated_proof(key_manager, [ValidatorIndex(5)], signed_5.data)
        proof_6 = make_aggregated_proof(key_manager, [ValidatorIndex(6)], signed_6.data)

        # Build payloads keyed by attestation data.
        # If data_5 == data_6 (same slot/head/target/source), they share a key.
        known_payloads: dict[AttestationData, set[AggregatedSignatureProof]] = {}
        known_payloads.setdefault(signed_5.data, set()).add(proof_5)
        known_payloads.setdefault(signed_6.data, set()).add(proof_6)

        gossip_sigs = {}
        gossip_sigs.setdefault(signed_5.data, set()).add(
            GossipSignatureEntry(ValidatorIndex(5), signed_5.signature)
        )
        gossip_sigs.setdefault(signed_6.data, set()).add(
            GossipSignatureEntry(ValidatorIndex(6), signed_6.signature)
        )

        sample_store = sample_store.model_copy(
            update={
                "latest_known_aggregated_payloads": known_payloads,
                "gossip_signatures": gossip_sigs,
            }
        )

        slot = Slot(2)
        validator_idx = ValidatorIndex(2)  # Proposer for slot 2

        store, block, signatures = sample_store.produce_block_with_signatures(
            slot,
            validator_idx,
        )

        # Block should include the attestations we added.
        # Attestations may be aggregated, so check the count matches.
        assert len(block.body.attestations) == len(signatures)

        # Verify block structure is correct
        assert block.slot == slot
        assert block.proposer_index == validator_idx
        assert block.state_root != Bytes32.zero()

        # Verify each aggregated signature proof
        for agg_att, proof in zip(block.body.attestations.data, signatures, strict=True):
            participants = proof.participants.to_validator_indices()
            public_keys = [key_manager.get_public_key(vid) for vid in participants]
            proof.verify(
                public_keys=public_keys,
                message=agg_att.data.data_root_bytes(),
                slot=agg_att.data.slot,
            )

    def test_produce_block_sequential_slots(self, sample_store: Store) -> None:
        """Test producing blocks in sequential slots."""
        # Produce block for slot 1
        sample_store, block1, _signatures1 = sample_store.produce_block_with_signatures(
            Slot(1),
            ValidatorIndex(1),
        )
        block1_hash = hash_tree_root(block1)

        # Verify first block is properly created
        assert block1.slot == Slot(1)
        assert block1.proposer_index == ValidatorIndex(1)
        assert block1_hash in sample_store.blocks
        assert block1_hash in sample_store.states

        # Without any attestations, the forkchoice will stay on genesis
        # This is the expected behavior: block1 exists but isn't the head
        # So block2 should build on genesis, not block1

        # Produce block for slot 2 (will build on genesis due to forkchoice)
        sample_store, block2, _signatures2 = sample_store.produce_block_with_signatures(
            Slot(2),
            ValidatorIndex(2),
        )

        # Verify block properties
        assert block2.slot == Slot(2)
        assert block2.proposer_index == ValidatorIndex(2)

        # The parent should be genesis (the current head), not block1
        genesis_hash = sample_store.head
        assert block2.parent_root == genesis_hash

        # Both blocks should exist in the store
        block2_hash = hash_tree_root(block2)
        assert block1_hash in sample_store.blocks
        assert block2_hash in sample_store.blocks
        assert genesis_hash in sample_store.blocks

    def test_produce_block_empty_attestations(self, sample_store: Store) -> None:
        """Test block production with no available attestations."""
        slot = Slot(3)
        validator_idx = ValidatorIndex(3)

        # Ensure no attestations in store (clear aggregated payloads)
        sample_store = sample_store.model_copy(
            update={
                "latest_known_aggregated_payloads": {},
            }
        )

        store, block, _signatures = sample_store.produce_block_with_signatures(
            slot,
            validator_idx,
        )

        # Should produce valid block with empty attestations
        assert len(block.body.attestations) == 0
        assert block.slot == slot
        assert block.proposer_index == validator_idx
        assert block.state_root != Bytes32.zero()

    def test_produce_block_state_consistency(
        self, sample_store: Store, key_manager: XmssKeyManager
    ) -> None:
        """Test that produced block's state is consistent with block content."""
        slot = Slot(4)
        validator_idx = ValidatorIndex(4)

        # Add some attestations to test state computation
        head_block = sample_store.blocks[sample_store.head]
        head_checkpoint = Checkpoint(root=sample_store.head, slot=head_block.slot)
        data_7 = AttestationData(
            slot=head_block.slot,
            head=head_checkpoint,
            target=sample_store.get_attestation_target(),
            source=sample_store.latest_justified,
        )
        signed_7 = SignedAttestation(
            validator_id=ValidatorIndex(7),
            data=data_7,
            signature=key_manager.sign_attestation_data(ValidatorIndex(7), data_7),
        )

        proof_7 = make_aggregated_proof(key_manager, [ValidatorIndex(7)], signed_7.data)

        sample_store = sample_store.model_copy(
            update={
                "latest_known_aggregated_payloads": {signed_7.data: {proof_7}},
                "gossip_signatures": {
                    signed_7.data: {GossipSignatureEntry(ValidatorIndex(7), signed_7.signature)},
                },
            }
        )

        store, block, signatures = sample_store.produce_block_with_signatures(
            slot,
            validator_idx,
        )
        block_hash = hash_tree_root(block)

        # Verify the stored state matches the block's state root
        stored_state = store.states[block_hash]
        assert hash_tree_root(stored_state) == block.state_root

        # Verify each aggregated signature proof
        for agg_att, proof in zip(block.body.attestations.data, signatures, strict=True):
            participants = proof.participants.to_validator_indices()
            public_keys = [key_manager.get_public_key(vid) for vid in participants]
            proof.verify(
                public_keys=public_keys,
                message=agg_att.data.data_root_bytes(),
                slot=agg_att.data.slot,
            )


class TestValidatorIntegration:
    """Test integration between block production and attestations."""

    def test_block_production_then_attestation(self, sample_store: Store) -> None:
        """Test producing a block then creating attestation for it."""
        # Proposer produces block for slot 1
        proposer_slot = Slot(1)
        proposer_idx = ValidatorIndex(1)
        sample_store.produce_block_with_signatures(proposer_slot, proposer_idx)

        # Update store state after block production
        sample_store = sample_store.update_head()

        # Other validator creates attestation for slot 2
        attestor_slot = Slot(2)
        attestor_idx = ValidatorIndex(7)
        attestation_data = sample_store.produce_attestation_data(attestor_slot)
        attestation = Attestation(validator_id=attestor_idx, data=attestation_data)

        # Attestation should reference the new block as head (if it became head)
        assert attestation.validator_id == attestor_idx
        assert attestation.data.slot == attestor_slot

        # The attestation should be consistent with current forkchoice state
        assert attestation.data.source == sample_store.latest_justified

    def test_multiple_validators_coordination(self, sample_store: Store) -> None:
        """Test multiple validators producing blocks and attestations."""
        # Validator 1 produces block for slot 1
        sample_store, block1, _signatures1 = sample_store.produce_block_with_signatures(
            Slot(1),
            ValidatorIndex(1),
        )
        block1_hash = hash_tree_root(block1)

        # Validators 2-5 create attestations for slot 2
        # These will be based on the current forkchoice head (genesis)
        attestations = []
        for i in range(2, 6):
            attestation_data = sample_store.produce_attestation_data(Slot(2))
            attestation = Attestation(validator_id=ValidatorIndex(i), data=attestation_data)
            attestations.append(attestation)

        # All attestations should be consistent
        first_attestation = attestations[0]
        for attestation in attestations[1:]:
            assert attestation.data.head.root == first_attestation.data.head.root
            assert attestation.data.target.root == first_attestation.data.target.root
            assert attestation.data.source.root == first_attestation.data.source.root

        # Validator 2 produces next block for slot 2
        # After processing block1, head should be block1 (fork choice walks the tree)
        # So block2 will build on block1
        sample_store, block2, _signatures2 = sample_store.produce_block_with_signatures(
            Slot(2),
            ValidatorIndex(2),
        )

        # Verify block properties
        assert block2.slot == Slot(2)
        assert block2.proposer_index == ValidatorIndex(2)

        # Both blocks should exist in the store
        block2_hash = hash_tree_root(block2)
        assert block1_hash in sample_store.blocks
        assert block2_hash in sample_store.blocks

        # block1 builds on genesis, block2 builds on block1 (current head)
        # Get the original genesis hash from the store's blocks
        genesis_hash = min(
            (
                root
                for root in sample_store.blocks.keys()
                if sample_store.blocks[root].slot == Slot(0)
            ),
            key=lambda root: root,
        )
        assert block1.parent_root == genesis_hash
        assert block2.parent_root == block1_hash

    def test_validator_edge_cases(self, sample_store: Store) -> None:
        """Test edge cases in validator operations."""
        # Test with validator index equal to number of validators - 1
        max_validator = ValidatorIndex(9)  # Last validator (0-indexed, 10 total)
        slot = Slot(9)  # This validator's slot

        # Should be able to produce block
        store, block, _signatures = sample_store.produce_block_with_signatures(
            slot,
            max_validator,
        )
        assert block.proposer_index == max_validator

        # Should be able to produce attestation
        attestation_data = sample_store.produce_attestation_data(Slot(10))
        attestation = Attestation(validator_id=max_validator, data=attestation_data)
        assert attestation.validator_id == max_validator

    def test_validator_operations_empty_store(self) -> None:
        """Test validator operations with minimal store state."""
        store = make_store(num_validators=3)

        # Should be able to produce block and attestation
        store, block, _signatures = store.produce_block_with_signatures(
            Slot(1),
            ValidatorIndex(1),
        )
        attestation_data = store.produce_attestation_data(Slot(1))
        attestation = Attestation(validator_id=ValidatorIndex(2), data=attestation_data)

        assert isinstance(block, Block)
        assert isinstance(attestation, Attestation)


class TestValidatorErrorHandling:
    """Test error handling in validator operations."""

    def test_produce_block_wrong_proposer(self, sample_store: Store) -> None:
        """Test error when wrong validator tries to produce block."""
        slot = Slot(5)
        wrong_proposer = ValidatorIndex(3)  # Should be validator 5 for slot 5

        with pytest.raises(AssertionError) as exc_info:
            sample_store.produce_block_with_signatures(slot, wrong_proposer)

        assert "is not the proposer for slot" in str(exc_info.value)

    def test_produce_block_missing_parent_state(self) -> None:
        """Test error when parent state is missing."""
        config = Config(genesis_time=Uint64(1000))
        checkpoint = Checkpoint(root=Bytes32(b"missing" + b"\x00" * 25), slot=Slot(0))

        # Create store with missing parent state
        store = Store(
            time=Interval(100),
            config=config,
            head=Bytes32(b"nonexistent" + b"\x00" * 21),
            safe_target=Bytes32(b"nonexistent" + b"\x00" * 21),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            blocks={},  # No blocks
            states={},  # No states
            validator_id=TEST_VALIDATOR_ID,
        )

        with pytest.raises(KeyError):  # Missing head in get_proposal_head
            store.produce_block_with_signatures(Slot(1), ValidatorIndex(1))

    def test_validator_operations_invalid_parameters(self, sample_store: Store) -> None:
        """Test validator operations with invalid parameters."""
        # Very large validator index (should work mathematically)
        large_validator = ValidatorIndex(1000000)
        large_slot = Slot(1000000)

        # Get the state to determine number of validators
        genesis_hash = sample_store.head
        state = sample_store.states[genesis_hash]
        num_validators = len(state.validators)

        # is_proposer_for should work (though likely return False)
        result = large_validator.is_proposer_for(large_slot, Uint64(num_validators))
        assert isinstance(result, bool)

        # Attestation can be created for any validator
        attestation_data = sample_store.produce_attestation_data(Slot(1))
        attestation = Attestation(validator_id=large_validator, data=attestation_data)
        assert attestation.validator_id == large_validator
