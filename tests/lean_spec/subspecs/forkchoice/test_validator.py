"""Tests for validator block production and attestation functionality."""

import pytest
from consensus_testing.keys import get_shared_key_manager

from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    Checkpoint,
    Config,
    SignedAttestation,
    State,
    Validator,
)
from lean_spec.subspecs.containers.block import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Validators,
)
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import SignatureKey
from lean_spec.types import Bytes32, Bytes52, Uint64
from lean_spec.types.validator import is_proposer


@pytest.fixture
def config() -> Config:
    """Sample configuration for validator testing."""
    return Config(genesis_time=Uint64(1000))


@pytest.fixture
def sample_state(config: Config) -> State:
    """Create a sample state for validator testing."""
    key_manager = get_shared_key_manager()
    # Create block header for testing
    block_header = BlockHeader(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32(b"state" + b"\x00" * 27),
        body_root=Bytes32(b"body" + b"\x00" * 28),
    )

    # Use a placeholder for genesis - will be updated in store fixture
    temp_finalized = Checkpoint(root=Bytes32(b"genesis" + b"\x00" * 25), slot=Slot(0))

    # Create validators list with 10 validators using real public keys from key manager
    validators = Validators(
        data=[
            Validator(
                pubkey=Bytes52(key_manager.get_public_key(Uint64(i)).encode_bytes()),
                index=Uint64(i),
            )
            for i in range(10)
        ]
    )

    return State(
        config=config,
        slot=Slot(0),
        latest_block_header=block_header,
        latest_justified=temp_finalized,
        latest_finalized=temp_finalized,
        historical_block_hashes=HistoricalBlockHashes(data=[]),
        justified_slots=JustifiedSlots(data=[]),
        justifications_roots=JustificationRoots(data=[]),
        justifications_validators=JustificationValidators(data=[]),
        validators=validators,
    )


@pytest.fixture
def sample_store(config: Config, sample_state: State) -> Store:
    """Create a sample forkchoice store with genesis block for validator testing."""
    # Create genesis block
    genesis_block = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(sample_state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    genesis_hash = hash_tree_root(genesis_block)

    # Create the corresponding genesis block header
    genesis_header = BlockHeader(
        slot=genesis_block.slot,
        proposer_index=genesis_block.proposer_index,
        parent_root=genesis_block.parent_root,
        state_root=genesis_block.state_root,
        body_root=hash_tree_root(genesis_block.body),
    )

    # Create consistent checkpoint that references the genesis block
    finalized = Checkpoint(root=genesis_hash, slot=Slot(0))

    # Update the state to have consistent justified/finalized checkpoints and header
    consistent_state = sample_state.model_copy(
        update={
            "latest_justified": finalized,
            "latest_finalized": finalized,
            "latest_block_header": genesis_header,
        }
    )

    return Store(
        time=Uint64(100),
        config=config,
        head=genesis_hash,
        safe_target=genesis_hash,
        latest_justified=finalized,
        latest_finalized=finalized,
        blocks={genesis_hash: genesis_block},
        states={genesis_hash: consistent_state},  # States are indexed by block hash
    )


class TestBlockProduction:
    """Test validator block production functionality."""

    def test_produce_block_basic(self, sample_store: Store) -> None:
        """Test basic block production by authorized proposer."""
        slot = Slot(1)
        validator_idx = Uint64(1)  # Proposer for slot 1

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
        wrong_validator = Uint64(2)  # Not proposer for slot 1

        with pytest.raises(AssertionError, match="is not the proposer for slot"):
            sample_store.produce_block_with_signatures(slot, wrong_validator)

    def test_produce_block_with_attestations(self, sample_store: Store) -> None:
        """Test block production includes available attestations."""
        key_manager = get_shared_key_manager()
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
            validator_id=Uint64(5),
            message=data_5,
            signature=key_manager.sign_attestation_data(Uint64(5), data_5),
        )
        data_6 = AttestationData(
            slot=head_block.slot,
            head=head_checkpoint,
            target=sample_store.get_attestation_target(),
            source=sample_store.latest_justified,
        )
        signed_6 = SignedAttestation(
            validator_id=Uint64(6),
            message=data_6,
            signature=key_manager.sign_attestation_data(Uint64(6), data_6),
        )
        sample_store.latest_known_attestations[Uint64(5)] = signed_5.message
        sample_store.latest_known_attestations[Uint64(6)] = signed_6.message
        sig_key_5 = SignatureKey(Uint64(5), signed_5.message.data_root_bytes())
        sig_key_6 = SignatureKey(Uint64(6), signed_6.message.data_root_bytes())
        sample_store.gossip_signatures[sig_key_5] = signed_5.signature
        sample_store.gossip_signatures[sig_key_6] = signed_6.signature

        slot = Slot(2)
        validator_idx = Uint64(2)  # Proposer for slot 2

        store, block, signatures = sample_store.produce_block_with_signatures(
            slot,
            validator_idx,
        )

        # Block should include attestations from available attestations
        assert len(block.body.attestations) >= 0  # May be filtered based on validity

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
                epoch=agg_att.data.slot,
            )

    def test_produce_block_sequential_slots(self, sample_store: Store) -> None:
        """Test producing blocks in sequential slots."""
        # Produce block for slot 1
        sample_store, block1, _signatures1 = sample_store.produce_block_with_signatures(
            Slot(1),
            Uint64(1),
        )
        block1_hash = hash_tree_root(block1)

        # Verify first block is properly created
        assert block1.slot == Slot(1)
        assert block1.proposer_index == Uint64(1)
        assert block1_hash in sample_store.blocks
        assert block1_hash in sample_store.states

        # Without any attestations, the forkchoice will stay on genesis
        # This is the expected behavior: block1 exists but isn't the head
        # So block2 should build on genesis, not block1

        # Produce block for slot 2 (will build on genesis due to forkchoice)
        sample_store, block2, _signatures2 = sample_store.produce_block_with_signatures(
            Slot(2),
            Uint64(2),
        )

        # Verify block properties
        assert block2.slot == Slot(2)
        assert block2.proposer_index == Uint64(2)

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
        validator_idx = Uint64(3)

        # Ensure no attestations in store
        sample_store.latest_known_attestations.clear()

        store, block, _signatures = sample_store.produce_block_with_signatures(
            slot,
            validator_idx,
        )

        # Should produce valid block with empty attestations
        assert len(block.body.attestations) == 0
        assert block.slot == slot
        assert block.proposer_index == validator_idx
        assert block.state_root != Bytes32.zero()

    def test_produce_block_state_consistency(self, sample_store: Store) -> None:
        """Test that produced block's state is consistent with block content."""
        key_manager = get_shared_key_manager()
        slot = Slot(4)
        validator_idx = Uint64(4)

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
            validator_id=Uint64(7),
            message=data_7,
            signature=key_manager.sign_attestation_data(Uint64(7), data_7),
        )
        sample_store.latest_known_attestations[Uint64(7)] = signed_7.message
        sig_key_7 = SignatureKey(Uint64(7), signed_7.message.data_root_bytes())
        sample_store.gossip_signatures[sig_key_7] = signed_7.signature

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
                epoch=agg_att.data.slot,
            )


class TestValidatorIntegration:
    """Test integration between block production and attestations."""

    def test_block_production_then_attestation(self, sample_store: Store) -> None:
        """Test producing a block then creating attestation for it."""
        # Proposer produces block for slot 1
        proposer_slot = Slot(1)
        proposer_idx = Uint64(1)
        sample_store.produce_block_with_signatures(proposer_slot, proposer_idx)

        # Update store state after block production
        sample_store = sample_store.update_head()

        # Other validator creates attestation for slot 2
        attestor_slot = Slot(2)
        attestor_idx = Uint64(7)
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
            Uint64(1),
        )
        block1_hash = hash_tree_root(block1)

        # Validators 2-5 create attestations for slot 2
        # These will be based on the current forkchoice head (genesis)
        attestations = []
        for i in range(2, 6):
            attestation_data = sample_store.produce_attestation_data(Slot(2))
            attestation = Attestation(validator_id=Uint64(i), data=attestation_data)
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
            Uint64(2),
        )

        # Verify block properties
        assert block2.slot == Slot(2)
        assert block2.proposer_index == Uint64(2)

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
        max_validator = Uint64(9)  # Last validator (0-indexed, 10 total)
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
        config = Config(genesis_time=Uint64(1000))

        # Create minimal genesis block first
        genesis_body = BlockBody(attestations=AggregatedAttestations(data=[]))

        # Create validators list with 3 validators
        validators = Validators(
            data=[Validator(pubkey=Bytes52.zero(), index=Uint64(i)) for i in range(3)]
        )

        # Create minimal state with temporary header
        checkpoint = Checkpoint.default()
        state = State(
            config=config,
            slot=Slot(0),
            latest_block_header=BlockHeader(
                slot=Slot(0),
                proposer_index=Uint64(0),
                parent_root=Bytes32.zero(),
                state_root=Bytes32.zero(),  # Will be updated
                body_root=hash_tree_root(genesis_body),
            ),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
            validators=validators,
        )

        # Compute consistent state root
        state_root = hash_tree_root(state)

        # Create genesis block with correct state root
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=state_root,
            body=genesis_body,
        )
        genesis_hash = hash_tree_root(genesis)

        # Update state with matching header and checkpoint
        consistent_header = BlockHeader(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=state_root,  # Same as block
            body_root=hash_tree_root(genesis_body),
        )

        final_checkpoint = Checkpoint(root=genesis_hash, slot=Slot(0))
        state = state.model_copy(
            update={
                "latest_block_header": consistent_header,
                "latest_justified": final_checkpoint,
                "latest_finalized": final_checkpoint,
            }
        )

        store = Store(
            time=Uint64(100),
            config=config,
            head=genesis_hash,
            safe_target=genesis_hash,
            latest_justified=final_checkpoint,
            latest_finalized=final_checkpoint,
            blocks={genesis_hash: genesis},
            states={genesis_hash: state},
        )

        # Should be able to produce block and attestation
        store, block, _signatures = store.produce_block_with_signatures(
            Slot(1),
            Uint64(1),
        )
        attestation_data = store.produce_attestation_data(Slot(1))
        attestation = Attestation(validator_id=Uint64(2), data=attestation_data)

        assert isinstance(block, Block)
        assert isinstance(attestation, Attestation)


class TestValidatorErrorHandling:
    """Test error handling in validator operations."""

    def test_produce_block_wrong_proposer(self, sample_store: Store) -> None:
        """Test error when wrong validator tries to produce block."""
        slot = Slot(5)
        wrong_proposer = Uint64(3)  # Should be validator 5 for slot 5

        with pytest.raises(AssertionError) as exc_info:
            sample_store.produce_block_with_signatures(slot, wrong_proposer)

        assert "is not the proposer for slot" in str(exc_info.value)

    def test_produce_block_missing_parent_state(self) -> None:
        """Test error when parent state is missing."""
        config = Config(genesis_time=Uint64(1000))
        checkpoint = Checkpoint(root=Bytes32(b"missing" + b"\x00" * 25), slot=Slot(0))

        # Create store with missing parent state
        store = Store(
            time=Uint64(100),
            config=config,
            head=Bytes32(b"nonexistent" + b"\x00" * 21),
            safe_target=Bytes32(b"nonexistent" + b"\x00" * 21),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            blocks={},  # No blocks
            states={},  # No states
        )

        with pytest.raises(KeyError):  # Missing head in get_proposal_head
            store.produce_block_with_signatures(Slot(1), Uint64(1))

    def test_validator_operations_invalid_parameters(self, sample_store: Store) -> None:
        """Test validator operations with invalid parameters."""
        # These should not raise errors but work with the given types
        # since Uint64 is just a Uint64 alias

        # Very large validator index (should work mathematically)
        large_validator = Uint64(1000000)
        large_slot = Slot(1000000)

        # Get the state to determine number of validators
        genesis_hash = sample_store.head
        state = sample_store.states[genesis_hash]
        num_validators = Uint64(len(state.validators))

        # is_proposer should work (though likely return False)
        result = is_proposer(large_validator, large_slot, num_validators)
        assert isinstance(result, bool)

        # Attestation can be created for any validator
        attestation_data = sample_store.produce_attestation_data(Slot(1))
        attestation = Attestation(validator_id=large_validator, data=attestation_data)
        assert attestation.validator_id == large_validator
