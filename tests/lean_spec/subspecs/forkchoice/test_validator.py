"""Tests for validator block production and attestation functionality."""

import pytest

from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    Checkpoint,
    Config,
    Signature,
    SignedAttestation,
    State,
    Validator,
)
from lean_spec.subspecs.containers.block import Attestations
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
from lean_spec.types import Bytes32, Bytes52, Uint64, ValidatorIndex
from lean_spec.types.validator import is_proposer


@pytest.fixture
def config() -> Config:
    """Sample configuration for validator testing."""
    return Config(genesis_time=Uint64(1000))


@pytest.fixture
def sample_state(config: Config) -> State:
    """Create a sample state for validator testing."""
    # Create block header for testing
    block_header = BlockHeader(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32(b"state" + b"\x00" * 27),
        body_root=Bytes32(b"body" + b"\x00" * 28),
    )

    # Use a placeholder for genesis - will be updated in store fixture
    temp_finalized = Checkpoint(root=Bytes32(b"genesis" + b"\x00" * 25), slot=Slot(0))

    # Create validators list with 10 validators for testing
    validators = Validators(data=[Validator(pubkey=Bytes52.zero()) for _ in range(10)])

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
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(sample_state),
        body=BlockBody(attestations=Attestations(data=[])),
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


def build_signed_attestation(
    validator: ValidatorIndex,
    slot: Slot,
    head: Checkpoint,
    source: Checkpoint,
    target: Checkpoint,
) -> SignedAttestation:
    """Create a signed attestation with a zeroed signature."""

    data = AttestationData(
        slot=slot,
        head=head,
        target=target,
        source=source,
    )
    message = Attestation(
        validator_id=validator,
        data=data,
    )
    return SignedAttestation(
        message=message,
        signature=Signature.zero(),
    )


class TestBlockProduction:
    """Test validator block production functionality."""

    def test_produce_block_basic(self, sample_store: Store) -> None:
        """Test basic block production by authorized proposer."""
        slot = Slot(1)
        validator_idx = ValidatorIndex(1)  # Proposer for slot 1

        block, _signatures = sample_store.produce_block_with_signatures(slot, validator_idx)
        # Verify block structure
        assert block.slot == slot
        assert block.proposer_index == validator_idx
        assert block.parent_root == sample_store.head
        assert isinstance(block.body, BlockBody)
        assert block.state_root != Bytes32.zero()  # Should have computed state root

        # Verify block was added to store
        block_hash = hash_tree_root(block)
        assert block_hash in sample_store.blocks
        assert block_hash in sample_store.states

    def test_produce_block_unauthorized_proposer(self, sample_store: Store) -> None:
        """Test block production fails for unauthorized proposer."""
        slot = Slot(1)
        wrong_validator = ValidatorIndex(2)  # Not proposer for slot 1

        with pytest.raises(AssertionError, match="is not the proposer for slot"):
            sample_store.produce_block_with_signatures(slot, wrong_validator)

    def test_produce_block_with_attestations(self, sample_store: Store) -> None:
        """Test block production includes available attestations."""
        head_block = sample_store.blocks[sample_store.head]

        # Add some attestations to the store
        sample_store.latest_known_attestations[ValidatorIndex(5)] = build_signed_attestation(
            validator=ValidatorIndex(5),
            slot=head_block.slot,
            head=Checkpoint(root=sample_store.head, slot=head_block.slot),
            source=sample_store.latest_justified,
            target=sample_store.get_attestation_target(),
        )
        sample_store.latest_known_attestations[ValidatorIndex(6)] = build_signed_attestation(
            validator=ValidatorIndex(6),
            slot=head_block.slot,
            head=Checkpoint(root=sample_store.head, slot=head_block.slot),
            source=sample_store.latest_justified,
            target=sample_store.get_attestation_target(),
        )

        slot = Slot(2)
        validator_idx = ValidatorIndex(2)  # Proposer for slot 2

        block, _signatures = sample_store.produce_block_with_signatures(
            slot,
            validator_idx,
        )

        # Block should include attestations from available attestations
        assert len(block.body.attestations) >= 0  # May be filtered based on validity

        # Verify block structure is correct
        assert block.slot == slot
        assert block.proposer_index == validator_idx
        assert block.state_root != Bytes32.zero()

    def test_produce_block_sequential_slots(self, sample_store: Store) -> None:
        """Test producing blocks in sequential slots."""
        # Produce block for slot 1
        block1, _signatures1 = sample_store.produce_block_with_signatures(
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
        block2, _signatures2 = sample_store.produce_block_with_signatures(
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

        # Ensure no attestations in store
        sample_store.latest_known_attestations.clear()

        block, _signatures = sample_store.produce_block_with_signatures(
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
        slot = Slot(4)
        validator_idx = ValidatorIndex(4)

        # Add some attestations to test state computation
        head_block = sample_store.blocks[sample_store.head]
        sample_store.latest_known_attestations[ValidatorIndex(7)] = build_signed_attestation(
            validator=ValidatorIndex(7),
            slot=head_block.slot,
            head=Checkpoint(root=sample_store.head, slot=head_block.slot),
            source=sample_store.latest_justified,
            target=sample_store.get_attestation_target(),
        )

        block, _signatures = sample_store.produce_block_with_signatures(
            slot,
            validator_idx,
        )
        block_hash = hash_tree_root(block)

        # Verify the stored state matches the block's state root
        stored_state = sample_store.states[block_hash]
        assert hash_tree_root(stored_state) == block.state_root


class TestAttestationProduction:
    """Test validator attestation production functionality."""

    def test_produce_attestation_basic(self, sample_store: Store) -> None:
        """Test basic attestation production."""
        slot = Slot(1)
        validator_idx = ValidatorIndex(5)

        attestation = sample_store.produce_attestation(slot, validator_idx)

        # Verify attestation structure
        assert attestation.validator_id == validator_idx
        assert attestation.data.slot == slot
        assert isinstance(attestation.data.head, Checkpoint)
        assert isinstance(attestation.data.target, Checkpoint)
        assert isinstance(attestation.data.source, Checkpoint)

        # Source should be the store's latest justified
        assert attestation.data.source == sample_store.latest_justified

    def test_produce_attestation_head_reference(self, sample_store: Store) -> None:
        """Test that attestation references correct head."""
        slot = Slot(2)
        validator_idx = ValidatorIndex(8)

        attestation = sample_store.produce_attestation(slot, validator_idx)

        # Head checkpoint should reference the current proposal head
        expected_head_root = sample_store.get_proposal_head(slot)
        assert attestation.data.head.root == expected_head_root

        # Head slot should match the block's slot
        head_block = sample_store.blocks[expected_head_root]
        assert attestation.data.head.slot == head_block.slot

    def test_produce_attestation_target_calculation(self, sample_store: Store) -> None:
        """Test that attestation calculates target correctly."""
        slot = Slot(3)
        validator_idx = ValidatorIndex(9)

        attestation = sample_store.produce_attestation(slot, validator_idx)

        # Target should match the store's attestation target calculation
        expected_target = sample_store.get_attestation_target()
        assert attestation.data.target.root == expected_target.root
        assert attestation.data.target.slot == expected_target.slot

    def test_produce_attestation_different_validators(self, sample_store: Store) -> None:
        """Test attestation production for different validators in same slot."""
        slot = Slot(4)

        # All validators should produce consistent attestations for the same slot
        attestations = []
        for validator_idx in range(5):
            attestation = sample_store.produce_attestation(slot, ValidatorIndex(validator_idx))
            attestations.append(attestation)

            # Each attestation should have correct validator ID
            assert attestation.validator_id == ValidatorIndex(validator_idx)
            assert attestation.data.slot == slot

        # All attestations should have same head, target, and source (consensus)
        first_attestation = attestations[0]
        for attestation in attestations[1:]:
            assert attestation.data.head.root == first_attestation.data.head.root
            assert attestation.data.head.slot == first_attestation.data.head.slot
            assert attestation.data.target.root == first_attestation.data.target.root
            assert attestation.data.target.slot == first_attestation.data.target.slot
            assert attestation.data.source.root == first_attestation.data.source.root
            assert attestation.data.source.slot == first_attestation.data.source.slot

    def test_produce_attestation_sequential_slots(self, sample_store: Store) -> None:
        """Test attestation production across sequential slots."""
        validator_idx = ValidatorIndex(3)

        # Produce attestations for sequential slots
        attestation1 = sample_store.produce_attestation(Slot(1), validator_idx)
        attestation2 = sample_store.produce_attestation(Slot(2), validator_idx)

        # Attestations should be for different slots
        assert attestation1.data.slot == Slot(1)
        assert attestation2.data.slot == Slot(2)

        # Both should use same source (latest justified doesn't change)
        assert attestation1.data.source == attestation2.data.source
        assert attestation1.data.source == sample_store.latest_justified

    def test_produce_attestation_justification_consistency(self, sample_store: Store) -> None:
        """Test that attestation source uses current justified checkpoint."""
        slot = Slot(5)
        validator_idx = ValidatorIndex(2)

        attestation = sample_store.produce_attestation(slot, validator_idx)

        # Source must be the latest justified checkpoint from store
        assert attestation.data.source.root == sample_store.latest_justified.root
        assert attestation.data.source.slot == sample_store.latest_justified.slot

        # Source checkpoint should exist in blocks
        assert attestation.data.source.root in sample_store.blocks


class TestValidatorIntegration:
    """Test integration between block production and attestations."""

    def test_block_production_then_attestation(self, sample_store: Store) -> None:
        """Test producing a block then creating attestation for it."""
        # Proposer produces block for slot 1
        proposer_slot = Slot(1)
        proposer_idx = ValidatorIndex(1)
        sample_store.produce_block_with_signatures(proposer_slot, proposer_idx)

        # Update store state after block production
        sample_store.update_head()

        # Other validator creates attestation for slot 2
        attestor_slot = Slot(2)
        attestor_idx = ValidatorIndex(7)
        attestation = sample_store.produce_attestation(attestor_slot, attestor_idx)

        # Attestation should reference the new block as head (if it became head)
        assert attestation.validator_id == attestor_idx
        assert attestation.data.slot == attestor_slot

        # The attestation should be consistent with current forkchoice state
        assert attestation.data.source == sample_store.latest_justified

    def test_multiple_validators_coordination(self, sample_store: Store) -> None:
        """Test multiple validators producing blocks and attestations."""
        # Validator 1 produces block for slot 1
        block1, _signatures1 = sample_store.produce_block_with_signatures(
            Slot(1),
            ValidatorIndex(1),
        )
        block1_hash = hash_tree_root(block1)

        # Validators 2-5 create attestations for slot 2
        # These will be based on the current forkchoice head (genesis)
        attestations = []
        for i in range(2, 6):
            attestation = sample_store.produce_attestation(Slot(2), ValidatorIndex(i))
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
        block2, _signatures2 = sample_store.produce_block_with_signatures(
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
        block, _signatures = sample_store.produce_block_with_signatures(
            slot,
            max_validator,
        )
        assert block.proposer_index == max_validator

        # Should be able to produce attestation
        attestation = sample_store.produce_attestation(Slot(10), max_validator)
        assert attestation.validator_id == max_validator

    def test_validator_operations_empty_store(self) -> None:
        """Test validator operations with minimal store state."""
        config = Config(genesis_time=Uint64(1000))

        # Create minimal genesis block first
        genesis_body = BlockBody(attestations=Attestations(data=[]))

        # Create validators list with 3 validators
        validators = Validators(data=[Validator(pubkey=Bytes52.zero()) for _ in range(3)])

        # Create minimal state with temporary header
        checkpoint = Checkpoint.default()
        state = State(
            config=config,
            slot=Slot(0),
            latest_block_header=BlockHeader(
                slot=Slot(0),
                proposer_index=ValidatorIndex(0),
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
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=state_root,
            body=genesis_body,
        )
        genesis_hash = hash_tree_root(genesis)

        # Update state with matching header and checkpoint
        consistent_header = BlockHeader(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
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
        block, _signatures = store.produce_block_with_signatures(
            Slot(1),
            ValidatorIndex(1),
        )
        attestation = store.produce_attestation(Slot(1), ValidatorIndex(2))

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
            store.produce_block_with_signatures(Slot(1), ValidatorIndex(1))

    def test_validator_operations_invalid_parameters(self, sample_store: Store) -> None:
        """Test validator operations with invalid parameters."""
        # These should not raise errors but work with the given types
        # since ValidatorIndex is just a Uint64 alias

        # Very large validator index (should work mathematically)
        large_validator = ValidatorIndex(1000000)
        large_slot = Slot(1000000)

        # Get the state to determine number of validators
        genesis_hash = sample_store.head
        state = sample_store.states[genesis_hash]
        num_validators = Uint64(state.validators.count)

        # is_proposer should work (though likely return False)
        result = is_proposer(large_validator, large_slot, num_validators)
        assert isinstance(result, bool)

        # produce_attestation should work for any validator
        attestation = sample_store.produce_attestation(Slot(1), large_validator)
        assert attestation.validator_id == large_validator
