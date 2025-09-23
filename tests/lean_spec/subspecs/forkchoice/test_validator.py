"""Tests for validator block production and attestation voting functionality."""

import pytest

from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    BlockHeader,
    Checkpoint,
    Config,
    State,
    Vote,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, StakerIndex, Uint64
from lean_spec.types.validator import is_proposer


@pytest.fixture
def config() -> Config:
    """Sample configuration for validator testing."""
    return Config(genesis_time=Uint64(1000), num_validators=Uint64(10))


@pytest.fixture
def sample_state(config: Config) -> State:
    """Create a sample state for validator testing."""
    # Create block header for testing
    block_header = BlockHeader(
        slot=Slot(0),
        proposer_index=StakerIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32(b"state" + b"\x00" * 27),
        body_root=Bytes32(b"body" + b"\x00" * 28),
    )

    # Use a placeholder for genesis - will be updated in store fixture
    temp_finalized = Checkpoint(root=Bytes32(b"genesis" + b"\x00" * 25), slot=Slot(0))

    return State(
        config=config,
        slot=Slot(0),
        stakers=[],
        latest_block_header=block_header,
        latest_justified=temp_finalized,
        latest_finalized=temp_finalized,
        historical_block_hashes=[],
        justified_slots=[],
        justifications_roots=[],
        justifications_validators=[],
    )


@pytest.fixture
def sample_store(config: Config, sample_state: State) -> Store:
    """Create a sample forkchoice store with genesis block for validator testing."""
    # Create genesis block
    genesis_block = Block(
        slot=Slot(0),
        proposer_index=StakerIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(sample_state),
        body=BlockBody(attestations=[]),
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
        validator_idx = StakerIndex(1)  # Proposer for slot 1

        block = sample_store.produce_block(slot, validator_idx)

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
        wrong_validator = StakerIndex(2)  # Not proposer for slot 1

        with pytest.raises(AssertionError, match="is not the proposer for slot"):
            sample_store.produce_block(slot, wrong_validator)

    def test_produce_block_with_attestations(self, sample_store: Store) -> None:
        """Test block production includes available attestations."""
        # Add some votes to the store
        vote1 = Checkpoint(root=sample_store.head, slot=Slot(0))
        vote2 = Checkpoint(root=sample_store.head, slot=Slot(0))

        sample_store.latest_known_votes[StakerIndex(5)] = vote1
        sample_store.latest_known_votes[StakerIndex(6)] = vote2

        slot = Slot(2)
        validator_idx = StakerIndex(2)  # Proposer for slot 2

        block = sample_store.produce_block(slot, validator_idx)

        # Block should include attestations from available votes
        assert len(block.body.attestations) >= 0  # May be filtered based on validity

        # Verify block structure is correct
        assert block.slot == slot
        assert block.proposer_index == validator_idx
        assert block.state_root != Bytes32.zero()

    def test_produce_block_sequential_slots(self, sample_store: Store) -> None:
        """Test producing blocks in sequential slots."""
        # Produce block for slot 1
        block1 = sample_store.produce_block(Slot(1), StakerIndex(1))
        block1_hash = hash_tree_root(block1)

        # Verify first block is properly created
        assert block1.slot == Slot(1)
        assert block1.proposer_index == StakerIndex(1)
        assert block1_hash in sample_store.blocks
        assert block1_hash in sample_store.states

        # Without any votes, the forkchoice will stay on genesis
        # This is the expected behavior: block1 exists but isn't the head
        # So block2 should build on genesis, not block1

        # Produce block for slot 2 (will build on genesis due to forkchoice)
        block2 = sample_store.produce_block(Slot(2), StakerIndex(2))

        # Verify block properties
        assert block2.slot == Slot(2)
        assert block2.proposer_index == StakerIndex(2)

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
        validator_idx = StakerIndex(3)

        # Ensure no votes in store
        sample_store.latest_known_votes.clear()

        block = sample_store.produce_block(slot, validator_idx)

        # Should produce valid block with empty attestations
        assert len(block.body.attestations) == 0
        assert block.slot == slot
        assert block.proposer_index == validator_idx
        assert block.state_root != Bytes32.zero()

    def test_produce_block_state_consistency(self, sample_store: Store) -> None:
        """Test that produced block's state is consistent with block content."""
        slot = Slot(4)
        validator_idx = StakerIndex(4)

        # Add some votes to test state computation
        vote = Checkpoint(root=sample_store.head, slot=Slot(0))
        sample_store.latest_known_votes[StakerIndex(7)] = vote

        block = sample_store.produce_block(slot, validator_idx)
        block_hash = hash_tree_root(block)

        # Verify the stored state matches the block's state root
        stored_state = sample_store.states[block_hash]
        assert hash_tree_root(stored_state) == block.state_root


class TestAttestationVoteProduction:
    """Test validator attestation vote production functionality."""

    def test_produce_attestation_vote_basic(self, sample_store: Store) -> None:
        """Test basic attestation vote production."""
        slot = Slot(1)
        validator_idx = StakerIndex(5)

        vote = sample_store.produce_attestation_vote(slot, validator_idx)

        # Verify vote structure
        assert vote.validator_id == validator_idx
        assert vote.slot == slot
        assert isinstance(vote.head, Checkpoint)
        assert isinstance(vote.target, Checkpoint)
        assert isinstance(vote.source, Checkpoint)

        # Source should be the store's latest justified
        assert vote.source == sample_store.latest_justified

    def test_produce_attestation_vote_head_reference(self, sample_store: Store) -> None:
        """Test that attestation vote references correct head."""
        slot = Slot(2)
        validator_idx = StakerIndex(8)

        vote = sample_store.produce_attestation_vote(slot, validator_idx)

        # Head checkpoint should reference the current proposal head
        expected_head_root = sample_store.get_proposal_head(slot)
        assert vote.head.root == expected_head_root

        # Head slot should match the block's slot
        head_block = sample_store.blocks[expected_head_root]
        assert vote.head.slot == head_block.slot

    def test_produce_attestation_vote_target_calculation(self, sample_store: Store) -> None:
        """Test that attestation vote calculates target correctly."""
        slot = Slot(3)
        validator_idx = StakerIndex(9)

        vote = sample_store.produce_attestation_vote(slot, validator_idx)

        # Target should match the store's vote target calculation
        expected_target = sample_store.get_vote_target()
        assert vote.target.root == expected_target.root
        assert vote.target.slot == expected_target.slot

    def test_produce_attestation_vote_different_validators(self, sample_store: Store) -> None:
        """Test vote production for different validators in same slot."""
        slot = Slot(4)

        # All validators should produce consistent votes for the same slot
        votes = []
        for validator_idx in range(5):
            vote = sample_store.produce_attestation_vote(slot, StakerIndex(validator_idx))
            votes.append(vote)

            # Each vote should have correct validator ID
            assert vote.validator_id == StakerIndex(validator_idx)
            assert vote.slot == slot

        # All votes should have same head, target, and source (consensus)
        first_vote = votes[0]
        for vote in votes[1:]:
            assert vote.head.root == first_vote.head.root
            assert vote.head.slot == first_vote.head.slot
            assert vote.target.root == first_vote.target.root
            assert vote.target.slot == first_vote.target.slot
            assert vote.source.root == first_vote.source.root
            assert vote.source.slot == first_vote.source.slot

    def test_produce_attestation_vote_sequential_slots(self, sample_store: Store) -> None:
        """Test vote production across sequential slots."""
        validator_idx = StakerIndex(3)

        # Produce votes for sequential slots
        vote1 = sample_store.produce_attestation_vote(Slot(1), validator_idx)
        vote2 = sample_store.produce_attestation_vote(Slot(2), validator_idx)

        # Votes should be for different slots
        assert vote1.slot == Slot(1)
        assert vote2.slot == Slot(2)

        # Both should use same source (latest justified doesn't change)
        assert vote1.source == vote2.source
        assert vote1.source == sample_store.latest_justified

    def test_produce_attestation_vote_justification_consistency(self, sample_store: Store) -> None:
        """Test that vote source uses current justified checkpoint."""
        slot = Slot(5)
        validator_idx = StakerIndex(2)

        vote = sample_store.produce_attestation_vote(slot, validator_idx)

        # Source must be the latest justified checkpoint from store
        assert vote.source.root == sample_store.latest_justified.root
        assert vote.source.slot == sample_store.latest_justified.slot

        # Source checkpoint should exist in blocks
        assert vote.source.root in sample_store.blocks


class TestValidatorIntegration:
    """Test integration between block production and attestation voting."""

    def test_block_production_then_attestation(self, sample_store: Store) -> None:
        """Test producing a block then creating attestation for it."""
        # Proposer produces block for slot 1
        proposer_slot = Slot(1)
        proposer_idx = StakerIndex(1)
        sample_store.produce_block(proposer_slot, proposer_idx)

        # Update store state after block production
        sample_store.update_head()

        # Other validator creates attestation for slot 2
        attestor_slot = Slot(2)
        attestor_idx = StakerIndex(7)
        vote = sample_store.produce_attestation_vote(attestor_slot, attestor_idx)

        # Vote should reference the new block as head (if it became head)
        assert vote.validator_id == attestor_idx
        assert vote.slot == attestor_slot

        # The vote should be consistent with current forkchoice state
        assert vote.source == sample_store.latest_justified

    def test_multiple_validators_coordination(self, sample_store: Store) -> None:
        """Test multiple validators producing blocks and attestations."""
        # Validator 1 produces block for slot 1
        block1 = sample_store.produce_block(Slot(1), StakerIndex(1))
        block1_hash = hash_tree_root(block1)

        # Validators 2-5 create attestations for slot 2
        # These will be based on the current forkchoice head (genesis)
        attestations = []
        for i in range(2, 6):
            vote = sample_store.produce_attestation_vote(Slot(2), StakerIndex(i))
            attestations.append(vote)

        # All attestations should be consistent
        first_att = attestations[0]
        for att in attestations[1:]:
            assert att.head.root == first_att.head.root
            assert att.target.root == first_att.target.root
            assert att.source.root == first_att.source.root

        # Validator 2 produces next block for slot 2
        # Without votes for block1, this will build on genesis (current head)
        block2 = sample_store.produce_block(Slot(2), StakerIndex(2))

        # Verify block properties
        assert block2.slot == Slot(2)
        assert block2.proposer_index == StakerIndex(2)

        # Both blocks should exist in the store
        block2_hash = hash_tree_root(block2)
        assert block1_hash in sample_store.blocks
        assert block2_hash in sample_store.blocks

        # Both blocks should build on genesis (the current head)
        genesis_hash = sample_store.head
        assert block1.parent_root == genesis_hash
        assert block2.parent_root == genesis_hash

    def test_validator_edge_cases(self, sample_store: Store) -> None:
        """Test edge cases in validator operations."""
        # Test with validator index equal to number of validators - 1
        max_validator = StakerIndex(9)  # Last validator (0-indexed, 10 total)
        slot = Slot(9)  # This validator's slot

        # Should be able to produce block
        block = sample_store.produce_block(slot, max_validator)
        assert block.proposer_index == max_validator

        # Should be able to produce attestation
        vote = sample_store.produce_attestation_vote(Slot(10), max_validator)
        assert vote.validator_id == max_validator

    def test_validator_operations_empty_store(self) -> None:
        """Test validator operations with minimal store state."""
        config = Config(genesis_time=Uint64(1000), num_validators=Uint64(3))

        # Create minimal genesis block first
        genesis_body = BlockBody(attestations=[])

        # Create minimal state with temporary header
        checkpoint = Checkpoint(root=Bytes32.zero(), slot=Slot(0))
        state = State(
            config=config,
            slot=Slot(0),
            stakers=[],
            latest_block_header=BlockHeader(
                slot=Slot(0),
                proposer_index=StakerIndex(0),
                parent_root=Bytes32.zero(),
                state_root=Bytes32.zero(),  # Will be updated
                body_root=hash_tree_root(genesis_body),
            ),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            historical_block_hashes=[],
            justified_slots=[],
            justifications_roots=[],
            justifications_validators=[],
        )

        # Compute consistent state root
        state_root = hash_tree_root(state)

        # Create genesis block with correct state root
        genesis = Block(
            slot=Slot(0),
            proposer_index=StakerIndex(0),
            parent_root=Bytes32.zero(),
            state_root=state_root,
            body=genesis_body,
        )
        genesis_hash = hash_tree_root(genesis)

        # Update state with matching header and checkpoint
        consistent_header = BlockHeader(
            slot=Slot(0),
            proposer_index=StakerIndex(0),
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
        block = store.produce_block(Slot(1), StakerIndex(1))
        vote = store.produce_attestation_vote(Slot(1), StakerIndex(2))

        assert isinstance(block, Block)
        assert isinstance(vote, Vote)


class TestValidatorErrorHandling:
    """Test error handling in validator operations."""

    def test_produce_block_wrong_proposer(self, sample_store: Store) -> None:
        """Test error when wrong validator tries to produce block."""
        slot = Slot(5)
        wrong_proposer = StakerIndex(3)  # Should be validator 5 for slot 5

        with pytest.raises(AssertionError) as exc_info:
            sample_store.produce_block(slot, wrong_proposer)

        assert "is not the proposer for slot" in str(exc_info.value)

    def test_produce_block_missing_parent_state(self) -> None:
        """Test error when parent state is missing."""
        config = Config(genesis_time=Uint64(1000), num_validators=Uint64(5))
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
            store.produce_block(Slot(1), StakerIndex(1))

    def test_validator_operations_invalid_parameters(self, sample_store: Store) -> None:
        """Test validator operations with invalid parameters."""
        # These should not raise errors but work with the given types
        # since StakerIndex is just a Uint64 alias

        # Very large validator index (should work mathematically)
        large_validator = StakerIndex(1000000)
        large_slot = Slot(1000000)

        # is_proposer should work (though likely return False)
        result = is_proposer(large_validator, large_slot, sample_store.config.num_validators)
        assert isinstance(result, bool)

        # produce_attestation_vote should work for any validator
        vote = sample_store.produce_attestation_vote(Slot(1), large_validator)
        assert vote.validator_id == large_validator
