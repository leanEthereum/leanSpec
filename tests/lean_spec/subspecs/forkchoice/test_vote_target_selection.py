"""Tests for vote target selection and calculation."""

import pytest  # type: ignore[import-not-found]

from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    Checkpoint,
    Config,
)
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex

from .conftest import build_signed_attestation


@pytest.fixture
def config() -> Config:
    """Sample configuration."""
    return Config(genesis_time=Uint64(1000), num_validators=Uint64(100))


class TestVoteTargetCalculation:
    """Test vote target calculation logic."""

    def test_get_vote_target_basic(self, config: Config) -> None:
        """Test basic vote target selection."""
        # Create blocks
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_1_hash = hash_tree_root(block_1)

        blocks = {
            genesis_hash: genesis,
            block_1_hash: block_1,
        }

        # Recent finalization
        finalized = Checkpoint(root=genesis_hash, slot=Slot(0))

        # Create a Store instance to call get_vote_target
        store = Store(
            time=Uint64(100),
            config=config,
            head=block_1_hash,
            safe_target=block_1_hash,
            latest_justified=finalized,
            latest_finalized=finalized,
            blocks=blocks,
            states={},
        )

        target = store.get_vote_target()

        # Should target the head block since finalization is recent
        assert target.root == block_1_hash
        assert target.slot == Slot(1)

    def test_vote_target_with_old_finalized(self, config: Config) -> None:
        """Test vote target selection with very old finalized checkpoint."""
        # Create a chain where finalized block is far back
        blocks = {}

        # Create 10 blocks
        prev_hash = Bytes32(b"pre-genesis" + b"\x00" * 21)
        for i in range(10):
            block = Block(
                slot=Slot(i),
                proposer_index=Uint64(i),
                parent_root=prev_hash,
                state_root=Bytes32(f"block{i}".encode() + b"\x00" * (32 - len(f"block{i}"))),
                body=BlockBody(attestations=Attestations(data=[])),
            )
            block_hash = hash_tree_root(block)
            blocks[block_hash] = block
            prev_hash = block_hash

        # Very old finalized checkpoint (slot 0)
        finalized = Checkpoint(
            root=next(h for h, b in blocks.items() if b.slot == Slot(0)), slot=Slot(0)
        )

        # Current head is at slot 9
        head_hash = next(h for h, b in blocks.items() if b.slot == Slot(9))

        # Create a Store instance to call get_vote_target
        store = Store(
            time=Uint64(100),
            config=config,
            head=head_hash,
            safe_target=head_hash,
            latest_justified=finalized,
            latest_finalized=finalized,
            blocks=blocks,
            states={},
        )

        target = store.get_vote_target()

        # Should return a valid checkpoint
        assert isinstance(target, Checkpoint)
        assert target.root in blocks
        assert target.slot.as_int() >= 0

    def test_vote_target_walks_back_from_head(self, config: Config) -> None:
        """Test that vote target walks back from head when needed."""
        # Create blocks
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_1_hash = hash_tree_root(block_1)

        block_2 = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=block_1_hash,
            state_root=Bytes32(b"block2" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_2_hash = hash_tree_root(block_2)

        blocks = {
            genesis_hash: genesis,
            block_1_hash: block_1,
            block_2_hash: block_2,
        }

        # Finalized at genesis
        finalized = Checkpoint(root=genesis_hash, slot=Slot(0))

        # Create a Store instance with head at block_2 and safe target at block_1
        store = Store(
            time=Uint64(100),
            config=config,
            head=block_2_hash,
            safe_target=block_1_hash,  # Different from head
            latest_justified=finalized,
            latest_finalized=finalized,
            blocks=blocks,
            states={},
        )

        target = store.get_vote_target()

        # Should walk back towards safe target
        assert target.root in blocks

    def test_vote_target_justifiable_slot_constraint(
        self,
        config: Config,
    ) -> None:
        """Test that vote target respects justifiable slot constraints."""
        # Create a long chain to test slot justification
        blocks = {}
        prev_hash = Bytes32.zero()

        # Create blocks from slot 0 to 20
        for i in range(21):
            block = Block(
                slot=Slot(i),
                proposer_index=Uint64(i % 10),
                parent_root=prev_hash,
                state_root=Bytes32(f"block{i}".encode() + b"\x00" * (32 - len(f"block{i}"))),
                body=BlockBody(attestations=Attestations(data=[])),
            )
            block_hash = hash_tree_root(block)
            blocks[block_hash] = block
            prev_hash = block_hash

        # Finalized very early (slot 0)
        finalized = Checkpoint(
            root=next(h for h, b in blocks.items() if b.slot == Slot(0)), slot=Slot(0)
        )

        # Head at slot 20
        head_hash = next(h for h, b in blocks.items() if b.slot == Slot(20))

        store = Store(
            time=Uint64(2000),
            config=config,
            head=head_hash,
            safe_target=head_hash,
            latest_justified=finalized,
            latest_finalized=finalized,
            blocks=blocks,
            states={},
        )

        target = store.get_vote_target()

        # Should return a justifiable slot
        assert isinstance(target, Checkpoint)
        assert target.root in blocks

        # Check that the slot is justifiable after finalized slot
        target_slot = blocks[target.root].slot
        finalized_slot = finalized.slot

        # The is_justifiable_after method should return True for valid slots
        assert target_slot.is_justifiable_after(finalized_slot)

    def test_vote_target_with_same_head_and_safe_target(self, config: Config) -> None:
        """Test vote target when head and safe_target are the same."""
        # Create simple chain
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        head_block = Block(
            slot=Slot(5),
            proposer_index=Uint64(5),
            parent_root=genesis_hash,
            state_root=Bytes32(b"head" + b"\x00" * 28),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        head_hash = hash_tree_root(head_block)

        blocks = {
            genesis_hash: genesis,
            head_hash: head_block,
        }

        finalized = Checkpoint(root=genesis_hash, slot=Slot(0))

        # Head and safe_target are the same
        store = Store(
            time=Uint64(500),
            config=config,
            head=head_hash,
            safe_target=head_hash,  # Same as head
            latest_justified=finalized,
            latest_finalized=finalized,
            blocks=blocks,
            states={},
        )

        target = store.get_vote_target()

        # Should target the head (which is also safe_target)
        assert target.root == head_hash
        assert target.slot == head_block.slot


class TestSafeTargetComputation:
    """Test safe target computation logic."""

    def test_update_safe_target_basic(self, config: Config) -> None:
        """Test basic safe target update."""
        # Create blocks
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_block_hash = hash_tree_root(genesis_block)

        checkpoint = Checkpoint(root=genesis_block_hash, slot=Slot(0))

        store = Store(
            time=Uint64(100),
            config=config,
            head=genesis_block_hash,
            safe_target=genesis_block_hash,
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            blocks={genesis_block_hash: genesis_block},
            states={},
        )

        # Update safe target (this tests the method exists and runs)
        store.update_safe_target()

        # Safe target should be set
        assert store.safe_target == genesis_block_hash

    def test_safe_target_with_votes(self, config: Config) -> None:
        """Test safe target computation with votes."""
        # Create blocks for voting
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block1" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_1_hash = hash_tree_root(block_1)

        blocks = {
            genesis_hash: genesis,
            block_1_hash: block_1,
        }

        checkpoint = Checkpoint(root=genesis_hash, slot=Slot(0))

        # Add some new votes
        new_votes = {
            ValidatorIndex(0): build_signed_attestation(
                ValidatorIndex(0),
                Checkpoint(root=block_1_hash, slot=Slot(1)),
            ),
            ValidatorIndex(1): build_signed_attestation(
                ValidatorIndex(1),
                Checkpoint(root=block_1_hash, slot=Slot(1)),
            ),
        }

        store = Store(
            time=Uint64(100),
            config=config,
            head=block_1_hash,
            safe_target=genesis_hash,
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            blocks=blocks,
            states={},
            latest_new_votes=new_votes,
        )

        # Update safe target with votes
        store.update_safe_target()

        # Should have computed a safe target
        assert store.safe_target is not None
        assert store.safe_target in blocks


class TestEdgeCases:
    """Test edge cases in vote target selection."""

    def test_vote_target_empty_blocks(self, config: Config) -> None:
        """Test vote target with minimal block set."""
        checkpoint = Checkpoint.default()

        store = Store(
            time=Uint64(100),
            config=config,
            head=Bytes32.zero(),
            safe_target=Bytes32.zero(),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            blocks={},  # Empty blocks
            states={},
        )

        # Should handle empty blocks gracefully (or raise appropriate error)
        with pytest.raises(KeyError):  # Expected since head block doesn't exist
            store.get_vote_target()

    def test_vote_target_single_block(self, config: Config) -> None:
        """Test vote target with only one block."""
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        checkpoint = Checkpoint(root=genesis_hash, slot=Slot(0))

        store = Store(
            time=Uint64(100),
            config=config,
            head=genesis_hash,
            safe_target=genesis_hash,
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            blocks={genesis_hash: genesis},
            states={},
        )

        target = store.get_vote_target()

        # Should target the only available block
        assert target.root == genesis_hash
        assert target.slot == Slot(0)
