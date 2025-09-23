"""Tests for pure forkchoice helper functions."""

from typing import Dict

import pytest

from lean_spec.subspecs.containers import Block, BlockBody, Checkpoint, State
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice.helpers import (
    get_fork_choice_head,
    get_latest_justified,
)
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


@pytest.fixture
def sample_blocks() -> Dict[Bytes32, Block]:
    """Create a valid, linked chain of sample blocks for testing."""
    genesis = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32(b"genesis" + b"\x00" * 25),
        body=BlockBody(attestations=Attestations(data=[])),
    )
    genesis_hash = hash_tree_root(genesis)

    block_a = Block(
        slot=Slot(1),
        proposer_index=Uint64(1),
        parent_root=genesis_hash,
        state_root=Bytes32(b"block_a" + b"\x00" * 25),
        body=BlockBody(attestations=Attestations(data=[])),
    )
    block_a_hash = hash_tree_root(block_a)

    block_b = Block(
        slot=Slot(2),
        proposer_index=Uint64(2),
        parent_root=block_a_hash,
        state_root=Bytes32(b"block_b" + b"\x00" * 25),
        body=BlockBody(attestations=Attestations(data=[])),
    )
    block_b_hash = hash_tree_root(block_b)

    return {
        genesis_hash: genesis,
        block_a_hash: block_a,
        block_b_hash: block_b,
    }


class TestForkChoiceHeadFunction:
    """Test the pure get_fork_choice_head helper function."""

    def test_get_fork_choice_head_with_votes(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head with validator votes."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Create votes pointing to target
        votes = {ValidatorIndex(0): Checkpoint(root=target_hash, slot=Slot(2))}

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_votes=votes, min_score=0
        )

        assert head == target_hash

    def test_get_fork_choice_head_no_votes(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head with no votes returns the root."""
        root_hash = list(sample_blocks.keys())[0]

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_votes={}, min_score=0
        )

        assert head == root_hash

    def test_get_fork_choice_head_with_min_score(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head respects minimum score."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Single vote, but require min_score of 2
        votes = {ValidatorIndex(0): Checkpoint(root=target_hash, slot=Slot(2))}

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_votes=votes, min_score=2
        )

        # Should fall back to root since min_score not met
        assert head == root_hash

    def test_get_fork_choice_head_multiple_votes(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head with multiple votes."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Multiple votes for same target
        votes = {
            ValidatorIndex(0): Checkpoint(root=target_hash, slot=Slot(2)),
            ValidatorIndex(1): Checkpoint(root=target_hash, slot=Slot(2)),
            ValidatorIndex(2): Checkpoint(root=target_hash, slot=Slot(2)),
        }

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_votes=votes, min_score=0
        )

        assert head == target_hash


class TestLatestJustifiedFunction:
    """Test the pure get_latest_justified helper function."""

    def test_get_latest_justified_empty(self) -> None:
        """Test get_latest_justified with empty states."""
        result = get_latest_justified({})
        assert result is None

    def test_get_latest_justified_single_state(self) -> None:
        """Test get_latest_justified with a single state."""
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(5))

        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint),  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == checkpoint

    def test_get_latest_justified_multiple_states(self) -> None:
        """Test get_latest_justified with states having different justified slots."""
        checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
        checkpoint2 = Checkpoint(
            root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(20)
        )  # Higher slot

        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint1),  # type: ignore
            Bytes32(b"state2" + b"\x00" * 26): MockState(checkpoint2),  # type: ignore
        }

        result = get_latest_justified(states)
        assert result == checkpoint2  # Should return the one with higher slot

    def test_get_latest_justified_tie_breaking(self) -> None:
        """Test get_latest_justified when multiple states have same justified slot."""
        checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
        checkpoint2 = Checkpoint(root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(10))

        class MockState:
            def __init__(self, justified: Checkpoint):
                self.latest_justified = justified

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): MockState(checkpoint1),  # type: ignore
            Bytes32(b"state2" + b"\x00" * 26): MockState(checkpoint2),  # type: ignore
        }

        result = get_latest_justified(states)
        # Should return one of them consistently
        assert result in [checkpoint1, checkpoint2]
        assert result.slot == Slot(10)
