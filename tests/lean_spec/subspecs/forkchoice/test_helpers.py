"""Tests for pure forkchoice helper functions."""

from typing import TYPE_CHECKING, Dict, Type

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

from .conftest import build_signed_attestation

if TYPE_CHECKING:
    from .conftest import MockState


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


def _byte32(fill: int) -> Bytes32:
    """Create a Bytes32 filled with the provided byte."""
    return Bytes32(bytes([fill]) * 32)


def _make_block(slot: int, parent_root: Bytes32, state_fill: int) -> Block:
    """Create a simple empty block for helper tests."""
    return Block(
        slot=Slot(slot),
        proposer_index=Uint64(slot),
        parent_root=parent_root,
        state_root=_byte32(state_fill),
        body=BlockBody(attestations=Attestations(data=[])),
    )


class TestForkChoiceHeadFunction:
    """Test the pure get_fork_choice_head helper function."""

    def test_get_fork_choice_head_with_attestations(
        self, sample_blocks: Dict[Bytes32, Block]
    ) -> None:
        """Test get_fork_choice_head with validator attestations."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Create attestations pointing to target
        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                ValidatorIndex(0),
                Checkpoint(root=target_hash, slot=Slot(2)),
            )
        }

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_attestations=attestations, min_score=0
        )

        assert head == target_hash

    def test_get_fork_choice_head_no_attestations(
        self, sample_blocks: Dict[Bytes32, Block]
    ) -> None:
        """Test get_fork_choice_head with no attestations walks to the leaf."""
        root_hash = list(sample_blocks.keys())[0]
        leaf_hash = list(sample_blocks.keys())[2]  # block_b is the leaf

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_attestations={}, min_score=0
        )

        assert head == leaf_hash

    def test_get_fork_choice_head_with_min_score(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """Test get_fork_choice_head respects minimum score."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Single attestation, but require min_score of 2
        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                ValidatorIndex(0),
                Checkpoint(root=target_hash, slot=Slot(2)),
            )
        }

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_attestations=attestations, min_score=2
        )

        # Should fall back to root since min_score not met
        assert head == root_hash

    def test_get_fork_choice_head_multiple_attestations(
        self, sample_blocks: Dict[Bytes32, Block]
    ) -> None:
        """Test get_fork_choice_head with multiple attestations."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        # Multiple attestations for same target
        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                ValidatorIndex(0),
                Checkpoint(root=target_hash, slot=Slot(2)),
            ),
            ValidatorIndex(1): build_signed_attestation(
                ValidatorIndex(1),
                Checkpoint(root=target_hash, slot=Slot(2)),
            ),
            ValidatorIndex(2): build_signed_attestation(
                ValidatorIndex(2),
                Checkpoint(root=target_hash, slot=Slot(2)),
            ),
        }

        head = get_fork_choice_head(
            blocks=sample_blocks, root=root_hash, latest_attestations=attestations, min_score=0
        )

        assert head == target_hash

    def test_get_fork_choice_head_prefers_lexicographically_larger_child(self) -> None:
        """Test tie-breaking picks lexicographically largest child when weights equal."""
        root_hash = _byte32(0)
        low_child_hash = _byte32(1)
        high_child_hash = _byte32(2)

        blocks = {
            root_hash: _make_block(slot=0, parent_root=Bytes32.zero(), state_fill=10),
            low_child_hash: _make_block(slot=1, parent_root=root_hash, state_fill=11),
            high_child_hash: _make_block(slot=1, parent_root=root_hash, state_fill=12),
        }

        head = get_fork_choice_head(
            blocks=blocks,
            root=root_hash,
            latest_attestations={},
            min_score=0,
        )

        assert head == high_child_hash

    def test_get_fork_choice_head_breaks_ties_for_equal_weight_forks(self) -> None:
        """Test tie-breaking prefers lexicographically larger fork when weights tie."""
        root_hash = _byte32(10)
        fork_a_2_hash = _byte32(20)
        fork_b_2_hash = _byte32(200)

        blocks = {
            root_hash: _make_block(slot=0, parent_root=Bytes32.zero(), state_fill=30),
            fork_a_2_hash: _make_block(slot=2, parent_root=root_hash, state_fill=31),
            fork_b_2_hash: _make_block(slot=2, parent_root=root_hash, state_fill=32),
        }

        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                ValidatorIndex(0),
                Checkpoint(root=fork_a_2_hash, slot=Slot(2)),
            ),
            ValidatorIndex(1): build_signed_attestation(
                ValidatorIndex(1),
                Checkpoint(root=fork_b_2_hash, slot=Slot(2)),
            ),
        }

        head = get_fork_choice_head(
            blocks=blocks,
            root=root_hash,
            latest_attestations=attestations,
            min_score=0,
        )

        assert head == fork_b_2_hash


class TestLatestJustifiedFunction:
    """Test the pure get_latest_justified helper function."""

    def test_get_latest_justified_empty(self) -> None:
        """Test get_latest_justified with empty states."""
        result = get_latest_justified({})
        assert result is None

    def test_get_latest_justified_single_state(self, mock_state_factory: Type["MockState"]) -> None:
        """Test get_latest_justified with a single state."""
        checkpoint = Checkpoint(root=Bytes32(b"test" + b"\x00" * 28), slot=Slot(5))

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): mock_state_factory(checkpoint),
        }

        result = get_latest_justified(states)
        assert result == checkpoint

    def test_get_latest_justified_multiple_states(
        self,
        mock_state_factory: Type["MockState"],
    ) -> None:
        """Test get_latest_justified when states have different slots."""
        checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
        checkpoint2 = Checkpoint(
            root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(20)
        )  # Higher slot

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): mock_state_factory(checkpoint1),
            Bytes32(b"state2" + b"\x00" * 26): mock_state_factory(checkpoint2),
        }

        result = get_latest_justified(states)
        assert result == checkpoint2  # Should return the one with higher slot

    def test_get_latest_justified_tie_breaking(self, mock_state_factory: Type["MockState"]) -> None:
        """Test get_latest_justified when slots tie."""
        checkpoint1 = Checkpoint(root=Bytes32(b"test1" + b"\x00" * 27), slot=Slot(10))
        checkpoint2 = Checkpoint(root=Bytes32(b"test2" + b"\x00" * 27), slot=Slot(10))

        states: Dict[Bytes32, State] = {
            Bytes32(b"state1" + b"\x00" * 26): mock_state_factory(checkpoint1),
            Bytes32(b"state2" + b"\x00" * 26): mock_state_factory(checkpoint2),
        }

        result = get_latest_justified(states)
        # Should return one of them consistently
        assert result in [checkpoint1, checkpoint2]
        assert result.slot == Slot(10)
