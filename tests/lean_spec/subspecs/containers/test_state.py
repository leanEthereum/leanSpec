"""
Tests for the State container.
"""

import pytest

from lean_spec.subspecs.containers import (
    BlockHeader,
    Checkpoint,
    Config,
    State,
)
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


@pytest.fixture
def sample_config() -> Config:
    """A sample configuration with 10 validators."""
    return Config(num_validators=10, genesis_time=0)


@pytest.fixture
def sample_block_header() -> BlockHeader:
    """A sample, empty block header."""
    return BlockHeader(
        slot=0,
        proposer_index=0,
        parent_root=Bytes32(b"\x00" * 32),
        state_root=Bytes32(b"\x00" * 32),
        body_root=Bytes32(b"\x00" * 32),
    )


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """A sample, empty checkpoint."""
    return Checkpoint(root=Bytes32(b"\x00" * 32), slot=0)


def test_is_proposer(
    sample_config: Config,
    sample_block_header: BlockHeader,
    sample_checkpoint: Checkpoint,
) -> None:
    """
    Test the `is_proposer` method with various slots and validator indices.
    """

    def create_state_at_slot(slot: int) -> State:
        """Create a state object at a given slot."""
        return State(
            config=sample_config,
            slot=Uint64(slot),
            latest_block_header=sample_block_header,
            latest_justified=sample_checkpoint,
            latest_finalized=sample_checkpoint,
            historical_block_hashes=[],
            justified_slots=[],
            justifications_roots=[],
            justifications_validators=[],
        )

    # Slot 0
    state_slot_0 = create_state_at_slot(0)
    assert state_slot_0.is_proposer(ValidatorIndex(0)) is True
    assert state_slot_0.is_proposer(ValidatorIndex(1)) is False

    # Slot 7
    state_slot_7 = create_state_at_slot(7)
    assert state_slot_7.is_proposer(ValidatorIndex(7)) is True
    assert state_slot_7.is_proposer(ValidatorIndex(8)) is False

    # Slot 10 (wraps around)
    state_slot_10 = create_state_at_slot(10)
    assert state_slot_10.is_proposer(ValidatorIndex(0)) is True
    assert state_slot_10.is_proposer(ValidatorIndex(1)) is False

    # Slot 23 (wraps around)
    state_slot_23 = create_state_at_slot(23)
    assert state_slot_23.is_proposer(ValidatorIndex(3)) is True
    assert state_slot_23.is_proposer(ValidatorIndex(2)) is False
