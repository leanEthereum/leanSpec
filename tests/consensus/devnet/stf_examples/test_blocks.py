"""Single block processing tests for the devnet fork."""

import pytest
from consensus_testing import BlockSpec, StateExpectation, StateTransitionTestFiller

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.types import Bytes52, Uint64

pytestmark = pytest.mark.valid_until("Devnet")


def test_single_empty_block(state_transition_test: StateTransitionTestFiller) -> None:
    """
    Test processing a single empty block (no attestations).

    This is the simplest possible block processing test.
    Uses default pre-state (auto-injected).
    """
    # Pre-state is auto-injected - no need to pass it explicitly
    state_transition_test(
        blocks=[BlockSpec(slot=Slot(1))],
        post=StateExpectation(
            slot=Slot(1),
        ),
    )


def test_single_block_with_slot_gap(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """Test processing a block with empty slots before it. Uses default pre-state."""
    state_transition_test(
        blocks=[BlockSpec(slot=Slot(5))],  # Skip slots 1-4
        post=StateExpectation(
            slot=Slot(5),
        ),
    )


def test_sequential_blocks(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """Test processing a sequence of blocks in consecutive slots. Uses default pre-state."""
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1)),
            BlockSpec(slot=Slot(2)),
            BlockSpec(slot=Slot(3)),
        ],
        post=StateExpectation(
            slot=Slot(3),
            validator_count=4,
        ),
    )
