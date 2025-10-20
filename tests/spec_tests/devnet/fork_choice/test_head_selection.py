"""Fork choice head selection tests for the devnet fork."""

import pytest
from lean_spec_tests import (
    BlockBuilder,
    BlockStep,
    ForkChoiceTestFiller,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State

pytestmark = pytest.mark.valid_until("Devnet")


def test_process_single_block(
    fork_choice_test: ForkChoiceTestFiller,
    genesis: State,
) -> None:
    """
    Test that a single block can be processed successfully.

    This is the simplest fork choice test - just verify that we can
    process a block through the Store without errors.
    """
    # Create a block at slot 1
    block1 = BlockBuilder(genesis).build(Slot(1))

    # Generate the test fixture
    # Note: anchor_block is auto-generated from anchor_state
    # We don't add checks here - just verify the block processes successfully
    fork_choice_test(
        anchor_state=genesis,
        steps=[
            BlockStep(block=block1),
        ],
    )


def test_process_two_blocks_sequential(
    fork_choice_test: ForkChoiceTestFiller,
    genesis: State,
) -> None:
    """Test processing two sequential blocks."""
    # Create blocks
    block1 = BlockBuilder(genesis).build(Slot(1))
    state_after_block1 = genesis.state_transition(block1)
    block2 = BlockBuilder(state_after_block1).build(Slot(2))

    # Generate the test fixture
    # Just verify both blocks process successfully
    fork_choice_test(
        anchor_state=genesis,
        steps=[
            BlockStep(block=block1),
            BlockStep(block=block2),
        ],
    )
