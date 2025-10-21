"""Single block processing tests for the devnet fork."""

import pytest
from lean_spec_tests import BlockBuilder, StateTransitionTestFiller

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.types import Uint64

pytestmark = pytest.mark.valid_until("Devnet")


def test_single_empty_block(state_transition_test: StateTransitionTestFiller) -> None:
    """
    Test processing a single empty block (no attestations).

    This is the simplest possible block processing test.
    """
    # Setup genesis state
    genesis = State.generate_genesis(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    # Use BlockBuilder to create a valid block (test setup tool)
    builder = BlockBuilder(genesis)
    block = builder.build(Slot(1))

    # Generate the test fixture - the SPEC does all the work
    state_transition_test(
        pre=genesis,
        blocks=[block],
    )


def test_single_block_with_slot_gap(state_transition_test: StateTransitionTestFiller) -> None:
    """Test processing a block with empty slots before it."""
    genesis = State.generate_genesis(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    # Create a block at slot 5 (skipping slots 1-4)
    builder = BlockBuilder(genesis)
    block = builder.build(Slot(5))

    # Spec processes and validates
    state_transition_test(
        pre=genesis,
        blocks=[block],
    )


def test_sequential_blocks(state_transition_test: StateTransitionTestFiller) -> None:
    """Test processing a sequence of blocks in consecutive slots."""
    genesis = State.generate_genesis(
        genesis_time=Uint64(1000000),
        num_validators=Uint64(4),
    )

    # Build blocks sequentially, updating builder state
    builder = BlockBuilder(genesis)

    block1 = builder.build(Slot(1))
    builder.state = genesis.state_transition(block1)

    block2 = builder.build(Slot(2))
    builder.state = builder.state.state_transition(block2)

    block3 = builder.build(Slot(3))

    # Spec processes all blocks
    state_transition_test(
        pre=genesis,
        blocks=[block1, block2, block3],
    )
