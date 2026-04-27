"""State Transition: Block Slot Monotonicity Rejections."""

import pytest
from consensus_testing import (
    BlockSpec,
    StateTransitionTestFiller,
    generate_pre_state,
)

from lean_spec.forks.lstar.containers.slot import Slot

pytestmark = pytest.mark.valid_until("Devnet")


def test_process_slots_target_equal_to_state_slot_rejected(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Block at a slot already reached by the state is rejected.

    Scenario
    --------
    - Pre-advance the state to slot 1.
    - Submit a block at slot 1 without skipping slot processing.
    - The state transition invokes slot advancement targeting slot 1.

    Expected Behavior
    -----------------
    Slot advancement fails with AssertionError: "Target slot must be in the future"

    Why This Matters
    ----------------
    Guards the slot-monotonicity invariant:

    - Slots only advance forward.
    - A target at or below the current slot is rejected.
    - Protects against replay of already-processed slots.
    """
    pre_state = generate_pre_state()
    pre_state = pre_state.process_slots(Slot(1))

    state_transition_test(
        pre=pre_state,
        blocks=[
            BlockSpec(slot=Slot(1)),
        ],
        post=None,
        expect_exception=AssertionError,
        expect_exception_message="Target slot must be in the future",
    )


def test_block_at_parent_slot_rejected_when_slot_processing_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A second block at the same slot as its parent is rejected.

    Scenario
    --------
    - Pre-advance state to slot 1 so slot processing is not re-run.
    - Submit a first block at slot 1 (skip_slot_processing=True). The latest
      block header now sits at slot 1.
    - Submit a second block at slot 1 (skip_slot_processing=True).

    Expected Behavior
    -----------------
    Block header validation fails with AssertionError:
    "Block is older than latest header"

    Why This Matters
    ----------------
    Enforces strict newness of each block relative to the last processed header:

    - Prevents replacing an already-processed block at the same slot.
    - Blocks header-rewrite attacks.
    - Complements the slot-mismatch check by rejecting even slot-matching blocks
      when the chain tip is at or above the claimed slot.
    """
    pre_state = generate_pre_state()
    pre_state = pre_state.process_slots(Slot(1))

    state_transition_test(
        pre=pre_state,
        blocks=[
            BlockSpec(slot=Slot(1), skip_slot_processing=True, label="first"),
            BlockSpec(slot=Slot(1), skip_slot_processing=True),
        ],
        post=None,
        expect_exception=AssertionError,
        expect_exception_message="Block is older than latest header",
    )
