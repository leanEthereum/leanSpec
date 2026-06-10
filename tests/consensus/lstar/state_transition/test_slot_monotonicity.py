"""State Transition: Block Slot Monotonicity Rejections."""

import pytest

from consensus_testing import (
    BlockSpec,
    ExpectedRejection,
    StateTransitionTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import RejectionReason, Slot
from lean_spec.spec.forks.lstar.spec import LstarSpec

pytestmark = pytest.mark.valid_until("Lstar")


def test_process_slots_target_equal_to_state_slot_rejected(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Slots only advance forward, so a block at the current slot is rejected.

    Given
    -----
    - the state is pre-advanced to slot 1.

    When
    ----
    - a block at slot 1 is processed without skipping slot processing.

    Then
    ----
    - slot advancement targets slot 1, which is not in the future.
    - the block is rejected as not in the future.
    """
    pre_state = generate_pre_state()
    pre_state = LstarSpec().process_slots(pre_state, Slot(1))

    state_transition_test(
        pre=pre_state,
        blocks=[
            BlockSpec(slot=Slot(1)),
        ],
        post=None,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.BLOCK_SLOT_NOT_IN_FUTURE,
            message_substring="Target slot must be in the future",
        ),
    )


def test_block_at_parent_slot_rejected_when_slot_processing_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A second block at the same slot as the chain tip is rejected.

    Given
    -----
    - the state is pre-advanced to slot 1, so slot processing is not re-run.
    - first(1) is processed, skipping slot processing.
    - the chain tip header now sits at slot 1.

    When
    ----
    - a second block at slot 1 is processed, skipping slot processing.

    Then
    ----
    - the second block is not newer than the chain tip header.
    - the block is rejected as older than the latest header.
    """
    pre_state = generate_pre_state()
    pre_state = LstarSpec().process_slots(pre_state, Slot(1))

    state_transition_test(
        pre=pre_state,
        blocks=[
            BlockSpec(slot=Slot(1), skip_slot_processing=True, label="first"),
            BlockSpec(slot=Slot(1), skip_slot_processing=True),
        ],
        post=None,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.BLOCK_OLDER_THAN_LATEST_HEADER,
            message_substring="Block is older than latest header",
        ),
    )
