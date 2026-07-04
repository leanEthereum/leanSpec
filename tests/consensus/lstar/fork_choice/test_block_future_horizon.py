"""Fork Choice: blocks past the clock's future horizon are rejected."""

import pytest

from consensus_testing import (
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Interval, RejectionReason, Slot

pytestmark = pytest.mark.valid_until("Lstar")


def test_block_beyond_future_horizon_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block two slots past the store clock is rejected as too far in future.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis
    - the store clock sits at genesis and never ticks.

    When
    ----
    - a block at slot 2 arrives while the clock reports current slot 0.

    Then
    ----
    - the store rejects the block with reason block too far in future.
    - store time stays at interval 0.
    - the head stays at genesis (slot 0).
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                tick_to_slot=False,
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.BLOCK_TOO_FAR_IN_FUTURE,
                    exact_message="Block too far in future",
                ),
                checks=StoreChecks(time=Interval(0), head_slot=Slot(0)),
            ),
        ],
    )


def test_block_at_clock_horizon_edge_imported(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block exactly one slot past the clock imports at the future horizon edge.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> block(2)
    - the clock ticks to the start of slot 1 (interval 5), so current slot is 1.

    When
    ----
    - a block at slot 2 arrives without advancing the clock.

    Then
    ----
    - the horizon is current slot plus one, so slot 2 is admissible.
    - store time stays at interval 5.
    - the head advances to the slot 2 block.
    """
    fork_choice_test(
        steps=[
            TickStep(
                interval=5,
                checks=StoreChecks(time=Interval(5), head_slot=Slot(0)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                tick_to_slot=False,
                checks=StoreChecks(time=Interval(5), head_slot=Slot(2)),
            ),
        ],
    )


def test_block_one_past_horizon_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block two slots past the clock is rejected even at a non-genesis clock.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis
    - the clock ticks to the start of slot 1 (interval 5), so current slot is 1.

    When
    ----
    - a block at slot 3 arrives without advancing the clock.

    Then
    ----
    - the horizon is current slot plus one, so slot 3 exceeds it.
    - the store rejects the block with reason block too far in future.
    - store time stays at interval 5.
    - the head stays at genesis (slot 0).
    """
    fork_choice_test(
        steps=[
            TickStep(
                interval=5,
                checks=StoreChecks(time=Interval(5), head_slot=Slot(0)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                tick_to_slot=False,
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.BLOCK_TOO_FAR_IN_FUTURE,
                    exact_message="Block too far in future",
                ),
                checks=StoreChecks(time=Interval(5), head_slot=Slot(0)),
            ),
        ],
    )
