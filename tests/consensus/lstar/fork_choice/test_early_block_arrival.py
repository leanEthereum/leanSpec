"""Fork Choice: blocks delivered ahead of the store clock still import."""

import pytest

from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Interval, Slot

pytestmark = pytest.mark.valid_until("Lstar")


def test_block_ahead_of_store_clock_is_imported(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block whose slot has not begun on the clock still imports and becomes head.

    Given
    -----
    - the chain:
        genesis -> block(1)
    - the store clock sits at genesis and never ticks.

    When
    ----
    - a block at slot 1 arrives before the clock reaches slot 1.

    Then
    ----
    - store time stays at interval 0.
    - head advances to the early block at slot 1.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                tick_to_slot=False,
                checks=StoreChecks(time=Interval(0), head_slot=Slot(1)),
            ),
        ],
    )


def test_early_block_then_clock_catches_up(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The clock catching up to an early block's slot leaves the head unchanged.

    Given
    -----
    - the chain:
        genesis -> block(1)
    - a block at slot 1 imports while the clock sits at interval 0.

    When
    ----
    - the clock ticks forward to the start of slot 2.

    Then
    ----
    - store time advances to interval 10.
    - head stays at the slot 1 block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                tick_to_slot=False,
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            TickStep(
                interval=10,
                checks=StoreChecks(time=Interval(10), head_slot=Slot(1)),
            ),
        ],
    )
