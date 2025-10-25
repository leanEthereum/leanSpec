"""Fork choice head selection tests for the devnet fork."""

import pytest
from consensus_testing import BlockSpec, BlockStep, ForkChoiceTestFiller, StoreChecks

from lean_spec.subspecs.containers.slot import Slot

pytestmark = pytest.mark.valid_until("Devnet")


def test_head_updates_after_single_block(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Test that head updates correctly after processing a single block.

    With no attestations, fork choice should select the latest block
    on the canonical chain.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
        ],
    )


def test_head_advances_with_sequential_blocks(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Test head selection advances through sequential blocks.

    Each new block should become the new head since there are no forks.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
        ],
    )
