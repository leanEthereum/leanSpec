"""Fork Choice: lexicographic tiebreaker between forks of equal weight."""

import pytest

from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)
from lean_spec.spec.forks import Slot

pytestmark = pytest.mark.valid_until("Lstar")


def test_equal_weight_forks_use_lexicographic_tiebreaker(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice breaks an equal-weight tie by the lexicographically highest root.

    Given
    -----
    - 4 validators.
    - the chain:
        base(1)
        - fork_a_2(2)
        - fork_b_3(3)
    - fork_a_2 and fork_b_3 share base as parent.
    - neither tip carries any votes.
    - the two tips have equal weight.

    When
    ----
    - fork_b_3 is added, creating the equal-weight tie.

    Then
    ----
    - head is the lexicographically highest root among fork_a_2 and fork_b_3.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_b_3"),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3"],
                ),
            ),
        ],
    )
