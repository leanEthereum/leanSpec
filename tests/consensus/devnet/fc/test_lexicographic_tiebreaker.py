"""
Fork Choice Lexicographic Tiebreaker Test.

This module tests the lexicographic tiebreaker behavior in fork choice when
competing forks have equal attestation weight.
"""

import pytest
from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)

from lean_spec.forks.lstar.containers.slot import Slot

pytestmark = pytest.mark.valid_until("Lstar")


def test_equal_weight_forks_use_lexicographic_tiebreaker(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice selects lexicographically highest branch when fork weights tie.

    Scenario
    --------
    - Slot 1: Build common ancestor
    - Slots 2-3: Build fork A to depth 2 (slots 2 & 3)
    - Slots 4-5: Build fork B to depth 2 (slots 4 & 5)

    Both forks have identical structure:
    - Same attestation weight (2 proposer attestations each)
    - Same parent (common ancestor at slot 1)

    Expected Behavior
    -----------------
    The competing forks have identical attestation weight. The head is chosen
    via lexicographic ordering of the block roots. The framework automatically
    verifies that the head is the lexicographically highest root among the
    two fork tips.
    """
    fork_choice_test(
        steps=[
            # Common ancestor at slot 1
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            # Fork A: first block
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            # Fork B: first block
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_b_3"),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3"],
                ),
            ),
        ],
    )
