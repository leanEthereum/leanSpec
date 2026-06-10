"""Fork Choice Head Selection (LMD-GHOST Algorithm)"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    generate_pre_state,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_head_advances_through_deep_chain(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The head follows a long linear chain to its tip.

    Given
    -----
    - the chain:
        genesis -> block(1) -> ... -> block_20(20)
    - no block carries any vote.

    When
    ----
    - 20 blocks are added one per slot.

    Then
    ----
    - head advances through every block.
    - the final head is block_20 at slot 20.
    """
    steps = []
    for i in range(1, 21):
        if i == 20:
            steps.append(
                BlockStep(
                    block=BlockSpec(slot=Slot(i), label="block_20"),
                    checks=StoreChecks(
                        head_slot=Slot(i),
                        head_root_label="block_20",
                    ),
                )
            )
        else:
            steps.append(
                BlockStep(
                    block=BlockSpec(slot=Slot(i)),
                    checks=StoreChecks(head_slot=Slot(i)),
                )
            )

    fork_choice_test(steps=steps)


def test_head_with_gaps_in_slots(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The head tolerates small gaps where slots carry no block.

    Given
    -----
    - the chain:
        genesis -> block(1) -> block(3) -> block(5) -> block(7) -> block(9)
    - slots 2, 4, 6, and 8 carry no block.
    - no block carries any vote.

    When
    ----
    - blocks are added at the odd slots only.

    Then
    ----
    - head advances to each present block.
    - the final head is the block at slot 9.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(head_slot=Slot(5)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7)),
                checks=StoreChecks(head_slot=Slot(7)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(9)),
                checks=StoreChecks(head_slot=Slot(9)),
            ),
        ],
    )


def test_head_with_large_gaps(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The head tolerates large gaps between blocks.

    Given
    -----
    - the chain:
        genesis -> block(1) -> block(10) -> block(20) -> block(30)
    - gaps of nine or ten slots sit between blocks.
    - no block carries any vote.

    When
    ----
    - blocks are added at slots 1, 10, 20, and 30.

    Then
    ----
    - head advances to each block despite the gaps.
    - the final head is the block at slot 30.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(10)),
                checks=StoreChecks(head_slot=Slot(10)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(20)),
                checks=StoreChecks(head_slot=Slot(20)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(30)),
                checks=StoreChecks(head_slot=Slot(30)),
            ),
        ],
    )


def test_duplicate_block_processed_idempotently(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Re-submitting an identical block leaves the store unchanged.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2)
    - block_2 includes 3 votes for block_1.
    - block_2 justifies slot 1.
    - block_2_dup repeats block_2 with identical parameters.

    When
    ----
    - block_2 is submitted, then block_2_dup is submitted.

    Then
    ----
    - both steps succeed.
    - block_2_dup resolves to the same root as block_2.
    - head, justified, and finalized stay unchanged after the duplicate.
    - the repeated votes are not double-counted.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="block_1",
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="block_2_dup",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    filled_block_root_label="block_2",
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="block_1",
                    latest_finalized_slot=Slot(0),
                ),
            ),
        ],
    )


def test_head_with_two_competing_forks(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Two equal-weight forks resolve by lexicographic tiebreaker.

    Given
    -----
    - the chain:
        genesis -> common(1)
        - fork_a(2)
        - fork_b(3)
    - each fork has one block and one proposer vote.
    - the two forks carry equal weight.

    When
    ----
    - both forks are added from the common ancestor.

    Then
    ----
    - head is common after slot 1.
    - head is fork_a while it is the only fork.
    - the tiebreaker picks the head by lexicographic root once fork_b exists.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="common",
                    label="fork_a",
                ),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="common",
                    label="fork_b",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a", "fork_b"],
                ),
            ),
        ],
    )


def test_head_switches_to_heavier_fork(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The head switches to a fork once a new vote makes it heavier.

    Given
    -----
    - the chain:
        genesis -> common(1)
        - fork_a(2)
        - fork_b(3) -> fork_b_4(4)
    - fork_a and fork_b start with equal weight.
    - fork_b_4 includes V2's vote for fork_b.

    When
    ----
    - both forks are added, then fork_b is extended with a vote.

    Then
    ----
    - head is fork_a while it is the only fork.
    - the tiebreaker picks the head once fork_b ties it.
    - the new vote gives fork_b more weight.
    - head switches to fork_b_4.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="common",
                    label="fork_a",
                ),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="common",
                    label="fork_b",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a", "fork_b"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_b",
                    label="fork_b_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_b",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_b_4"),
            ),
        ],
    )


def test_head_with_deep_fork_split(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The head follows the deeper fork once it accumulates more weight.

    Given
    -----
    - the chain:
        genesis -> common(1)
        - fork_a_2(2) -> fork_a_3(3) -> fork_a_4(4)
        - fork_b_5(5) -> fork_b_6(6) -> fork_b_7(7) -> fork_b_8(8)
    - fork_a holds three blocks built first.
    - fork_b starts later and grows to four blocks.
    - each block after the branch head votes for its parent.

    When
    ----
    - fork_a is built, then fork_b is built deeper.

    Then
    ----
    - head stays on fork_a_4 while fork_b is shorter.
    - head moves to fork_b_8 once fork_b grows heavier.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="fork_a_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a_2"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_a_2",
                    label="fork_a_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="fork_a_2",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="fork_a_3"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_a_3",
                    label="fork_a_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_a_3",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="common", label="fork_b_5"),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_b_5",
                    label="fork_b_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_b_5",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="fork_a_4"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    parent_label="fork_b_6",
                    label="fork_b_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(6),
                            target_slot=Slot(6),
                            target_root_label="fork_b_6",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="fork_b_7",
                    label="fork_b_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(7),
                            target_slot=Slot(7),
                            target_root_label="fork_b_7",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(8), head_root_label="fork_b_8"),
            ),
        ],
    )


def test_head_selection_by_weight_not_depth(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A shorter fork with more votes beats a deeper fork with fewer votes.

    Given
    -----
    - 6 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> common(1)
        - a_2(2) -> a_3(3) -> a_4(4) -> a_5(5) -> a_6(6)
        - b_9(9) -> b_12(12)
    - fork_a is five blocks deep.
    - a_3 includes V0's vote for a_2.
    - fork_a carries 1 vote total.
    - fork_b is two blocks deep.
    - b_12 includes V1, V2, V3's votes for b_9.
    - fork_b carries 3 votes total.
    - 3 votes stay below the 4-vote threshold (3/6).
    - no fork reaches justification.

    When
    ----
    - fork_a is built first, then fork_b is built.

    Then
    ----
    - head stays on a_6 while fork_a is the only branch.
    - head stays on a_6 after b_9, which carries no vote yet.
    - fork_b's 3 votes outweigh fork_a's 1 vote at the fork point.
    - head moves to b_12.
    - justified stays at slot 0.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(block=BlockSpec(slot=Slot(2), parent_label="common", label="a_2")),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="a_2",
                    label="a_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="a_2",
                        ),
                    ],
                ),
            ),
            BlockStep(block=BlockSpec(slot=Slot(4), parent_label="a_3", label="a_4")),
            BlockStep(block=BlockSpec(slot=Slot(5), parent_label="a_4", label="a_5")),
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="a_5", label="a_6"),
                checks=StoreChecks(head_slot=Slot(6), head_root_label="a_6"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(9), parent_label="common", label="b_9"),
                checks=StoreChecks(head_slot=Slot(6), head_root_label="a_6"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="b_9",
                    label="b_12",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                                ValidatorIndex(3),
                            ],
                            slot=Slot(9),
                            target_slot=Slot(9),
                            target_root_label="b_9",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="b_12",
                    latest_justified_slot=Slot(0),
                ),
            ),
        ],
    )


def test_fork_from_before_finalization_not_considered(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A heavier fork is ignored when it branches before the finalized slot.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
        - dead_6(6) -> dead_7(7)
    - the dead fork branches off block_2, below the finalized slot.
    - blocks 2 through 5 each include 6 votes for their parent.
    - the canonical chain justifies slot 4 and finalizes slot 3.
    - dead_7 includes V3, V4, V5, V6, V7's votes for dead_6.
    - V3, V4, V5 move their latest vote from the canonical chain to the dead fork.
    - the dead fork holds 5 votes, more than the canonical chain.
    - 5 votes stay below the 6-vote threshold (5/8).
    - the dead fork reaches no justification.

    When
    ----
    - the canonical chain is built, then the dead fork is built off block_2.

    Then
    ----
    - head stays on block_5 after dead_6, which carries no vote yet.
    - head stays on block_5 after dead_7, despite the dead fork's extra weight.
    - justified stays at slot 4.
    - finalized stays at slot 3.

    Reachability
    ------------
    - head selection starts from the justified root at block_4.
    - the forward walk reaches block_4, then block_5, then stops.
    - the dead fork branches off block_2, an ancestor of block_4.
    - the walk never descends into the dead fork, so its weight cannot count.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    label="block_2",
                    parent_label="block_1",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    latest_justified_slot=Slot(1),
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    label="block_3",
                    parent_label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    label="block_4",
                    parent_label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(4),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    latest_justified_slot=Slot(3),
                    latest_finalized_slot=Slot(2),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    label="block_5",
                    parent_label="block_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(5),
                            target_slot=Slot(4),
                            target_root_label="block_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                    latest_justified_slot=Slot(4),
                    latest_finalized_slot=Slot(3),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="block_2", label="dead_6"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    parent_label="dead_6",
                    label="dead_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(3, 8)],
                            slot=Slot(7),
                            target_slot=Slot(6),
                            target_root_label="dead_6",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                    latest_justified_slot=Slot(4),
                    latest_finalized_slot=Slot(3),
                ),
            ),
        ],
    )
