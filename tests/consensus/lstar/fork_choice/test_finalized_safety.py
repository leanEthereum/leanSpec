"""Fork Choice: a finalized block is never reverted, even by a heavier fork."""

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


def test_heavier_fork_below_finalized_slot_never_wins(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A fork branching below the finalized slot loses even when it is genuinely heavier.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis
        - block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
          - dead_6(6) -> dead_7(7) -> dead_8(8) -> dead_9(9)
    - block_2 includes V0..V5's votes for block_1.
    - block_3 includes V0..V5's votes for block_2.
    - block_4 includes V0..V5's votes for block_3.
    - block_5 includes V0..V5's votes for block_4.
    - the canonical chain justifies slot 4.
    - the canonical chain finalizes slot 3.
    - the dead fork branches off block_1, below the finalized slot 3.
    - dead_9 includes V0..V6's votes for dead_8.
    - the dead fork holds 7 votes, more than the 4 on any canonical block.

    When
    ----
    - the canonical chain is built, then the heavier dead fork is built off block_1.

    Then
    ----
    - head stays on block_5, never descending into the heavier dead fork.
    - justified stays at slot 4.
    - finalized stays at slot 3.
    - the finalized root block_3 is still an ancestor of the head.

    Reachability
    ------------
    - head selection starts from the justified root at block_4.
    - the dead fork branches off block_1, below the justified root.
    - the forward walk never reaches the dead fork, so its weight cannot count.
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
                    parent_label="block_1",
                    label="block_2",
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
                    parent_label="block_2",
                    label="block_3",
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
                    parent_label="block_3",
                    label="block_4",
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
                    parent_label="block_4",
                    label="block_5",
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
                block=BlockSpec(slot=Slot(6), parent_label="block_1", label="dead_6"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="dead_6", label="dead_7"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(8), parent_label="dead_7", label="dead_8"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(9),
                    parent_label="dead_8",
                    label="dead_9",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(7)],
                            slot=Slot(9),
                            target_slot=Slot(8),
                            target_root_label="dead_8",
                            source_root_label="block_1",
                            source_slot=Slot(1),
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                    latest_justified_slot=Slot(4),
                    latest_justified_root_label="block_4",
                    latest_finalized_slot=Slot(3),
                    latest_finalized_root_label="block_3",
                ),
            ),
        ],
    )


def test_fork_above_finalized_wins_at_or_below_loses(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A fork rooted above the finalized slot may win; one at the finalized slot may not.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis
        - block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
          - above_6(6) -> above_7(7)
          - at_8(8) -> at_9(9)
    - block_2 through block_5 each include V0..V5's votes for their parent.
    - the canonical chain justifies slot 4.
    - the canonical chain finalizes slot 3.
    - above branches off block_4, above the finalized slot 3.
    - at branches off block_3, the finalized slot itself.
    - above_7 includes V0..V5's votes for above_6.
    - those 6 votes justify above_6 at slot 6, source block_4 at slot 4.
    - slot 5 between source and target is justifiable, so finalization does not advance.
    - at_9 includes V0..V6's votes for at_8.

    When
    ----
    - the above fork justifies slot 6, the at fork gathers 7 votes.

    Then
    ----
    - the justified checkpoint moves to above_6 at slot 6, on the above fork.
    - head moves onto the above fork, which descends from the old justified root.
    - the at fork, rooted at the finalized slot, never takes the head.
    - the at fork's votes carry an unjustified source, so they justify nothing.
    - justified stays at above_6 at slot 6.
    - finalized stays at slot 3 on block_3.

    Reachability
    ------------
    - head selection starts from the justified root at block_4.
    - above branches off block_4, so the forward walk can descend into it.
    - at branches off block_3, below the justified root, so the walk never reaches it.
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
                    parent_label="block_1",
                    label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(latest_justified_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
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
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="block_3",
                    label="block_4",
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
                    latest_justified_slot=Slot(3),
                    latest_finalized_slot=Slot(2),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="block_4",
                    label="block_5",
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
                    latest_justified_root_label="block_4",
                    latest_finalized_slot=Slot(3),
                    latest_finalized_root_label="block_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="block_4", label="above_6"),
                checks=StoreChecks(
                    latest_justified_slot=Slot(4),
                    latest_justified_root_label="block_4",
                    latest_finalized_slot=Slot(3),
                    latest_finalized_root_label="block_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    parent_label="above_6",
                    label="above_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(7),
                            target_slot=Slot(6),
                            target_root_label="above_6",
                            source_root_label="block_4",
                            source_slot=Slot(4),
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="above_7",
                    latest_justified_slot=Slot(6),
                    latest_justified_root_label="above_6",
                    latest_finalized_slot=Slot(3),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(8), parent_label="block_3", label="at_8"),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="above_7",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(9),
                    parent_label="at_8",
                    label="at_9",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(7)],
                            slot=Slot(9),
                            target_slot=Slot(8),
                            target_root_label="at_8",
                            source_root_label="block_3",
                            source_slot=Slot(3),
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="above_7",
                    latest_justified_slot=Slot(6),
                    latest_justified_root_label="above_6",
                    latest_finalized_slot=Slot(3),
                    latest_finalized_root_label="block_3",
                ),
            ),
        ],
    )


def test_losing_fork_higher_finalized_does_not_latch(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A fork that finalizes a higher slot but loses head selection must not leave its
    finalized checkpoint latched in the store.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis
        - block_1(1) -> block_2(2) -> block_3(3)
          - dead_4(4) -> dead_5(5) -> dead_6(6)
          - heavy_7(7) -> heavy_8(8)
    - block_2 includes V0..V5's votes for block_1.
    - block_3 includes V0..V5's votes for block_2.
    - the chain through block_3 justifies slot 2 and finalizes slot 1.
    - the dead fork branches off block_3:
        - dead_4 includes V0..V5's votes for block_3, finalizing slot 2.
        - dead_5 includes V0..V5's votes for dead_4, finalizing slot 3.
        - dead_6 includes V0..V5's votes for dead_5, finalizing slot 4.
      so the dead fork reaches justified slot 5 and finalized slot 4 on dead_4.
    - the heavy fork branches off block_3:
        - heavy_8 includes V0..V5's votes for heavy_7, source block_2.
        - those 6 votes justify heavy_7 at slot 7.
        - slots 3, 4, 5, 6 between source block_2 and target heavy_7 are justifiable,
          so the heavy fork finalizes nothing beyond slot 1.

    When
    ----
    - the dead fork is built to justified slot 5 and finalized slot 4, then the
      heavy fork justifies slot 7, the highest justified checkpoint in the store.

    Then
    ----
    - the justified checkpoint moves to heavy_7 at slot 7, on the heavy fork.
    - head moves onto the heavy fork at heavy_8.
    - the finalized checkpoint tracks the canonical head heavy_8's state: slot 1 on
      block_1. It must not stay at the dead fork's higher finalized slot 4 on dead_4,
      which is not an ancestor of the head.

    Reachability
    ------------
    - head selection starts from the justified root at heavy_7.
    - the dead fork branches off block_3, below the justified root, so the forward
      walk never reaches it and its finalized checkpoint cannot stay canonical.
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
                    parent_label="block_1",
                    label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(latest_justified_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                            source_slot=Slot(1),
                            source_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="block_3",
                    label="dead_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(4),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                            source_slot=Slot(2),
                            source_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    latest_justified_slot=Slot(3),
                    latest_finalized_slot=Slot(2),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="dead_4",
                    label="dead_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(5),
                            target_slot=Slot(4),
                            target_root_label="dead_4",
                            source_slot=Slot(3),
                            source_root_label="block_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    latest_justified_slot=Slot(4),
                    latest_finalized_slot=Slot(3),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="dead_5",
                    label="dead_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(6),
                            target_slot=Slot(5),
                            target_root_label="dead_5",
                            source_slot=Slot(4),
                            source_root_label="dead_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_root_label="dead_6",
                    latest_justified_slot=Slot(5),
                    latest_finalized_slot=Slot(4),
                    latest_finalized_root_label="dead_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="block_3", label="heavy_7"),
                checks=StoreChecks(head_root_label="dead_6"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="heavy_7",
                    label="heavy_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(8),
                            target_slot=Slot(7),
                            target_root_label="heavy_7",
                            source_slot=Slot(2),
                            source_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_root_label="heavy_8",
                    latest_justified_slot=Slot(7),
                    latest_justified_root_label="heavy_7",
                    latest_finalized_slot=Slot(1),
                    latest_finalized_root_label="block_1",
                ),
            ),
        ],
    )
