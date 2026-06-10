"""Fork Choice: how the head moves when justification jumps between forks."""

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


def test_head_retreats_onto_shorter_justified_fork(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The head retreats to a lower slot when a shorter fork becomes justified.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis
        - a_2(2) -> a_3(3) -> a_4(4) -> ... -> a_10(10)
        - b_1(1) -> b_2(2)
    - fork A branches from genesis at slot 2.
    - a_3 includes V6's vote for a_2, giving fork A weight 1.
    - fork A leads on weight and length.
    - fork A's head sits at slot 10.
    - fork B branches from genesis at slot 1.
    - b_1 sits at slot 1, a justifiable distance from the finalized slot 0.
    - b_2 includes V0..V5's votes for b_1.
    - those 6 votes justify b_1 at slot 1.

    When
    ----
    - fork A is built to slot 10, then fork B justifies b_1.

    Then
    ----
    - head stays on a_10 at slot 10 while fork B carries no decisive votes.
    - the justified checkpoint moves to b_1 at slot 1.
    - fork A is discarded, since it does not descend from the new checkpoint.
    - head becomes b_2 at slot 2, retreating from slot 10.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="genesis", label="a_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="a_2"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="a_2",
                    label="a_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(6)],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="a_2",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="a_3"),
            ),
            *[
                BlockStep(
                    block=BlockSpec(
                        slot=Slot(i),
                        parent_label=f"a_{i - 1}",
                        label=f"a_{i}",
                    ),
                    checks=StoreChecks(head_slot=Slot(i), head_root_label=f"a_{i}"),
                )
                for i in range(4, 11)
            ],
            BlockStep(
                block=BlockSpec(slot=Slot(1), parent_label="genesis", label="b_1"),
                checks=StoreChecks(head_slot=Slot(10), head_root_label="a_10"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="b_1",
                    label="b_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="b_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="b_2",
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="b_1",
                ),
            ),
        ],
    )


def test_block_that_justifies_reanchors_within_one_import(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A single justifying block abandons the leading sibling in that same import.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis -> common(1)
        - lead_2(2) -> lead_3(3)
        - other_4(4) -> other_5(5)
    - lead_3 includes V6's vote for lead_2.
    - the lead fork holds weight 1.
    - the lead fork is the head.
    - other branches from common at slot 4 with no votes.
    - other_5 includes V0..V5's votes for other_4.
    - those 6 votes justify other_4 at slot 4 in a single block import.

    When
    ----
    - the lead fork is built, then other_5 is imported in one step.

    Then
    ----
    - the import justifies other_4.
    - the import recomputes the head.
    - the justified checkpoint moves to other_4 at slot 4.
    - head switches to other_5, abandoning the lead fork in the same import.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="lead_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="lead_2"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="lead_2",
                    label="lead_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(6)],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="lead_2",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="lead_3"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="common", label="other_4"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="lead_3"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="other_4",
                    label="other_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(5),
                            target_slot=Slot(4),
                            target_root_label="other_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="other_5",
                    latest_justified_slot=Slot(4),
                    latest_justified_root_label="other_4",
                ),
            ),
        ],
    )


def test_equal_slot_justified_candidate_keeps_original_root(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A later justification at the same slot does not swap the stored justified root.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis
        - a_1(1) -> a_2(2)
        - b_1(1) -> b_2(2)
    - a_1 and b_1 are sibling blocks, both at slot 1 off genesis.
    - a_2 includes V0..V5's votes for a_1.
    - those 6 votes justify a_1 at slot 1, the first justified candidate.
    - b_2 includes V0..V5's votes for b_1.
    - those 6 votes also justify a block at slot 1, but a different root.

    When
    ----
    - fork A justifies a_1 at slot 1 first, then fork B justifies b_1 at slot 1.

    Then
    ----
    - the store adopts a_1 at slot 1 as justified first.
    - the fork B candidate sits at the same justified slot 1.
    - the store keeps a_1, since an equal slot does not advance the checkpoint.
    - head stays on fork A at a_2, never anchoring to fork B.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), parent_label="genesis", label="a_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="a_1"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="a_1",
                    label="a_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="a_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="a_2",
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="a_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(1), parent_label="genesis", label="b_1"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="a_2",
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="a_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="b_1",
                    label="b_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="b_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="a_2",
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="a_1",
                ),
            ),
        ],
    )
