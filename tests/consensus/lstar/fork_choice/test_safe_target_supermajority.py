"""Fork Choice: safe-target threshold rounds up at odd validator counts."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
    generate_pre_state,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_odd_five_validators_three_votes_hold_safe_target_at_genesis(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    With 5 validators the safe target needs 4 votes, so 3 fall short.

    Given
    -----
    - 5 validators; a slot needs 4 votes to be a safe target.
    - the threshold rounds up: two thirds of 5 is 3.33, ceiled to 4.
    - the chain:
        genesis -> block_1(1) -> block_2(2)
    - genesis is the justified anchor.
    - V0, V1, V2 gossip one aggregate for block_2.
    - every ancestor of block_2 carries 3 votes.

    When
    ----
    - time reaches slot 3 interval 3, the safe-target computation.

    Then
    ----
    - block_1 carries 3 votes, one short of the threshold.
    - the safe-target walk halts at slot 0.
    - head still advances to block_2, since head selection has no threshold.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=5),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            TickStep(time=14),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(0),
                ),
            ),
        ],
    )


def test_odd_five_validators_four_votes_advance_safe_target(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    With 5 validators four votes clear the rounded-up threshold.

    Given
    -----
    - 5 validators; a slot needs 4 votes to be a safe target.
    - the threshold rounds up: two thirds of 5 is 3.33, ceiled to 4.
    - the chain:
        genesis -> block_1(1) -> block_2(2)
    - genesis is the justified anchor.
    - V0, V1, V2, V3 gossip one aggregate for block_2.
    - every ancestor of block_2 carries 4 votes.

    When
    ----
    - time reaches slot 3 interval 3, the safe-target computation.

    Then
    ----
    - block_1 and block_2 each carry 4 votes, meeting the threshold.
    - the safe-target walk advances to block_2.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=5),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            TickStep(time=14),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                ),
            ),
        ],
    )


def test_odd_seven_validators_four_votes_hold_safe_target_at_genesis(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    With 7 validators the safe target needs 5 votes, so 4 fall short.

    Given
    -----
    - 7 validators; a slot needs 5 votes to be a safe target.
    - the threshold rounds up: two thirds of 7 is 4.67, ceiled to 5.
    - the chain:
        genesis -> block_1(1) -> block_2(2)
    - genesis is the justified anchor.
    - V0, V1, V2, V3 gossip one aggregate for block_2.
    - every ancestor of block_2 carries 4 votes.

    When
    ----
    - time reaches slot 3 interval 3, the safe-target computation.

    Then
    ----
    - block_1 carries 4 votes, one short of the threshold.
    - the safe-target walk halts at slot 0.
    - head still advances to block_2, since head selection has no threshold.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=7),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            TickStep(time=14),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(0),
                ),
            ),
        ],
    )


def test_odd_seven_validators_five_votes_advance_safe_target(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    With 7 validators five votes clear the rounded-up threshold.

    Given
    -----
    - 7 validators; a slot needs 5 votes to be a safe target.
    - the threshold rounds up: two thirds of 7 is 4.67, ceiled to 5.
    - the chain:
        genesis -> block_1(1) -> block_2(2)
    - genesis is the justified anchor.
    - V0, V1, V2, V3, V4 gossip one aggregate for block_2.
    - every ancestor of block_2 carries 5 votes.

    When
    ----
    - time reaches slot 3 interval 3, the safe-target computation.

    Then
    ----
    - block_1 and block_2 each carry 5 votes, meeting the threshold.
    - the safe-target walk advances to block_2.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=7),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            TickStep(time=14),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                        ValidatorIndex(4),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                ),
            ),
        ],
    )
