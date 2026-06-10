"""Fork Choice: LMD latest-message selection and the strict-slot replacement rule."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_higher_slot_vote_replaces_lower_slot_vote(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A validator's higher-slot vote replaces its earlier lower-slot vote.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> common(1)
        - fork_a(2) -> reach_5(5)
        - fork_b(3)
    - V0 first casts a slot-3 vote for fork_b.
    - V0 then casts a slot-5 vote for fork_a, on the reach_5 branch.
    - reach_5 extends fork_a so a slot-5 head vote is available there.

    When
    ----
    - the slot-3 vote lands first, then the higher slot-5 vote lands.

    Then
    ----
    - fork_b leads while V0's only vote is its slot-3 vote.
    - the slot-5 vote replaces the slot-3 vote, since it sits at a strictly higher slot.
    - V0's weight moves from fork_b onto the fork_a branch.
    - head flips onto the fork_a branch at reach_5.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="fork_a"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="common", label="fork_b"),
                checks=StoreChecks(lexicographic_head_among=["fork_a", "fork_b"]),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_a", label="reach_5"),
            ),
            TickStep(interval=28),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0)],
                    slot=Slot(3),
                    target_slot=Slot(3),
                    target_root_label="fork_b",
                ),
            ),
            TickStep(
                interval=29,
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_b",
                ),
            ),
            TickStep(interval=33),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0)],
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="reach_5",
                    source_root_label="common",
                    source_slot=Slot(1),
                ),
            ),
            TickStep(
                interval=34,
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="reach_5",
                ),
            ),
        ],
    )


def test_lexicographic_tiebreak_selects_larger_root_and_is_stable(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The tiebreaker picks the lexicographically larger root and holds it stable.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> base(1)
        - fork_a(2) -> extend_a(4)
        - fork_b(3) -> extend_b(5)
    - fork_a and fork_b share base as parent.
    - neither tip carries any vote.
    - the two tips have equal weight.
    - fork_a holds the lexicographically larger root.

    When
    ----
    - fork_b is added, creating the equal-weight tie.
    - extend_a is added on the chosen head fork_a.
    - extend_b is added on the losing fork_b as an unrelated block.

    Then
    ----
    - head is fork_a, the lexicographically larger of the two tied roots.
    - the head walk descends onto extend_a after it extends the chosen fork.
    - extend_b on the losing fork never takes the head.
    - head is extend_a, stable after the unrelated block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="base"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_b"),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a", "fork_b"],
                    head_root_label="fork_a",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="fork_a", label="extend_a"),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="extend_a"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_b", label="extend_b"),
                checks=StoreChecks(head_slot=Slot(4), head_root_label="extend_a"),
            ),
        ],
    )
