"""Fork choice tick interval progression tests."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    AttestationCheck,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Interval, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_tick_interval_progression_through_full_slot(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Each interval of a slot drives its own store transition over one tick cycle.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - genesis time is 0, so 800 ms intervals place slot 3 at intervals 15 to 19.
    - tick times in seconds map to: 12s = interval 15, 13s = 16, 14s = 17, 15s = 18.
    - 16s lands at interval 20, passing through interval 19.

    When
    ----
    - time advances through slot 3 intervals 0 to 4.
    - V0, V1, V2 gossip an aggregate for block_2 during interval 2.

    Then
    ----
    - intervals 0 to 2 leave the store unchanged with head at block_2.
    - the gossiped aggregate lands in the new pool.
    - interval 3 recomputes safe target to block_2 from the new pool.
    - interval 4 migrates the votes from the new pool to the known pool.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            TickStep(
                time=12,
                checks=StoreChecks(
                    time=Interval(15),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            TickStep(
                time=13,
                checks=StoreChecks(
                    time=Interval(16),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            TickStep(
                time=14,
                checks=StoreChecks(
                    time=Interval(17),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
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
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            TickStep(
                time=15,
                checks=StoreChecks(
                    time=Interval(18),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            TickStep(
                time=16,
                checks=StoreChecks(
                    time=Interval(20),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="known",
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_on_tick_advances_across_multiple_empty_slots(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Time advances through empty slots while the head stays put.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1)
    - no further blocks are produced.

    When
    ----
    - time advances to slot 2, then slot 3, then slot 4.

    Then
    ----
    - store time tracks each slot boundary.
    - head stays at block_1 throughout.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            TickStep(
                time=8,
                checks=StoreChecks(
                    time=Interval(10),
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            TickStep(
                time=12,
                checks=StoreChecks(
                    time=Interval(15),
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            TickStep(
                time=16,
                checks=StoreChecks(
                    time=Interval(20),
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
        ],
    )


def test_tick_interval_0_skips_acceptance_when_not_proposer(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Interval 0 accepts pending votes only for the slot's proposer.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - V0 is the proposer for slot 4.
    - V0 is not the proposer for slot 3.

    When
    ----
    - a pending vote is held while time crosses slot 3 interval 0 without a proposal.
    - a pending vote is held while time crosses slot 4 interval 0 with a proposal.
    - a pending vote is held while time crosses slot 5 interval 4 without a proposal.

    Then
    ----
    - slot 3 interval 0 leaves the vote in the new pool.
    - slot 4 interval 0 migrates the vote to the known pool early.
    - slot 5 interval 4 migrates the vote to the known pool regardless of proposer.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            TickStep(
                interval=14,
                checks=StoreChecks(
                    time=Interval(14),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
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
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            TickStep(
                interval=15,
                checks=StoreChecks(
                    time=Interval(15),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            TickStep(
                interval=19,
                checks=StoreChecks(
                    time=Interval(19),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            TickStep(
                interval=20,
                has_proposal=True,
                checks=StoreChecks(
                    time=Interval(20),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            location="known",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            TickStep(
                interval=28,
                checks=StoreChecks(
                    time=Interval(28),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(5),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            TickStep(
                interval=29,
                checks=StoreChecks(
                    time=Interval(29),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="known",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
        ],
    )
