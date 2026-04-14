"""Fork choice tick interval progression tests."""

import pytest
from consensus_testing import (
    AttestationCheck,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Uint64

pytestmark = pytest.mark.valid_until("Devnet")


def test_tick_interval_progression_through_full_slot(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Advance through slot 3's five-interval tick cycle and verify the
    interval-specific store transitions.

    Scenario
    --------
    TickStep.time uses integer unix seconds. With genesis_time=0 and
    MILLISECONDS_PER_INTERVAL=800, slot 3 intervals map to:

    - 12s -> interval 15 (slot 3, interval 0)
    - 13s -> interval 16 (slot 3, interval 1)
    - 14s -> interval 17 (slot 3, interval 2)
    - 15s -> interval 18 (slot 3, interval 3)
    - 16s -> interval 20 (passes through interval 19 = slot 3 interval 4,
      then lands at slot 4 interval 0)

    Expected Behavior
    -----------------
    1. Intervals 0-2: no observable store mutation (no proposal, no pending data)
    2. After gossip at interval 2: attestation lands in "new" pool
    3. Interval 3: safe_target recomputed using "new" pool
    4. Interval 4: attestations migrate from "new" to "known"
    """
    fork_choice_test(
        steps=[
            # Build a short chain so slot 3 can be reached.
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            # Interval 0 with no proposal: the store reaches slot 3, but
            # acceptance does not run because has_proposal is False.
            TickStep(
                time=12,
                checks=StoreChecks(
                    time=Uint64(15),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            # Interval 1 is the vote propagation window, so there is no direct
            # store mutation to assert beyond time/head stability.
            TickStep(
                time=13,
                checks=StoreChecks(
                    time=Uint64(16),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            # Interval 2 is the aggregation window. We tick through it first, then
            # inject an already aggregated gossip attestation so it remains in the
            # "new" pool for the interval-3 and interval-4 checks below.
            TickStep(
                time=14,
                checks=StoreChecks(
                    time=Uint64(17),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
            # Interval 3 recomputes safe_target using both the "new" and "known"
            # attestation pools. The attestation is still unaccepted, so it remains
            # in "new" while still being strong enough to move safe_target.
            TickStep(
                time=15,
                checks=StoreChecks(
                    time=Uint64(18),
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
            # time=16 lands at slot 4 interval 0, passing through slot 3 interval 4
            # on the way. Interval 4 always accepts new attestations, so the
            # attestation migrates from "new" to "known".
            TickStep(
                time=16,
                checks=StoreChecks(
                    time=Uint64(20),
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
    """Time advances through multiple empty slots without changing the head."""
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            # Slot boundaries are the cleanest integer-second checkpoints:
            # 8s -> slot 2 interval 0 -> store time 10
            TickStep(
                time=8,
                checks=StoreChecks(
                    time=Uint64(10),
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            # 12s -> slot 3 interval 0 -> store time 15
            TickStep(
                time=12,
                checks=StoreChecks(
                    time=Uint64(15),
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            # 16s -> slot 4 interval 0 -> store time 20
            TickStep(
                time=16,
                checks=StoreChecks(
                    time=Uint64(20),
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
    Interval 0 only accepts new attestations when a proposal exists.

    Scenario
    --------
    1. Tick to slot 3 interval 0 without a proposal: attestations stay in "new"
    2. Tick to slot 4 interval 0 with has_proposal=True: attestations migrate
       to "known" immediately
    3. Tick to slot 5 interval 4 (unconditional acceptance): fresh attestations
       also migrate without a proposal

    Expected Behavior
    -----------------
    1. Non-proposer interval 0: no acceptance
    2. Proposer interval 0: early acceptance
    3. Interval 4: always accepts regardless of proposer status
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
            # Reach the interval immediately before slot 3 interval 0 so a fresh
            # attestation can remain pending into the non-proposer check.
            TickStep(
                interval=14,
                checks=StoreChecks(
                    time=Uint64(14),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            # Start with a pending aggregated attestation for slot 3.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
            # Exact interval 15 is slot 3 interval 0. Validator 0 is not the
            # proposer for slot 3, so interval 0 must leave the attestation
            # in the "new" pool.
            TickStep(
                interval=15,
                checks=StoreChecks(
                    time=Uint64(15),
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
            # Move to the interval immediately before slot 4 interval 0. We do
            # not assert on the old pending attestation here because interval 2's
            # aggregation path rewrites the "new" pool before slot 3 interval 4.
            TickStep(
                interval=19,
                checks=StoreChecks(
                    time=Uint64(19),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            # Add a fresh pending attestation right before slot 4 interval 0.
            # At store time 19, current slot is still 3, so a slot-4 attestation
            # is within the allowed +1 future-slot margin.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
            # Exact interval 20 is slot 4 interval 0. Validator 0 is the proposer
            # for slot 4, so interval 0 should accept the pending attestation
            # immediately instead of waiting until interval 4.
            TickStep(
                interval=20,
                has_proposal=True,
                checks=StoreChecks(
                    time=Uint64(20),
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
            # Reach slot 5 interval 3, inject a fresh attestation after the
            # aggregation interval, then verify interval 4 accepts it even
            # without a proposal.
            TickStep(
                interval=28,
                checks=StoreChecks(
                    time=Uint64(28),
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
                    time=Uint64(29),
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
