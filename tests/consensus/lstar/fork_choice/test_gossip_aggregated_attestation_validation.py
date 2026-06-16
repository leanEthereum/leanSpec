"""Gossip aggregated attestation validation vectors."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Interval, RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import GOSSIP_DISPARITY_INTERVALS
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


SLOT_3_BOUNDARY_INTERVAL = int(Interval.from_slot(Slot(3))) - int(GOSSIP_DISPARITY_INTERVALS)
"""Latest local interval that still admits a slot-3 aggregate."""

SLOT_3_JUST_BEYOND_BOUNDARY_INTERVAL = SLOT_3_BOUNDARY_INTERVAL - 1
"""First local interval that rejects a slot-3 aggregate."""


def test_valid_gossip_aggregated_attestation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A valid aggregated gossip attestation is accepted.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips an aggregate voting for block_2 at slot 2.

    Then
    ----
    - the aggregate is validated and stored.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
        ]
    )


def test_aggregated_attestation_unknown_source_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate naming an unknown source block is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips an aggregate for block_2 whose source root is absent from the store.

    Then
    ----
    - validation fails with an unknown source block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root=Bytes32(b"\xff" * 32),
                    source_slot=Slot(999),
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.UNKNOWN_SOURCE_BLOCK,
                    message_substring="Unknown source block",
                ),
            ),
        ]
    )


def test_aggregated_attestation_target_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate whose target slot disagrees with the target block is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips an aggregate naming target slot 3 for block_2, which sits at slot 2.

    Then
    ----
    - validation fails with a target checkpoint slot mismatch.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(2),
                    target_slot=Slot(3),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.TARGET_SLOT_MISMATCH,
                    exact_message="Target checkpoint slot mismatch",
                ),
            ),
        ]
    )


def test_aggregated_attestation_head_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate whose head slot disagrees with the head block is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - V1 gossips an aggregate naming head slot 5 for block_1, which sits at slot 1.

    Then
    ----
    - validation fails with a head checkpoint slot mismatch.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    head_root_label="block_1",
                    head_slot=Slot(5),
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.HEAD_SLOT_MISMATCH,
                    exact_message="Head checkpoint slot mismatch",
                ),
            ),
        ]
    )


def test_aggregated_attestation_source_after_target_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate whose source slot exceeds its target slot is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2) -> block_3(3)

    When
    ----
    - V1 gossips an aggregate with source block_3 at slot 3 and target block_2 at slot 2.

    Then
    ----
    - validation fails because source slot must not exceed target.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.SOURCE_AFTER_TARGET,
                    exact_message="Source checkpoint slot must not exceed target",
                ),
            ),
        ]
    )


def test_aggregated_attestation_too_far_in_future_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate whose slot is two slots ahead of local time is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - local time is at slot 2.

    When
    ----
    - V1 gossips an aggregate at slot 4, two slots in the future.

    Then
    ----
    - validation fails with attestation too far in future.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.ATTESTATION_TOO_FAR_IN_FUTURE,
                    exact_message="Attestation too far in future",
                ),
            ),
        ]
    )


def test_aggregated_attestation_at_disparity_boundary_allowed(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate exactly at the disparity boundary is accepted.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - local time is the latest interval that still admits a slot-3 vote.

    When
    ----
    - V1 gossips an aggregate at slot 3.

    Then
    ----
    - the aggregate is validated and stored.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            TickStep(interval=SLOT_3_BOUNDARY_INTERVAL),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
        ]
    )


def test_aggregated_attestation_just_beyond_disparity_boundary_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate one interval beyond the disparity boundary is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - local time is one interval before the boundary for a slot-3 vote.

    When
    ----
    - V1 gossips an aggregate at slot 3.

    Then
    ----
    - validation fails with attestation too far in future.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            TickStep(interval=SLOT_3_JUST_BEYOND_BOUNDARY_INTERVAL),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.ATTESTATION_TOO_FAR_IN_FUTURE,
                    exact_message="Attestation too far in future",
                ),
            ),
        ]
    )


def test_aggregated_attestation_one_full_slot_in_future_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate a full slot ahead of local time is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - local time is slot 2 interval 0.

    When
    ----
    - V1 gossips an aggregate at slot 3, five intervals ahead.

    Then
    ----
    - validation fails with attestation too far in future.

    Regression
    ----------
    - an earlier rule admitted aggregates up to a full slot ahead.
    - that window let an adversary pre-publish next-slot aggregates early.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.ATTESTATION_TOO_FAR_IN_FUTURE,
                    exact_message="Attestation too far in future",
                ),
            ),
        ]
    )
