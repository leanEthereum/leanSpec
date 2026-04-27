"""Gossip aggregated attestation validation vectors."""

import pytest
from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)

from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.chain.config import GOSSIP_DISPARITY_INTERVALS
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32

pytestmark = pytest.mark.valid_until("Devnet")


SLOT_3_BOUNDARY_INTERVAL = int(Interval.from_slot(Slot(3)) - GOSSIP_DISPARITY_INTERVALS)
"""Latest local interval that still admits a slot-3 aggregate."""

SLOT_3_JUST_BEYOND_BOUNDARY_INTERVAL = SLOT_3_BOUNDARY_INTERVAL - 1
"""First local interval that rejects a slot-3 aggregate."""


def test_valid_gossip_aggregated_attestation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """A valid aggregated gossip attestation is accepted."""
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
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
    """Aggregated attestation referencing unknown source is rejected."""
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root=Bytes32(b"\xff" * 32),
                    source_slot=Slot(999),
                ),
                valid=False,
                expected_error="Unknown source block",
            ),
        ]
    )


def test_aggregated_attestation_target_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Aggregated attestation with wrong target slot is rejected."""
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
                    slot=Slot(2),
                    target_slot=Slot(3),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_error="Target checkpoint slot mismatch",
            ),
        ]
    )


def test_aggregated_attestation_head_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Head checkpoint slot mismatches are rejected."""
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    head_root_label="block_1",
                    head_slot=Slot(5),
                ),
                valid=False,
                expected_error="Head checkpoint slot mismatch",
            ),
        ]
    )


def test_aggregated_attestation_source_after_target_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Topology violations (source > target) are rejected."""
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
                valid=False,
                expected_error="Source checkpoint slot must not exceed target",
            ),
        ]
    )


def test_aggregated_attestation_too_far_in_future_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Attestations whose slot is multiple slots ahead of local time are rejected."""
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_error="Attestation too far in future",
            ),
        ]
    )


def test_aggregated_attestation_at_disparity_boundary_allowed(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Aggregate exactly at the disparity boundary is allowed.

    Scenario
    --------
    Build a chain through slot 2.
    Tick to the latest local interval that still admits a slot-3 vote.
    Gossip a slot-3 aggregate.

    Expected:

    - Aggregate is validated and stored.
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
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
    Aggregate one interval beyond the disparity boundary is rejected.

    Scenario
    --------
    Build a chain through slot 2.
    Tick to one interval before the disparity boundary for a slot-3 vote.
    Gossip a slot-3 aggregate.

    Expected:

    - Validation fails with "Attestation too far in future" error.
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_error="Attestation too far in future",
            ),
        ]
    )


def test_aggregated_attestation_one_full_slot_in_future_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Aggregate a full slot ahead of local time is rejected.

    Regression: an earlier rule admitted aggregates up to a full slot ahead.
    That window let an adversary pre-publish next-slot aggregates before
    any honest validator could produce them.

    Scenario
    --------
    Build a chain through slot 2.
    At slot-2 interval 0, gossip a slot-3 aggregate (5 intervals ahead).

    Expected:

    - Validation fails with "Attestation too far in future" error.
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_error="Attestation too far in future",
            ),
        ]
    )
