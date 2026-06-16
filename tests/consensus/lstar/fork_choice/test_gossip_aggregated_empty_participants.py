"""Gossip aggregated attestation with an empty participant set is rejected."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
)
from lean_spec.spec.forks import AggregationBits, RejectionReason, Slot

pytestmark = pytest.mark.valid_until("Lstar")


def test_gossip_aggregated_attestation_empty_participants_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregated gossip attestation naming no participants is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - an aggregate voting for block_2 at slot 2 carries no participants.

    Then
    ----
    - the aggregate names no validator to verify against.
    - validation fails with empty aggregation bits.
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
                    validator_indices=[],
                    aggregation_bits=AggregationBits(data=[]),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.EMPTY_AGGREGATION_BITS,
                    exact_message="Aggregated attestation must reference at least one validator",
                ),
            ),
        ]
    )
