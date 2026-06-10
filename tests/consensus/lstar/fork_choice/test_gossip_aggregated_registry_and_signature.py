"""Gossip aggregated attestation registry and aggregate-signature rejections."""

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
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_aggregated_attestation_participant_outside_registry_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate naming a participant outside the target registry is rejected.

    Given
    -----
    - 4 validators, so valid indices are V0 through V3.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - an aggregate for block_2 names participant V999.
    - V999 lies outside the target state registry.

    Then
    ----
    - the per-participant registry check fails before aggregate verification.
    - the aggregate is rejected because the validator is not in the state.
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
                    validator_indices=[ValidatorIndex(999)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    valid_signature=False,
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.VALIDATOR_NOT_IN_STATE,
                    message_substring="not found in state",
                ),
            ),
        ]
    )


@pytest.mark.real_crypto(smoke=True)
def test_aggregated_attestation_proof_verification_failure_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An aggregate whose proof fails verification is rejected.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)

    When
    ----
    - an aggregate for block_2 claims participant V1.
    - the proof is signed by V2 instead of V1.
    - every participant lies inside the registry.

    Then
    ----
    - aggregate verification rejects the proof against the claimed key.
    - the aggregate is rejected with an invalid signature.
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
                    signer_indices=[ValidatorIndex(2)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.INVALID_SIGNATURE,
                    message_substring="Committee aggregation signature verification failed",
                ),
            ),
        ]
    )
