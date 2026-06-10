"""Signature verification rejects blocks carrying an invalid proposer or attester signature."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    ExpectedRejection,
    VerifySignaturesTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_invalid_proposer_signature(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block carrying an invalid proposer signature is rejected.

    Given
    -----
    - a registry of 1 validator.
    - a block at slot 1 with no attestations.
    - the proposer signature is invalid.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an invalid block proof.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=1),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
            valid_signature=False,
        ),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_BLOCK_PROOF),
    )


def test_invalid_aggregated_attestation_signature(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block is rejected when any one of its aggregates carries an invalid signature.

    Given
    -----
    - a registry of 3 validators.
    - a valid aggregate from V0.
    - an invalid aggregate from V2 targeting different data, forcing a separate group.
    - the proposer signature is valid.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an invalid block proof.
    - one bad aggregate rejects the block even when another aggregate is valid.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=3),
        block=BlockSpec(
            slot=Slot(2),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0)],
                    slot=Slot(2),
                    target_slot=Slot(1),
                    target_root_label="genesis",
                    valid_signature=True,
                ),
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(2)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                    valid_signature=False,
                ),
            ],
        ),
        expected_rejection=ExpectedRejection(reason=RejectionReason.INVALID_BLOCK_PROOF),
    )
