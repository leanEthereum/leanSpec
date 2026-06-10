"""Signature verification rejects an aggregate that names zero participants."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    ClearFirstAttestationBits,
    ExpectedRejection,
    VerifySignaturesTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_empty_aggregation_bits_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    An aggregate that names zero participants is rejected.

    Given
    -----
    - a registry of 3 validators.
    - an aggregate whose participation bitfield has no bit set.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected because the aggregate names no participants.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=3),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                    valid_signature=False,
                ),
            ],
        ),
        tamper=ClearFirstAttestationBits(),
        expected_rejection=ExpectedRejection(reason=RejectionReason.EMPTY_AGGREGATION_BITS),
    )
