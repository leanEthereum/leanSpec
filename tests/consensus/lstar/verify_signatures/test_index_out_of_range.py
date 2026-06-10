"""Signature verification rejects an aggregate naming a validator index past the registry."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    ExpectedRejection,
    VerifySignaturesTestFiller,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_attestation_validator_index_out_of_range_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    An aggregate naming a validator index past the registry is rejected.

    Given
    -----
    - a registry of 4 validators (indices 0 through 3).
    - an aggregate naming validator index 99.
    - the aggregate carries an invalid signature, so no signing is attempted for the missing index.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an out-of-range validator index.
    - the bound check runs before signature checking, so the reason is unambiguous.
    """
    verify_signatures_test(
        block=BlockSpec(
            slot=Slot(2),
            attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(99)],
                    slot=Slot(1),
                    target_slot=Slot(0),
                    target_root_label="genesis",
                    valid_signature=False,
                ),
            ],
        ),
        expected_rejection=ExpectedRejection(reason=RejectionReason.VALIDATOR_INDEX_OUT_OF_RANGE),
    )
