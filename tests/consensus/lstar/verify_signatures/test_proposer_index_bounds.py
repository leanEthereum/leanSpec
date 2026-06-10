"""Signature verification rejects a block whose proposer index exceeds the registry."""

import pytest

from consensus_testing import (
    BlockSpec,
    ExpectedRejection,
    SetProposerIndex,
    VerifySignaturesTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.real_crypto]


def test_proposer_index_out_of_range_rejected(
    verify_signatures_test: VerifySignaturesTestFiller,
) -> None:
    """
    A block whose proposer index exceeds the registry is rejected.

    Given
    -----
    - a registry of 4 validators (indices 0 through 3).
    - a block at slot 1 signed honestly by the in-range proposer.
    - the proposer index is then rewritten to 99.

    When
    ----
    - signature verification runs.

    Then
    ----
    - verification is rejected as an out-of-range proposer index.
    - this is distinct from the wrong-but-in-range proposer check during state transition.
    """
    verify_signatures_test(
        anchor_state=generate_pre_state(num_validators=4),
        block=BlockSpec(
            slot=Slot(1),
            attestations=[],
        ),
        tamper=SetProposerIndex(proposer_index=ValidatorIndex(99)),
        expected_rejection=ExpectedRejection(reason=RejectionReason.PROPOSER_INDEX_OUT_OF_RANGE),
    )
