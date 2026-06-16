"""Fork Choice: Duplicate AttestationData Rejection."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    StoreChecks,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_block_with_duplicate_aggregated_attestation_data_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block carrying two byte-identical votes is rejected.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1)
    - two votes from V0 share the same slot, target, source, and validator set.
    - the two votes are forced in so the builder does not merge them.

    When
    ----
    - a block at slot 2 carries both identical votes.

    Then
    ----
    - the store rejects the block for holding duplicate attestation data.
    - the rule stops a proposer inflating weight by repeating one vote.
    """
    duplicated_spec = AggregatedAttestationSpec(
        validator_indices=[ValidatorIndex(0)],
        slot=Slot(1),
        target_slot=Slot(1),
        target_root_label="block_1",
    )

    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    forced_attestations=[duplicated_spec, duplicated_spec],
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.DUPLICATE_ATTESTATION_DATA,
                    exact_message=(
                        "Block contains duplicate AttestationData entries; "
                        "each AttestationData must appear at most once"
                    ),
                ),
            ),
        ],
    )
