"""State Transition: justification-bitfield range guard"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    ExpectedRejection,
    StateTransitionTestFiller,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_source_slot_beyond_tracked_range_rejects_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose source slot sits past the tracked justification window rejects the block.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - finalization stays at genesis, so the tracked window is anchored at slot 0.
    - processing block(2) tracks justification only for slot 1, a window of length 1.
    - block(2) carries a forced V0, V1, V2 vote targeting block_1.
    - the vote's source slot is forced to 2, one past the tracked window.

    When
    ----
    - the chain processes block(2).

    Then
    ----
    - the source-slot read finds no tracked bit for slot 2.
    - the block is rejected with JUSTIFIED_SLOT_OUT_OF_RANGE.
    - the message names slot 2, finalized boundary 0, and tracked length 1.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                        source_root_label="block_1",
                        source_slot=Slot(2),
                    ),
                ],
            ),
        ],
        post=None,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.JUSTIFIED_SLOT_OUT_OF_RANGE,
            exact_message=(
                "Slot 2 is outside the tracked range (finalized_boundary=0, tracked_length=1)"
            ),
        ),
    )
