"""Fork choice rejects a block whose parent the store never imported."""

import pytest

from consensus_testing import (
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    StoreChecks,
)
from lean_spec.spec.forks import RejectionReason, Slot
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_block_with_fabricated_parent_is_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block pointing at a never-seen parent is rejected as an unknown parent.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis
        - block_1(1)
    - block_1 imports cleanly and becomes the head.

    When
    ----
    - orphan(2) is delivered with a parent root the store never imported.

    Then
    ----
    - the store rejects orphan with reason unknown parent block.
    - the head stays at block_1.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_root=Bytes32(b"\xde\xad\xbe\xef" * 8),
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.UNKNOWN_PARENT_BLOCK,
                    message_substring="Parent state not found",
                ),
            ),
        ],
    )
