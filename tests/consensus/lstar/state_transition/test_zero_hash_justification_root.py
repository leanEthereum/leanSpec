"""State Transition: zero-hash justification root guard"""

import pytest
from ssz import ZERO_ROOT, Boolean

from consensus_testing import (
    BlockSpec,
    ExpectedRejection,
    StateTransitionTestFiller,
    build_genesis_state,
)
from lean_spec.spec.forks import RejectionReason, Slot
from lean_spec.spec.forks.lstar.containers import JustificationRoots, JustificationValidators

pytestmark = pytest.mark.valid_until("Lstar")


def test_zero_hash_tracked_justification_root_rejects_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A tracked justification root equal to the zero hash rejects the block.

    Given
    -----
    - 4 validators.
    - the tracked justification roots hold the zero hash.
    - the flat vote list holds 4 bits, one full validator round.
    - the vote list length matches the required layout.

    When
    ----
    - a block at slot 1 is processed.

    Then
    ----
    - the length guard passes, so the zero-hash guard is reached.
    - the zero hash marks a skipped slot and cannot track votes.
    - the block is rejected with ZERO_HASH_JUSTIFICATION_ROOT.
    - the message states the tracked justification roots contain the zero hash.
    """
    state_transition_test(
        pre=build_genesis_state(num_validators=4).model_copy(
            update={
                "justifications_roots": JustificationRoots(data=[ZERO_ROOT]),
                "justifications_validators": JustificationValidators(
                    data=[Boolean(False), Boolean(False), Boolean(False), Boolean(False)]
                ),
            }
        ),
        blocks=[
            BlockSpec(slot=Slot(1)),
        ],
        post=None,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.ZERO_HASH_JUSTIFICATION_ROOT,
            exact_message="Tracked justification roots contain the zero hash",
        ),
    )
