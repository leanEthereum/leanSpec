"""State Transition: justification vote-list layout guard"""

import pytest

from consensus_testing import (
    BlockSpec,
    ExpectedRejection,
    StateTransitionTestFiller,
    build_genesis_state,
)
from lean_spec.spec.forks import RejectionReason, Slot
from lean_spec.spec.forks.lstar.containers import JustificationRoots, JustificationValidators
from lean_spec.spec.ssz import Boolean, Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_vote_list_length_not_root_count_times_validators_rejects_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A flat vote list whose length is not the tracked-root count times the validators rejects.

    Given
    -----
    - 4 validators.
    - the tracked justification roots hold one non-zero root.
    - a full layout needs 4 bits (1 root times 4 validators).
    - the flat vote list holds only 2 bits.
    - the vote list length does not match the required layout.

    When
    ----
    - a block at slot 1 is processed.

    Then
    ----
    - the flat vote list cannot be segmented into full validator rounds.
    - the block is rejected with JUSTIFICATION_VOTES_LENGTH_MISMATCH.
    - the message states the vote list length does not equal the tracked-root count times the
      validator count.
    """
    state_transition_test(
        pre=build_genesis_state(num_validators=4).model_copy(
            update={
                "justifications_roots": JustificationRoots(data=[Bytes32(b"\x11" * 32)]),
                "justifications_validators": JustificationValidators(
                    data=[Boolean(False), Boolean(False)]
                ),
            }
        ),
        blocks=[
            BlockSpec(slot=Slot(1)),
        ],
        post=None,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.JUSTIFICATION_VOTES_LENGTH_MISMATCH,
            exact_message=(
                "Justification vote list length does not equal tracked-root count times "
                "validator count"
            ),
        ),
    )
