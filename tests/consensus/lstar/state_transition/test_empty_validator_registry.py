"""State Transition: Proposer Scheduling Against An Empty Validator Registry."""

import pytest

from consensus_testing import (
    BlockSpec,
    ExpectedRejection,
    StateTransitionTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import RejectionReason, Slot

pytestmark = pytest.mark.valid_until("Lstar")


def test_proposer_scheduling_on_empty_registry_rejected(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    An empty validator registry has no validator to schedule as proposer.

    Given
    -----
    - the genesis state carries zero validators.

    When
    ----
    - a block at slot 1 is processed, driving round-robin proposer selection.

    Then
    ----
    - proposer selection has no registry size to take a modulo against.
    - the block is rejected as scheduling against an empty registry.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=0),
        blocks=[
            BlockSpec(slot=Slot(1)),
        ],
        post=None,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.EMPTY_VALIDATOR_REGISTRY,
            exact_message="Cannot schedule a proposer for an empty validator registry",
        ),
    )
