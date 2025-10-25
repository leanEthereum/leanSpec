"""Invalid block processing tests for the devnet fork."""

import pytest
from consensus_testing import BlockSpec, StateTransitionTestFiller

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.types import Bytes52, Uint64, ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


@pytest.fixture
def pre() -> State:
    """
    Custom pre-state for invalid proposer test.

    This demonstrates how to override the default pre fixture
    to provide custom initial state for specific tests.
    """
    validators = Validators(data=[Validator(pubkey=Bytes52.zero()) for _ in range(4)])
    return State.generate_genesis(
        genesis_time=Uint64(1000000),
        validators=validators,
    )


def test_invalid_proposer(
    state_transition_test: StateTransitionTestFiller,
    pre: State,
) -> None:
    """
    Test that blocks with incorrect proposer are rejected.

    The proposer index must match the round-robin selection for that slot.
    This test demonstrates customizing the pre-state via fixture override.
    """
    # For slot 1, the correct proposer is: 1 % 4 = 1
    # create a block spec with wrong proposer (index 2)
    wrong_proposer = ValidatorIndex(2)

    # Use BlockSpec with wrong proposer
    invalid_block_spec = BlockSpec(
        slot=Slot(1),
        proposer_index=wrong_proposer,
    )

    # This should fail with "Incorrect block proposer"
    state_transition_test(
        pre=pre,
        blocks=[invalid_block_spec],
        expect_exception=AssertionError,
    )
