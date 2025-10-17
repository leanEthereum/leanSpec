"""Public API for creating consensus test fixtures."""

from typing import List

from lean_spec.subspecs.containers.block import SignedBlock
from lean_spec.subspecs.containers.config import Config
from lean_spec.subspecs.containers.state import State
from lean_spec.types import Uint64

from .spec_fixtures.genesis import GenesisTest
from .spec_fixtures.state_transition import StateTransitionTest


def genesis_test(
    genesis_time: Uint64,
    num_validators: Uint64,
    config: Config | None = None,
) -> GenesisTest:
    """
    Create a genesis test fixture.

    Parameters
    ----------
    genesis_time : Uint64
        Unix timestamp for genesis.
    num_validators : Uint64
        Number of validators at genesis.
    config : Config, optional
        Custom chain configuration. If None, uses default.

    Returns:
    -------
    GenesisTest
        A filled fixture ready for serialization.
    """
    # Create instance with parameters
    test_instance = GenesisTest(
        genesis_time=genesis_time,
        num_validators=num_validators,
        config=config,
    )

    # Run the spec to fill expected_state
    filled = test_instance.make_fixture()

    # Return filled fixture
    return filled


def state_transition_test(
    pre: State,
    blocks: List[SignedBlock],
    expect_exception: type[Exception] | None = None,
) -> StateTransitionTest:
    """
    Create a state transition test fixture.

    This is the public API that test writers use. It internally:
    1. Creates a StateTransitionTest instance
    2. Calls make_fixture() to run State.state_transition() for each block
    3. Validates exception expectations
    4. Returns the filled fixture

    Parameters
    ----------
    pre : State
        Initial consensus state before processing blocks.
    blocks : List[SignedBlock]
        Sequence of signed blocks to process.
    expect_exception : type[Exception], optional
        Expected exception type for invalid tests. If None, expects success.

    Returns:
    -------
    StateTransitionTest
        A filled fixture ready for serialization.
    """
    # Create instance with parameters
    test_instance = StateTransitionTest(
        pre=pre,
        blocks=blocks,
        expect_exception=expect_exception,
    )

    # Run the spec to fill post state and validate
    filled = test_instance.make_fixture()

    # Return filled fixture
    return filled
