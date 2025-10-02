"""Filler for GenesisTest fixtures."""

from lean_spec.subspecs.containers.config import Config
from lean_spec.subspecs.containers.state import State
from lean_spec.types import Uint64

from ..spec_fixtures.genesis import GenesisTest


def fill_genesis_test(
    genesis_time: Uint64,
    num_validators: Uint64,
    config: Config | None = None,
) -> GenesisTest:
    """
    Generate a GenesisTest fixture.

    This filler runs the spec's genesis initialization function to get
    the expected state. This follows the "spec as oracle" pattern -
    we don't hand-calculate the expected state.

    Parameters
    ----------
    genesis_time : Uint64
        Unix timestamp for genesis.
    num_validators : Uint64
        Number of validators at genesis.
    config : Config, optional
        Chain configuration. If None, uses default from generate_genesis.

    Returns:
    -------
    GenesisTest
        A complete genesis test fixture ready for serialization.

    Examples:
    --------
    >>> from lean_spec.types import Uint64
    >>> test = fill_genesis_test(genesis_time=Uint64(1000000), num_validators=Uint64(4))
    >>> assert test.expected_state.slot.as_int() == 0
    >>> assert test.expected_state.config.num_validators == Uint64(4)
    """
    # Run the spec to get expected genesis state
    expected_state = State.generate_genesis(
        genesis_time=genesis_time,
        num_validators=num_validators,
    )

    # If custom config provided, override the generated one
    if config is not None:
        expected_state = expected_state.model_copy(update={"config": config})

    # Build the test fixture
    return GenesisTest(
        genesis_time=genesis_time,
        num_validators=num_validators,
        config=expected_state.config,
        expected_state=expected_state,
    )
