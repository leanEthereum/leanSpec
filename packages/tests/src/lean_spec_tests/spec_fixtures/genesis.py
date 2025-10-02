"""Genesis test fixture format."""

from typing import ClassVar

from lean_spec.subspecs.containers.config import Config
from lean_spec.subspecs.containers.state.state import State
from lean_spec.types import Uint64

from .base import BaseConsensusFixture


class GenesisTest(BaseConsensusFixture):
    """
    Test fixture for genesis state initialization.

    Tests the genesis initialization process that creates the initial
    beacon state before any blocks exist.

    Structure:
        genesis_time: Unix timestamp for genesis
        num_validators: Number of validators at genesis
        config: Chain configuration (optional, generated if not provided)
        expected_state: Expected state after initialization (filled by spec)
    """

    format_name: ClassVar[str] = "genesis_test"
    description: ClassVar[str] = "Tests genesis state initialization"

    genesis_time: Uint64
    """Unix timestamp for genesis."""

    num_validators: Uint64
    """Number of validators at genesis."""

    config: Config | None = None
    """Chain configuration (auto-generated if None)."""

    expected_state: State | None = None
    """The expected state after genesis initialization (filled by make_fixture)."""

    def make_fixture(self) -> "GenesisTest":
        """
        Generate the fixture by running the spec.

        Returns:
        -------
        GenesisTest
            A filled fixture with expected_state populated.
        """
        # Run the spec to get expected genesis state (spec as oracle)
        expected_state = State.generate_genesis(
            genesis_time=self.genesis_time,
            num_validators=self.num_validators,
        )

        # If custom config provided, override the generated one
        if self.config is not None:
            expected_state = expected_state.model_copy(update={"config": self.config})

        # Return a new instance with filled expected_state
        return self.model_copy(
            update={
                "config": expected_state.config,
                "expected_state": expected_state,
            }
        )
