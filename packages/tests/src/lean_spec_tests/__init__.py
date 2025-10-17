"""Test tools for generating and consuming leanSpec consensus test vectors."""

from typing import Type

from .base_types import CamelModel
from .builders import BlockBuilder
from .consensus_env import ConsensusEnvironment
from .filler_api import genesis_test, state_transition_test
from .spec_fixtures import (
    BaseConsensusFixture,
    ForkChoiceTest,
    GenesisTest,
    StateTransitionTest,
)

GenesisTestFiller = Type[GenesisTest]
StateTransitionTestFiller = Type[StateTransitionTest]

__all__ = [
    # Public API
    "genesis_test",
    "state_transition_test",
    "ConsensusEnvironment",
    "BlockBuilder",
    # Base types
    "CamelModel",
    # Fixture classes
    "BaseConsensusFixture",
    "GenesisTest",
    "StateTransitionTest",
    "ForkChoiceTest",
    # Type aliases for test function signatures
    "GenesisTestFiller",
    "StateTransitionTestFiller",
]
