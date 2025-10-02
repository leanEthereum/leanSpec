"""Test tools for generating and consuming leanSpec consensus test vectors."""

from typing import Type

from .base_types import CamelModel
from .builders import BlockBuilder
from .consensus_env import ConsensusEnvironment
from .filler_api import consensus_chain_test, genesis_test
from .spec_fixtures import (
    BaseConsensusFixture,
    ConsensusChainTest,
    ForkChoiceTest,
    GenesisTest,
)

GenesisTestFiller = Type[GenesisTest]
ConsensusChainTestFiller = Type[ConsensusChainTest]

__all__ = [
    # Public API
    "genesis_test",
    "consensus_chain_test",
    "ConsensusEnvironment",
    "BlockBuilder",
    # Base types
    "CamelModel",
    # Fixture classes
    "BaseConsensusFixture",
    "GenesisTest",
    "ConsensusChainTest",
    "ForkChoiceTest",
    # Type aliases for test function signatures
    "GenesisTestFiller",
    "ConsensusChainTestFiller",
]
