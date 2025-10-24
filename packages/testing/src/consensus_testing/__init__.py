"""Test tools for generating and consuming leanSpec consensus test vectors."""

from typing import Type

from framework.base_types import CamelModel

from .builders import BlockBuilder
from .test_fixtures import (
    BaseConsensusFixture,
    ForkChoiceTest,
    StateTransitionTest,
)
from .test_types import (
    AttestationStep,
    BaseForkChoiceStep,
    BlockStep,
    ForkChoiceStep,
    StateExpectation,
    StoreChecks,
    TickStep,
)

StateTransitionTestFiller = Type[StateTransitionTest]
ForkChoiceTestFiller = Type[ForkChoiceTest]

__all__ = [
    # Public API
    "BlockBuilder",
    # Base types
    "CamelModel",
    # Fixture classes
    "BaseConsensusFixture",
    "StateTransitionTest",
    "ForkChoiceTest",
    # Test types
    "BaseForkChoiceStep",
    "TickStep",
    "BlockStep",
    "AttestationStep",
    "ForkChoiceStep",
    "StateExpectation",
    "StoreChecks",
    # Type aliases for test function signatures
    "StateTransitionTestFiller",
    "ForkChoiceTestFiller",
]
