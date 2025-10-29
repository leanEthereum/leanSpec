"""Test tools for generating and consuming leanSpec consensus test vectors."""

from typing import Type

from . import forks
from .test_fixtures import (
    BaseConsensusFixture,
    ForkChoiceTest,
    StateTransitionTest,
)
from .test_types import (
    AttestationStep,
    BaseForkChoiceStep,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    StateExpectation,
    StoreChecks,
    TickStep,
    generate_pre_state,
)

StateTransitionTestFiller = Type[StateTransitionTest]
ForkChoiceTestFiller = Type[ForkChoiceTest]

__all__ = [
    # Public API
    "BlockSpec",
    "forks",
    "generate_pre_state",
    # Base types
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
