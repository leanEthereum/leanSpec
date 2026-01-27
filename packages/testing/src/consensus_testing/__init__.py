"""Test tools for generating and consuming leanSpec consensus test vectors."""

from typing import Type

from . import forks
from .test_fixtures import (
    BaseConsensusFixture,
    ForkChoiceTest,
    StateTransitionTest,
    VerifySignaturesTest,
)
from .test_types import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    AttestationCheck,
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
VerifySignaturesTestFiller = Type[VerifySignaturesTest]

__all__ = [
    # Public API
    "AggregatedAttestationSpec",
    "BlockSpec",
    "forks",
    "generate_pre_state",
    # Base types
    # Fixture classes
    "BaseConsensusFixture",
    "StateTransitionTest",
    "ForkChoiceTest",
    "VerifySignaturesTest",
    # Test types
    "BaseForkChoiceStep",
    "TickStep",
    "BlockStep",
    "AttestationStep",
    "ForkChoiceStep",
    "StateExpectation",
    "StoreChecks",
    "AttestationCheck",
    "AggregatedAttestationCheck",
    # Type aliases for test function signatures
    "StateTransitionTestFiller",
    "ForkChoiceTestFiller",
    "VerifySignaturesTestFiller",
]
