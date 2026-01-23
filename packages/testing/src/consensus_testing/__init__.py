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
    AggregatedAttestationSpec,
    AttestationCheck,
    AttestationStep,
    BaseForkChoiceStep,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    SignedAttestationSpec,
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
    "SignedAttestationSpec",
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
    # Type aliases for test function signatures
    "StateTransitionTestFiller",
    "ForkChoiceTestFiller",
    "VerifySignaturesTestFiller",
]
