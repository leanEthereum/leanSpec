"""Test tools for generating and consuming leanSpec consensus test vectors."""

from typing import Type

from . import forks
from .genesis import build_anchor, generate_pre_state
from .test_fixtures import (
    ApiEndpointTest,
    BaseConsensusFixture,
    ForkChoiceTest,
    GossipsubHandlerTest,
    IncrementEmittedSlot,
    JustifiabilityTest,
    NetworkingCodecTest,
    PoseidonPermutationTest,
    RebindToAlternateHeadRoot,
    SlotClockTest,
    SSZTest,
    StateTransitionTest,
    SwapParticipantPublicKey,
    SyncTest,
    VerifyProofsTest,
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
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    GossipAttestationSpec,
    StateExpectation,
    StoreChecks,
    TickStep,
)

StateTransitionTestFiller = Type[StateTransitionTest]
ForkChoiceTestFiller = Type[ForkChoiceTest]
VerifyProofsTestFiller = Type[VerifyProofsTest]
VerifySignaturesTestFiller = Type[VerifySignaturesTest]
SSZTestFiller = Type[SSZTest]
NetworkingCodecTestFiller = Type[NetworkingCodecTest]
GossipsubHandlerTestFiller = Type[GossipsubHandlerTest]
ApiEndpointTestFiller = Type[ApiEndpointTest]
SlotClockTestFiller = Type[SlotClockTest]
JustifiabilityTestFiller = Type[JustifiabilityTest]
PoseidonPermutationTestFiller = Type[PoseidonPermutationTest]
SyncTestFiller = Type[SyncTest]

__all__ = [
    # Public API
    "AggregatedAttestationSpec",
    "GossipAggregatedAttestationSpec",
    "GossipAttestationSpec",
    "BlockSpec",
    "forks",
    "build_anchor",
    "generate_pre_state",
    # Base types
    # Fixture classes
    "BaseConsensusFixture",
    "StateTransitionTest",
    "ForkChoiceTest",
    "VerifyProofsTest",
    "RebindToAlternateHeadRoot",
    "IncrementEmittedSlot",
    "SwapParticipantPublicKey",
    "VerifySignaturesTest",
    "SSZTest",
    "NetworkingCodecTest",
    "GossipsubHandlerTest",
    "ApiEndpointTest",
    "SlotClockTest",
    "JustifiabilityTest",
    "PoseidonPermutationTest",
    "SyncTest",
    # Test types
    "BaseForkChoiceStep",
    "TickStep",
    "BlockStep",
    "AttestationStep",
    "GossipAggregatedAttestationStep",
    "ForkChoiceStep",
    "StateExpectation",
    "StoreChecks",
    "AttestationCheck",
    "AggregatedAttestationCheck",
    # Type aliases for test function signatures
    "StateTransitionTestFiller",
    "ForkChoiceTestFiller",
    "VerifyProofsTestFiller",
    "VerifySignaturesTestFiller",
    "SSZTestFiller",
    "NetworkingCodecTestFiller",
    "GossipsubHandlerTestFiller",
    "ApiEndpointTestFiller",
    "SlotClockTestFiller",
    "JustifiabilityTestFiller",
    "PoseidonPermutationTestFiller",
    "SyncTestFiller",
]
