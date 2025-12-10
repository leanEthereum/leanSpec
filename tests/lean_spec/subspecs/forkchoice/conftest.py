"""Shared test utilities for forkchoice tests."""

from typing import Type

import pytest

from lean_spec.subspecs.containers import (
    AttestationData,
    BlockBody,
    Checkpoint,
    SignedAttestation,
    State,
)
from lean_spec.subspecs.containers.block import AggregatedAttestationsList, BlockHeader
from lean_spec.subspecs.containers.config import Config
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness
from lean_spec.types import Bytes32, Uint64


class MockState(State):
    """Mock state that exposes configurable ``latest_justified``."""

    def __init__(self, latest_justified: Checkpoint) -> None:
        """Initialize a mock state with minimal defaults."""
        # Create minimal defaults for all required fields
        genesis_config = Config(
            genesis_time=Uint64(0),
        )

        genesis_header = BlockHeader(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(BlockBody(attestations=AggregatedAttestationsList(data=[]))),
        )

        super().__init__(
            config=genesis_config,
            slot=Slot(0),
            latest_block_header=genesis_header,
            latest_justified=latest_justified,
            latest_finalized=Checkpoint.default(),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            validators=Validators(data=[]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        )


def build_signed_attestation(
    validator: Uint64,
    target: Checkpoint,
    source: Checkpoint | None = None,
) -> SignedAttestation:
    """Construct a SignedValidatorAttestation pointing to ``target``."""

    source_checkpoint = source or Checkpoint.default()
    attestation_data = AttestationData(
        slot=target.slot,
        head=target,
        target=target,
        source=source_checkpoint,
    )
    return SignedAttestation(
        validator_id=validator,
        message=attestation_data,
        signature=Signature(
            path=HashTreeOpening(siblings=HashDigestList(data=[])),
            rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
            hashes=HashDigestList(data=[]),
        ),
    )


@pytest.fixture
def mock_state_factory() -> Type[MockState]:
    """Factory fixture for creating MockState instances."""
    return MockState
