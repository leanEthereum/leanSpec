"""Shared test utilities for forkchoice tests."""

from typing import Type

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    Checkpoint,
    Signature,
    SignedAttestation,
    State,
)
from lean_spec.subspecs.containers.block import Attestations, BlockHeader
from lean_spec.subspecs.containers.config import Config
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex


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
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(BlockBody(attestations=Attestations(data=[]))),
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


@pytest.fixture
def xmss_key_manager() -> XmssKeyManager:
    """Fixture for creating an XMSS key manager."""
    return XmssKeyManager()


def build_signed_attestation(
    key_manager: XmssKeyManager,
    validator: ValidatorIndex,
    target: Checkpoint,
    source: Checkpoint | None = None,
    slot: Slot | None = None,
    head: Checkpoint | None = None,
) -> SignedAttestation:
    """Construct a SignedValidatorAttestation pointing to ``target``."""

    source_checkpoint = source or Checkpoint.default()
    attestation_slot = slot if slot is not None else target.slot
    head_checkpoint = head if head is not None else target

    attestation_data = AttestationData(
        slot=attestation_slot,
        head=head_checkpoint,
        target=target,
        source=source_checkpoint,
    )
    message = Attestation(
        validator_id=validator,
        data=attestation_data,
    )

    # key manager will create a key if it doesn't exist
    signature = key_manager.sign_attestation(message)

    return SignedAttestation(
        message=message,
        signature=signature,
    )


@pytest.fixture
def mock_state_factory() -> Type[MockState]:
    """Factory fixture for creating MockState instances."""
    return MockState
