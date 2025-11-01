"""Shared test utilities for forkchoice tests."""

from typing import Type

import pytest

from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    BlockBody,
    Checkpoint,
    Signature,
    SignedAttestation,
    State,
    Validator,
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
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME
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


class XmssKeyManager:
    """
    Manages XMSS keys for test validators.

    Generates and manages XMSS key pairs for validators on demand.
    """

    def __init__(self) -> None:
        """Initialize the XMSS key manager."""
        self.public_keys: dict[ValidatorIndex, PublicKey] = {}
        self.secret_keys: dict[ValidatorIndex, SecretKey] = {}

    def get_or_create_key(self, validator_index: ValidatorIndex) -> tuple[PublicKey, SecretKey]:
        """
        Get or create an XMSS key pair for the given validator index.

        Args:
            validator_index: The index of the validator to get or create a key for.

        Returns:
            A tuple containing the public and secret keys for the given validator index.
        """
        if validator_index not in self.public_keys:
            # Use a reasonable default for num_active_epochs in tests
            num_active_epochs = 100
            self.public_keys[validator_index], self.secret_keys[validator_index] = (
                TEST_SIGNATURE_SCHEME.key_gen(0, num_active_epochs)
            )
        return self.public_keys[validator_index], self.secret_keys[validator_index]

    def get_validator(self, validator_index: ValidatorIndex) -> Validator:
        """
        Get a validator from the key manager.

        Args:
            validator_index: The index of the validator to get.

        Returns:
            A validator with the given index.
        """
        pk, _ = self.get_or_create_key(validator_index)
        return Validator.from_xmss_pubkey(pk)

    def sign_attestation(self, attestation: Attestation) -> Signature:
        """
        Sign an attestation with the given validator index.

        Args:
            attestation: The attestation to sign.

        Returns:
            A signature for the given attestation.
        """
        validator_id = attestation.validator_id

        _, sk = self.get_or_create_key(validator_id)
        message = bytes(hash_tree_root(attestation))
        epoch = int(attestation.data.slot)
        xmss_sig = TEST_SIGNATURE_SCHEME.sign(sk, epoch, message)
        return Signature.from_xmss(xmss_sig)

    def __contains__(self, validator_index: ValidatorIndex) -> bool:
        """
        Check if a validator has a registered key.

        Args:
            validator_index: The index of the validator to check.

        Returns:
            True if the validator has a registered key, False otherwise.
        """
        return validator_index in self.secret_keys

    def __len__(self) -> int:
        """Return the number of registered keys."""
        return len(self.secret_keys)


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
