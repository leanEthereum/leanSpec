"""XMSS key management utilities for testing."""

from lean_spec.subspecs.containers import (
    Attestation,
    Block,
    Signature,
    Validator,
)
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME
from lean_spec.types import ValidatorIndex


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

    def sign_block(self, block: Block, proposer_index: ValidatorIndex) -> Signature:
        """
        Sign a block with the given proposer index.

        Args:
            block: The block to sign.
            proposer_index: The validator index of the block proposer.

        Returns:
            A signature for the given block.
        """
        _, sk = self.get_or_create_key(proposer_index)
        message = bytes(hash_tree_root(block))
        epoch = int(block.slot)
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
