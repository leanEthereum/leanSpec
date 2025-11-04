"""XMSS key management utilities for testing."""

from typing import Optional

from lean_spec.subspecs.containers import Attestation, Signature
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey
from lean_spec.subspecs.xmss.interface import DEFAULT_SIGNATURE_SCHEME
from lean_spec.types import ValidatorIndex


class XmssKeyManager:
    """
    Manages XMSS keys for test validators.

    Generates and manages XMSS key pairs for validators on demand.
    Keys are generated to be valid up to the specified max_slot.
    """

    DEFAULT_MAX_SLOT = Slot(100)
    """Default maximum slot for key generation."""

    max_slot: Slot
    public_keys: dict[ValidatorIndex, PublicKey]
    secret_keys: dict[ValidatorIndex, SecretKey]

    def __init__(
        self,
        max_slot: Optional[Slot] = None,
    ) -> None:
        """
        Initialize the XMSS key manager.

        Args:
            max_slot: Maximum slot for which keys should be valid. Keys will be
                generated with enough capacity to sign messages up to this slot.
                Defaults to 100 slots.
        """
        self.max_slot = max_slot if max_slot is not None else self.DEFAULT_MAX_SLOT
        self.public_keys: dict[ValidatorIndex, PublicKey] = {}
        self.secret_keys: dict[ValidatorIndex, SecretKey] = {}

    def create_key_pair(self, validator_index: ValidatorIndex) -> tuple[PublicKey, SecretKey]:
        """
        Create an XMSS key pair for the given validator index.

        Args:
            validator_index: The index of the validator to create a key for.

        Returns:
            A tuple containing the public and secret keys for the given validator index.
        """
        if validator_index not in self.public_keys:
            # Use max_slot + 1 as num_active_epochs since slots are used as epochs in the spec.
            # +1 to include genesis slot
            num_active_epochs = self.max_slot.as_int() + 1
            self.public_keys[validator_index], self.secret_keys[validator_index] = (
                DEFAULT_SIGNATURE_SCHEME.key_gen(0, num_active_epochs)
            )
        return self.public_keys[validator_index], self.secret_keys[validator_index]

    def sign_attestation(self, attestation: Attestation) -> Signature:
        """
        Sign an attestation with the given validator index.

        Args:
            attestation: The attestation to sign.

        Returns:
            A signature for the given attestation.
        """
        validator_id = attestation.validator_id

        sk = self.secret_keys[validator_id]
        message = bytes(hash_tree_root(attestation))
        epoch = int(attestation.data.slot)
        xmss_sig = DEFAULT_SIGNATURE_SCHEME.sign(sk, epoch, message)

        signature_bytes = xmss_sig.to_bytes(DEFAULT_SIGNATURE_SCHEME.config)
        # Pad to 3100 bytes (Signature.LENGTH) with zeros on the right
        # Padding only occurs with TEST_CONFIG(796 bytes) and not PROD_CONFIG(3100 bytes).
        padded_bytes = signature_bytes.ljust(Signature.LENGTH, b"\x00")
        signature = Signature(padded_bytes)
        return signature

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
