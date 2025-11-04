"""XMSS key management utilities for testing."""

from lean_spec.subspecs.containers import Attestation, Signature
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import ValidatorIndex

DEFAULT_MAX_SLOT = Slot(100)
"""Default maximum slot for key generation."""
DEFAULT_SCHEMA = TEST_SIGNATURE_SCHEME
"""Default XMSS signature scheme."""


class XmssKeyManager:
    """
    Manages XMSS keys for test validators.

    Generates and manages XMSS key pairs for validators on demand.
    Keys are generated to be valid up to the specified max_slot.
    """

    schema: GeneralizedXmssScheme

    def __init__(
        self,
        max_slot: Slot = DEFAULT_MAX_SLOT,
        schema: GeneralizedXmssScheme = DEFAULT_SCHEMA,
    ) -> None:
        """
        Initialize the XMSS key manager.

        Args:
            max_slot: Maximum slot for which keys should be valid. Keys will be
                generated with enough capacity to sign messages up to this slot.
                Defaults to 100 slots.
            schema: The signature scheme to use. Defaults to TEST_SIGNATURE_SCHEME.
        """
        self.schema = schema
        self.max_slot = max_slot
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
            # Use max_slot + 1 as num_active_epochs since slots are used as epochs in the spec.
            # +1 to include genesis slot
            num_active_epochs = self.max_slot.as_int() + 1
            self.public_keys[validator_index], self.secret_keys[validator_index] = (
                self.schema.key_gen(0, num_active_epochs)
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

        _, sk = self.get_or_create_key(validator_id)
        message = bytes(hash_tree_root(attestation))
        epoch = int(attestation.data.slot)
        xmss_sig = self.schema.sign(sk, epoch, message)

        signature_bytes = xmss_sig.to_bytes(self.schema.config)
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
