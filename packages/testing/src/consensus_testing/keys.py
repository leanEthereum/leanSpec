"""XMSS key management utilities for testing."""

from typing import NamedTuple, Optional

from lean_spec.subspecs.containers import Attestation, Signature
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey
from lean_spec.subspecs.xmss.interface import DEFAULT_SIGNATURE_SCHEME
from lean_spec.types import ValidatorIndex


class KeyPair(NamedTuple):
    """A validator’s XMSS key pair."""

    public: PublicKey
    """The validator’s public key (used for verification)."""

    secret: SecretKey
    """The validator’s secret key (used for signing)."""


class XmssKeyManager:
    """Lazy key manager for test validators using XMSS signatures."""

    DEFAULT_MAX_SLOT = Slot(100)
    """Default maximum slot horizon if not specified."""

    def __init__(self, max_slot: Optional[Slot] = None) -> None:
        """
        Initialize the key manager.

        Parameters
        ----------
        max_slot : Slot, optional
            Highest slot number for which keys must remain valid.
            Defaults to `Slot(100)`.

        Notes:
        -----
        Internally, keys are stored in a single dictionary:
        `{ValidatorIndex → KeyPair}`.
        """
        self.max_slot = max_slot if max_slot is not None else self.DEFAULT_MAX_SLOT
        self._key_pairs: dict[ValidatorIndex, KeyPair] = {}

    def __getitem__(self, validator_index: ValidatorIndex) -> KeyPair:
        """
        Retrieve or lazily generate a validator’s key pair.

        Parameters
        ----------
        validator_index : ValidatorIndex
            The validator whose key pair to fetch.

        Returns:
        -------
        KeyPair
            The validator’s XMSS key pair.

        Notes:
        -----
        - Generates a new key if none exists.
        - Keys are deterministic for testing (`seed=0`).
        - Lifetime = `max_slot + 1` to include the genesis slot.
        """
        # Return cached keys if they exist.
        if validator_index in self._key_pairs:
            return self._key_pairs[validator_index]

        # Generate New Key Pair
        #
        # XMSS requires knowing the total number of signatures in advance.
        # We use max_slot + 1 as the lifetime since:
        # - Validators may sign once per slot (attestations)
        # - We include slot 0 (genesis) in the count
        num_active_epochs = self.max_slot.as_int() + 1

        # Generate the key pair using the default XMSS scheme.
        #
        # The seed is set to 0 for deterministic test keys.
        pk, sk = DEFAULT_SIGNATURE_SCHEME.key_gen(0, num_active_epochs)

        # Store as a cohesive unit and return.
        key_pair = KeyPair(public=pk, secret=sk)
        self._key_pairs[validator_index] = key_pair
        return key_pair

    def sign_attestation(self, attestation: Attestation) -> Signature:
        """
        Sign an attestation with the validator’s XMSS key.

        Parameters
        ----------
        attestation : Attestation
            The attestation to sign. Must include `validator_id` and `data.slot`.

        Returns:
        -------
        Signature
            A consensus-compatible XMSS signature.

        Notes:
        -----
        - Automatically generates missing keys.
        - One XMSS epoch is consumed per slot.
        - Produces deterministic test signatures.
        """
        # Identify the validator who is attesting.
        validator_id = attestation.validator_id

        # Lazy key retrieval: creates keys if first time seeing this validator.
        key_pair = self[validator_id]

        # Compute the message digest from the attestation's SSZ tree root.
        #
        # This produces a cryptographic hash of the entire attestation structure.
        message = bytes(hash_tree_root(attestation))

        # Map the attestation slot to an XMSS epoch.
        #
        # Each slot gets its own epoch to avoid key reuse.
        epoch = int(attestation.data.slot)

        # Generate the XMSS signature using the validator's secret key.
        xmss_sig = DEFAULT_SIGNATURE_SCHEME.sign(key_pair.secret, epoch, message)

        # Convert the signature to the wire format (byte array).
        signature_bytes = xmss_sig.to_bytes(DEFAULT_SIGNATURE_SCHEME.config)

        # Ensure the signature meets the consensus spec length (3100 bytes).
        #
        # This is necessary when using TEST_CONFIG (796 bytes) vs PROD_CONFIG.
        # Padding with zeros on the right maintains compatibility.
        padded_bytes = signature_bytes.ljust(Signature.LENGTH, b"\x00")

        return Signature(padded_bytes)

    def get_public_key(self, validator_index: ValidatorIndex) -> PublicKey:
        """
        Return the public key for a validator.

        Parameters
        ----------
        validator_index : ValidatorIndex

        Returns:
        -------
        PublicKey
            The validator’s public key.
        """
        return self[validator_index].public

    def get_all_public_keys(self) -> dict[ValidatorIndex, PublicKey]:
        """
        Return all generated public keys.

        Returns:
        -------
        dict[ValidatorIndex, PublicKey]
            Snapshot of all currently known public keys.

        Notes:
        -----
        Only includes validators whose keys have been generated.
        """
        return {i: p.public for i, p in self._key_pairs.items()}

    def __contains__(self, validator_index: ValidatorIndex) -> bool:
        """Check if a validator has generated keys."""
        return validator_index in self._key_pairs

    def __len__(self) -> int:
        """Return the number of validators with generated keys."""
        return len(self._key_pairs)
