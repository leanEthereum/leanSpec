"""XMSS key management utilities for testing."""

from typing import NamedTuple, Optional

from lean_spec.subspecs.containers import Attestation, Signature
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey
from lean_spec.subspecs.xmss.interface import (
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.types import ValidatorIndex


class KeyPair(NamedTuple):
    """A validator's XMSS key pair."""

    public: PublicKey
    """The validator's public key (used for verification)."""

    secret: SecretKey
    """The validator's secret key (used for signing)."""


_KEY_CACHE: dict[tuple[int, int], KeyPair] = {}
"""
Cache keys across tests to avoid regenerating them for the same validator/lifetime combo.

Key: (validator_index, num_active_epochs) -> KeyPair
"""


class XmssKeyManager:
    """Lazy key manager for test validators using XMSS signatures."""

    DEFAULT_MAX_SLOT = Slot(100)
    """Default maximum slot horizon if not specified."""

    def __init__(
        self,
        max_slot: Optional[Slot] = None,
        scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME,
    ) -> None:
        """
        Initialize the key manager.

        Parameters
        ----------
        max_slot : Slot, optional
            Highest slot number for which keys must remain valid.
            Defaults to `Slot(100)`.
        scheme : GeneralizedXmssScheme, optional
            The XMSS scheme to use.
            Defaults to `TEST_SIGNATURE_SCHEME`.

        Notes:
        -----
        Internally, keys are stored in a single dictionary:
        `{ValidatorIndex → KeyPair}`.
        """
        self.max_slot = max_slot if max_slot is not None else self.DEFAULT_MAX_SLOT
        self.scheme = scheme
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

        # Check global cache first (keys are reused across tests)
        cache_key = (int(validator_index), num_active_epochs)
        if cache_key in _KEY_CACHE:
            key_pair = _KEY_CACHE[cache_key]
            self._key_pairs[validator_index] = key_pair
            return key_pair

        # Generate the key pair using the default XMSS scheme.
        #
        # The seed is set to 0 for deterministic test keys.
        from lean_spec.types import Uint64

        pk, sk = self.scheme.key_gen(Uint64(0), Uint64(num_active_epochs))

        # Store as a cohesive unit and return.
        key_pair = KeyPair(public=pk, secret=sk)
        _KEY_CACHE[cache_key] = key_pair  # Cache globally for reuse across tests
        self._key_pairs[validator_index] = key_pair
        return key_pair

    def sign_attestation(self, attestation: Attestation) -> Signature:
        """
        Sign an attestation with the validator's XMSS key.

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
        # Get the current secret key
        sk = key_pair.secret

        # Map the attestation slot to an XMSS epoch.
        #
        # Each slot gets its own epoch to avoid key reuse.
        epoch = attestation.data.slot

        # Loop until the epoch is inside the prepared interval
        prepared_interval = self.scheme.get_prepared_interval(sk)
        while int(epoch) not in prepared_interval:
            # Check if we're advancing past the key's total lifetime
            activation_interval = self.scheme.get_activation_interval(sk)
            if prepared_interval.stop >= activation_interval.stop:
                raise ValueError(
                    f"Cannot sign for epoch {epoch}: "
                    f"it is beyond the key's max lifetime {activation_interval.stop}"
                )

            # Advance the key and get the new key object
            sk = self.scheme.advance_preparation(sk)

            # Update the prepared interval for the next loop check
            prepared_interval = self.scheme.get_prepared_interval(sk)

        # Update the cached key pair with the new, advanced secret key.
        # This ensures the *next* call to sign() uses the advanced state.
        self._key_pairs[validator_id] = KeyPair(public=key_pair.public, secret=sk)

        # Compute the message digest from the attestation's SSZ tree root.
        #
        # This produces a cryptographic hash of the entire attestation structure.
        message = bytes(hash_tree_root(attestation))

        # Generate the XMSS signature using the validator's (now prepared) secret key.
        xmss_sig = self.scheme.sign(sk, epoch, message)

        # Convert the signature to the wire format (byte array).
        signature_bytes = xmss_sig.to_bytes(self.scheme.config)

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
