"""XMSS key management utilities for testing."""

from __future__ import annotations

from typing import Any, NamedTuple, Optional

from lean_spec.subspecs.containers import Attestation, Signature
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey
from lean_spec.subspecs.xmss.interface import (
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.types import Uint64, ValidatorIndex


class KeyPair(NamedTuple):
    """A validator's XMSS key pair."""

    public: PublicKey
    """The validator's public key (used for verification)."""

    secret: SecretKey
    """The validator's secret key (used for signing)."""


_KEY_CACHE: dict[tuple[int, int, int, int], KeyPair] = {}
"""
Cache keys across tests to avoid regenerating them for the same validator/lifetime combo.

Key: (validator_index, activation_epoch, num_active_epochs, seed) -> KeyPair
"""


class XmssKeyManager:
    """Lazy key manager for test validators using XMSS signatures."""

    DEFAULT_MAX_SLOT = Slot(100)
    """Default maximum slot horizon if not specified."""
    DEFAULT_ACTIVATION_EPOCH = Uint64(0)
    """Default activation epoch when none is provided."""
    DEFAULT_SEED = 0
    """Default deterministic seed when none is provided."""

    def __init__(
        self,
        activation_epoch: Optional[Uint64 | Slot | int] = None,
        *,
        default_activation_epoch: Optional[Uint64 | Slot | int] = None,
        default_seed: Optional[int] = None,
        max_slot: Optional[Slot] = None,
        scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME,
    ) -> None:
        """
        Initialize the key manager.

        Parameters
        ----------
        activation_epoch : Uint64 | Slot | int, optional
            Deprecated alias for `default_activation_epoch`.
        default_activation_epoch : Uint64 | Slot | int, optional
            Activation epoch used when none is provided for key generation.
        default_seed : int, optional
            Seed value used when none is provided for key generation.
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

        This class manages stateful XMSS keys for testing, handling the complexity of
        epoch updates and key evolution that stateless helpers cannot provide.
        """
        self.max_slot = max_slot if max_slot is not None else self.DEFAULT_MAX_SLOT
        self.scheme = scheme
        if activation_epoch is not None and default_activation_epoch is not None:
            raise ValueError("Use either activation_epoch or default_activation_epoch, not both.")
        effective_activation = (
            default_activation_epoch if default_activation_epoch is not None else activation_epoch
        )
        activation_value = (
            self.DEFAULT_ACTIVATION_EPOCH
            if effective_activation is None
            else self._coerce_uint64(effective_activation)
        )
        self._default_activation_epoch = activation_value
        self._default_seed = int(default_seed) if default_seed is not None else self.DEFAULT_SEED
        self._key_pairs: dict[ValidatorIndex, KeyPair] = {}
        self._key_metadata: dict[ValidatorIndex, dict[str, Any]] = {}

    @staticmethod
    def _coerce_uint64(value: Uint64 | Slot | int) -> Uint64:
        """Convert supported numeric inputs to Uint64."""
        if isinstance(value, Uint64):
            return Uint64(int(value))
        if isinstance(value, Slot):
            return Uint64(value.as_int())
        return Uint64(int(value))

    @property
    def default_max_epoch(self) -> int:
        """Default lifetime derived from the manager's configured max_slot."""
        return self.default_num_active_epochs

    @property
    def default_num_active_epochs(self) -> int:
        """Number of epochs keys stay active when not overridden."""
        return self.max_slot.as_int() + 1

    @property
    def default_activation_epoch(self) -> int:
        """Default activation epoch as an int."""
        return int(self._default_activation_epoch)

    @property
    def default_seed(self) -> int:
        """Default seed used when none is provided."""
        return self._default_seed

    def create_and_store_key_pair(
        self,
        validator_index: ValidatorIndex,
        *,
        activation_epoch: Optional[Uint64 | Slot | int] = None,
        num_active_epochs: Optional[Uint64 | Slot | int] = None,
        seed: Optional[int] = None,
    ) -> KeyPair:
        """
        Generate and store a key pair with explicit control over key generation.

        Parameters
        ----------
        validator_index : ValidatorIndex
            The validator for whom a key pair should be generated.
        activation_epoch : Uint64 | Slot | int, optional
            First epoch for which the key is valid. Defaults to the manager's
            configured `default_activation_epoch`.
        num_active_epochs : Uint64 | Slot | int, optional
            Number of consecutive epochs the key should remain active.
            Defaults to `default_num_active_epochs` (derived from `max_slot` to include genesis).
        seed : int, optional
            Deterministic seed for caching/reuse. Defaults to manager's `default_seed`.
        """
        activation_epoch_val = (
            self._coerce_uint64(activation_epoch)
            if activation_epoch is not None
            else self._default_activation_epoch
        )
        num_active_epochs_val = (
            self._coerce_uint64(num_active_epochs)
            if num_active_epochs is not None
            else self._coerce_uint64(self.default_num_active_epochs)
        )
        seed_val = int(seed) if seed is not None else self.default_seed

        cache_key = (
            int(validator_index),
            int(activation_epoch_val),
            int(num_active_epochs_val),
            seed_val,
        )

        if cache_key in _KEY_CACHE:
            key_pair = _KEY_CACHE[cache_key]
        else:
            pk, sk = self.scheme.key_gen(activation_epoch_val, num_active_epochs_val)
            key_pair = KeyPair(public=pk, secret=sk)
            _KEY_CACHE[cache_key] = key_pair

        self._key_pairs[validator_index] = key_pair
        self._key_metadata[validator_index] = {
            "activation_epoch": int(activation_epoch_val),
            "num_active_epochs": int(num_active_epochs_val),
            "seed": seed_val,
        }
        # TODO: support multiple keys per validator keyed by activation_epoch.
        return key_pair

    def __getitem__(self, validator_index: ValidatorIndex) -> KeyPair:
        """
        Retrieve or lazily generate a validator's key pair.

        Parameters
        ----------
        validator_index : ValidatorIndex
            The validator whose key pair to fetch.

        Returns:
        -------
        KeyPair
            The validator's XMSS key pair.

        Notes:
        -----
        - Generates a new key if none exists.
        - Keys are deterministic for testing (`seed=0`).
        - Lifetime defaults to `default_num_active_epochs` to include the genesis slot.
        """
        if validator_index in self._key_pairs:
            return self._key_pairs[validator_index]

        return self.create_and_store_key_pair(validator_index)

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

        # Convert to the consensus Signature container (handles padding internally).
        return Signature.from_xmss(xmss_sig, self.scheme)

        # Ensure the signature meets the consensus spec length (3116 bytes).
        #
        # This is necessary when using TEST_CONFIG (796 bytes) vs PROD_CONFIG.
        # Padding with zeros on the right maintains compatibility.
        padded_bytes = signature_bytes.ljust(Signature.LENGTH, b"\x00")

        Returns:
        -------
        list[dict[str, Any]]
            A list of entries keyed by validator_index with metadata and hex keys.
        """
        vectors: list[dict[str, Any]] = []
        for validator_index in sorted(self._key_pairs.keys(), key=int):
            key_pair = self._key_pairs[validator_index]
            metadata = self._key_metadata.get(validator_index, {})
            entry: dict[str, Any] = {
                "validator_index": int(validator_index),
                "activation_epoch": metadata.get("activation_epoch", self.default_activation_epoch),
                "num_active_epochs": metadata.get(
                    "num_active_epochs", self.default_num_active_epochs
                ),
                "seed": metadata.get("seed", self.default_seed),
                "public_key": key_pair.public.to_bytes(self.scheme.config).hex(),
            }
            if include_private_keys:
                entry["secret_key"] = key_pair.secret.model_dump()
            vectors.append(entry)
        return vectors

    def get_public_key(self, validator_index: ValidatorIndex) -> PublicKey:
        """
        Return the public key for a validator.

        Parameters
        ----------
        validator_index : ValidatorIndex

        Returns:
        -------
        PublicKey
            The validator's public key.
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
