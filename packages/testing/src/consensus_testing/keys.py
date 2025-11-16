"""XMSS key management utilities for testing."""

from __future__ import annotations

import random
from typing import Any, NamedTuple, Optional

from lean_spec.subspecs.containers import Attestation, Signature
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.koalabear import Fp, P
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.constants import PRF_KEY_LENGTH, XmssConfig
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey
from lean_spec.subspecs.xmss.interface import (
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.subspecs.xmss.prf import Prf
from lean_spec.subspecs.xmss.utils import Rand
from lean_spec.types import Uint64, ValidatorIndex


class KeyPair(NamedTuple):
    """A validator's XMSS key pair."""

    public: PublicKey
    """The validator's public key (used for verification)."""

    secret: SecretKey
    """The validator's secret key (used for signing)."""


_KEY_CACHE: dict[tuple[int, int, int, int | None], KeyPair] = {}
"""
Cache keys across tests to avoid regenerating them for the same validator/lifetime combo.

Key: (validator_index, activation_epoch, num_active_epochs, seed) -> KeyPair
"""


def _to_int(value: int | Slot | Uint64 | None, default: int = 0) -> int:
    """Normalize Slot/Uint64/int to int with an optional default."""
    if value is None:
        return default
    if isinstance(value, Slot):
        return value.as_int()
    return int(value)


class SeededRand(Rand):
    """Deterministic Rand helper to make key generation repeatable in tests."""

    def __init__(self, config: XmssConfig, seed: int) -> None:
        """Initialize with a deterministic seed."""
        super().__init__(config)
        self._rng = random.Random(seed)

    def field_elements(self, length: int) -> list[Fp]:
        """Generate deterministic field elements from the seeded RNG."""
        return [Fp(value=self._rng.randrange(P)) for _ in range(length)]


class SeededPrf(Prf):
    """Deterministic PRF helper for repeatable PRF key generation."""

    def __init__(self, config: XmssConfig, seed: int) -> None:
        """Initialize with a deterministic seed."""
        super().__init__(config)
        self._rng = random.Random(seed)

    def key_gen(self) -> bytes:
        """Generate a deterministic PRF key for repeatable tests."""
        # Use a deterministic stream rather than os.urandom for repeatability in tests.
        return self._rng.randbytes(PRF_KEY_LENGTH)


class XmssKeyManager:
    """Lazy key manager for test validators using XMSS signatures."""

    DEFAULT_MAX_SLOT = Slot(100)
    """Default maximum slot horizon if not specified."""
    DEFAULT_ACTIVATION_EPOCH = 0

    def __init__(
        self,
        max_slot: Optional[Slot] = None,
        scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME,
        default_activation_epoch: int | Slot | Uint64 = DEFAULT_ACTIVATION_EPOCH,
        default_seed: int | None = 0,
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
        default_activation_epoch : int | Slot | Uint64, optional
            Activation epoch used when none is provided for key generation.
        default_seed : int | None, optional
            Seed for deterministic key generation. Set to None to use non-deterministic
            randomness from the underlying XMSS scheme.

        Notes:
        -----
        Internally, keys are stored in a single dictionary:
        `{ValidatorIndex → KeyPair}`.
        """
        self.max_slot = max_slot if max_slot is not None else self.DEFAULT_MAX_SLOT
        self.scheme = scheme
        self.default_activation_epoch = _to_int(
            default_activation_epoch, self.DEFAULT_ACTIVATION_EPOCH
        )
        self.default_seed = default_seed
        self._key_pairs: dict[ValidatorIndex, KeyPair] = {}
        self._key_metadata: dict[ValidatorIndex, dict[str, Any]] = {}
        self._schemes_by_seed: dict[int, GeneralizedXmssScheme] = {}

    @property
    def default_num_active_epochs(self) -> int:
        """Default lifetime derived from the configured max_slot."""
        return self.max_slot.as_int() + 1

    def _scheme_for_seed(self, seed: int | None) -> GeneralizedXmssScheme:
        """
        Return a scheme instance appropriate for the provided seed.

        A deterministic scheme (SeededRand + SeededPrf) is returned when a specific
        seed is provided; otherwise the base scheme is used.
        """
        if seed is None:
            return self.scheme

        if seed not in self._schemes_by_seed:
            self._schemes_by_seed[seed] = GeneralizedXmssScheme(
                config=self.scheme.config,
                prf=SeededPrf(self.scheme.config, seed),
                hasher=self.scheme.hasher,
                merkle_tree=self.scheme.merkle_tree,
                encoder=self.scheme.encoder,
                rand=SeededRand(self.scheme.config, seed),
            )

        return self._schemes_by_seed[seed]

    def create_and_store_key_pair(
        self,
        validator_index: ValidatorIndex,
        *,
        activation_epoch: int | Slot | Uint64 | None = None,
        num_active_epochs: int | Slot | Uint64 | None = None,
        seed: int | None = None,
    ) -> KeyPair:
        """
        Generate and store a key pair with explicit control over key generation.

        Parameters
        ----------
        validator_index : ValidatorIndex
            The validator for whom a key pair should be generated.
        activation_epoch : int | Slot | Uint64, optional
            First epoch for which the key is valid. Defaults to `default_activation_epoch`.
        num_active_epochs : int | Slot | Uint64, optional
            Number of consecutive epochs the key should remain active.
            Defaults to `max_slot + 1` (to include genesis).
        seed : int | None, optional
            Seed used for deterministic key generation. If None, the base scheme's
            randomness is used.
        """
        activation_epoch_int = _to_int(activation_epoch, self.default_activation_epoch)
        num_active_epochs_int = _to_int(num_active_epochs, self.default_num_active_epochs)
        key_seed = seed if seed is not None else self.default_seed

        scheme = self._scheme_for_seed(key_seed)

        cache_key = (
            int(validator_index),
            activation_epoch_int,
            num_active_epochs_int,
            key_seed,
        )

        if cache_key in _KEY_CACHE:
            key_pair = _KEY_CACHE[cache_key]
        else:
            pk, sk = scheme.key_gen(Uint64(activation_epoch_int), Uint64(num_active_epochs_int))
            key_pair = KeyPair(public=pk, secret=sk)
            _KEY_CACHE[cache_key] = key_pair

        self._key_pairs[validator_index] = key_pair
        self._key_metadata[validator_index] = {
            "activation_epoch": activation_epoch_int,
            "num_active_epochs": num_active_epochs_int,
            "seed": key_seed,
        }
        return key_pair

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

        metadata = self._key_metadata.get(
            validator_id,
            {
                "seed": self.default_seed,
                "activation_epoch": self.default_activation_epoch,
                "num_active_epochs": self.default_num_active_epochs,
            },
        )
        scheme = self._scheme_for_seed(metadata.get("seed"))

        # Map the attestation slot to an XMSS epoch.
        #
        # Each slot gets its own epoch to avoid key reuse.
        epoch = attestation.data.slot

        # Loop until the epoch is inside the prepared interval
        prepared_interval = scheme.get_prepared_interval(sk)
        while int(epoch) not in prepared_interval:
            # Check if we're advancing past the key's total lifetime
            activation_interval = scheme.get_activation_interval(sk)
            if prepared_interval.stop >= activation_interval.stop:
                raise ValueError(
                    f"Cannot sign for epoch {epoch}: "
                    f"it is beyond the key's max lifetime {activation_interval.stop}"
                )

            # Advance the key and get the new key object
            sk = scheme.advance_preparation(sk)

            # Update the prepared interval for the next loop check
            prepared_interval = scheme.get_prepared_interval(sk)

        # Update the cached key pair with the new, advanced secret key.
        # This ensures the *next* call to sign() uses the advanced state.
        self._key_pairs[validator_id] = KeyPair(public=key_pair.public, secret=sk)

        # Compute the message digest from the attestation's SSZ tree root.
        #
        # This produces a cryptographic hash of the entire attestation structure.
        message = bytes(hash_tree_root(attestation))

        # Generate the XMSS signature using the validator's (now prepared) secret key.
        xmss_sig = scheme.sign(sk, epoch, message)

        # Convert to the consensus Signature container (handles padding internally).
        return Signature.from_xmss(xmss_sig, scheme)

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

    def export_test_vectors(self, include_private_keys: bool = False) -> list[dict[str, Any]]:
        """
        Export generated keys in a JSON-serializable structure for downstream clients.

        Parameters
        ----------
        include_private_keys : bool
            When True, include the full secret key dump; otherwise only public data.
        """
        vectors: list[dict[str, Any]] = []
        for validator_index, key_pair in self._key_pairs.items():
            meta = self._key_metadata.get(validator_index, {})
            entry: dict[str, Any] = {
                "validator_index": int(validator_index),
                "activation_epoch": meta.get("activation_epoch"),
                "num_active_epochs": meta.get("num_active_epochs"),
                "seed": meta.get("seed"),
                "public_key": key_pair.public.to_bytes(self.scheme.config).hex(),
            }
            if include_private_keys:
                # Pydantic models are JSON-serializable; keep the raw dump for full fidelity.
                entry["secret_key"] = key_pair.secret.model_dump(mode="json")

            vectors.append(entry)

        return vectors
