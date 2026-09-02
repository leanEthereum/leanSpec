"""
XMSS key management for test validators.

Keys are pre-generated and cached on disk to avoid expensive generation during tests.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import ClassVar, Literal

from ssz import hash_tree_root

from lean_spec.config import LEAN_ENV
from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.xmss.constants import TARGET_CONFIG
from lean_spec.spec.crypto.xmss.containers import (
    PublicKey,
    SecretKey,
    Signature,
    ValidatorKeyPair,
)
from lean_spec.spec.crypto.xmss.interface import (
    PROD_SIGNATURE_SCHEME,
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.spec.crypto.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Randomness,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    AttestationData,
    SingleMessageAggregate,
)
from lean_spec.spec.ssz_types import Bytes32

KeyRole = Literal["attestation", "proposal"]
"""Discriminator for which signing role's key to load from a validator key pair."""

LEAN_ENV_TO_SCHEMES: dict[str, GeneralizedXmssScheme] = {
    "test": TEST_SIGNATURE_SCHEME,
    "prod": PROD_SIGNATURE_SCHEME,
}
"""Short scheme names mapped to their XMSS scheme instances."""


def create_dummy_signature() -> Signature:
    """Create a zero-filled signature that passes structural checks but fails verification."""
    zero_digest = HashDigestVector(data=[Fp(0)] * TARGET_CONFIG.HASH_LENGTH_FIELD_ELEMENTS)

    # The Merkle authentication path needs one sibling per tree level.
    # The tree height equals the log of the key lifetime.
    siblings = HashDigestList(data=[zero_digest] * TARGET_CONFIG.LOG_LIFETIME)

    # Winternitz one-time signatures use one hash chain per dimension.
    hashes = HashDigestList(data=[zero_digest] * TARGET_CONFIG.DIMENSION)

    return Signature(
        path=HashTreeOpening(siblings=siblings),
        rho=Randomness(data=[Fp(0)] * TARGET_CONFIG.RAND_LENGTH_FIELD_ELEMENTS),
        hashes=hashes,
    )


DEFAULT_MAX_SLOT = Slot(10)
"""Default max slot, high enough for most unit tests while keeping key generation fast."""


def get_keys_directory(scheme_name: str) -> Path:
    """Resolve the on-disk directory that holds key files for a scheme."""
    return Path(__file__).parent / "test_keys" / f"{scheme_name}_scheme"


def compute_key_set_digest(keys_directory: Path) -> str:
    """
    Compute the SHA-256 digest identifying a directory's key set.

    Two fills agree on vectors only if they agree on this digest.

    Returns:
        Hex digest prefixed with 0x.
    """
    digest = hashlib.sha256()
    key_files = sorted(keys_directory.glob("*.json"), key=lambda key_file: int(key_file.stem))
    for key_file in key_files:
        key_data = json.loads(key_file.read_text())
        digest.update(key_file.stem.encode())
        digest.update(bytes.fromhex(key_data["attestation_keypair"]["public_key"]))
        digest.update(bytes.fromhex(key_data["proposal_keypair"]["public_key"]))
    return f"0x{digest.hexdigest()}"


class XmssKeyManager:
    """
    Stateful manager for XMSS signing in tests.

    Each signing operation consumes a one-time leaf and advances the key.
    Keys load lazily into a three-tier cache: raw JSON, public keys, advanced secret state.
    """

    __slots__ = (
        "max_slot",
        "scheme_name",
        "scheme",
        "_keys_directory",
        "_json_cache",
        "_public_cache",
        "_available_indices",
        "_secret_state",
        "_key_set_digest",
    )

    _cache: ClassVar[dict[str, XmssKeyManager]] = {}
    """Per-scheme singleton cache, replaced when a wider max slot is requested."""

    @classmethod
    def shared(cls, max_slot: Slot = DEFAULT_MAX_SLOT) -> XmssKeyManager:
        """Return a shared manager, reusing the cache when its range covers the requested slot."""
        # A cached manager is usable if its range covers the requested max slot.
        cached = cls._cache.get(LEAN_ENV)
        if cached is not None and cached.max_slot >= max_slot:
            return cached

        # No suitable cached manager exists. Build a new one and cache it.
        manager = cls(max_slot=max_slot)
        cls._cache[LEAN_ENV] = manager
        return manager

    @classmethod
    def reset_signing_state(cls) -> None:
        """
        Clear advanced secret-key state from the cached manager.

        Without a reset, signing at high slots poisons low-slot signing for later tests.
        Only the mutable signing state is cleared; the immutable caches stay to avoid re-loading.
        """
        cached = cls._cache.get(LEAN_ENV)
        if cached is not None:
            cached._secret_state.clear()

    def __init__(self, max_slot: Slot = DEFAULT_MAX_SLOT) -> None:
        """Initialize with the active scheme and a maximum slot for key validity."""
        if LEAN_ENV not in LEAN_ENV_TO_SCHEMES:
            raise ValueError(f"Unknown scheme: {LEAN_ENV!r}")
        self.max_slot = max_slot
        self.scheme_name = LEAN_ENV
        self.scheme = LEAN_ENV_TO_SCHEMES[LEAN_ENV]
        self._keys_directory = get_keys_directory(LEAN_ENV)

        # Raw JSON cache: nested dict of hex-encoded SSZ strings, very lightweight.
        self._json_cache: dict[ValidatorIndex, dict[str, dict[str, str]]] = {}

        # Deserialized public key pairs, avoiding secret key overhead.
        self._public_cache: dict[ValidatorIndex, tuple[PublicKey, PublicKey]] = {}

        # Populated lazily on first directory scan.
        self._available_indices: set[ValidatorIndex] | None = None

        # Advanced secret-key state held as live Python objects.
        self._secret_state: dict[tuple[ValidatorIndex, KeyRole], SecretKey] = {}

        # Computed lazily on first request.
        self._key_set_digest: str | None = None

    def _scan_indices(self) -> set[ValidatorIndex]:
        """
        Discover which validator indices have key files on disk, caching the result.

        Raises:
            FileNotFoundError: If the directory is missing or empty.
        """
        if self._available_indices is None:
            if not self._keys_directory.exists():
                raise FileNotFoundError(
                    f"Keys directory not found: {self._keys_directory} - "
                    f"Run: uv run keys --scheme {self.scheme_name}"
                )

            # Each JSON file is named by its validator index (e.g. "0.json").
            self._available_indices = {
                ValidatorIndex(int(key_file.stem))
                for key_file in self._keys_directory.glob("*.json")
            }

            # An empty directory is as bad as a missing one.
            if not self._available_indices:
                raise FileNotFoundError(
                    f"No key files found in: {self._keys_directory} - "
                    f"Run: uv run keys --scheme {self.scheme_name}"
                )
        return self._available_indices

    def _load_json(self, index: ValidatorIndex) -> dict[str, dict[str, str]]:
        """
        Load raw JSON for a single validator, caching the result.

        Keeping the blobs as hex strings avoids the cost of deserializing secret keys.

        Raises:
            KeyError: If no key file exists for the index.
        """
        if index not in self._json_cache:
            key_file = self._keys_directory / f"{index}.json"
            try:
                with key_file.open() as key_file_handle:
                    self._json_cache[index] = json.load(key_file_handle)
            except FileNotFoundError:
                raise KeyError(f"Key file not found: {key_file}") from None
        return self._json_cache[index]

    def _get_secret_key(self, index: ValidatorIndex, role: KeyRole) -> SecretKey:
        """
        Deserialize a single secret key from disk.

        Only the requested role's secret is decoded; the rest stay as lightweight hex strings.
        """
        data = self._load_json(index)
        return SecretKey.decode_bytes(bytes.fromhex(data[f"{role}_keypair"]["secret_key"]))

    def __getitem__(self, index: ValidatorIndex) -> ValidatorKeyPair:
        """
        Fully deserialize a key pair including secrets.

        Prefer the public-key or signing accessors to avoid loading heavy secret key objects.
        """
        try:
            return ValidatorKeyPair.model_validate(self._load_json(index))
        except KeyError:
            raise KeyError(f"Validator {index} not found (available: {len(self)})") from None

    def __contains__(self, index: object) -> bool:
        """Check whether a validator index has keys on disk."""
        if not isinstance(index, ValidatorIndex):
            return False
        return index in self._scan_indices()

    def __len__(self) -> int:
        """Return the number of available validator key pairs."""
        return len(self._scan_indices())

    def __iter__(self) -> Iterator[ValidatorIndex]:
        """Iterate over validator indices in ascending order."""
        return iter(sorted(self._scan_indices()))

    def key_set_digest(self) -> str:
        """Return the digest identifying this manager's on-disk key set, computed once."""
        if self._key_set_digest is None:
            self._key_set_digest = compute_key_set_digest(self._keys_directory)
        return self._key_set_digest

    def get_public_keys(self, index: ValidatorIndex) -> tuple[PublicKey, PublicKey]:
        """
        Return the attestation and proposal public keys without touching secrets.

        Decoding the secret keys would cost ~370 MB of Python objects, so it is avoided.

        Returns:
            Tuple of (attestation public key, proposal public key).
        """
        if index not in self._public_cache:
            data = self._load_json(index)
            self._public_cache[index] = (
                PublicKey.decode_bytes(bytes.fromhex(data["attestation_keypair"]["public_key"])),
                PublicKey.decode_bytes(bytes.fromhex(data["proposal_keypair"]["public_key"])),
            )
        return self._public_cache[index]

    def _sign_with_secret(
        self,
        validator_index: ValidatorIndex,
        slot: Slot,
        message: Bytes32,
        role: KeyRole,
    ) -> Signature:
        """
        Core signing logic shared by attestation and proposal paths.

        An XMSS key has a prepared interval, the range of slots it can currently sign.
        A target slot outside that range forces the key state forward until the slot is covered.

        Raises:
            ValueError: If the slot exceeds the key's total lifetime.
        """
        cache_key = (validator_index, role)

        # Reuse the cached object when present, else decode from disk.
        # Holding the object avoids a bytes-to-object round-trip that dominated prod-scheme runtime.
        if cache_key in self._secret_state:
            secret_key = self._secret_state[cache_key]
        else:
            secret_key = self._get_secret_key(validator_index, role)

        # Advance the key until the target slot falls within the prepared interval.
        # Each step extends the interval by consuming the next one-time signing leaf.
        prepared = self.scheme.get_prepared_interval(secret_key)
        while int(slot) not in prepared:
            activation = self.scheme.get_activation_interval(secret_key)

            # Reaching the activation boundary means the key is exhausted.
            if prepared.stop >= activation.stop:
                raise ValueError(f"Slot {slot} exceeds key lifetime {activation.stop}")

            secret_key = self.scheme.advance_preparation(secret_key)
            prepared = self.scheme.get_prepared_interval(secret_key)

        signature = self.scheme.sign(secret_key, slot, message)

        # Park the advanced object back in the cache for the next sign.
        self._secret_state[cache_key] = secret_key

        return signature

    def sign_attestation_data(
        self,
        validator_index: ValidatorIndex,
        attestation_data: AttestationData,
    ) -> Signature:
        """
        Sign attestation data using the validator's attestation key.

        Advances only the attestation key state, leaving the proposal key untouched.

        Returns:
            XMSS signature over the attestation data root.

        Raises:
            ValueError: If the attestation slot exceeds key lifetime.
        """
        return self._sign_with_secret(
            validator_index,
            attestation_data.slot,
            hash_tree_root(attestation_data),
            "attestation",
        )

    def sign_block_root(
        self,
        validator_index: ValidatorIndex,
        slot: Slot,
        block_root: Bytes32,
    ) -> Signature:
        """
        Sign a block root using the validator's proposal key.

        Advances only the proposal key state, leaving the attestation key untouched.

        Returns:
            XMSS signature over the block root.

        Raises:
            ValueError: If the slot exceeds key lifetime.
        """
        return self._sign_with_secret(validator_index, slot, block_root, "proposal")

    def sign_and_aggregate(
        self,
        validator_indices: list[ValidatorIndex],
        attestation_data: AttestationData,
        precomputed_signatures: Mapping[ValidatorIndex, Signature] | None = None,
    ) -> SingleMessageAggregate:
        """
        Sign attestation data with each validator and aggregate the result.

        Each key signs the data root, then a binding folds them into one proof over data and slot.

        Args:
            validator_indices: Validators to sign with.
            attestation_data: The attestation data to sign.
            precomputed_signatures: Optional signatures keyed by validator index.
                Missing entries are signed on the fly.

        Returns:
            A single-message aggregate proof covering the given validators.
        """
        signatures = precomputed_signatures or {}
        raw_xmss = [
            (
                validator_index,
                self.get_public_keys(validator_index)[0],
                signatures.get(validator_index)
                or self.sign_attestation_data(validator_index, attestation_data),
            )
            for validator_index in validator_indices
        ]
        return SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=raw_xmss,
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )

    def build_attestation_proofs(
        self,
        aggregated_attestations: AggregatedAttestations,
        signature_lookup: Mapping[AttestationData, Mapping[ValidatorIndex, Signature]]
        | None = None,
    ) -> list[SingleMessageAggregate]:
        """
        Produce one single-message aggregate proof per attestation, parallel to the input.

        Participants come from each attestation's bitfield.
        The lookup supplies pre-computed signatures; missing entries are signed on the fly.

        Args:
            aggregated_attestations: Attestations with aggregation bitfields set.
            signature_lookup: Optional signatures keyed by attestation data then validator index.

        Returns:
            One proof per attestation, parallel to the input.
        """
        lookup = signature_lookup or {}
        return [
            self.sign_and_aggregate(
                list(aggregate.aggregation_bits.to_validator_indices()),
                aggregate.data,
                precomputed_signatures=lookup.get(aggregate.data, {}),
            )
            for aggregate in aggregated_attestations
        ]
