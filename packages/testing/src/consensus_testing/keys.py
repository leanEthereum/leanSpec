"""
XMSS Key Management for Consensus Testing

Management of XMSS key pairs for test validators.

Keys are pre-generated and cached on disk to avoid expensive generation during tests.

Downloading Pre-generated Keys:

    python -m consensus_testing.keys --download --scheme test    # test scheme
    python -m consensus_testing.keys --download --scheme prod    # prod scheme

Regenerating Keys:

    python -m consensus_testing.keys                   # defaults
    python -m consensus_testing.keys --count 20        # more validators
    python -m consensus_testing.keys --max-slot 200    # longer lifetime

File format:

- Each key pair is stored in a separate JSON file with hex-encoded SSZ.
- Directory structure: ``test_keys/{scheme}_scheme/{index}.json``
- Each file has four hex-encoded SSZ fields:
  ``attestation_public``, ``attestation_secret``,
  ``proposal_public``, ``proposal_secret``
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tarfile
import tempfile
import urllib.request
from collections.abc import Iterator, Mapping
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path
from typing import Literal

from lean_spec.config import LEAN_ENV
from lean_spec.subspecs.containers import AttestationData, ValidatorIndex
from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.constants import TARGET_CONFIG
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey, Signature, ValidatorKeyPair
from lean_spec.subspecs.xmss.interface import (
    PROD_SIGNATURE_SCHEME,
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Randomness,
)
from lean_spec.types import Bytes32, Uint64

SecretField = Literal["attestation_secret", "proposal_secret"]
"""The two secret key field names on ValidatorKeyPair."""

__all__ = [
    "CLI_DEFAULT_MAX_SLOT",
    "KEY_DOWNLOAD_URLS",
    "LEAN_ENV_TO_SCHEMES",
    "LazyKeyDict",
    "NUM_VALIDATORS",
    "XmssKeyManager",
    "create_dummy_signature",
    "download_keys",
    "get_keys_dir",
    "get_shared_key_manager",
]

KEY_DOWNLOAD_URLS = {
    "test": "https://github.com/leanEthereum/leansig-test-keys/releases/download/leanSpec-ad9a3226/test_scheme.tar.gz",
    "prod": "https://github.com/leanEthereum/leansig-test-keys/releases/download/leanSpec-ad9a3226/prod_scheme.tar.gz",
}
"""URLs for downloading pre-generated keys."""

LEAN_ENV_TO_SCHEMES = {
    "test": TEST_SIGNATURE_SCHEME,
    "prod": PROD_SIGNATURE_SCHEME,
}
"""
Mapping from short name to scheme objects. This mapping is useful for:

- The CLI argument for choosing the signature scheme to generate
- Deriving the file name for the cached keys
- Caching key managers in test fixtures
"""

_KEY_MANAGER_CACHE: dict[tuple[str, Slot], XmssKeyManager] = {}
"""Cache for key managers: {(scheme_name, max_slot): XmssKeyManager}"""

_SHARED_MANAGER_MAX_SLOT: Slot = Slot(10)
"""Default max slot for the shared key manager."""


def create_dummy_signature() -> Signature:
    """
    Create a structurally valid but cryptographically invalid individual signature.

    The signature has proper structure (correct number of siblings, hashes, etc.)
    but all values are zeros, so it will fail cryptographic verification.
    """
    # Create zero-filled hash digests with correct dimensions
    zero_digest = HashDigestVector(data=[Fp(0) for _ in range(TARGET_CONFIG.HASH_LEN_FE)])

    # Path needs LOG_LIFETIME siblings for the Merkle authentication path
    siblings = HashDigestList(data=[zero_digest for _ in range(TARGET_CONFIG.LOG_LIFETIME)])

    # Hashes need DIMENSION vectors for the Winternitz chain hashes
    hashes = HashDigestList(data=[zero_digest for _ in range(TARGET_CONFIG.DIMENSION)])

    return Signature(
        path=HashTreeOpening(siblings=siblings),
        rho=Randomness(data=[Fp(0) for _ in range(TARGET_CONFIG.RAND_LEN_FE)]),
        hashes=hashes,
    )


def get_shared_key_manager(max_slot: Slot = _SHARED_MANAGER_MAX_SLOT) -> XmssKeyManager:
    """
    Get a shared XMSS key manager for reusing keys across tests.

    Implements caching that reuses key managers with sufficient capacity.
    If a cached key manager exists with max slot >= the requested max slot, it will
    be reused instead of creating a new one.

    Args:
        max_slot: Maximum slot for which XMSS keys should be valid. Defaults to 10 slots.

    Returns:
        Shared XmssKeyManager instance for the target scheme that supports at least max slot.
    """
    scheme = LEAN_ENV_TO_SCHEMES[LEAN_ENV]

    # Check if we have a cached key manager with sufficient capacity
    for (cached_lean_env, cached_max_slot), manager in _KEY_MANAGER_CACHE.items():
        if cached_lean_env == LEAN_ENV and cached_max_slot >= max_slot:
            return manager

    # No suitable cached manager found, create a new one
    manager = XmssKeyManager(max_slot=max_slot, scheme=scheme)
    _KEY_MANAGER_CACHE[(LEAN_ENV, max_slot)] = manager
    return manager


NUM_VALIDATORS: int = 12
"""Default number of validator key pairs."""

CLI_DEFAULT_MAX_SLOT = Slot(100)
"""Maximum slot for CLI-generated test signatures (inclusive)."""


def get_keys_dir(scheme_name: str) -> Path:
    """Get the keys directory path for the given scheme."""
    return Path(__file__).parent / "test_keys" / f"{scheme_name}_scheme"


class LazyKeyDict(Mapping[ValidatorIndex, ValidatorKeyPair]):
    """Load pre-generated keys from disk (cached after first call)."""

    def __init__(self, scheme_name: str) -> None:
        """Initialize with scheme name for locating key files."""
        self._scheme_name = scheme_name
        self._keys_dir = get_keys_dir(scheme_name)
        self._cache: dict[ValidatorIndex, ValidatorKeyPair] = {}
        self._public_cache: dict[ValidatorIndex, tuple[PublicKey, PublicKey]] = {}
        self._raw_cache: dict[ValidatorIndex, dict[str, str]] = {}
        self._available_indices: set[ValidatorIndex] | None = None

    def _ensure_dir_exists(self) -> None:
        """Raise FileNotFoundError if the keys directory does not exist."""
        if not self._keys_dir.exists():
            raise FileNotFoundError(
                f"Keys directory not found: {self._keys_dir} - "
                f"Run: python -m consensus_testing.keys --scheme {self._scheme_name}"
            )

    def _get_available_indices(self) -> set[ValidatorIndex]:
        """Scan directory for available key indices (cached)."""
        if self._available_indices is None:
            self._ensure_dir_exists()
            self._available_indices = {
                ValidatorIndex(int(f.stem)) for f in self._keys_dir.glob("*.json")
            }
            if not self._available_indices:
                raise FileNotFoundError(
                    f"No key files found in: {self._keys_dir} - "
                    f"Run: python -m consensus_testing.keys --scheme {self._scheme_name}"
                )
        return self._available_indices

    def _load_raw(self, idx: ValidatorIndex) -> dict[str, str]:
        """Load raw JSON data from disk (cached)."""
        if idx not in self._raw_cache:
            key_file = self._keys_dir / f"{idx}.json"
            try:
                self._raw_cache[idx] = json.loads(key_file.read_text())
            except FileNotFoundError:
                raise KeyError(f"Key file not found: {key_file}") from None
        return self._raw_cache[idx]

    def _load_key(self, idx: ValidatorIndex) -> ValidatorKeyPair:
        """Load a single key from disk."""
        return ValidatorKeyPair.from_dict(self._load_raw(idx))

    def _load_public_keys(self, idx: ValidatorIndex) -> tuple[PublicKey, PublicKey]:
        """Load only public keys from disk, skipping expensive SecretKey deserialization."""
        data = self._load_raw(idx)
        return (
            PublicKey.decode_bytes(bytes.fromhex(data["attestation_public"])),
            PublicKey.decode_bytes(bytes.fromhex(data["proposal_public"])),
        )

    def get_public_keys(self, idx: ValidatorIndex) -> tuple[PublicKey, PublicKey]:
        """
        Get (attestation_public, proposal_public) without loading secret keys.

        Returns cached public keys if available, otherwise loads only the public
        key portions from disk. Avoids deserializing the heavy SecretKey objects
        (each ~2.7KB raw with 3 HashSubTree structures) until signing is needed.
        """
        if idx in self._cache:
            kp = self._cache[idx]
            return (kp.attestation_public, kp.proposal_public)
        if idx not in self._public_cache:
            self._public_cache[idx] = self._load_public_keys(idx)
        return self._public_cache[idx]

    def get_secret_key(self, idx: ValidatorIndex, field: SecretField) -> SecretKey:
        """
        Load a specific secret key from disk without deserializing the other keys.

        Only the requested SecretKey is deserialized (~370 MB in Python objects).
        The other three fields remain as lightweight hex strings (~2.7 KB each).
        """
        if idx in self._cache:
            return getattr(self._cache[idx], field)
        data = self._load_raw(idx)
        return SecretKey.decode_bytes(bytes.fromhex(data[field]))

    def __getitem__(self, idx: ValidatorIndex) -> ValidatorKeyPair:
        """Get key pair by validator index, loading from disk if needed."""
        if idx not in self._cache:
            self._cache[idx] = self._load_key(idx)
            # Full pair supersedes raw/public caches for this index.
            self._raw_cache.pop(idx, None)
            self._public_cache.pop(idx, None)
        return self._cache[idx]

    def __contains__(self, idx: object) -> bool:
        """Check if a key exists for the given validator index."""
        if not isinstance(idx, ValidatorIndex):
            return False
        return idx in self._get_available_indices()

    def __len__(self) -> int:
        """Return the number of available keys."""
        return len(self._get_available_indices())

    def __iter__(self) -> Iterator[ValidatorIndex]:
        """Iterate over available validator indices in sorted order."""
        return iter(sorted(self._get_available_indices()))


_LAZY_KEY_CACHE: dict[str, LazyKeyDict] = {}
"""Cache for lazy key dictionaries by scheme name."""


class XmssKeyManager:
    """
    Stateful manager for XMSS signing operations.

    Handles automatic key state advancement for the stateful XMSS scheme.

    Keys are lazily loaded from disk on first access.
    """

    def __init__(
        self,
        max_slot: Slot,
        scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME,
    ) -> None:
        """Initialize the manager with optional custom configuration."""
        self.max_slot = max_slot
        self.scheme = scheme
        self._secret_state: dict[tuple[ValidatorIndex, SecretField], bytes] = {}
        """
        Advanced secret key state cached as raw SSZ bytes.

        Raw bytes (~2.7 KB each) instead of deserialized SecretKey objects
        (~370 MB each) to avoid holding massive Pydantic model trees in memory.
        """

        try:
            self.scheme_name = next(
                name for name, obj in LEAN_ENV_TO_SCHEMES.items() if obj is scheme
            )
        except StopIteration:
            raise ValueError(f"Unknown scheme: {scheme}") from None

    @property
    def keys(self) -> LazyKeyDict:
        """Lazy access to immutable base keys."""
        if self.scheme_name not in _LAZY_KEY_CACHE:
            _LAZY_KEY_CACHE[self.scheme_name] = LazyKeyDict(self.scheme_name)
        return _LAZY_KEY_CACHE[self.scheme_name]

    def __getitem__(self, idx: ValidatorIndex) -> ValidatorKeyPair:
        """Get key pair. Prefer get_public_keys() or signing methods to avoid loading all keys."""
        if idx not in self.keys:
            raise KeyError(f"Validator {idx} not found (max: {len(self.keys) - 1})")
        return self.keys[idx]

    def __contains__(self, idx: object) -> bool:
        """Check if validator index exists."""
        if not isinstance(idx, ValidatorIndex):
            return False
        return idx in self.keys

    def __len__(self) -> int:
        """Number of available validators."""
        return len(self.keys)

    def __iter__(self) -> Iterator[ValidatorIndex]:
        """Iterate over validator indices."""
        return iter(self.keys)

    def get_public_keys(self, idx: ValidatorIndex) -> tuple[PublicKey, PublicKey]:
        """
        Get (attestation_public, proposal_public) without loading secret keys.

        Delegates to lazy disk loading that skips SecretKey deserialization.
        """
        return self.keys.get_public_keys(idx)

    def _sign_with_secret(
        self,
        validator_id: ValidatorIndex,
        slot: Slot,
        message: Bytes32,
        secret_field: SecretField,
    ) -> Signature:
        """
        Shared signing logic for attestation/proposal paths.

        Handles XMSS state advancement until the requested slot is within the
        prepared interval, caches the updated secret as raw bytes, and produces
        the signature.

        Only the needed SecretKey is deserialized (~370 MB in Python objects).
        After signing, the advanced state is re-serialized to compact bytes
        (~2.7 KB) so only one SecretKey is in memory at a time.

        Args:
            validator_id: Validator index whose key should be used.
            slot: The slot to sign for.
            message: The message bytes to sign.
            secret_field: Which secret on the key pair should advance.
        """
        cache_key = (validator_id, secret_field)

        # Deserialize the secret key: from cached bytes or from disk.
        if cache_key in self._secret_state:
            sk = SecretKey.decode_bytes(self._secret_state[cache_key])
        else:
            sk = self.keys.get_secret_key(validator_id, secret_field)

        # Advance key state until the slot is ready for signing.
        prepared = self.scheme.get_prepared_interval(sk)
        while int(slot) not in prepared:
            activation = self.scheme.get_activation_interval(sk)
            if prepared.stop >= activation.stop:
                raise ValueError(f"Slot {slot} exceeds key lifetime {activation.stop}")
            sk = self.scheme.advance_preparation(sk)
            prepared = self.scheme.get_prepared_interval(sk)

        signature = self.scheme.sign(sk, slot, message)

        # Cache advanced state as raw bytes to keep memory compact.
        self._secret_state[cache_key] = sk.encode_bytes()

        return signature

    def sign_attestation_data(
        self,
        validator_id: ValidatorIndex,
        attestation_data: AttestationData,
    ) -> Signature:
        """
        Sign attestation data with the attestation key.

        XMSS is stateful: this delegates to the shared helper which advances the
        attestation key state as needed while leaving the proposal key untouched.

        Args:
            validator_id: The validator index to sign the attestation data for.
            attestation_data: The attestation data to sign.

        Returns:
            XMSS signature.

        Raises:
            ValueError: If slot exceeds key lifetime.
        """
        return self._sign_with_secret(
            validator_id,
            attestation_data.slot,
            attestation_data.data_root_bytes(),
            "attestation_secret",
        )

    def sign_block_root(
        self,
        validator_id: ValidatorIndex,
        slot: Slot,
        block_root: Bytes32,
    ) -> Signature:
        """
        Sign a block root with the proposal key.

        Advances the proposal key state until the requested slot is within the
        prepared interval, then signs the block root.

        Args:
            validator_id: The validator index to sign the block for.
            slot: The slot of the block being signed.
            block_root: The hash_tree_root(block) to sign.

        Returns:
            XMSS signature.

        Raises:
            ValueError: If slot exceeds key lifetime.
        """
        return self._sign_with_secret(validator_id, slot, block_root, "proposal_secret")

    def build_attestation_signatures(
        self,
        aggregated_attestations: AggregatedAttestations,
        signature_lookup: Mapping[AttestationData, Mapping[ValidatorIndex, Signature]]
        | None = None,
    ) -> AttestationSignatures:
        """
        Build attestation signatures for already-aggregated attestations.

        For each aggregated attestation, collect the participating validators' public keys and
        signatures, then produce a single leanVM aggregated signature proof.
        """
        lookup = signature_lookup or {}

        proofs: list[AggregatedSignatureProof] = []
        for agg in aggregated_attestations:
            validator_ids = agg.aggregation_bits.to_validator_indices()
            message = agg.data.data_root_bytes()
            slot = agg.data.slot

            # Look up pre-computed signatures by attestation data and validator ID.
            sigs_for_data = lookup.get(agg.data, {})

            public_keys: list[PublicKey] = [self.get_public_keys(vid)[0] for vid in validator_ids]
            signatures: list[Signature] = [
                sigs_for_data.get(vid) or self.sign_attestation_data(vid, agg.data)
                for vid in validator_ids
            ]

            # If the caller supplied raw signatures and any are invalid,
            # aggregation should fail with exception.
            participants = AggregationBits.from_validator_indices(validator_ids)
            raw_xmss = list(zip(public_keys, signatures, strict=True))
            proof = AggregatedSignatureProof.aggregate(
                xmss_participants=participants,
                children=[],
                raw_xmss=raw_xmss,
                message=message,
                slot=slot,
            )
            proofs.append(proof)

        return AttestationSignatures(data=proofs)


def _generate_single_keypair(
    scheme: GeneralizedXmssScheme, num_slots: int, index: int
) -> dict[str, str]:
    """Generate dual key pairs for one validator (module-level for pickling)."""
    print(f"Starting key #{index} generation...")
    att_pk, att_sk = scheme.key_gen(Slot(0), Uint64(num_slots))
    prop_pk, prop_sk = scheme.key_gen(Slot(0), Uint64(num_slots))
    return ValidatorKeyPair(
        attestation_public=att_pk,
        attestation_secret=att_sk,
        proposal_public=prop_pk,
        proposal_secret=prop_sk,
    ).to_dict()


def _generate_keys(lean_env: str, count: int, max_slot: int) -> None:
    """
    Generate XMSS key pairs in parallel and save to individual files.

    Uses ProcessPoolExecutor to saturate CPU cores for faster generation.
    Each keypair is saved to a separate file to avoid the keyfile being
    very large for production keys.

    Args:
        lean_env: Name of the XMSS signature scheme to use (e.g. "test" or "prod").
        count: Number of validators.
        max_slot: Maximum slot (key lifetime = max_slot + 1 slots).
    """
    scheme = LEAN_ENV_TO_SCHEMES[lean_env]
    keys_dir = get_keys_dir(lean_env)
    num_slots = max_slot + 1
    num_workers = os.cpu_count() or 1

    print(
        f"Generating {count} XMSS key pairs for {lean_env} environment "
        f"({num_slots} slots) using {num_workers} cores..."
    )

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        worker_func = partial(_generate_single_keypair, scheme, num_slots)
        key_pairs = list(executor.map(worker_func, range(count)))

    # Create keys directory (remove old one if it exists)
    if keys_dir.exists():
        shutil.rmtree(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Save each keypair to a separate file
    for idx, key_pair in enumerate(key_pairs):
        key_file = keys_dir / f"{idx}.json"
        key_file.write_text(json.dumps(key_pair, indent=2))

    print(f"Saved {len(key_pairs)} key pairs to {keys_dir}/")

    # Clear cache so new keys are loaded
    _LAZY_KEY_CACHE.clear()


def download_keys(scheme: str) -> None:
    """
    Download pre-generated XMSS key pairs from GitHub releases.

    Downloads and extracts tar.gz archive for the specified scheme
    into its respective directory.

    Args:
        scheme: Scheme name to download (e.g., 'test' or 'prod').
    """
    base_dir = Path(__file__).parent / "test_keys"
    url = KEY_DOWNLOAD_URLS[scheme]

    print(f"Downloading {scheme} keys from {url}...")

    # Download to a temporary file
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp_file:
        try:
            with urllib.request.urlopen(url) as response:
                tmp_file.write(response.read())
            tmp_path = tmp_file.name
        except Exception as e:
            print(f"Failed to download {scheme} keys: {e}")
            return

    # Extract the archive
    try:
        target_dir = base_dir / f"{scheme}_scheme"

        # Remove existing directory if present
        if target_dir.exists():
            shutil.rmtree(target_dir)

        # Create parent directory
        base_dir.mkdir(parents=True, exist_ok=True)

        # Extract tar.gz
        with tarfile.open(tmp_path, "r:gz") as tar:
            tar.extractall(path=base_dir, filter="data")

        print(f"Extracted {scheme} keys to {target_dir}/")

    except Exception as e:
        print(f"Failed to extract {scheme} keys: {e}")
    finally:
        # Clean up temporary file
        os.unlink(tmp_path)

    # Clear cache so new keys are loaded
    _LAZY_KEY_CACHE.clear()
    print("Download complete!")


def main() -> None:
    """CLI entry point for key generation."""
    parser = argparse.ArgumentParser(
        description="Generate XMSS key pairs for consensus testing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download pre-generated keys from a GitHub release",
    )
    parser.add_argument(
        "--scheme",
        choices=LEAN_ENV_TO_SCHEMES.keys(),
        default="test",
        help="XMSS scheme to use",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=NUM_VALIDATORS,
        help="Number of validator key pairs",
    )
    parser.add_argument(
        "--max-slot",
        type=int,
        default=int(CLI_DEFAULT_MAX_SLOT),
        help="Maximum slot (key lifetime = max_slot + 1)",
    )
    args = parser.parse_args()

    # Download keys instead of generating if specified
    if args.download:
        download_keys(scheme=args.scheme)
        return

    _generate_keys(lean_env=args.scheme, count=args.count, max_slot=args.max_slot)


if __name__ == "__main__":
    main()
