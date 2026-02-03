"""
XMSS Key Management for Consensus Testing
==========================================

Management of XMSS key pairs for test validators.

Keys are pre-generated and cached on disk to avoid expensive generation during tests.

Downloading Pre-generated Keys:

    python -m consensus_testing.keys --download --scheme test    # test scheme
    python -m consensus_testing.keys --download --scheme prod    # prod scheme

Regenerating Keys:

    python -m consensus_testing.keys                   # defaults
    python -m consensus_testing.keys --count 20        # more validators
    python -m consensus_testing.keys --max-slot 200    # longer lifetime

File Format:
    Each key pair is stored in a separate JSON file with hex-encoded SSZ.
    Directory structure: test_keys/{scheme}_scheme/{index}.json
    Each file contains: {"public": "0a1b...", "secret": "2c3d..."}
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tarfile
import tempfile
import urllib.request
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from lean_spec.config import LEAN_ENV
from lean_spec.subspecs.containers import AttestationData, ValidatorIndex
from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.xmss.aggregation import (
    AggregatedSignatureProof,
    SignatureKey,
)
from lean_spec.subspecs.xmss.containers import KeyPair, PublicKey, Signature
from lean_spec.subspecs.xmss.interface import (
    PROD_SIGNATURE_SCHEME,
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.types import Uint64

if TYPE_CHECKING:
    from collections.abc import Mapping

# Pre-generated key download URLs
KEY_DOWNLOAD_URLS = {
    "test": "https://github.com/leanEthereum/leansig-test-keys/releases/download/leanSpec-77bde6b/test_scheme.tar.gz",
    "prod": "https://github.com/leanEthereum/leansig-test-keys/releases/download/leanSpec-77bde6b/prod_scheme.tar.gz",
}
"""URLs for downloading pre-generated keys."""

# Signature scheme definitions
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

_VALIDATOR_INDEX_CACHE: dict[Uint64, ValidatorIndex] = {}
"""Cache for converting Uint64 to ValidatorIndex."""

_DEFAULT_MAX_SLOT: Slot = Slot(10)
"""Default number of max slots that the shared key manager is generated with"""


def get_shared_key_manager(max_slot: Slot = _DEFAULT_MAX_SLOT) -> XmssKeyManager:
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


NUM_VALIDATORS = 12
"""Default number of validator key pairs."""

DEFAULT_MAX_SLOT = Slot(100)
"""Maximum slot for test signatures (inclusive)."""

NUM_ACTIVE_EPOCHS = int(DEFAULT_MAX_SLOT) + 1
"""Key lifetime in epochs (derived from DEFAULT_MAX_SLOT)."""


def _get_keys_dir(scheme_name: str) -> Path:
    """Get the keys directory path for the given scheme."""
    return Path(__file__).parent / "test_keys" / f"{scheme_name}_scheme"


class LazyKeyDict:
    """Load pre-generated keys from disk (cached after first call)."""

    def __init__(self, scheme_name: str) -> None:
        """Initialize with scheme name for locating key files."""
        self._scheme_name = scheme_name
        self._keys_dir = _get_keys_dir(scheme_name)
        self._cache: dict[ValidatorIndex, KeyPair] = {}
        self._available_indices: set[int] | None = None

    def _ensure_dir_exists(self) -> None:
        if not self._keys_dir.exists():
            raise FileNotFoundError(
                f"Keys directory not found: {self._keys_dir} - "
                f"Run: python -m consensus_testing.keys --scheme {self._scheme_name}"
            )

    def _get_available_indices(self) -> set[int]:
        """Scan directory for available key indices (cached)."""
        if self._available_indices is None:
            self._ensure_dir_exists()
            self._available_indices = {int(f.stem) for f in self._keys_dir.glob("*.json")}
            if not self._available_indices:
                raise FileNotFoundError(
                    f"No key files found in: {self._keys_dir} - "
                    f"Run: python -m consensus_testing.keys --scheme {self._scheme_name}"
                )
        return self._available_indices

    def _load_key(self, idx: int) -> KeyPair:
        """Load a single key from disk."""
        key_file = self._keys_dir / f"{idx}.json"
        if not key_file.exists():
            raise KeyError(f"Key file not found: {key_file}")
        data = json.loads(key_file.read_text())
        return KeyPair.from_dict(data)

    def __getitem__(self, idx: ValidatorIndex) -> KeyPair:
        """Get key pair by validator index, loading from disk if needed."""
        if idx not in self._cache:
            self._cache[idx] = self._load_key(int(idx))
        return self._cache[idx]

    def __contains__(self, idx: ValidatorIndex) -> bool:
        """Check if a key exists for the given validator index."""
        return int(idx) in self._get_available_indices()

    def __len__(self) -> int:
        """Return the number of available keys."""
        return len(self._get_available_indices())

    def __iter__(self) -> Iterator[ValidatorIndex]:
        """Iterate over available validator indices in sorted order."""
        return iter(ValidatorIndex(i) for i in sorted(self._get_available_indices()))

    def items(self) -> Iterator[tuple[ValidatorIndex, KeyPair]]:
        """Iterate over all keys (loads all into memory)."""
        for idx in self:
            yield idx, self[idx]


_LAZY_KEY_CACHE: dict[str, LazyKeyDict] = {}
"""Cache for lazy key dictionaries by scheme name."""


def load_keys(scheme_name: str) -> LazyKeyDict:
    """
    Get a lazy-loading key dictionary for the given scheme.

    Keys are loaded individually on first access, not all at once.
    Reduces memory from ~4.8 GB to ~400 MB per key for prod scheme.

    Args:
        scheme_name: Name of the signature scheme.

    Returns:
        Lazy-loading dictionary mapping validator index to key pair.

    Raises:
        FileNotFoundError: If keys directory is missing.
    """
    if scheme_name not in _LAZY_KEY_CACHE:
        _LAZY_KEY_CACHE[scheme_name] = LazyKeyDict(scheme_name)
    return _LAZY_KEY_CACHE[scheme_name]


class XmssKeyManager:
    """
    Stateful manager for XMSS signing operations.

    Handles automatic key state advancement for the stateful XMSS scheme.

    Keys are lazily loaded from disk on first access.

    Args:
        max_slot: Maximum slot for signatures.
        scheme: XMSS scheme instance.

    Examples:
        >>> mgr = XmssKeyManager()
        >>> mgr[Uint64(0)]  # Get key pair
        >>> mgr.get_public_key(Uint64(1))  # Get public key only
        >>> mgr.sign_attestation_data(validator_id, attestation_data)  # Sign with auto-advancement
    """

    def __init__(
        self,
        max_slot: Slot,
        scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME,
    ) -> None:
        """Initialize the manager with optional custom configuration."""
        self.max_slot = max_slot
        self.scheme = scheme
        self._state: dict[ValidatorIndex, KeyPair] = {}

        for scheme_name, scheme_obj in LEAN_ENV_TO_SCHEMES.items():
            if scheme_obj is scheme:
                self.scheme_name = scheme_name

    @property
    def keys(self) -> LazyKeyDict:
        """Lazy access to immutable base keys."""
        return load_keys(self.scheme_name)

    def __getitem__(self, idx: ValidatorIndex) -> KeyPair:
        """Get key pair, returning advanced state if available."""
        if idx in self._state:
            return self._state[idx]
        if idx not in self.keys:
            raise KeyError(f"Validator {idx} not found (max: {len(self.keys) - 1})")
        return self.keys[idx]

    def __contains__(self, idx: ValidatorIndex) -> bool:
        """Check if validator index exists."""
        return idx in self.keys

    def __len__(self) -> int:
        """Number of available validators."""
        return len(self.keys)

    def __iter__(self) -> Iterator[ValidatorIndex]:
        """Iterate over validator indices."""
        return iter(self.keys)

    def get_public_key(self, idx: ValidatorIndex) -> PublicKey:
        """Get a validator's public key."""
        return self[idx].public

    def get_all_public_keys(self) -> dict[ValidatorIndex, PublicKey]:
        """Get all public keys (from base keys, not advanced state)."""
        return {idx: kp.public for idx, kp in self.keys.items()}

    def sign_attestation_data(
        self,
        validator_id: ValidatorIndex,
        attestation_data: AttestationData,
    ) -> Signature:
        """
        Sign an attestation data with automatic key state advancement.

        XMSS is stateful: signing advances the internal key state.
        This method handles advancement transparently.

        Args:
            validator_id: The validator index to sign the attestation data for.
            attestation_data: The attestation data to sign.

        Returns:
            XMSS signature.

        Raises:
            ValueError: If slot exceeds key lifetime.
        """
        epoch = attestation_data.slot
        kp = self[validator_id]
        sk = kp.secret

        # Advance key state until epoch is in prepared interval
        prepared = self.scheme.get_prepared_interval(sk)
        while int(epoch) not in prepared:
            activation = self.scheme.get_activation_interval(sk)
            if prepared.stop >= activation.stop:
                raise ValueError(f"Epoch {epoch} exceeds key lifetime {activation.stop}")
            sk = self.scheme.advance_preparation(sk)
            prepared = self.scheme.get_prepared_interval(sk)

        # Cache advanced state
        self._state[validator_id] = kp._replace(secret=sk)

        # Sign hash tree root of the attestation data
        message = attestation_data.data_root_bytes()
        return self.scheme.sign(sk, epoch, message)

    def build_attestation_signatures(
        self,
        aggregated_attestations: AggregatedAttestations,
        signature_lookup: Mapping[SignatureKey, Signature] | None = None,
    ) -> AttestationSignatures:
        """
        Build `AttestationSignatures` for already-aggregated attestations.

        For each aggregated attestation, collect the participating validators' public keys and
        signatures, then produce a single leanVM aggregated signature proof.
        """
        lookup = signature_lookup or {}

        proofs: list[AggregatedSignatureProof] = []
        for agg in aggregated_attestations:
            validator_ids = agg.aggregation_bits.to_validator_indices()
            message = agg.data.data_root_bytes()
            epoch = agg.data.slot

            public_keys: list[PublicKey] = [self.get_public_key(vid) for vid in validator_ids]
            signatures: list[Signature] = [
                (
                    lookup.get(SignatureKey(vid, message))
                    or self.sign_attestation_data(vid, agg.data)
                )
                for vid in validator_ids
            ]

            # If the caller supplied raw signatures and any are invalid,
            # aggregation should fail with exception.
            participants = AggregationBits.from_validator_indices(validator_ids)
            proof = AggregatedSignatureProof.aggregate(
                participants=participants,
                public_keys=public_keys,
                signatures=signatures,
                message=message,
                epoch=epoch,
            )
            proofs.append(proof)

        return AttestationSignatures(data=proofs)


def _generate_single_keypair(
    scheme: GeneralizedXmssScheme, num_epochs: int, index: int
) -> dict[str, str]:
    """Generate one key pair (module-level for pickling in ProcessPoolExecutor)."""
    print(f"Starting key #{index} generation...")
    pk, sk = scheme.key_gen(Uint64(0), Uint64(num_epochs))
    return KeyPair(public=pk, secret=sk).to_dict()


def _generate_keys(lean_env: str, count: int, max_slot: int) -> None:
    """
    Generate XMSS key pairs in parallel and save to individual files.

    Uses ProcessPoolExecutor to saturate CPU cores for faster generation.
    Each keypair is saved to a separate file to avoid the keyfile being
    very large for production keys.

    Args:
        lean_env: Name of the XMSS signature scheme to use (e.g. "test" or "prod").
        count: Number of validators.
        max_slot: Maximum slot (key lifetime = max_slot + 1 epochs).
    """
    scheme = LEAN_ENV_TO_SCHEMES[lean_env]
    keys_dir = _get_keys_dir(lean_env)
    num_epochs = max_slot + 1
    num_workers = os.cpu_count() or 1

    print(
        f"Generating {count} XMSS key pairs for {lean_env} environment "
        f"({num_epochs} epochs) using {num_workers} cores..."
    )

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        worker_func = partial(_generate_single_keypair, scheme, num_epochs)
        key_pairs = list(executor.map(worker_func, range(count)))

    # Create keys directory (remove old one if it exists)
    if keys_dir.exists():
        shutil.rmtree(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Save each keypair to a separate file
    for idx, key_pair in enumerate(key_pairs):
        key_file = keys_dir / f"{idx}.json"
        with open(key_file, "w") as f:
            json.dump(key_pair, f, indent=2)

    print(f"Saved {len(key_pairs)} key pairs to {keys_dir}/")

    # Clear cache so new keys are loaded
    _LAZY_KEY_CACHE.clear()


def _download_keys(scheme: str) -> None:
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
            tar.extractall(path=base_dir)

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
        default=int(DEFAULT_MAX_SLOT),
        help="Maximum slot (key lifetime = max_slot + 1)",
    )
    args = parser.parse_args()

    # Download keys instead of generating if specified
    if args.download:
        _download_keys(scheme=args.scheme)
        return

    _generate_keys(lean_env=args.scheme, count=args.count, max_slot=args.max_slot)


if __name__ == "__main__":
    main()
