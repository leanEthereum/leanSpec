"""
XMSS Key Management for Consensus Testing
==========================================

Management of XMSS key pairs for test validators.

Keys are pre-generated and cached on disk to avoid expensive generation during tests.

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
from dataclasses import dataclass
from functools import cache, partial
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Self

from lean_spec.subspecs.containers import Attestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey, Signature
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
    "test": "https://github.com/unnawut/leansig-test-keys/releases/download/leanSpec-d6cec9b/test_scheme.tar.gz",
    "prod": "https://github.com/unnawut/leansig-test-keys/releases/download/leanSpec-d6cec9b/prod_scheme.tar.gz",
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

_DEFAULT_MAX_SLOT = Slot(10)
"""Default maximum slot for shared key manager."""


@cache
def get_target_signauture_scheme() -> tuple[str, GeneralizedXmssScheme]:
    """
    Get the target XMSS signature scheme based on the LEAN_ENV environment variable.

    Reads the LEAN_ENV environment variable to determine which signature scheme
    to use for testing. The result is cached to avoid repeated environment lookups.

    Returns:
        Tuple of (scheme_name, scheme_object) where scheme_name is the environment
        variable value and scheme_object is the corresponding GeneralizedXmssScheme.

    Raises:
        ValueError: If LEAN_ENV contains an invalid scheme name.
    """
    lean_env = os.environ.get("LEAN_ENV", "test").lower()
    scheme = LEAN_ENV_TO_SCHEMES.get(lean_env)

    if scheme is None:
        raise ValueError(
            f"Invalid LEAN_ENV: {lean_env}. "
            f"Available lean environments: {', '.join(LEAN_ENV_TO_SCHEMES.keys())}"
        )

    # Currently assuming the scheme name is the env var value
    scheme_name = lean_env
    return scheme_name, scheme


def get_shared_key_manager(max_slot: Slot = _DEFAULT_MAX_SLOT) -> XmssKeyManager:
    """
    Get a shared XMSS key manager for reusing keys across tests.

    Implements caching that reuses key managers with sufficient capacity.
    If a cached key manager exists with max slot >= the requested max slot, it will
    be reused instead of creating a new one.

    Args:
        max_slot: Maximum slot for which XMSS keys should be valid.
                  Defaults to 10 slots.

    Returns:
        Shared XmssKeyManager instance for the current scheme that supports at least max slot.
    """
    scheme_name, scheme = get_target_signauture_scheme()

    # Check if we have a cached key manager with sufficient capacity
    for (cached_scheme, cached_max_slot), manager in _KEY_MANAGER_CACHE.items():
        if cached_scheme == scheme_name and cached_max_slot >= max_slot:
            return manager

    # No suitable cached manager found, create a new one
    manager = XmssKeyManager(max_slot=max_slot, scheme=scheme)
    _KEY_MANAGER_CACHE[(scheme_name, max_slot)] = manager
    return manager


NUM_VALIDATORS = 12
"""Default number of validator key pairs."""

DEFAULT_MAX_SLOT = Slot(100)
"""Maximum slot for test signatures (inclusive)."""

NUM_ACTIVE_EPOCHS = int(DEFAULT_MAX_SLOT) + 1
"""Key lifetime in epochs (derived from DEFAULT_MAX_SLOT)."""


@dataclass(frozen=True, slots=True)
class KeyPair:
    """
    Immutable XMSS key pair for a validator.

    Attributes:
        public: Public key for signature verification.
        secret: Secret key containing Merkle tree structures.
    """

    public: PublicKey
    secret: SecretKey

    @classmethod
    def from_dict(cls, data: Mapping[str, str]) -> Self:
        """Deserialize from JSON-compatible dict with hex-encoded SSZ."""
        return cls(
            public=PublicKey.decode_bytes(bytes.fromhex(data["public"])),
            secret=SecretKey.decode_bytes(bytes.fromhex(data["secret"])),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialize to JSON-compatible dict with hex-encoded SSZ."""
        return {
            "public": self.public.encode_bytes().hex(),
            "secret": self.secret.encode_bytes().hex(),
        }

    def with_secret(self, secret: SecretKey) -> KeyPair:
        """Return a new KeyPair with updated secret key (for state advancement)."""
        return KeyPair(public=self.public, secret=secret)


def _get_keys_dir(scheme_name: str) -> Path:
    """Get the keys directory path for the given scheme."""
    return Path(__file__).parent / "test_keys" / f"{scheme_name}_scheme"


@cache
def load_keys(scheme_name: str) -> dict[Uint64, KeyPair]:
    """
    Load pre-generated keys from disk (cached after first call).

    Args:
        scheme_name: Name of the signature scheme.

    Returns:
        Mapping from validator index to key pair.

    Raises:
        FileNotFoundError: If keys directory is missing.
    """
    keys_dir = _get_keys_dir(scheme_name)

    if not keys_dir.exists():
        raise FileNotFoundError(
            f"Keys directory not found: {keys_dir} - "
            f"Run: python -m consensus_testing.keys --scheme {scheme_name}"
        )

    # Load all keypair files from the directory
    result = {}
    for key_file in sorted(keys_dir.glob("*.json")):
        # Extract validator index from filename (e.g., "0.json" -> 0)
        validator_idx = Uint64(int(key_file.stem))
        data = json.loads(key_file.read_text())
        result[validator_idx] = KeyPair.from_dict(data)

    if not result:
        raise FileNotFoundError(
            f"No key files found in: {keys_dir} - "
            f"Run: python -m consensus_testing.keys --scheme {scheme_name}"
        )

    return result


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
        >>> mgr.sign_attestation(attestation)  # Sign with auto-advancement
    """

    def __init__(
        self,
        max_slot: Slot,
        scheme: GeneralizedXmssScheme,
    ) -> None:
        """Initialize the manager with optional custom configuration."""
        self.max_slot = max_slot
        self.scheme = scheme
        self._state: dict[Uint64, KeyPair] = {}

        for scheme_name, scheme_obj in LEAN_ENV_TO_SCHEMES.items():
            if scheme_obj is scheme:
                self.scheme_name = scheme_name

    @property
    def keys(self) -> dict[Uint64, KeyPair]:
        """Lazy access to immutable base keys."""
        return load_keys(self.scheme_name)

    def __getitem__(self, idx: Uint64) -> KeyPair:
        """Get key pair, returning advanced state if available."""
        if idx in self._state:
            return self._state[idx]
        if idx not in self.keys:
            raise KeyError(f"Validator {idx} not found (max: {len(self.keys) - 1})")
        return self.keys[idx]

    def __contains__(self, idx: Uint64) -> bool:
        """Check if validator index exists."""
        return idx in self.keys

    def __len__(self) -> int:
        """Number of available validators."""
        return len(self.keys)

    def __iter__(self) -> Iterator[Uint64]:
        """Iterate over validator indices."""
        return iter(self.keys)

    def get_public_key(self, idx: Uint64) -> PublicKey:
        """Get a validator's public key."""
        return self[idx].public

    def get_all_public_keys(self) -> dict[Uint64, PublicKey]:
        """Get all public keys (from base keys, not advanced state)."""
        return {idx: kp.public for idx, kp in self.keys.items()}

    def sign_attestation(self, attestation: Attestation) -> Signature:
        """
        Sign an attestation with automatic key state advancement.

        XMSS is stateful: signing advances the internal key state.
        This method handles advancement transparently.

        Args:
            attestation: The attestation to sign.

        Returns:
            XMSS signature.

        Raises:
            ValueError: If slot exceeds key lifetime.
        """
        idx = attestation.validator_id
        epoch = attestation.data.slot
        kp = self[idx]
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
        self._state[idx] = kp.with_secret(sk)

        # Sign hash tree root
        message = bytes(hash_tree_root(attestation))
        return self.scheme.sign(sk, epoch, message)


def _generate_single_keypair(
    scheme: GeneralizedXmssScheme, num_epochs: int, _idx: int
) -> dict[str, str]:
    """Generate one key pair (module-level for pickling in ProcessPoolExecutor)."""
    pk, sk = scheme.key_gen(Uint64(0), Uint64(num_epochs))
    return KeyPair(public=pk, secret=sk).to_dict()


def _generate_keys(lean_env: str, count: int, max_slot: int) -> None:
    """
    Generate XMSS key pairs in parallel and save to individual files.

    Uses ProcessPoolExecutor to saturate CPU cores for faster generation.
    Each keypair is saved to a separate file for better manageability.

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
    load_keys.cache_clear()


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
    load_keys.cache_clear()
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
