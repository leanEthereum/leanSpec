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
    Keys are stored as hex-encoded SSZ in JSON:
    [{"public": "0a1b...", "secret": "2c3d..."}, ...]
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
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

# Signature scheme definitions
SIGNATURE_SCHEMES = {
    "test": TEST_SIGNATURE_SCHEME,
    "prod": PROD_SIGNATURE_SCHEME,
}
"""
Mapping from short name to scheme objects. This mapping is useful for:
- The CLI argument for choosing the signature scheme to generate
- Deriving the file name for the cached keys
- Caching key managers in test fixtures
"""

NUM_VALIDATORS = 12
"""Default number of validator key pairs."""

DEFAULT_MAX_SLOT = Slot(100)
"""Maximum slot for test signatures (inclusive)."""

NUM_ACTIVE_EPOCHS = int(DEFAULT_MAX_SLOT) + 1
"""Key lifetime in epochs (derived from DEFAULT_MAX_SLOT)."""


def get_current_signature_scheme() -> GeneralizedXmssScheme:
    """
    Get the current signature scheme from SIGNATURE_SCHEME environment variable.

    Returns:
        The current signature scheme for the test session (defaults to "test").

    Raises:
        ValueError: If SIGNATURE_SCHEME env var contains an invalid scheme name.
    """
    scheme_name = os.environ.get("SIGNATURE_SCHEME", "test").lower()
    scheme = SIGNATURE_SCHEMES.get(scheme_name)
    if scheme is None:
        raise ValueError(
            f"Invalid SIGNATURE_SCHEME: {scheme_name}. "
            f"Available signature schemes: {', '.join(SIGNATURE_SCHEMES.keys())}"
        )
    return scheme


def get_name_by_signature_scheme(scheme: GeneralizedXmssScheme) -> str:
    """
    Get the scheme name for a given scheme object.

    Args:
        scheme: The XMSS signature scheme.

    Returns:
        The scheme name string (e.g. "test" or "prod").

    Raises:
        ValueError: If the scheme is not recognized.
    """
    for scheme_name, scheme_obj in SIGNATURE_SCHEMES.items():
        if scheme_obj is scheme:
            return scheme_name
    raise ValueError(f"Unknown scheme: {scheme}")

@cache
def get_shared_key_manager() -> XmssKeyManager:
    """
    Get or create the shared XMSS key manager for reusing keys across tests.

    Uses functools.cache to create a singleton instance that's shared
    across all test fixture generations within a session. This optimizes
    performance by reusing keys when possible.

    The scheme is determined by the SIGNATURE_SCHEME environment variable.

    Returns:
        Shared XmssKeyManager instance with max_slot=10 for the current scheme.
    """
    scheme = get_current_signature_scheme()
    return XmssKeyManager(max_slot=Slot(10), scheme=scheme)


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


def _get_keys_file(scheme_name: str) -> Path:
    """Get the keys file path for the given scheme."""
    return Path(__file__).parent / f"{scheme_name}_keys.json"


@cache
def load_keys(scheme_name: str) -> dict[Uint64, KeyPair]:
    """
    Load pre-generated keys from disk (cached after first call).

    Args:
        scheme_name: Name of the signature scheme.

    Returns:
        Mapping from validator index to key pair.

    Raises:
        FileNotFoundError: If keys file is missing.
    """
    keys_file = _get_keys_file(scheme_name)

    if not keys_file.exists():
        raise FileNotFoundError(
            f"Keys not found: {keys_file} - ",
            f"Run: python -m consensus_testing.keys --scheme {scheme_name}",
        )
    data = json.loads(keys_file.read_text())
    return {Uint64(i): KeyPair.from_dict(kp) for i, kp in enumerate(data)}


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

    @property
    def keys(self) -> dict[Uint64, KeyPair]:
        """Lazy access to immutable base keys."""
        scheme_name = get_name_by_signature_scheme(self.scheme)
        return load_keys(scheme_name)

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


def _generate_keys(scheme_name: str, count: int, max_slot: int) -> None:
    """
    Generate XMSS key pairs in parallel and save atomically.

    Uses ProcessPoolExecutor to saturate CPU cores for faster generation.
    Writes to a temp file then renames for crash safety.

    Args:
        scheme_name: Name of the XMSS signature scheme to use (e.g. "test" or "prod").
        count: Number of validators.
        max_slot: Maximum slot (key lifetime = max_slot + 1 epochs).
    """
    scheme = SIGNATURE_SCHEMES[scheme_name]
    keys_file = _get_keys_file(scheme_name)
    num_epochs = max_slot + 1
    num_workers = os.cpu_count() or 1

    print(
        f"Generating {count} XMSS key pairs for {scheme_name} scheme "
        f"({num_epochs} epochs) using {num_workers} cores..."
    )

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        worker_func = partial(_generate_single_keypair, scheme, num_epochs)
        key_pairs = list(executor.map(worker_func, range(count)))

    # Atomic write: temp file -> rename
    fd, temp_path = tempfile.mkstemp(suffix=".json", dir=keys_file.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(key_pairs, f, indent=2)
        Path(temp_path).replace(keys_file)
    except Exception:
        Path(temp_path).unlink(missing_ok=True)
        raise

    print(f"Saved {len(key_pairs)} key pairs to {keys_file}")

    # Clear cache so new keys are loaded
    load_keys.cache_clear()


def main() -> None:
    """CLI entry point for key generation."""
    parser = argparse.ArgumentParser(
        description="Generate XMSS key pairs for consensus testing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--scheme",
        choices=SIGNATURE_SCHEMES.keys(),
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

    _generate_keys(scheme_name=args.scheme, count=args.count, max_slot=args.max_slot)


if __name__ == "__main__":
    main()
