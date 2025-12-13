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
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Self

from lean_spec.subspecs.containers import AttestationData
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
    NaiveAggregatedSignature,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey, Signature
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import Uint64

if TYPE_CHECKING:
    from collections.abc import Mapping


KEYS_FILE = Path(__file__).parent / "test_keys.json"
"""Path to the pre-generated keys file."""

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


@cache
def load_keys() -> dict[Uint64, KeyPair]:
    """
    Load pre-generated keys from disk (cached after first call).

    Returns:
        Mapping from validator index to key pair.

    Raises:
        FileNotFoundError: If keys file is missing.
    """
    if not KEYS_FILE.exists():
        raise FileNotFoundError(
            f"Keys not found: {KEYS_FILE}\nRun: python -m consensus_testing.keys"
        )
    data = json.loads(KEYS_FILE.read_text())
    return {Uint64(i): KeyPair.from_dict(kp) for i, kp in enumerate(data)}


class XmssKeyManager:
    """
    Stateful manager for XMSS signing operations.

    Handles automatic key state advancement for the stateful XMSS scheme.

    Keys are lazily loaded from disk on first access.

    Args:
        max_slot: Maximum slot for signatures. Defaults to DEFAULT_MAX_SLOT.
        scheme: XMSS scheme instance. Defaults to TEST_SIGNATURE_SCHEME.

    Examples:
        >>> mgr = XmssKeyManager()
        >>> mgr[Uint64(0)]  # Get key pair
        >>> mgr.get_public_key(Uint64(1))  # Get public key only
        >>> mgr.sign_attestation_data(validator_id, attestation_data)  # Sign with auto-advancement
    """

    def __init__(
        self,
        max_slot: Slot | None = None,
        scheme: GeneralizedXmssScheme = TEST_SIGNATURE_SCHEME,
    ) -> None:
        """Initialize the manager with optional custom configuration."""
        self.max_slot = max_slot or DEFAULT_MAX_SLOT
        self.scheme = scheme
        self._state: dict[Uint64, KeyPair] = {}

    @property
    def keys(self) -> dict[Uint64, KeyPair]:
        """Lazy access to immutable base keys."""
        return load_keys()

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

    def sign_attestation_data(
        self,
        validator_id: Uint64,
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
        self._state[validator_id] = kp.with_secret(sk)

        # Sign hash tree root of the attestation data
        message = bytes(hash_tree_root(attestation_data))
        return self.scheme.sign(sk, epoch, message)

    def build_attestation_signatures(
        self,
        aggregated_attestations: AggregatedAttestations,
        signature_lookup: Mapping[tuple[Uint64, bytes], Signature] | None = None,
    ) -> AttestationSignatures:
        """
        Build `AttestationSignatures` for already-aggregated attestations.

        This is a convenience helper for tests/fixtures that need to produce
        `BlockSignatures.attestation_signatures` for a block.

        Args:
            aggregated_attestations: Iterable of aggregated attestation containers.
                Each item is expected to have:
                - `.data` (AttestationData)
                - `.aggregation_bits.to_validator_indices()` (Iterable[Uint64])
            signature_lookup: Optional override map keyed by
                `(validator_id, bytes(hash_tree_root(attestation_data))) -> signature`.
                When provided and a key exists, that signature is used instead of signing.

        Returns:
            AttestationSignatures matching the ordering of `aggregated_attestations`
            and per-attestation validator index ordering.
        """
        return AttestationSignatures(
            data=[
                NaiveAggregatedSignature(
                    data=[
                        (
                            signature_lookup.get(
                                (validator_id, aggregated_attestation.data.data_root_bytes())
                            )
                            if signature_lookup is not None
                            else None
                        )
                        or self.sign_attestation_data(validator_id, aggregated_attestation.data)
                        for validator_id in (
                            aggregated_attestation.aggregation_bits.to_validator_indices()
                        )
                    ]
                )
                for aggregated_attestation in aggregated_attestations
            ]
        )


def _generate_single_keypair(num_epochs: int) -> dict[str, str]:
    """Generate one key pair (module-level for pickling in ProcessPoolExecutor)."""
    pk, sk = TEST_SIGNATURE_SCHEME.key_gen(Uint64(0), Uint64(num_epochs))
    return KeyPair(public=pk, secret=sk).to_dict()


def generate_keys(count: int = NUM_VALIDATORS, max_slot: int = int(DEFAULT_MAX_SLOT)) -> None:
    """
    Generate XMSS key pairs in parallel and save atomically.

    Uses ProcessPoolExecutor to saturate CPU cores for faster generation.
    Writes to a temp file then renames for crash safety.

    Args:
        count: Number of validators.
        max_slot: Maximum slot (key lifetime = max_slot + 1 epochs).
    """
    num_epochs = max_slot + 1
    num_workers = os.cpu_count() or 1

    print(f"Generating {count} XMSS key pairs ({num_epochs} epochs) using {num_workers} cores...")

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        key_pairs = list(executor.map(_generate_single_keypair, [num_epochs] * count))

    # Atomic write: temp file -> rename
    fd, temp_path = tempfile.mkstemp(suffix=".json", dir=KEYS_FILE.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(key_pairs, f, indent=2)
        Path(temp_path).replace(KEYS_FILE)
    except Exception:
        Path(temp_path).unlink(missing_ok=True)
        raise

    print(f"Saved {len(key_pairs)} key pairs to {KEYS_FILE}")

    # Clear cache so new keys are loaded
    load_keys.cache_clear()


def main() -> None:
    """CLI entry point for key generation."""
    parser = argparse.ArgumentParser(
        description="Generate XMSS key pairs for consensus testing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
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

    generate_keys(count=args.count, max_slot=args.max_slot)


if __name__ == "__main__":
    main()
