"""
Data containers for the Generalized XMSS signature scheme.

This module defines the high-level containers: PublicKey, Signature, and SecretKey.
Base types (HashDigestVector, Parameter, etc.) are defined in types.py.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import NamedTuple, override

from pydantic import model_serializer

from lean_spec.forks.lstar.containers.slot import Slot

from ...types import Uint64
from ...types.container import Container
from .constants import TARGET_CONFIG
from .subtree import HashSubTree
from .types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    PRFKey,
    Randomness,
)


class PublicKey(Container):
    """
    The public-facing component of a key pair.

    This is the data a verifier needs to check signatures. It is compact, safe to
    distribute publicly, and acts as the signer's identity.

    SSZ Container with fields:
    - root: Vector[Fp, HASH_LEN_FE]
    - parameter: Vector[Fp, PARAMETER_LEN]

    Serialization is handled automatically by SSZ.
    """

    root: HashDigestVector
    """The Merkle root, which commits to all one-time keys for the key's lifetime."""
    parameter: Parameter
    """The public parameter `P` that personalizes the hash function."""


class Signature(Container):
    """
    A signature produced by the `sign` function.

    It contains all the necessary components for a verifier to confirm that a
    specific message was signed by the owner of a `PublicKey` for a specific slot.

    SSZ Container with fields:
    - path: HashTreeOpening (container with siblings list)
    - rho: Vector[Fp, RAND_LEN_FE]
    - hashes: List[Vector[Fp, HASH_DIGEST_LENGTH], NODE_LIST_LIMIT]

    Although the fields are internally variable-size SSZ types, every valid
    signature serializes to exactly `SIGNATURE_LEN_BYTES`. This class overrides
    `is_fixed_size()` to report as fixed-size so that parent containers treat
    it as an opaque byte blob. This avoids leaking internal structure (field
    count, offset layout) into the wire format, keeping the signature scheme
    an implementation detail that can evolve independently.
    """

    path: HashTreeOpening
    """The authentication path proving the one-time key's inclusion in the Merkle tree."""
    rho: Randomness
    """The randomness used to successfully encode the message."""
    hashes: HashDigestList
    """The one-time signature itself: a list of intermediate Winternitz chain hashes."""

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """
        Report as fixed-size for cross-client SSZ interoperability.

        Ream serializes XMSS signatures as `FixedBytes<3112>`, so parent
        containers must inline the bytes without an offset pointer.
        """
        return True

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """Return the fixed byte length of the SSZ-encoded signature."""
        return TARGET_CONFIG.SIGNATURE_LEN_BYTES

    @model_serializer(mode="plain", when_used="json")
    def _serialize_as_bytes(self) -> str:
        """Serialize as hex-encoded SSZ bytes for JSON output."""
        return "0x" + self.encode_bytes().hex()


class SecretKey(Container):
    """
    The private component of a key pair. **MUST BE KEPT CONFIDENTIAL.**

    This object contains all the secret material and pre-computed data needed to
    generate signatures for any slot within its active lifetime.

    SSZ Container with fields:
    - prf_key: Bytes[PRF_KEY_LENGTH]
    - parameter: Vector[Fp, PARAMETER_LEN]
    - activation_slot: uint64
    - num_active_slots: uint64
    - top_tree: HashSubTree
    - left_bottom_tree_index: uint64
    - left_bottom_tree: HashSubTree
    - right_bottom_tree: HashSubTree

    Serialization is handled automatically by SSZ.
    """

    prf_key: PRFKey
    """The master secret key used to derive all one-time secrets."""

    parameter: Parameter
    """The public parameter `P`, stored for convenience during signing."""

    activation_slot: Slot
    """
    The first slot for which this secret key is valid.

    Note: With top-bottom trees, this is aligned to a multiple of `sqrt(LIFETIME)`
    to ensure efficient tree partitioning.
    """

    num_active_slots: Uint64
    """
    The number of consecutive slots this key can be used for.

    Note: With top-bottom trees, this is rounded up to be a multiple of
    `sqrt(LIFETIME)`, with a minimum of `2 * sqrt(LIFETIME)`.
    """

    top_tree: HashSubTree
    """
    The top tree containing the root and top `LOG_LIFETIME/2` layers.

    This tree is always kept in memory and contains the roots of all bottom trees
    in its lowest layer. Its root is the public key's Merkle root.
    """

    left_bottom_tree_index: Uint64
    """
    The index of the left bottom tree in the sliding window.

    Bottom trees are numbered 0, 1, 2, ... where tree `i` covers slots
    `[i * sqrt(LIFETIME), (i+1) * sqrt(LIFETIME))`.

    The prepared interval is:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    """

    left_bottom_tree: HashSubTree
    """
    The left bottom tree in the sliding window.

    This covers slots:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 1) * sqrt(LIFETIME))
    """

    right_bottom_tree: HashSubTree
    """
    The right bottom tree in the sliding window.

    This covers slots:
    [(left_bottom_tree_index + 1) * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    Together with `left_bottom_tree`, this provides a prepared interval of
    exactly `2 * sqrt(LIFETIME)` consecutive slots.
    """


class KeyPair(NamedTuple):
    """
    Immutable XMSS key pair produced by key generation.

    Used at the scheme level for a single public/secret pair.
    """

    public: PublicKey
    secret: SecretKey


class ValidatorKeyPair(NamedTuple):
    """
    Immutable dual XMSS key pair for a validator.

    Attestation and proposal keys are separate to allow independent signing
    within the same slot. OTS requires a distinct key for each signing purpose.
    """

    attestation_public: PublicKey
    attestation_secret: SecretKey
    proposal_public: PublicKey
    proposal_secret: SecretKey

    @classmethod
    def from_dict(cls, data: Mapping[str, str]) -> ValidatorKeyPair:
        """Deserialize from JSON-compatible dict with hex-encoded SSZ."""
        return cls(
            attestation_public=PublicKey.decode_bytes(bytes.fromhex(data["attestation_public"])),
            attestation_secret=SecretKey.decode_bytes(bytes.fromhex(data["attestation_secret"])),
            proposal_public=PublicKey.decode_bytes(bytes.fromhex(data["proposal_public"])),
            proposal_secret=SecretKey.decode_bytes(bytes.fromhex(data["proposal_secret"])),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialize to JSON-compatible dict with hex-encoded SSZ."""
        return {
            "attestation_public": self.attestation_public.encode_bytes().hex(),
            "attestation_secret": self.attestation_secret.encode_bytes().hex(),
            "proposal_public": self.proposal_public.encode_bytes().hex(),
            "proposal_secret": self.proposal_secret.encode_bytes().hex(),
        }
