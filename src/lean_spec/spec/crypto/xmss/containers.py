"""Generalized XMSS containers."""

from typing import Self, override

from pydantic import model_serializer, model_validator

from lean_spec.base import StrictBaseModel
from lean_spec.spec.crypto.xmss.constants import TARGET_CONFIG
from lean_spec.spec.crypto.xmss.merkle import HashSubTree
from lean_spec.spec.crypto.xmss.prf import PRFKey
from lean_spec.spec.crypto.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    Randomness,
)
from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import Uint64
from lean_spec.spec.ssz.container import Container
from lean_spec.spec.ssz.exceptions import SSZSerializationError


class HexSerializedContainer(Container):
    """Container that serializes to a 0x-prefixed hex SSZ payload in JSON mode."""

    @model_serializer(mode="plain", when_used="json")
    def _serialize_as_hex(self) -> str:
        """Serialize as a 0x-prefixed hex string for JSON output."""
        return "0x" + self.encode_bytes().hex()


class PublicKey(HexSerializedContainer):
    """Long-lived public component of an XMSS key pair."""

    root: HashDigestVector
    """Merkle root over every one-time public key in the lifetime."""

    parameter: Parameter
    """Public personalization tag mixed into every hash."""


class Signature(HexSerializedContainer):
    """
    A single XMSS signature for one slot and message under one public key.

    # Fixed size on the wire

    Two fields hold variable-length lists at the type level:

    - the authentication path siblings,
    - the released Winternitz chain hashes.

    Yet every valid signature pins both lengths to scheme constants:

    - one sibling per tree level, so exactly LOG_LIFETIME siblings,
    - one released hash per chain, so exactly DIMENSION hashes.

    The encoded byte length is therefore the same constant for every signature.

    Inherited container decoding reads each list through an attacker-controlled
    offset, so distinct byte strings of equal length could otherwise decode to
    signatures whose lists hold the wrong number of digests.
    A post-construction check rejects any signature off these two lengths,
    so the fixed-size declaration holds and the SSZ root pins one encoding.
    """

    path: HashTreeOpening
    """Authentication path from the one-time key up to the Merkle root."""

    rho: Randomness
    """Randomness that succeeded in encoding the message to a valid codeword."""

    hashes: HashDigestList
    """Released Winternitz chain hashes that form the one-time signature."""

    @model_validator(mode="after")
    def _check_list_lengths(self) -> Self:
        """Pin the two variable-length lists to their scheme-constant counts."""
        sibling_count = len(self.path.siblings)
        if sibling_count != TARGET_CONFIG.LOG_LIFETIME:
            raise SSZSerializationError(
                f"Signature.path.siblings requires exactly {TARGET_CONFIG.LOG_LIFETIME} "
                f"siblings, got {sibling_count}"
            )

        hash_count = len(self.hashes)
        if hash_count != TARGET_CONFIG.DIMENSION:
            raise SSZSerializationError(
                f"Signature.hashes requires exactly {TARGET_CONFIG.DIMENSION} hashes, "
                f"got {hash_count}"
            )

        return self

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """Always fixed-size on the wire (see class docstring)."""
        return True

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """Fixed byte length of an SSZ-encoded signature."""
        return TARGET_CONFIG.SIGNATURE_LENGTH_BYTES

    def __hash__(self) -> int:
        """Content-deterministic hash via SSZ encoding."""
        return hash(self.encode_bytes())


class SecretKey(HexSerializedContainer):
    """
    Private state of an XMSS key pair.

    Must be kept confidential.

    # Tree layout

    - The one-time keys split into one top tree over many bottom trees.
    - Each bottom tree spans W = 2^(LOG_LIFETIME / 2) slots.
    - Bottom tree i covers the W slots starting at i times W.

    # Sliding window

    - The signer keeps the top tree resident plus two adjacent bottom trees.
    - That window can sign 2W consecutive slots.
    - Resident memory stays near the square root of the lifetime.
    """

    prf_key: PRFKey
    """Master secret seed.

    Every one-time key is derived from this.
    """

    parameter: Parameter
    """Public parameter mirrored here so signing is self-contained."""

    activation_slot: Slot
    """First slot this key can sign for.

    - Aligned down to a multiple of W.
    - Each bottom tree then covers exactly W slots.
    """

    num_active_slots: Uint64
    """Number of consecutive slots this key can sign for.

    - Rounded up to a multiple of W, with a minimum of 2W.
    - The prepared window then always fits.
    """

    top_tree: HashSubTree
    """
    Full top tree, always resident.

    - Its lowest layer holds the bottom-tree roots.
    - Its top layer is the public-key root.
    """

    left_bottom_tree_index: Uint64
    """
    Bottom-tree index i for the left half of the prepared window.

    - Tree i covers slots [i*W, (i+1)*W);
    - The window covers [i*W, (i+2)*W).
    """

    left_bottom_tree: HashSubTree
    """Bottom tree at index i, covering slots [i*W, (i+1)*W)."""

    right_bottom_tree: HashSubTree
    """Bottom tree at index i+1, covering slots [(i+1)*W, (i+2)*W)."""


class KeyPair(StrictBaseModel):
    """A single XMSS public/secret pair returned by key generation."""

    public_key: PublicKey
    """Public key."""

    secret_key: SecretKey
    """Secret key."""


class ValidatorKeyPair(StrictBaseModel):
    """
    Two independent XMSS key pairs for one validator's two signing roles.

    A validator signs two messages per slot:

    - one attestation, always,
    - one block proposal, only when chosen as proposer.

    A one-time signature exhausts a leaf.
    So one key cannot cover both roles in the same slot.
    Two independent pairs let each role sign from its own Winternitz chains.
    """

    attestation_keypair: KeyPair
    """Key pair used to sign attestation data."""

    proposal_keypair: KeyPair
    """Key pair used to sign proposed block roots."""
