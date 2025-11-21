"""Defines the data containers for the Generalized XMSS signature scheme."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, List, Tuple

from pydantic import Field

from ...types import StrictBaseModel
from ..koalabear import P_BYTES, Fp
from . import bincode
from .constants import PRF_KEY_LENGTH

if TYPE_CHECKING:
    from .constants import XmssConfig
    from .subtree import HashSubTree

PRFKey = Annotated[bytes, Field(min_length=PRF_KEY_LENGTH, max_length=PRF_KEY_LENGTH)]
"""
A type alias for the PRF **master secret key**.

This is a high-entropy byte string that acts as the single root secret from
which all one-time signing keys are deterministically derived.
"""


HashDigest = List[Fp]
"""
A type alias representing a hash digest.

In this scheme, a digest is the output of the Poseidon2 hash function. It is a
fixed-length list of field elements (`Fp`) and serves as the fundamental
building block for all cryptographic structures (e.g., a node in a Merkle tree).
"""

Parameter = List[Fp]
"""
A type alias for the public parameter `P`.

This is a unique, randomly generated value associated with a single key pair. It
is mixed into every hash computation to "personalize" the hash function, preventing
certain cross-key attacks. It is public knowledge.
"""

Randomness = List[Fp]
"""
A type alias for the randomness `rho` (ρ) used during signing.

This value provides a variable input to the message hash, allowing the signer to
repeatedly try hashing until a valid "codeword" is found. It must be included in
the final signature for the verifier to reproduce the same hash.
"""


def _serialize_digests(digests: List[HashDigest]) -> bytes:
    """
    Serialize a list of hash digests.

    Each digest is a list of field elements.
    """
    return b"".join(Fp.serialize_list(digest) for digest in digests)


def _deserialize_digests(data: bytes, count: int, elements_per_digest: int) -> List[HashDigest]:
    """
    Deserialize multiple hash digests from bytes.

    Args:
        data: Raw bytes to deserialize.
        count: Number of digests.
        elements_per_digest: Field elements per digest.

    Returns:
        List of hash digests.

    Raises:
        ValueError: If data length doesn't match expectations.
    """
    total_elements = count * elements_per_digest
    all_elements = Fp.deserialize_list(data, total_elements)

    return [
        all_elements[i : i + elements_per_digest]
        for i in range(0, len(all_elements), elements_per_digest)
    ]


class HashTreeOpening(StrictBaseModel):
    """
    A Merkle authentication path.

    This object contains the minimal proof required to connect a specific leaf
    to the Merkle root. It consists of the list of all sibling nodes along the
    path from the leaf to the top of the tree.
    """

    siblings: List[HashDigest]
    """List of sibling hashes, from bottom to top."""


class HashTreeLayer(StrictBaseModel):
    """
    Represents a single horizontal "slice" of the sparse Merkle tree.

    Because the tree is sparse, we only store the nodes that are actually computed
    for the active range of leaves, not the entire conceptual layer.
    """

    start_index: int
    """The starting index of the first node in this layer."""
    nodes: List[HashDigest]
    """A list of the actual hash digests stored for this layer."""


class HashTree(StrictBaseModel):
    """
    A simple representation of a sparse Merkle tree.

    This structure contains the necessary nodes to generate an authentication path
    for any signature within a key's active lifetime. For production use with
    long lifetimes, prefer `HashSubTree` with the top-bottom tree approach.
    """

    depth: int
    """The total depth of the tree (e.g., 32 for a 2^32 leaf space)."""
    layers: List[HashTreeLayer]
    """
    A list of `HashTreeLayer` objects, from the leaf hashes
    (layer 0) up to the layer just below the root.
    """


class PublicKey(StrictBaseModel):
    """
    The public-facing component of a key pair.

    This is the data a verifier needs to check signatures. It is compact, safe to
    distribute publicly, and acts as the signer's identity.

    Binary Format
    -------------
    The serialized format concatenates:
    1. Merkle root (`HASH_LEN_FE` field elements)
    2. Public parameter (`PARAMETER_LEN` field elements)

    All field elements are serialized in little-endian byte order.
    """

    root: List[Fp]
    """The Merkle root, which commits to all one-time keys for the key's lifetime."""
    parameter: Parameter
    """The public parameter `P` that personalizes the hash function."""

    def __bytes__(self) -> bytes:
        """
        Serialize using Python's bytes protocol.

        Format: root || parameter (concatenated field elements).

        Example:
            >>> pk = PublicKey(root=[Fp(value=0)] * 8, parameter=[Fp(value=1)] * 5)
            >>> data = bytes(pk)
            >>> isinstance(data, bytes)
            True
        """
        return Fp.serialize_list(self.root) + Fp.serialize_list(self.parameter)

    def to_bytes(self, config: XmssConfig) -> bytes:
        """
        Serialize with validation against configuration.

        This validates field lengths match the expected configuration before
        serialization, providing better error messages for invalid keys.

        Args:
            config: XMSS configuration for validation.

        Returns:
            Binary representation of the public key.

        Raises:
            ValueError: If field lengths don't match configuration.
        """
        if len(self.root) != config.HASH_LEN_FE:
            raise ValueError(
                f"Invalid root length: expected {config.HASH_LEN_FE}, got {len(self.root)}"
            )

        if len(self.parameter) != config.PARAMETER_LEN:
            raise ValueError(
                f"Invalid parameter length: expected {config.PARAMETER_LEN}, "
                f"got {len(self.parameter)}"
            )

        return bytes(self)

    @classmethod
    def from_bytes(cls, data: bytes, config: XmssConfig) -> PublicKey:
        """
        Deserialize a public key from bytes.

        Args:
            data: Binary representation of a public key.
            config: The XMSS configuration defining field lengths.

        Returns:
            Deserialized PublicKey instance.

        Raises:
            ValueError: If the data has incorrect length or format.

        Example:
            >>> data = bytes(PROD_CONFIG.PUBLIC_KEY_LEN_BYTES)
            >>> pk = PublicKey.from_bytes(data, PROD_CONFIG)
            >>> isinstance(pk, PublicKey)
            True
        """
        expected_length = config.PUBLIC_KEY_LEN_BYTES

        if len(data) != expected_length:
            raise ValueError(
                f"Invalid public key length: expected {expected_length} bytes "
                f"({config.HASH_LEN_FE} root + {config.PARAMETER_LEN} parameter "
                f"× {P_BYTES} bytes each), got {len(data)} bytes"
            )

        # Parse: root || parameter
        root_len = config.HASH_LEN_FE * P_BYTES
        root = Fp.deserialize_list(data[:root_len], config.HASH_LEN_FE)
        parameter = Fp.deserialize_list(data[root_len:], config.PARAMETER_LEN)

        return cls(root=root, parameter=parameter)

    def to_bincode_bytes(self, config: XmssConfig) -> bytes:
        """
        Serialize the public key to bincode-compatible bytes.

        This method produces bytes compatible with Rust's bincode serialization format.

        Args:
            config: The XMSS configuration for validation.

        Returns:
            Bincode-compatible binary representation.

        Raises:
            ValueError: If field lengths don't match configuration.
        """
        if len(self.root) != config.HASH_LEN_FE:
            raise ValueError(f"Invalid root length: {len(self.root)}")
        if len(self.parameter) != config.PARAMETER_LEN:
            raise ValueError(f"Invalid parameter length: {len(self.parameter)}")

        # Both fields are fixed arrays with varint-encoded field elements
        root_bytes = Fp.serialize_fixed_array_bincode(self.root)
        param_bytes = Fp.serialize_fixed_array_bincode(self.parameter)
        return root_bytes + param_bytes

    @classmethod
    def from_bincode_bytes(cls, data: bytes, config: XmssConfig) -> PublicKey:
        """
        Deserialize a public key from bincode-compatible bytes.

        This method can read bytes produced by Rust's bincode serialization.

        Args:
            data: Bincode binary representation of a public key.
            config: The XMSS configuration defining field lengths.

        Returns:
            Deserialized PublicKey instance.

        Raises:
            ValueError: If the data has incorrect format.
        """
        offset = 0

        # 1. root: [F; HASH_LEN] - fixed array with varint-encoded Fp
        root, consumed = Fp.deserialize_fixed_array_bincode(data, offset, config.HASH_LEN_FE)
        offset += consumed

        # 2. parameter: [F; PARAMETER_LEN] - fixed array with varint-encoded Fp
        parameter, consumed = Fp.deserialize_fixed_array_bincode(data, offset, config.PARAMETER_LEN)
        offset += consumed

        if offset != len(data):
            raise ValueError(f"Extra bytes in bincode data: {len(data) - offset}")

        return cls(root=root, parameter=parameter)


class Signature(StrictBaseModel):
    """
    A signature produced by the `sign` function.

    It contains all the necessary components for a verifier to confirm that a
    specific message was signed by the owner of a `PublicKey` for a specific epoch.

    All field elements are serialized in little-endian byte order.
    """

    path: HashTreeOpening
    """The authentication path proving the one-time key's inclusion in the Merkle tree."""
    rho: Randomness
    """The randomness used to successfully encode the message."""
    hashes: List[HashDigest]
    """The one-time signature itself: a list of intermediate Winternitz chain hashes."""

    def __bytes__(self) -> bytes:
        """
        Serialize using Python's bytes protocol.

        Format: path siblings || rho || hashes (concatenated field elements).
        """
        return (
            _serialize_digests(self.path.siblings)
            + Fp.serialize_list(self.rho)
            + _serialize_digests(self.hashes)
        )

    def to_bytes(self, config: XmssConfig) -> bytes:
        """
        Serialize the signature to bytes with validation.

        Args:
            config: The XMSS configuration defining field lengths.

        Returns:
            Binary representation of the signature.

        Raises:
            ValueError: If any component has incorrect length.
        """
        # Validate Merkle path
        if len(self.path.siblings) != config.LOG_LIFETIME:
            raise ValueError(
                f"Invalid path length: expected {config.LOG_LIFETIME} siblings, "
                f"got {len(self.path.siblings)}"
            )

        for i, sibling in enumerate(self.path.siblings):
            if len(sibling) != config.HASH_LEN_FE:
                raise ValueError(
                    f"Invalid sibling {i} length: expected {config.HASH_LEN_FE} elements, "
                    f"got {len(sibling)}"
                )

        # Validate randomness
        if len(self.rho) != config.RAND_LEN_FE:
            raise ValueError(
                f"Invalid rho length: expected {config.RAND_LEN_FE} elements, got {len(self.rho)}"
            )

        # Validate OTS hashes
        if len(self.hashes) != config.DIMENSION:
            raise ValueError(
                f"Invalid hashes length: expected {config.DIMENSION} hashes, got {len(self.hashes)}"
            )

        for i, hash_digest in enumerate(self.hashes):
            if len(hash_digest) != config.HASH_LEN_FE:
                raise ValueError(
                    f"Invalid hash {i} length: expected {config.HASH_LEN_FE} elements, "
                    f"got {len(hash_digest)}"
                )

        return bytes(self)

    @classmethod
    def from_bytes(cls, data: bytes, config: XmssConfig) -> Signature:
        """
        Deserialize a signature from bytes.

        Args:
            data: Binary representation of a signature.
            config: The XMSS configuration defining field lengths.

        Returns:
            Deserialized Signature instance.

        Raises:
            ValueError: If the data has incorrect length or format.
        """
        expected_length = config.SIGNATURE_LEN_BYTES

        if len(data) != expected_length:
            raise ValueError(
                f"Invalid signature length: expected {expected_length} bytes, got {len(data)} bytes"
            )

        # Calculate section sizes
        path_size = config.LOG_LIFETIME * config.HASH_LEN_FE * P_BYTES
        rho_size = config.RAND_LEN_FE * P_BYTES

        # Parse: path siblings || rho || hashes
        offset = 0
        path_data = data[offset : offset + path_size]
        offset += path_size
        rho_data = data[offset : offset + rho_size]
        offset += rho_size
        hashes_data = data[offset:]

        # Deserialize components
        siblings = _deserialize_digests(
            path_data,
            count=config.LOG_LIFETIME,
            elements_per_digest=config.HASH_LEN_FE,
        )
        rho = Fp.deserialize_list(rho_data, count=config.RAND_LEN_FE)
        hashes = _deserialize_digests(
            hashes_data,
            count=config.DIMENSION,
            elements_per_digest=config.HASH_LEN_FE,
        )

        return cls(
            path=HashTreeOpening(siblings=siblings),
            rho=rho,
            hashes=hashes,
        )

    def to_bincode_bytes(self, config: XmssConfig) -> bytes:
        """
        Serialize the signature to bincode-compatible bytes.

        Args:
            config: The XMSS configuration defining field lengths.

        Returns:
            Bincode-compatible binary representation.

        Raises:
            ValueError: If any component has incorrect length.
        """
        # Validate (same as to_bytes)
        if len(self.path.siblings) != config.LOG_LIFETIME:
            raise ValueError(
                f"Invalid path length: expected {config.LOG_LIFETIME} siblings, "
                f"got {len(self.path.siblings)}"
            )

        for i, sibling in enumerate(self.path.siblings):
            if len(sibling) != config.HASH_LEN_FE:
                raise ValueError(
                    f"Invalid sibling {i} length: expected {config.HASH_LEN_FE} elements, "
                    f"got {len(sibling)}"
                )

        if len(self.rho) != config.RAND_LEN_FE:
            raise ValueError(
                f"Invalid rho length: expected {config.RAND_LEN_FE} elements, got {len(self.rho)}"
            )

        if len(self.hashes) != config.DIMENSION:
            raise ValueError(
                f"Invalid hashes length: expected {config.DIMENSION} hashes, got {len(self.hashes)}"
            )

        for i, hash_digest in enumerate(self.hashes):
            if len(hash_digest) != config.HASH_LEN_FE:
                raise ValueError(
                    f"Invalid hash {i} length: expected {config.HASH_LEN_FE} elements, "
                    f"got {len(hash_digest)}"
                )

        # Serialize with bincode format:
        # 1. path.siblings: Vec<[F; HASH_LEN]> - varint length + varint-encoded arrays
        path_bytes = bincode.serialize_vec(self.path.siblings, Fp.serialize_fixed_array_bincode)

        # 2. rho: [F; RAND_LEN] - fixed-size array with varint-encoded Fp, no length prefix
        rho_bytes = Fp.serialize_fixed_array_bincode(self.rho)

        # 3. hashes: Vec<[F; HASH_LEN]> - varint length + varint-encoded arrays
        hashes_bytes = bincode.serialize_vec(self.hashes, Fp.serialize_fixed_array_bincode)

        return path_bytes + rho_bytes + hashes_bytes

    @classmethod
    def from_bincode_bytes(cls, data: bytes, config: XmssConfig) -> Signature:
        """
        Deserialize a signature from bincode-compatible bytes.

        This method can read bytes produced by Rust's bincode serialization.

        Args:
            data: Bincode binary representation of a signature.
            config: The XMSS configuration defining field lengths.

        Returns:
            Deserialized Signature instance.

        Raises:
            ValueError: If the data has incorrect format.
        """
        offset = 0

        # Helper to deserialize [F; HASH_LEN] with varint-encoded Fp
        def deserialize_digest_fixed(data: bytes, offset: int) -> Tuple[List[Fp], int]:
            return Fp.deserialize_fixed_array_bincode(data, offset, config.HASH_LEN_FE)

        # 1. Deserialize path.siblings: Vec<[F; HASH_LEN]>
        siblings, siblings_consumed = bincode.deserialize_vec(
            data, offset, deserialize_digest_fixed
        )
        offset += siblings_consumed

        # Validate siblings count
        if len(siblings) != config.LOG_LIFETIME:
            raise ValueError(
                f"Invalid path length: expected {config.LOG_LIFETIME} siblings, got {len(siblings)}"
            )

        # 2. Deserialize rho: [F; RAND_LEN] (fixed-size array with varint Fp, no length prefix)
        rho, consumed = Fp.deserialize_fixed_array_bincode(data, offset, config.RAND_LEN_FE)
        offset += consumed

        # 3. Deserialize hashes: Vec<[F; HASH_LEN]>
        hashes, hashes_consumed = bincode.deserialize_vec(data, offset, deserialize_digest_fixed)
        offset += hashes_consumed

        # Validate hashes count
        if len(hashes) != config.DIMENSION:
            raise ValueError(
                f"Invalid hashes length: expected {config.DIMENSION} hashes, got {len(hashes)}"
            )

        # Validate we consumed all data
        if offset != len(data):
            raise ValueError(
                f"Signature has extra bytes: consumed {offset} bytes, got {len(data)} bytes"
            )

        return cls(
            path=HashTreeOpening(siblings=siblings),
            rho=rho,
            hashes=hashes,
        )


class SecretKey(StrictBaseModel):
    """
    The private component of a key pair. **MUST BE KEPT CONFIDENTIAL.**

    This object contains all the secret material and pre-computed data needed to
    generate signatures for any epoch within its active lifetime.
    """

    prf_key: PRFKey
    """The master secret key used to derive all one-time secrets."""

    parameter: Parameter
    """The public parameter `P`, stored for convenience during signing."""

    activation_epoch: int
    """
    The first epoch for which this secret key is valid.

    Note: With top-bottom trees, this is aligned to a multiple of `sqrt(LIFETIME)`
    to ensure efficient tree partitioning.
    """

    num_active_epochs: int
    """
    The number of consecutive epochs this key can be used for.

    Note: With top-bottom trees, this is rounded up to be a multiple of
    `sqrt(LIFETIME)`, with a minimum of `2 * sqrt(LIFETIME)`.
    """

    top_tree: HashSubTree | None = None
    """
    The top tree containing the root and top `LOG_LIFETIME/2` layers.

    This tree is always kept in memory and contains the roots of all bottom trees
    in its lowest layer. Its root is the public key's Merkle root.
    """

    left_bottom_tree_index: int | None = None
    """
    The index of the left bottom tree in the sliding window.

    Bottom trees are numbered 0, 1, 2, ... where tree `i` covers epochs
    `[i * sqrt(LIFETIME), (i+1) * sqrt(LIFETIME))`.

    The prepared interval is:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    """

    left_bottom_tree: HashSubTree | None = None
    """
    The left bottom tree in the sliding window.

    This covers epochs:
    [left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 1) * sqrt(LIFETIME))
    """

    right_bottom_tree: HashSubTree | None = None
    """
    The right bottom tree in the sliding window.

    This covers epochs:
    [(left_bottom_tree_index + 1) * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))

    Together with `left_bottom_tree`, this provides a prepared interval of
    exactly `2 * sqrt(LIFETIME)` consecutive epochs.
    """
