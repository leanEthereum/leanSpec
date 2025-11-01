"""Defines the data containers for the Generalized XMSS signature scheme."""

from __future__ import annotations

from typing import Annotated, List

from pydantic import Field

from ...types import StrictBaseModel
from ..koalabear import Fp
from .constants import (
    FE_SIZE_BYTES,
    PRF_KEY_LENGTH,
    PROD_DIMENSION,
    PROD_HASH_LEN_FE,
    PROD_LOG_LIFETIME,
    PROD_PARAMETER_LEN,
    PROD_PUBKEY_SIZE_BYTES,
    PROD_RAND_LEN_FE,
    PROD_SIGNATURE_SIZE_BYTES,
    PUBKEY_PADDING_LENGTH,
    PUBKEY_SIZE_BYTES,
    SIGNATURE_PADDING_LENGTH,
    SIGNATURE_SIZE_BYTES,
    TEST_DIMENSION,
    TEST_HASH_LEN_FE,
    TEST_LOG_LIFETIME,
    TEST_PARAMETER_LEN,
    TEST_PUBKEY_SIZE_BYTES,
    TEST_RAND_LEN_FE,
    TEST_SIGNATURE_SIZE_BYTES,
)

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
    The pre-computed, stored portion of the sparse Merkle tree.

    This structure is part of the `SecretKey` and contains all the necessary nodes
    to generate an authentication path for any signature within the key's active lifetime.
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
    """

    root: List[Fp]
    """The Merkle root, which commits to all one-time keys for the key's lifetime."""
    parameter: Parameter
    """The public parameter `P` that personalizes the hash function."""

    def to_bytes(self) -> bytes:
        """
        Serialize the public key to a byte array.

        The serialization format is:
        1. root (HASH_LEN_FE field elements × _FE_SIZE_BYTES bytes)
        2. parameter (PARAMETER_LEN field elements × _FE_SIZE_BYTES bytes)

        Total: _PUBKEY_SIZE_BYTES bytes for PROD config

        Returns:
            A byte array of exactly _PUBKEY_SIZE_BYTES bytes.

        """
        result = bytearray()

        # Serialize root (HASH_LEN_FE field elements)
        for fe in self.root:
            result.extend(fe.value.to_bytes(FE_SIZE_BYTES, "little"))

        # Serialize parameter (PARAMETER_LEN field elements)
        for fe in self.parameter:
            result.extend(fe.value.to_bytes(FE_SIZE_BYTES, "little"))

        # Won't be called because both PROD and TEST pubkey sizes are the same
        if len(result) != PROD_PUBKEY_SIZE_BYTES and len(result) != TEST_PUBKEY_SIZE_BYTES:
            raise ValueError(
                f"Expected {PROD_PUBKEY_SIZE_BYTES} or {TEST_PUBKEY_SIZE_BYTES} bytes, "
                f"got {len(result)}"
            )

        if len(result) < PUBKEY_SIZE_BYTES:
            append_zero_bytes = b"\x00" * (PUBKEY_SIZE_BYTES - len(result))
            result.extend(append_zero_bytes)

        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        """
        Deserialize a public key from a byte array.

        Args:
            data: A byte array of exactly _PUBKEY_SIZE_BYTES bytes.

        Returns:
            The deserialized PublicKey object.

        Raises:
            ValueError: If the data is not the expected size.
        """
        if len(data) != PUBKEY_SIZE_BYTES:
            raise ValueError(
                f"Invalid public key length: expected {PUBKEY_SIZE_BYTES}, got {len(data)}"
            )

        # Won't be called because both PROD and TEST pubkey sizes are the same
        # Remove padding bytes if any
        if data[-PUBKEY_PADDING_LENGTH:] == b"\x00" * PUBKEY_PADDING_LENGTH:
            data = data[:-PUBKEY_PADDING_LENGTH]
            hash_len_fe = TEST_HASH_LEN_FE
            parameter_len = TEST_PARAMETER_LEN
        else:
            hash_len_fe = PROD_HASH_LEN_FE
            parameter_len = PROD_PARAMETER_LEN

        offset = 0

        # Deserialize root (HASH_LEN_FE field elements)
        root: List[Fp] = []
        for _ in range(hash_len_fe):
            value = int.from_bytes(data[offset : offset + FE_SIZE_BYTES], byteorder="little")
            root.append(Fp(value=value))
            offset += FE_SIZE_BYTES

        # Deserialize parameter (PARAMETER_LEN field elements)
        parameter: Parameter = []
        for _ in range(parameter_len):
            value = int.from_bytes(data[offset : offset + FE_SIZE_BYTES], byteorder="little")
            parameter.append(Fp(value=value))
            offset += FE_SIZE_BYTES

        return cls(root=root, parameter=parameter)


class Signature(StrictBaseModel):
    """
    A signature produced by the `sign` function.

    It contains all the necessary components for a verifier to confirm that a
    specific message was signed by the owner of a `PublicKey` for a specific epoch.
    """

    path: HashTreeOpening
    """The authentication path proving the one-time key's inclusion in the Merkle tree."""
    rho: Randomness
    """The randomness used to successfully encode the message."""
    hashes: List[HashDigest]
    """The one-time signature itself: a list of intermediate Winternitz chain hashes."""

    def to_bytes(self) -> bytes:
        """
        Serialize the signature to a byte array.

        The serialization format is:
        1. path.siblings (LOG_LIFETIME siblings × HASH_LEN_FE field elements × _FE_SIZE_BYTES bytes)
        2. rho (RAND_LEN_FE field elements × _FE_SIZE_BYTES bytes)
        3. hashes (DIMENSION hashes × HASH_LEN_FE field elements × _FE_SIZE_BYTES bytes)

        Total: _SIGNATURE_SIZE_BYTES bytes for PROD config

        Returns:
            A byte array of exactly _SIGNATURE_SIZE_BYTES bytes.
        """
        result = bytearray()

        # Serialize path siblings (LOG_LIFETIME siblings, each HASH_LEN_FE field elements)
        for sibling in self.path.siblings:
            for fe in sibling:
                result.extend(fe.value.to_bytes(FE_SIZE_BYTES, byteorder="little"))

        # Serialize rho (RAND_LEN_FE field elements)
        for fe in self.rho:
            result.extend(fe.value.to_bytes(FE_SIZE_BYTES, byteorder="little"))

        # Serialize hashes (DIMENSION hashes, each HASH_LEN_FE field elements)
        for hash_digest in self.hashes:
            for fe in hash_digest:
                result.extend(fe.value.to_bytes(FE_SIZE_BYTES, byteorder="little"))

        if len(result) != PROD_SIGNATURE_SIZE_BYTES and len(result) != TEST_SIGNATURE_SIZE_BYTES:
            raise ValueError(
                f"Expected {PROD_SIGNATURE_SIZE_BYTES} or {TEST_SIGNATURE_SIZE_BYTES} bytes, "
                f"got {len(result)}"
            )

        if len(result) != SIGNATURE_SIZE_BYTES:
            append_zero_bytes = b"\x00" * (SIGNATURE_SIZE_BYTES - len(result))
            result.extend(append_zero_bytes)

        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> Signature:
        """
        Deserialize a signature from a byte array.

        Args:
            data: A byte array of exactly _SIGNATURE_SIZE_BYTES bytes.

        Returns:
            The deserialized Signature object.

        Raises:
            ValueError: If the data is not the expected size.
        """
        if len(data) != SIGNATURE_SIZE_BYTES:
            raise ValueError(f"Expected {SIGNATURE_SIZE_BYTES} bytes, got {len(data)}")

        # Remove padding bytes if any
        if data[-SIGNATURE_PADDING_LENGTH:] == b"\x00" * SIGNATURE_PADDING_LENGTH:
            data = data[:-SIGNATURE_PADDING_LENGTH]
            log_lifetime = TEST_LOG_LIFETIME
            hash_len_fe = TEST_HASH_LEN_FE
            rand_len_fe = TEST_RAND_LEN_FE
            dimension = TEST_DIMENSION
        else:
            log_lifetime = PROD_LOG_LIFETIME
            hash_len_fe = PROD_HASH_LEN_FE
            rand_len_fe = PROD_RAND_LEN_FE
            dimension = PROD_DIMENSION

        offset = 0

        # Deserialize path siblings (LOG_LIFETIME siblings, each HASH_LEN_FE field elements)
        siblings: List[HashDigest] = []
        for _ in range(log_lifetime):
            sibling: HashDigest = []
            for _ in range(hash_len_fe):
                value = int.from_bytes(data[offset : offset + FE_SIZE_BYTES], byteorder="little")
                sibling.append(Fp(value=value))
                offset += FE_SIZE_BYTES
            siblings.append(sibling)

        path = HashTreeOpening(siblings=siblings)

        # Deserialize rho (RAND_LEN_FE field elements)
        rho: Randomness = []
        for _ in range(rand_len_fe):
            value = int.from_bytes(data[offset : offset + FE_SIZE_BYTES], byteorder="little")
            rho.append(Fp(value=value))
            offset += FE_SIZE_BYTES

        # Deserialize hashes (DIMENSION hashes, each HASH_LEN_FE field elements)
        hashes: List[HashDigest] = []
        for _ in range(dimension):
            hash_digest: HashDigest = []
            for _ in range(hash_len_fe):
                value = int.from_bytes(data[offset : offset + FE_SIZE_BYTES], byteorder="little")
                hash_digest.append(Fp(value=value))
                offset += FE_SIZE_BYTES
            hashes.append(hash_digest)

        return cls(path=path, rho=rho, hashes=hashes)


class SecretKey(StrictBaseModel):
    """
    The private component of a key pair. **MUST BE KEPT CONFIDENTIAL.**

    This object contains all the secret material and pre-computed data needed to
    generate signatures for any epoch within its active lifetime.
    """

    prf_key: PRFKey
    """The master secret key used to derive all one-time secrets."""
    tree: HashTree
    """The pre-computed sparse Merkle tree needed to generate authentication paths."""
    parameter: Parameter
    """The public parameter `P`, stored for convenience during signing."""
    activation_epoch: int
    """The first epoch for which this secret key is valid."""
    num_active_epochs: int
    """The number of consecutive epochs this key can be used for."""
