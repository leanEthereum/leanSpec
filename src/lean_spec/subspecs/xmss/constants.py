"""
Defines the cryptographic constants and configuration presets for the
XMSS spec.

This specification corresponds to the "hashing-optimized" Top Level Target Sum
instantiation from the canonical Rust implementation
(production instantiation).

We also provide a test instantiation for testing purposes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List

from typing_extensions import Final

from lean_spec.types import StrictBaseModel

from ..koalabear import P_BYTES, Fp

if TYPE_CHECKING:
    from .containers import HashTreeOpening, PublicKey, Signature


class XmssConfig(StrictBaseModel):
    """A model holding the configuration constants for an XMSS preset."""

    # --- Core Scheme Configuration ---
    MESSAGE_LENGTH: int
    """The length in bytes for all messages to be signed."""

    LOG_LIFETIME: int
    """The base-2 logarithm of the scheme's maximum lifetime."""

    @property
    def LIFETIME(self) -> int:  # noqa: N802
        """
        The maximum number of epochs supported by this configuration.

        An individual key pair can be active for a smaller sub-range.
        """
        return 1 << self.LOG_LIFETIME

    DIMENSION: int
    """The total number of hash chains, `v`."""

    BASE: int
    """The alphabet size for the digits of the encoded message."""

    FINAL_LAYER: int
    """Number of top layers of the hypercube to map the hash output into."""

    TARGET_SUM: int
    """The required sum of all codeword chunks for a signature to be valid."""

    MAX_TRIES: int
    """
    How often one should try at most to resample a random value.

    This is currently based on experiments with the Rust implementation.
    Should probably be modified in production.
    """

    PARAMETER_LEN: int
    """
    The length of the public parameter `P`.

    It is used to specialize the hash function.
    """

    TWEAK_LEN_FE: int
    """The length of a domain-separating tweak."""

    MSG_LEN_FE: int
    """The length of a message after being encoded into field elements."""

    RAND_LEN_FE: int
    """The length of the randomness `rho` used during message encoding."""

    HASH_LEN_FE: int
    """The output length of the main tweakable hash function."""

    CAPACITY: int
    """The capacity of the Poseidon2 sponge, defining its security level."""

    POS_OUTPUT_LEN_PER_INV_FE: int
    """Output length per invocation for the message hash."""

    POS_INVOCATIONS: int
    """Number of invocations for the message hash."""

    @property
    def POS_OUTPUT_LEN_FE(self) -> int:  # noqa: N802
        """Total output length for the message hash."""
        return self.POS_OUTPUT_LEN_PER_INV_FE * self.POS_INVOCATIONS

    # --- Serialization and deserialization ---
    @property
    def PUBLIC_KEY_SIZE_BYTES(self) -> int:  # noqa: N802
        """The size of the public key in bytes."""
        return self.HASH_LEN_FE * P_BYTES + self.PARAMETER_LEN * P_BYTES

    @property
    def SIGNATURE_SIZE_BYTES(self) -> int:  # noqa: N802
        """The size of the signature in bytes."""
        # path siblings: LOG_LIFETIME siblings × HASH_LEN_FE elements
        # rho: RAND_LEN_FE elements
        # hashes: DIMENSION hashes × HASH_LEN_FE elements per hash
        path_size = self.LOG_LIFETIME * self.HASH_LEN_FE * P_BYTES
        rho_size = self.RAND_LEN_FE * P_BYTES
        hashes_size = self.DIMENSION * self.HASH_LEN_FE * P_BYTES
        return path_size + rho_size + hashes_size

    def serialize_field_elements(self, field_elements: List[Fp]) -> bytes:
        """Serialize a list of field elements to a byte array."""
        return b"".join(fe.serialize() for fe in field_elements)

    def deserialize_field_elements(self, data: bytes) -> List[Fp]:
        """Deserialize a list of field elements from a byte array."""
        return [Fp.deserialize(data[i : i + P_BYTES]) for i in range(0, len(data), P_BYTES)]

    def serialize_public_key(self, public_key: PublicKey) -> bytes:
        """
        Serialize the public key to a byte array.

        Args:
            public_key: The public key to serialize.

        Returns:
            The serialized public key.
        """
        return self.serialize_field_elements(public_key.root) + self.serialize_field_elements(
            public_key.parameter
        )

    def deserialize_public_key(self, data: bytes) -> PublicKey:
        """
        Deserialize a public key from a byte array.

        Args:
            data: The serialized public key.

        Returns:
            The deserialized public key.

        Raises:
            ValueError: If the public key is not the expected size.
        """
        if len(data) != self.PUBLIC_KEY_SIZE_BYTES:
            raise ValueError(
                f"Invalid public key length: expected {self.PUBLIC_KEY_SIZE_BYTES}, got {len(data)}"
            )

        root_size = self.HASH_LEN_FE * P_BYTES
        root = self.deserialize_field_elements(data[:root_size])
        parameter = self.deserialize_field_elements(data[root_size:])

        return PublicKey(root=root, parameter=parameter)

    def serialize_signature(self, signature: Signature) -> bytes:
        """
        Serialize the signature to a byte array.

        Args:
            signature: The signature to serialize.

        Returns:
            The serialized signature.
        """
        # Serialize path siblings (LOG_LIFETIME siblings, each HASH_LEN_FE field elements)
        # signature.path.siblings is List[HashDigest] = List[List[Fp]], needs flattening
        siblings_flat = [fe for sibling in signature.path.siblings for fe in sibling]

        # Serialize rho (RAND_LEN_FE field elements)
        # signature.rho is Randomness = List[Fp], already flat

        # Serialize hashes (DIMENSION hashes, each HASH_LEN_FE field elements)
        # signature.hashes is List[HashDigest] = List[List[Fp]], needs flattening
        hashes_flat = [fe for hash_digest in signature.hashes for fe in hash_digest]

        return (
            self.serialize_field_elements(siblings_flat)
            + self.serialize_field_elements(signature.rho)
            + self.serialize_field_elements(hashes_flat)
        )

    def deserialize_signature(self, data: bytes) -> Signature:
        """
        Deserialize the signature from a byte array.

        Args:
            data: The serialized signature.

        Returns:
            The deserialized signature.

        Raises:
            ValueError: If the signature is not the expected size.
        """
        if len(data) != self.SIGNATURE_SIZE_BYTES:
            raise ValueError(
                f"Invalid signature length: expected {self.SIGNATURE_SIZE_BYTES}, got {len(data)}"
            )

        # Calculate sizes for each component
        path_size = self.LOG_LIFETIME * self.HASH_LEN_FE * P_BYTES
        rho_size = self.RAND_LEN_FE * P_BYTES

        # Split data into sections
        offset = 0
        path_data = data[offset : offset + path_size]
        offset += path_size
        rho_data = data[offset : offset + rho_size]
        offset += rho_size
        hashes_data = data[offset:]

        # Deserialize path siblings (LOG_LIFETIME siblings, each HASH_LEN_FE field elements)
        siblings_flat = self.deserialize_field_elements(path_data)
        siblings = [
            siblings_flat[i : i + self.HASH_LEN_FE]
            for i in range(0, len(siblings_flat), self.HASH_LEN_FE)
        ]

        # Deserialize rho (RAND_LEN_FE field elements)
        rho = self.deserialize_field_elements(rho_data)

        # Deserialize hashes (DIMENSION hashes, each HASH_LEN_FE field elements)
        hashes_flat = self.deserialize_field_elements(hashes_data)
        hashes = [
            hashes_flat[i : i + self.HASH_LEN_FE]
            for i in range(0, len(hashes_flat), self.HASH_LEN_FE)
        ]

        return Signature(
            path=HashTreeOpening(siblings=siblings),
            rho=rho,
            hashes=hashes,
        )


PROD_CONFIG: Final = XmssConfig(
    MESSAGE_LENGTH=32,
    LOG_LIFETIME=32,
    DIMENSION=64,
    BASE=8,
    FINAL_LAYER=77,
    TARGET_SUM=375,
    MAX_TRIES=100_000,
    PARAMETER_LEN=5,
    TWEAK_LEN_FE=2,
    MSG_LEN_FE=9,
    RAND_LEN_FE=7,
    HASH_LEN_FE=8,
    CAPACITY=9,
    POS_OUTPUT_LEN_PER_INV_FE=15,
    POS_INVOCATIONS=1,
)


TEST_CONFIG: Final = XmssConfig(
    MESSAGE_LENGTH=32,
    LOG_LIFETIME=8,
    DIMENSION=16,
    BASE=4,
    FINAL_LAYER=24,
    TARGET_SUM=24,
    MAX_TRIES=100_000,
    PARAMETER_LEN=5,
    TWEAK_LEN_FE=2,
    MSG_LEN_FE=9,
    RAND_LEN_FE=7,
    HASH_LEN_FE=8,
    CAPACITY=9,
    POS_OUTPUT_LEN_PER_INV_FE=15,
    POS_INVOCATIONS=1,
)


TWEAK_PREFIX_CHAIN: Final = Fp(value=0x00)
"""The unique prefix for tweaks used in Winternitz-style hash chains."""

TWEAK_PREFIX_TREE: Final = Fp(value=0x01)
"""The unique prefix for tweaks used when hashing Merkle tree nodes."""

TWEAK_PREFIX_MESSAGE: Final = Fp(value=0x02)
"""The unique prefix for tweaks used in the initial message hashing step."""

PRF_KEY_LENGTH: int = 32
"""The length of the PRF secret key in bytes."""
