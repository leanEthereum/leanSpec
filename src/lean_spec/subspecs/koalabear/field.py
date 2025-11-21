"""Core definition of the KoalaBear prime field Fp."""

from typing import Self

from pydantic import Field, field_validator

from lean_spec.subspecs.xmss import bincode
from lean_spec.types import StrictBaseModel

# =================================================================
# Field Constants
#
# The prime is chosen because the cube map (x -> x^3) is an
# automorphism of the multiplicative group.
# =================================================================

P: int = 2**31 - 2**24 + 1
"""The KoalaBear Prime: P = 2^31 - 2^24 + 1"""

P_BITS: int = 31
"""The number of bits in the prime P."""

P_BYTES: int = (P_BITS + 7) // 8
"""The size of a KoalaBear field element in bytes."""

TWO_ADICITY: int = 24
"""
The largest integer n such that 2^n divides (P - 1).

P - 1 = 2^24 * 127
"""

TWO_ADIC_GENERATORS: list[int] = [
    0x1,
    0x7F000000,
    0x7E010002,
    0x6832FE4A,
    0x8DBD69C,
    0xA28F031,
    0x5C4A5B99,
    0x29B75A80,
    0x17668B8A,
    0x27AD539B,
    0x334D48C7,
    0x7744959C,
    0x768FC6FA,
    0x303964B2,
    0x3E687D4D,
    0x45A60E61,
    0x6E2F4D7A,
    0x163BD499,
    0x6C4A8A45,
    0x143EF899,
    0x514DDCAD,
    0x484EF19B,
    0x205D63C3,
    0x68E7DD49,
    0x6AC49F88,
]
"""
A pre-computed list of 2^n-th roots of unity.

The element at index `n` is a generator for
the multiplicative subgroup of order 2^n.
"""


# =================================================================
# Base Field Fp
#
# This class implements the finite field F_p where p is the KoalaBear prime.
# All arithmetic is performed modulo P.
# =================================================================


class Fp(StrictBaseModel):
    """An element in the KoalaBear prime field F_p."""

    value: int = Field(ge=0, lt=P, description="Field element value in the range [0, P)")

    @field_validator("value", mode="before")
    @classmethod
    def reduce_modulo_p(cls, v: int) -> int:
        """Reduces an integer input modulo P before validation."""
        return v % P

    def __add__(self, other: Self) -> Self:
        """Field addition."""
        return self.__class__(value=self.value + other.value)

    def __sub__(self, other: Self) -> Self:
        """Field subtraction."""
        return self.__class__(value=self.value - other.value)

    def __neg__(self) -> Self:
        """Field negation."""
        return self.__class__(value=-self.value)

    def __mul__(self, other: Self) -> Self:
        """Field multiplication."""
        return self.__class__(value=self.value * other.value)

    def __pow__(self, exponent: int) -> Self:
        """Field exponentiation."""
        return self.__class__(value=pow(self.value, exponent, P))

    def inverse(self) -> Self:
        """Computes the multiplicative inverse."""
        if self.value == 0:
            raise ZeroDivisionError("Cannot invert the zero element.")
        # a^(P-2) is the multiplicative inverse of a in F_p
        return self ** (P - 2)

    def __truediv__(self, other: Self) -> Self:
        """Field division."""
        return self * other.inverse()

    @classmethod
    def two_adic_generator(cls, bits: int) -> Self:
        """
        Get a generator for the multiplicative subgroup of order 2^bits.

        This is a direct lookup from a pre-computed list of generators.

        Args:
            bits: The order of the subgroup will be 2^bits.
            Must be in [0, TWO_ADICITY].

        Returns:
            A generator of the multiplicative subgroup of order 2^bits.

        Raises:
            ValueError: If `bits` is outside the valid range.
        """
        if not (0 <= bits <= TWO_ADICITY):
            raise ValueError(f"bits must be between 0 and {TWO_ADICITY}")
        return cls(value=TWO_ADIC_GENERATORS[bits])

    def __bytes__(self) -> bytes:
        """
        Serialize the field element using Python's bytes protocol.

        This enables `bytes(fp)` to work naturally with field elements.

        Returns:
            4-byte little-endian representation of the field element.

        Example:
            >>> fp = Fp(value=42)
            >>> data = bytes(fp)
            >>> len(data) == 4
            True
        """
        return self.value.to_bytes(P_BYTES, byteorder="little")

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """
        Deserialize a field element from bytes.

        This is the inverse of `__bytes__()` and follows Python's standard
        deserialization pattern.

        Args:
            data: 4-byte little-endian representation of a field element.

        Returns:
            Deserialized field element.

        Raises:
            ValueError: If data has incorrect length or represents an invalid field value.

        Example:
            >>> fp = Fp(value=42)
            >>> recovered = Fp.from_bytes(bytes(fp))
            >>> recovered == fp
            True
        """
        if len(data) != P_BYTES:
            raise ValueError(f"Expected {P_BYTES} bytes, got {len(data)}")

        value = int.from_bytes(data, byteorder="little")

        if value >= P:
            raise ValueError(f"Value {value} (0x{value:08x}) exceeds field modulus {P} (0x{P:08x})")

        return cls(value=value)

    @classmethod
    def serialize_list(cls, elements: list[Self]) -> bytes:
        """
        Serialize a list of field elements to bytes.

        This is a convenience method for serializing multiple field elements
        at once, useful for container serialization.

        Args:
            elements: List of field elements to serialize.

        Returns:
            Concatenated bytes of all field elements.

        Example:
            >>> elements = [Fp(value=1), Fp(value=2), Fp(value=3)]
            >>> data = Fp.serialize_list(elements)
            >>> len(data) == 3 * P_BYTES
            True
        """
        return b"".join(bytes(elem) for elem in elements)

    @classmethod
    def deserialize_list(cls, data: bytes, count: int) -> list[Self]:
        """
        Deserialize a fixed number of field elements from bytes.

        Args:
            data: Raw bytes to deserialize.
            count: Expected number of field elements.

        Returns:
            List of deserialized field elements.

        Raises:
            ValueError: If data length doesn't match expected count.

        Example:
            >>> elements = [Fp(value=1), Fp(value=2), Fp(value=3)]
            >>> data = Fp.serialize_list(elements)
            >>> recovered = Fp.deserialize_list(data, 3)
            >>> recovered == elements
            True
        """
        expected_len = count * P_BYTES
        if len(data) != expected_len:
            raise ValueError(f"Expected {expected_len} bytes for {count} elements, got {len(data)}")

        return [cls.from_bytes(data[i : i + P_BYTES]) for i in range(0, len(data), P_BYTES)]

    def to_bincode_bytes(self) -> bytes:
        """
        Serialize this Fp to bincode format using varint encoding.

        Note: This serializes the canonical form value. Plonky3 `MontyField31`
        serializes the internal Montgomery representation, so when
        interoperating with Rust, ensure you're comparing the same forms.

        Returns:
            Bincode-encoded bytes of this field element.

        Example:
            >>> fp = Fp(value=42)
            >>> data = fp.to_bincode_bytes()
            >>> recovered, _ = Fp.from_bincode_bytes(data)
            >>> recovered == fp
            True
        """
        return bincode.encode_varint_u64(self.value)

    @classmethod
    def from_bincode_bytes(cls, data: bytes, offset: int = 0) -> tuple[Self, int]:
        """
        Deserialize an Fp from bincode format.

        Args:
            data: Raw bytes to deserialize.
            offset: Starting position in the byte array (default: 0).

        Returns:
            Tuple of (deserialized field element, bytes consumed).

        Raises:
            ValueError: If deserialization fails or value is invalid.

        Example:
            >>> fp = Fp(value=42)
            >>> data = fp.to_bincode_bytes()
            >>> recovered, consumed = Fp.from_bincode_bytes(data)
            >>> recovered == fp and consumed == len(data)
            True
        """
        val, consumed = bincode.decode_varint_u64(data, offset)
        return cls(value=val), consumed

    @staticmethod
    def serialize_fixed_array_bincode(elements: list["Fp"]) -> bytes:
        """
        Serialize a fixed-size array of Fp elements in bincode format.

        Note: In Rust, fixed-size arrays [F; N] do NOT have a length prefix
        in bincode serialization. Each element is varint-encoded sequentially.

        Args:
            elements: List of field elements to serialize.

        Returns:
            Concatenated bincode bytes of all elements.

        Example:
            >>> elements = [Fp(value=1), Fp(value=2), Fp(value=3)]
            >>> data = Fp.serialize_fixed_array_bincode(elements)
            >>> # Deserialize manually
            >>> offset = 0
            >>> recovered = []
            >>> for _ in range(len(elements)):
            ...     fp, consumed = Fp.from_bincode_bytes(data, offset)
            ...     recovered.append(fp)
            ...     offset += consumed
            >>> recovered == elements
            True
        """
        return b"".join(fp.to_bincode_bytes() for fp in elements)

    @staticmethod
    def deserialize_fixed_array_bincode(
        data: bytes, offset: int, count: int
    ) -> tuple[list["Fp"], int]:
        """
        Deserialize a fixed-size array [F; N] from bincode format.

        Each field element is varint-encoded sequentially without a length prefix.

        Args:
            data: Raw bytes to deserialize.
            offset: Starting position in the byte array.
            count: Number of field elements to deserialize.

        Returns:
            Tuple of (list of deserialized field elements, bytes consumed).

        Raises:
            ValueError: If deserialization fails.

        Example:
            >>> elements = [Fp(value=1), Fp(value=2), Fp(value=3)]
            >>> data = Fp.serialize_fixed_array_bincode(elements)
            >>> recovered, consumed = Fp.deserialize_fixed_array_bincode(data, 0, 3)
            >>> recovered == elements and consumed == len(data)
            True
        """
        elements = []
        current_offset = offset
        for _ in range(count):
            fp, consumed = Fp.from_bincode_bytes(data, current_offset)
            elements.append(fp)
            current_offset += consumed
        return elements, current_offset - offset
