"""Core definition of the KoalaBear prime field Fp."""

from typing import IO, Any, Self

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import core_schema

from lean_spec.types import SSZType

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


class Fp(SSZType):
    """
    An element in the KoalaBear prime field F_p.

    This is an SSZ-serializable type.

    Each field element is represented as a 4-byte little-endian unsigned integer.
    """

    def __init__(self, value: int) -> None:
        """
        Create a field element.

        Args:
            value: The value to wrap. Must be in the range [0, P).

            Negative values will be normalized to the range [0, P).

        Raises:
            TypeError: If value is not an integer.
        """
        if not isinstance(value, int):
            raise TypeError(f"Field value must be an integer, got {type(value).__name__}")

        # Normalize to [0, P) - handles negative values correctly
        self.value: int = value % P

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Fp elements are fixed-size (4 bytes)."""
        return True

    @classmethod
    def get_byte_length(cls) -> int:
        """Get the byte length of an Fp element."""
        return P_BYTES

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize the field element to a binary stream."""
        data = self.value.to_bytes(P_BYTES, byteorder="little")
        stream.write(data)
        return len(data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a field element from a binary stream."""
        if scope != P_BYTES:
            raise ValueError(f"Expected {P_BYTES} bytes for Fp, got {scope}")
        data = stream.read(P_BYTES)
        if len(data) != P_BYTES:
            raise ValueError(f"Expected {P_BYTES} bytes for Fp, got {len(data)}")
        value = int.from_bytes(data, byteorder="little")
        if value >= P:
            raise ValueError(f"Value {value} exceeds field modulus {P}")
        return cls(value=value)

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

    def __eq__(self, other: object) -> bool:
        """Check equality of two field elements."""
        if not isinstance(other, Fp):
            return False
        return self.value == other.value

    def __hash__(self) -> int:
        """Compute hash of the field element."""
        return hash(self.value)

    def __repr__(self) -> str:
        """String representation."""
        return f"Fp(value={self.value})"

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
        return self.encode_bytes()

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
        return cls.decode_bytes(data)

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
