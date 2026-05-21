"""Core definition of the KoalaBear prime field Fp."""

from __future__ import annotations

from typing import IO, Final, Self

from lean_spec.types import SSZType

P: Final = 2**31 - 2**24 + 1
"""
The KoalaBear Prime: P = 2^31 - 2^24 + 1

The prime is chosen because the cube map (x -> x^3) is an automorphism of the multiplicative group.
"""

P_BITS: Final = 31
"""The number of bits in the prime P."""

P_BYTES: Final = (P_BITS + 7) // 8
"""The size of a KoalaBear field element in bytes."""


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
        if not isinstance(value, int) or isinstance(value, bool):
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
        stream.write(self.value.to_bytes(P_BYTES, byteorder="little"))
        return P_BYTES

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
