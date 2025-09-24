"""Bitvector and Bitlist type specifications.

This module provides two SSZ (SimpleSerialize) collection types:

- BaseBitvector: fixed-length, immutable sequence of booleans.
- BaseBitlist: variable-length, immutable sequence of booleans with max capacity.

Both types support SSZ byte encoding/decoding:
- Bitvector packs bits little-endian within each byte (bit 0 -> LSB).
- Bitlist packs bits the same way and appends a single delimiter bit set to 1
  immediately after the last data bit (may create a new byte).

Concrete types inherit from the base classes and specify LENGTH or LIMIT:
- class MyBitvector(BaseBitvector): LENGTH = 128
- class MyBitlist(BaseBitlist): LIMIT = 2048
"""

from __future__ import annotations

from typing import (
    IO,
    Any,
    ClassVar,
    Tuple,
)

from pydantic import Field, field_validator
from typing_extensions import Self

from .boolean import Boolean
from .ssz_base import SSZModel


class BaseBitvector(SSZModel):
    """
    Base class for fixed-length bit vectors using SSZModel pattern.

    Immutable collection with exact LENGTH bits.
    """

    LENGTH: ClassVar[int]
    """Number of bits in the vector."""

    data: Tuple[Boolean, ...] = Field(default_factory=tuple)
    """The immutable bit data stored as a tuple."""

    @field_validator("data", mode="before")
    @classmethod
    def _validate_vector_data(cls, v: Any) -> Tuple[Boolean, ...]:
        """Validate and convert input data to typed tuple of Booleans."""
        if not hasattr(cls, "LENGTH"):
            raise TypeError(f"{cls.__name__} must define LENGTH")

        if not isinstance(v, (list, tuple)):
            v = tuple(v)

        # Convert each bit to Boolean
        typed_values = tuple(Boolean(item) if not isinstance(item, Boolean) else item for item in v)

        if len(typed_values) != cls.LENGTH:
            raise ValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} bits, "
                f"but {len(typed_values)} were provided."
            )

        return typed_values

    @classmethod
    def is_fixed_size(cls) -> bool:
        """A Bitvector is always fixed-size."""
        return True

    @classmethod
    def get_byte_length(cls) -> int:
        """Get the byte length for the fixed-size bitvector."""
        return (cls.LENGTH + 7) // 8  # Ceiling division

    def serialize(self, stream: IO[bytes]) -> int:
        """Write SSZ bytes to a binary stream."""
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read SSZ bytes from a stream and return an instance."""
        if scope != cls.get_byte_length():
            raise ValueError(
                f"Invalid scope for {cls.__name__}: expected {cls.get_byte_length()}, got {scope}"
            )
        data = stream.read(scope)
        if len(data) != scope:
            raise IOError(f"Expected {scope} bytes, got {len(data)}")
        return cls.decode_bytes(data)

    def encode_bytes(self) -> bytes:
        """
        Encode to SSZ bytes.

        Packs bits little-endian within each byte:
        bit i goes to byte i // 8 at bit position (i % 8).
        """
        byte_len = (self.LENGTH + 7) // 8
        byte_array = bytearray(byte_len)
        for i, bit in enumerate(self.data):
            if bit:
                byte_index = i // 8
                bit_index_in_byte = i % 8
                byte_array[byte_index] |= 1 << bit_index_in_byte
        return bytes(byte_array)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Decode from SSZ bytes.

        Expects exactly ceil(LENGTH / 8) bytes. No delimiter bit for Bitvector.
        """
        expected_len = cls.get_byte_length()
        if len(data) != expected_len:
            raise ValueError(f"{cls.__name__} expected {expected_len} bytes, got {len(data)}")

        bits_generator = (Boolean((data[i // 8] >> (i % 8)) & 1) for i in range(cls.LENGTH))
        return cls(data=tuple(bits_generator))


class BaseBitlist(SSZModel):
    """
    Base class for variable-length bit lists using SSZModel pattern.

    Immutable collection with 0 to LIMIT bits.
    """

    LIMIT: ClassVar[int]
    """Maximum number of bits allowed."""

    data: Tuple[Boolean, ...] = Field(default_factory=tuple)
    """The immutable bit data stored as a tuple."""

    @field_validator("data", mode="before")
    @classmethod
    def _validate_list_data(cls, v: Any) -> Tuple[Boolean, ...]:
        """Validate and convert input to a tuple of Boolean elements."""
        if not hasattr(cls, "LIMIT"):
            raise TypeError(f"{cls.__name__} must define LIMIT")

        # Handle various input types
        if isinstance(v, (list, tuple)):
            elements = v
        elif hasattr(v, "__iter__") and not isinstance(v, (str, bytes)):
            elements = list(v)
        else:
            raise TypeError(f"Bitlist data must be iterable, got {type(v)}")

        # Check limit
        if len(elements) > cls.LIMIT:
            raise ValueError(
                f"{cls.__name__} cannot contain more than {cls.LIMIT} bits, got {len(elements)}"
            )

        # Convert and validate each bit
        typed_values = []
        for i, element in enumerate(elements):
            if isinstance(element, Boolean):
                typed_values.append(element)
            else:
                try:
                    typed_values.append(Boolean(element))
                except Exception as e:
                    raise ValueError(f"Bit {i} cannot be converted to Boolean: {e}") from e

        return tuple(typed_values)

    def __getitem__(self, key: int | slice) -> Boolean | tuple[Boolean, ...]:
        """Get a bit by index or slice."""
        return self.data[key]

    @classmethod
    def is_fixed_size(cls) -> bool:
        """A Bitlist is never fixed-size (length varies from 0 to LIMIT)."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Lists are variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")

    def serialize(self, stream: IO[bytes]) -> int:
        """Write SSZ bytes to a binary stream."""
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read SSZ bytes from a stream and return an instance."""
        data = stream.read(scope)
        if len(data) != scope:
            raise IOError(f"Expected {scope} bytes, got {len(data)}")
        return cls.decode_bytes(data)

    def encode_bytes(self) -> bytes:
        """
        Encode to SSZ bytes with a trailing delimiter bit.

        Data bits are packed little-endian within each byte.
        Then a single delimiter bit set to 1 is placed immediately after
        the last data bit. If the last data bit ends a byte (num_bits % 8 == 0),
        the delimiter is a new byte 0b00000001 appended at the end.
        """
        num_bits = len(self.data)
        if num_bits == 0:
            # Empty list: just the delimiter byte.
            return b"\x01"

        byte_len = (num_bits + 7) // 8
        byte_array = bytearray(byte_len)

        # Pack data bits.
        for i, bit in enumerate(self.data):
            if bit:
                byte_index = i // 8
                bit_index_in_byte = i % 8
                byte_array[byte_index] |= 1 << bit_index_in_byte

        # Place delimiter bit (1) immediately after the last data bit.
        if num_bits % 8 == 0:
            # Delimiter starts a new byte.
            return bytes(byte_array) + b"\x01"
        else:
            # Delimiter lives in the last byte at position num_bits % 8.
            delimiter_byte_index = num_bits // 8
            delimiter_bit_index = num_bits % 8
            byte_array[delimiter_byte_index] |= 1 << delimiter_bit_index
            return bytes(byte_array)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Decode from SSZ bytes with a delimiter bit.

        The data must contain a delimiter bit set to 1 immediately after
        the last data bit. All bits after the delimiter are assumed to be 0.
        """
        if len(data) == 0:
            raise ValueError("Cannot decode empty data to Bitlist")

        # Find the position of the delimiter bit (rightmost 1).
        delimiter_pos = None
        for byte_idx in range(len(data) - 1, -1, -1):
            byte_val = data[byte_idx]
            if byte_val != 0:
                # Find the rightmost 1 bit in this byte.
                for bit_idx in range(7, -1, -1):
                    if (byte_val >> bit_idx) & 1:
                        delimiter_pos = byte_idx * 8 + bit_idx
                        break
                break

        if delimiter_pos is None:
            raise ValueError("No delimiter bit found in Bitlist data")

        # Extract data bits (everything before the delimiter).
        num_data_bits = delimiter_pos
        if num_data_bits > cls.LIMIT:
            raise ValueError(
                f"{cls.__name__} decoded length {num_data_bits} exceeds limit {cls.LIMIT}"
            )

        bits = []
        for i in range(num_data_bits):
            byte_index = i // 8
            bit_index_in_byte = i % 8
            if byte_index < len(data):
                bit_value = bool((data[byte_index] >> bit_index_in_byte) & 1)
            else:
                bit_value = False
            bits.append(bit_value)

        return cls(data=bits)
