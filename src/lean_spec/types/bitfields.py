"""Bitvector and Bitlist type specifications.

Provides two SSZ bitfield types:

- BaseBitvector: fixed-length sequence of booleans
- BaseBitlist: variable-length sequence with max capacity

Both pack bits little-endian within each byte (bit 0 -> LSB).
Bitlist appends a delimiter bit set to 1 after the last data bit.

Subclasses must define LENGTH (bitvector) or LIMIT (bitlist).
"""

from __future__ import annotations

from typing import (
    IO,
    Any,
    ClassVar,
    Sequence,
    overload,
)

from pydantic import Field, field_validator
from typing_extensions import Self

from .boolean import Boolean
from .exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from .ssz_base import SSZModel


class BaseBitvector(SSZModel):
    """
    Base class for fixed-length bit vectors using SSZModel pattern.

    Immutable collection with exact LENGTH bits.
    """

    LENGTH: ClassVar[int]
    """Number of bits in the vector."""

    data: Sequence[Boolean] = Field(default_factory=tuple)
    """
    The immutable bit data stored as a sequence of Booleans.

    Accepts lists, tuples, or iterables of bool-like values on input;
    stored as a tuple of Boolean after validation.
    """

    @field_validator("data", mode="before")
    @classmethod
    def _coerce_and_validate(cls, v: Any) -> tuple[Boolean, ...]:
        """Validate and convert input data to typed tuple of Booleans."""
        if not hasattr(cls, "LENGTH"):
            raise SSZTypeError(f"{cls.__name__} must define LENGTH")

        if not isinstance(v, (list, tuple)):
            v = tuple(v)

        if len(v) != cls.LENGTH:
            raise SSZValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} elements, got {len(v)}"
            )

        return tuple(Boolean(bit) for bit in v)

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
        expected_len = cls.get_byte_length()
        if scope != expected_len:
            raise SSZSerializationError(
                f"{cls.__name__}: expected {expected_len} bytes, got {scope}"
            )
        data = stream.read(scope)
        if len(data) != scope:
            raise SSZSerializationError(f"{cls.__name__}: expected {scope} bytes, got {len(data)}")
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
                byte_array[i // 8] |= 1 << (i % 8)
        return bytes(byte_array)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Decode from SSZ bytes.

        Expects exactly ceil(LENGTH / 8) bytes. No delimiter bit for Bitvector.
        """
        expected = cls.get_byte_length()
        if len(data) != expected:
            raise SSZValueError(f"{cls.__name__}: expected {expected} bytes, got {len(data)}")

        bits = tuple(Boolean((data[i // 8] >> (i % 8)) & 1) for i in range(cls.LENGTH))
        return cls(data=bits)


class BaseBitlist(SSZModel):
    """
    Base class for variable-length bit lists using SSZModel pattern.

    Immutable collection with 0 to LIMIT bits.
    """

    LIMIT: ClassVar[int]
    """Maximum number of bits allowed."""

    data: Sequence[Boolean] = Field(default_factory=tuple)
    """
    The immutable bit data stored as a sequence of Booleans.

    Accepts lists, tuples, or iterables of bool-like values on input;
    stored as a tuple of Boolean after validation.
    """

    @field_validator("data", mode="before")
    @classmethod
    def _coerce_and_validate(cls, v: Any) -> tuple[Boolean, ...]:
        """Validate and convert input to a tuple of Boolean elements."""
        if not hasattr(cls, "LIMIT"):
            raise SSZTypeError(f"{cls.__name__} must define LIMIT")

        # Handle various input types
        if isinstance(v, (list, tuple)):
            elements = v
        elif hasattr(v, "__iter__") and not isinstance(v, (str, bytes)):
            elements = list(v)
        else:
            raise SSZTypeError(f"Expected iterable, got {type(v).__name__}")

        # Check limit
        if len(elements) > cls.LIMIT:
            raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {len(elements)}")

        return tuple(Boolean(bit) for bit in elements)

    @overload
    def __getitem__(self, key: int) -> Boolean: ...

    @overload
    def __getitem__(self, key: slice) -> list[Boolean]: ...

    def __getitem__(self, key: int | slice) -> Boolean | list[Boolean]:
        """Get a bit by index or slice."""
        if isinstance(key, slice):
            return list(self.data[key])
        return self.data[key]

    def __setitem__(self, key: int, value: bool | Boolean) -> None:
        """Set a bit by index."""
        new_data = list(self.data)
        new_data[key] = Boolean(value)
        object.__setattr__(self, "data", tuple(new_data))

    def __add__(self, other: Any) -> Self:
        """Concatenate this bitlist with another sequence."""
        if isinstance(other, BaseBitlist):
            new_data = (*self.data, *other.data)
        elif isinstance(other, (list, tuple)):
            new_data = (*self.data, *(Boolean(b) for b in other))
        else:
            return NotImplemented
        return type(self)(data=new_data)

    @classmethod
    def is_fixed_size(cls) -> bool:
        """A Bitlist is never fixed-size (length varies from 0 to LIMIT)."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Lists are variable-size, so this raises an SSZTypeError."""
        raise SSZTypeError(f"{cls.__name__}: variable-size bitlist has no fixed byte length")

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
            raise SSZSerializationError(f"{cls.__name__}: expected {scope} bytes, got {len(data)}")
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
                byte_array[i // 8] |= 1 << (i % 8)

        # Place delimiter bit (1) immediately after the last data bit.
        if num_bits % 8 == 0:
            # Delimiter starts a new byte.
            return bytes(byte_array) + b"\x01"
        else:
            # Delimiter lives in the last byte at position num_bits % 8.
            byte_array[num_bits // 8] |= 1 << (num_bits % 8)
            return bytes(byte_array)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Decode from SSZ bytes with a delimiter bit.

        The data must contain a delimiter bit set to 1 immediately after
        the last data bit. All bits after the delimiter are assumed to be 0.
        """
        if len(data) == 0:
            raise SSZSerializationError(f"{cls.__name__}: cannot decode empty bytes")

        # Find the position of the delimiter bit (rightmost 1).
        delimiter_pos = None
        for byte_idx in range(len(data) - 1, -1, -1):
            byte_val = data[byte_idx]
            if byte_val != 0:
                # Find the highest set bit in this byte using bit_length
                bit_idx = byte_val.bit_length() - 1
                delimiter_pos = byte_idx * 8 + bit_idx
                break

        if delimiter_pos is None:
            raise SSZSerializationError(f"{cls.__name__}: no delimiter bit found")

        # Extract data bits (everything before the delimiter).
        num_bits = delimiter_pos
        if num_bits > cls.LIMIT:
            raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {num_bits}")

        bits = tuple(Boolean((data[i // 8] >> (i % 8)) & 1) for i in range(num_bits))
        return cls(data=bits)
