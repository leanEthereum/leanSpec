"""
SSZ bitfield types.

A bitfield is a packed sequence of booleans serialized to bytes.

Two flavors are defined by the SSZ spec:

- Fixed-length: exactly N bits encoded in ceil(N / 8) bytes.
- Variable-length: 0 to N bits encoded with a trailing delimiter bit that marks the end.

Both flavors pack bits little-endian within each byte.
Bit i of the input lands in byte i // 8 at position i % 8.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import (
    IO,
    Any,
    ClassVar,
    Self,
    overload,
    override,
)

from pydantic import Field, field_validator

from .boolean import Boolean
from .exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from .ssz_base import SSZModel


class BaseBitvector(SSZModel):
    """
    Fixed-length SSZ bitfield with exactly N bits.

    - Subclasses pin the bit count by setting the class-level length.
    - Serialization packs bits little-endian into ceil(N / 8) bytes.
    - Trailing bits in the last byte are zero when N is not a multiple of 8.

    For example, [1, 1, 1, 1, 1] (5 bits, all set) encodes to a single byte.
    list[i] lands at bit i, where bit 0 is the LSB (rightmost in the byte):

        bit position:  7 6 5 4 3 2 1 0
        byte 0:        0 0 0 1 1 1 1 1   ->  0b00011111

    Bits 5, 6, 7 are trailing zeros — only the lowest 5 hold data.
    """

    LENGTH: ClassVar[int]
    """Number of bits in the vector."""

    data: Sequence[Boolean] = Field(default_factory=tuple)
    """
    The immutable bit data stored as a sequence of booleans.

    Accepts lists, tuples, or iterables of bool-like values on input.
    Stored as an immutable tuple after validation.
    """

    @field_validator("data", mode="before")
    @classmethod
    def _coerce_and_validate(cls, v: Any) -> tuple[Boolean, ...]:
        """Enforce the exact bit count and coerce inputs into booleans."""
        # Subclasses must declare LENGTH before any instances can be validated.
        if not hasattr(cls, "LENGTH"):
            raise SSZTypeError(f"{cls.__name__} must define LENGTH")

        # Materialize generic iterables into a tuple so the length check works.
        if not isinstance(v, (list, tuple)):
            v = tuple(v)

        # Fixed-length type: the input must contain exactly LENGTH elements.
        if len(v) != cls.LENGTH:
            raise SSZValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} elements, got {len(v)}"
            )

        # Wrap each value in Boolean — the constructor rejects anything outside 0 or 1.
        return tuple(Boolean(bit) for bit in v)

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """Always fixed-size by definition."""
        return True

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """Return the number of bytes needed to pack the bits."""
        return math.ceil(cls.LENGTH / 8)

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write SSZ bytes to a binary stream."""
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read SSZ bytes from a stream and return an instance."""
        expected_byte_count = cls.get_byte_length()
        if scope != expected_byte_count:
            raise SSZSerializationError(
                f"{cls.__name__}: expected {expected_byte_count} bytes, got {scope}"
            )
        data = stream.read(scope)
        if len(data) != scope:
            raise SSZSerializationError(f"{cls.__name__}: expected {scope} bytes, got {len(data)}")
        return cls.decode_bytes(data)

    @override
    def encode_bytes(self) -> bytes:
        """
        Encode the bitfield to SSZ bytes.

        Bits are packed little-endian within each byte.
        Bit i of the input lands in byte i // 8 at position i % 8.

        Returns:
            ceil(N / 8) bytes containing the packed bits.
        """
        # Zero-filled buffer sized for every bit — only the 1 bits need writing.
        byte_array = bytearray(math.ceil(self.LENGTH / 8))

        # Walk every input bit and set its position in the output.
        #
        # For bit index i:
        #
        #   - i // 8        identifies the target byte.
        #   - i % 8         is the position within that byte (0 = LSB).
        #   - 1 << (i % 8)  builds a one-hot mask for that position.
        #   - |=            sets the bit while preserving everything already there.
        #
        # Example: bits = [1, 0, 1, 0, 0, 0, 0, 0, 1]  (9 bits, crosses a byte boundary)
        #
        #   i=0, bit=1:  byte_array[0] |= 1 << 0  ->  [0b00000001]
        #   i=2, bit=1:  byte_array[0] |= 1 << 2  ->  [0b00000101]
        #   i=8, bit=1:  byte_array[1] |= 1 << 0  ->  [0b00000101, 0b00000001]
        for i, bit in enumerate(self.data):
            if bit:
                byte_array[i // 8] |= 1 << (i % 8)

        return bytes(byte_array)

    @classmethod
    @override
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Decode SSZ bytes into a bitfield.

        Input must be exactly ceil(N / 8) bytes.
        Fixed-length bitfields carry no delimiter — the byte count alone is enough to recover N.

        Args:
            data: SSZ-encoded bytes with the packed bits.

        Returns:
            A bitfield instance with N bits read from the input.

        Raises:
            SSZValueError: If the input length does not match the expected byte count.
        """
        # Reject inputs whose byte count does not match the expected size.
        expected_byte_count = cls.get_byte_length()
        if len(data) != expected_byte_count:
            raise SSZValueError(
                f"{cls.__name__}: expected {expected_byte_count} bytes, got {len(data)}"
            )

        # Read every bit position out of the byte stream.
        #
        # For bit index i:
        #
        #   - data[i // 8]  picks the byte that holds bit i.
        #   - >> (i % 8)    shifts that byte so bit i is in the LSB.
        #   - & 1           masks off every other bit.
        #
        # Example: data = [0b00000101, 0b00000001]  (encoding of 9 bits, 2 bytes)
        #
        #   i=0:  (data[0] >> 0) & 1  =  0b00000101 & 1  =  1
        #   i=1:  (data[0] >> 1) & 1  =  0b00000010 & 1  =  0
        #   i=2:  (data[0] >> 2) & 1  =  0b00000001 & 1  =  1
        #   i=3:  (data[0] >> 3) & 1  =  0b00000000 & 1  =  0
        #   ...
        #   i=7:  (data[0] >> 7) & 1  =  0b00000000 & 1  =  0
        #   i=8:  (data[1] >> 0) & 1  =  0b00000001 & 1  =  1
        #
        # Recovered bits: [1, 0, 1, 0, 0, 0, 0, 0, 1]
        return cls(data=[Boolean((data[i // 8] >> (i % 8)) & 1) for i in range(cls.LENGTH)])


class BaseBitlist(SSZModel):
    """
    Variable-length SSZ bitfield with 0 to N bits.

    - Subclasses pin the maximum bit count by setting the class-level limit.
    - Serialization packs data bits little-endian, then appends a single 1 bit as a delimiter.
    - The delimiter is what lets the decoder recover the original bit count.

    For example, [1, 0, 1] (3 data bits) encodes to a single byte.

    list[i] lands at bit i, where bit 0 is the LSB (rightmost in the byte):

        bit position:  7 6 5 4  3  2 1 0
        byte 0:        0 0 0 0 [1] 1 0 1   ->  0b00001101   (bracketed bit is the delimiter)

    Without the delimiter, two different lists would collide:

        [1, 0, 1]                ->  0b00000101
        [1, 0, 1, 0, 0, 0, 0, 0] ->  0b00000101
    """

    LIMIT: ClassVar[int]
    """Maximum number of bits allowed."""

    data: Sequence[Boolean] = Field(default_factory=tuple)
    """
    The immutable bit data stored as a sequence of booleans.

    Accepts lists, tuples, or iterables of bool-like values on input.
    Stored as an immutable tuple after validation.
    """

    @field_validator("data", mode="before")
    @classmethod
    def _coerce_and_validate(cls, v: Any) -> tuple[Boolean, ...]:
        """Enforce the maximum bit count and coerce inputs into booleans."""
        # Subclasses must declare LIMIT before any instances can be validated.
        if not hasattr(cls, "LIMIT"):
            raise SSZTypeError(f"{cls.__name__} must define LIMIT")

        # Accept different input shapes:
        #
        #   - list or tuple    pass through directly.
        #   - other iterables  materialize into a list so length is known.
        #   - str or bytes     rejected — iterable but elements are not booleans.
        if isinstance(v, (list, tuple)):
            elements = v
        elif hasattr(v, "__iter__") and not isinstance(v, (str, bytes)):
            elements = list(v)
        else:
            raise SSZTypeError(f"Expected iterable, got {type(v).__name__}")

        # Variable-length type: any count is fine, up to LIMIT.
        if len(elements) > cls.LIMIT:
            raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {len(elements)}")

        # Wrap each value in Boolean — the constructor rejects anything outside 0 or 1.
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

    def __add__(self, other: Any) -> Self:
        """Concatenate with another bit sequence."""
        if isinstance(other, BaseBitlist):
            new_data = (*self.data, *other.data)
        elif isinstance(other, (list, tuple)):
            new_data = (*self.data, *(Boolean(b) for b in other))
        else:
            return NotImplemented
        return type(self)(data=new_data)

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """Variable-size by definition — the bit count ranges from zero to the class limit."""
        return False

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """
        Variable-size types have no fixed byte length.

        Raises:
            SSZTypeError: Always — call this only on fixed-size types.
        """
        raise SSZTypeError(f"{cls.__name__}: variable-size bitlist has no fixed byte length")

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write SSZ bytes to a binary stream."""
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read SSZ bytes from a stream and return an instance."""
        data = stream.read(scope)
        if len(data) != scope:
            raise SSZSerializationError(f"{cls.__name__}: expected {scope} bytes, got {len(data)}")
        return cls.decode_bytes(data)

    @override
    def encode_bytes(self) -> bytes:
        """
        Encode the bitlist to SSZ bytes with a trailing delimiter.

        # Overview

        Data bits are packed little-endian within each byte.
        A single 1 bit is placed immediately after the last data bit.
        The trailing bit is what lets the decoder recover the original count.

        # Why a delimiter

        SSZ encodes bitlists as raw bytes with no length prefix.
        Without a marker, [1, 0] and [1, 0, 0, 0, 0, 0, 0, 0] would share the byte 0x01.
        A trailing 1 bit is the smallest sentinel that disambiguates them.

        # Layout

            bits = [1, 0, 1]   ->  byte 0:  0 0 0 0 [1] 1 0 1   (delimiter at bit 3)

            bits = [1] * 8     ->  byte 0:  1 1 1 1 1 1 1 1
                                   byte 1:  0 0 0 0 0 0 0 [1]   (delimiter spills)

        Returns:
            SSZ bytes containing the data bits followed by the delimiter.
        """
        # Phase 1: handle the empty case.
        #
        # No data bits means the encoding is just the delimiter byte.
        num_bits = len(self.data)
        if num_bits == 0:
            return b"\x01"

        # Phase 2: pack data bits little-endian into a byte array.
        #
        # For bit index i:
        #
        #   - i // 8        identifies the target byte.
        #   - i % 8         is the position within that byte (0 = LSB).
        #   - 1 << (i % 8)  builds a one-hot mask for that position.
        #   - |=            sets the bit, preserving anything already there.
        #
        # Example: bits = [1, 0, 1, 0, 0, 0, 0, 0, 1]  (9 bits, crosses a byte boundary)
        #
        #   i=0, bit=1:  byte_array[0] |= 1 << 0  ->  [0b00000001]
        #   i=2, bit=1:  byte_array[0] |= 1 << 2  ->  [0b00000101]
        #   i=8, bit=1:  byte_array[1] |= 1 << 0  ->  [0b00000101, 0b00000001]
        byte_array = bytearray(math.ceil(num_bits / 8))
        for i, bit in enumerate(self.data):
            if bit:
                byte_array[i // 8] |= 1 << (i % 8)

        # Phase 3: place the delimiter immediately after the last data bit.
        #
        # Two cases, by where the last data bit fell:
        #
        #   - num_bits % 8 == 0   data fills its bytes; delimiter spills into a new trailing byte.
        #   - otherwise           delimiter lands at bit (num_bits % 8) of the last byte.
        #
        # Example A: data bits = [1, 0, 1]  (num_bits = 3, fits in same byte)
        #
        #   byte_array after Phase 2:   [0b00000101]
        #   byte_array[0] |= 1 << 3  -> [0b00001101]   (delimiter at bit 3)
        #
        # Example B: data bits = [1, 1, 1, 1, 1, 1, 1, 1]  (num_bits = 8, spills)
        #
        #   byte_array after Phase 2:   [0b11111111]
        #   bytes(byte_array) + 0x01 -> [0b11111111, 0b00000001]
        if num_bits % 8 == 0:
            return bytes(byte_array) + b"\x01"
        byte_array[num_bits // 8] |= 1 << (num_bits % 8)
        return bytes(byte_array)

    @classmethod
    @override
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Decode SSZ bytes into a bitlist by locating the delimiter bit.

        # Overview

        - The highest set bit in the input is the delimiter.
        - Bits below it are data.
        - Bits above it are zero padding.
        - Empty input is invalid (the empty bitlist still encodes as one byte, 0x01).

        # Why integer interpretation

        Reading the byte stream as a little-endian integer aligns bits and bytes perfectly:

            byte 0 bit j  ->  integer bit j
            byte 1 bit j  ->  integer bit (8 + j)
            byte k bit j  ->  integer bit (8 * k + j)

        For example, data = [0b00000101, 0b00000010]:

            int.from_bytes(data, "little")  =  0b1000000101

            byte 0 bit 0 (=1)  ->  integer bit 0
            byte 0 bit 2 (=1)  ->  integer bit 2
            byte 1 bit 1 (=1)  ->  integer bit 9      (= 8 * 1 + 1)

        The highest set bit of the integer is exactly the delimiter position.

        Args:
            data: SSZ-encoded bytes containing data bits followed by a single 1 delimiter.

        Returns:
            A bitlist instance with the recovered data bits.

        Raises:
            SSZSerializationError: If the input is empty or contains no 1 bits.
            SSZValueError: If the recovered bit count exceeds the class limit.
        """
        # Phase 1: reject empty input.
        #
        # The empty bitlist still encodes to one byte (0x01).
        if len(data) == 0:
            raise SSZSerializationError(f"{cls.__name__}: cannot decode empty bytes")

        # Phase 2: locate the delimiter — the topmost 1 in the entire byte stream.
        #
        #   - int.from_bytes(data, "little")   reads the stream as one little-endian integer.
        #   - bit_length()                     1-indexed position of its highest set bit.
        #   - bit_length() - 1                 0-indexed delimiter position in the stream.
        #
        # Example A: data = [0b00001101]  (encoding of bits [1, 0, 1])
        #
        #   int.from_bytes(data, "little")  =  13   =  0b00001101
        #   bit_length()                    =  4
        #   delimiter_pos                   =  3      ->  num_bits = 3
        #
        # Example B: data = [0b11111111, 0b00000001]  (encoding of bits [1] * 8)
        #
        #   int.from_bytes(data, "little")  =  511  =  0b111111111
        #   bit_length()                    =  9
        #   delimiter_pos                   =  8      ->  num_bits = 8
        total = int.from_bytes(data, "little")
        if total == 0:
            raise SSZSerializationError(f"{cls.__name__}: no delimiter bit found")
        delimiter_pos = total.bit_length() - 1

        # Phase 3: extract data bits below the delimiter and enforce the size limit.
        #
        # The delimiter position equals the data bit count. For each bit index i:
        #
        #   - data[i // 8]  picks the byte that holds bit i.
        #   - >> (i % 8)    shifts that byte so bit i is in the LSB.
        #   - & 1           masks off every other bit.
        #
        # Example: data = [0b00001101], num_bits = 3  (delimiter at bit 3)
        #
        #   i=0:  (data[0] >> 0) & 1  =  0b00001101 & 1  =  1
        #   i=1:  (data[0] >> 1) & 1  =  0b00000110 & 1  =  0
        #   i=2:  (data[0] >> 2) & 1  =  0b00000011 & 1  =  1
        #
        # Recovered bits: [1, 0, 1]
        num_bits = delimiter_pos
        if num_bits > cls.LIMIT:
            raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {num_bits}")

        return cls(data=[Boolean((data[i // 8] >> (i % 8)) & 1) for i in range(num_bits)])
