"""
SSZ bitfield types.

A bitfield is a packed sequence of booleans serialized to bytes.

Two flavors are defined by the SSZ spec:

- Fixed-length: exactly N bits encoded in ceil(N / 8) bytes.
- Variable-length: 0 to N bits encoded with a trailing delimiter bit that marks the end.

Both flavors pack bits little-endian within each byte.
Bit i of the input lands in byte i // 8 at position i % 8.
"""

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

from lean_spec.spec.ssz.boolean import Boolean
from lean_spec.spec.ssz.exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from lean_spec.spec.ssz.ssz_base import SSZModel


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
    def _coerce_and_validate(cls, bits_input: Any) -> tuple[Boolean, ...]:
        """Enforce the exact bit count and coerce inputs into booleans."""
        # Subclasses must declare LENGTH before any instances can be validated.
        if not hasattr(cls, "LENGTH"):
            raise SSZTypeError(f"{cls.__name__} must define LENGTH")

        # Materialize generic iterables into a tuple so the length check works.
        if not isinstance(bits_input, (list, tuple)):
            bits_input = tuple(bits_input)

        # Fixed-length type: the input must contain exactly LENGTH elements.
        if len(bits_input) != cls.LENGTH:
            raise SSZValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} elements, got {len(bits_input)}"
            )

        # Wrap each value in Boolean — the constructor rejects anything outside 0 or 1.
        return tuple(Boolean(bit) for bit in bits_input)

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
        serialized_bytes = stream.read(scope)
        if len(serialized_bytes) != scope:
            raise SSZSerializationError(
                f"{cls.__name__}: expected {scope} bytes, got {len(serialized_bytes)}"
            )
        return cls.decode_bytes(serialized_bytes)

    @override
    def encode_bytes(self) -> bytes:
        """
        Encode the bitfield to SSZ bytes.

        Bits are packed little-endian within each byte.
        Bit i of the input lands in byte i // 8 at position i % 8.

        Returns:
            ceil(N / 8) bytes containing the packed bits.
        """
        # Build the packed bits as one integer, then split into little-endian bytes.
        packed_bits = sum(1 << i for i, bit in enumerate(self.data) if bit)
        return packed_bits.to_bytes(self.get_byte_length(), "little")

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
            SSZValueError: If any padding bit above the last data bit is set.
        """
        # Reject inputs whose byte count does not match the expected size.
        expected_byte_count = cls.get_byte_length()
        if len(data) != expected_byte_count:
            raise SSZValueError(
                f"{cls.__name__}: expected {expected_byte_count} bytes, got {len(data)}"
            )

        # When the bit count is not a multiple of 8, the last byte holds padding
        # bits above the highest data bit.
        # SSZ requires those padding bits to be zero so the encoding is canonical.
        # Without this check, 0b00011111 and 0b11111111 both decode to a 5-bit
        # vector of all ones.
        if trailing_bit_count := cls.LENGTH % 8:
            if data[-1] >> trailing_bit_count:
                raise SSZValueError(
                    f"{cls.__name__}: non-zero padding bits in final byte {data[-1]:#04x}"
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
    def _coerce_and_validate(cls, bits_input: Any) -> tuple[Boolean, ...]:
        """Enforce the maximum bit count and coerce inputs into booleans."""
        # Subclasses must declare LIMIT before any instances can be validated.
        if not hasattr(cls, "LIMIT"):
            raise SSZTypeError(f"{cls.__name__} must define LIMIT")

        # Accept different input shapes:
        #
        #   - list or tuple    pass through directly.
        #   - other iterables  materialize into a list so length is known.
        #   - str or bytes     rejected — iterable but elements are not booleans.
        if isinstance(bits_input, (list, tuple)):
            elements = bits_input
        elif hasattr(bits_input, "__iter__") and not isinstance(bits_input, (str, bytes)):
            elements = list(bits_input)
        else:
            raise SSZTypeError(f"Expected iterable, got {type(bits_input).__name__}")

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
        serialized_bytes = stream.read(scope)
        if len(serialized_bytes) != scope:
            raise SSZSerializationError(
                f"{cls.__name__}: expected {scope} bytes, got {len(serialized_bytes)}"
            )
        return cls.decode_bytes(serialized_bytes)

    @override
    def encode_bytes(self) -> bytes:
        """
        Encode the bitlist to SSZ bytes with a trailing delimiter.

        # Overview

        Data bits are packed little-endian within each byte.
        A single 1 bit is placed immediately after the last data bit.
        The trailing bit is what lets the decoder recover the original count.

        # Delimiter

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
        # Empty bitlist still needs the delimiter byte.
        num_bits = len(self.data)
        if num_bits == 0:
            return b"\x01"

        # Pack data bits and the delimiter into one integer.
        # The trailing 1 sentinel sits at the bit just past the data.
        # It is what lets the decoder recover the original bit count.
        # Converting an integer to bytes runs the bit-to-byte split in C.
        # That avoids a Python loop over every bit.
        packed_bits = sum(1 << i for i, bit in enumerate(self.data) if bit) | (1 << num_bits)
        return packed_bits.to_bytes(math.ceil((num_bits + 1) / 8), "little")

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

        # Integer interpretation

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
        packed_integer = int.from_bytes(data, "little")
        if packed_integer == 0:
            raise SSZSerializationError(f"{cls.__name__}: no delimiter bit found")
        delimiter_pos = packed_integer.bit_length() - 1

        # The delimiter must sit in the final byte of the input.
        # Reading the stream as one integer silently drops trailing zero bytes.
        # So a canonical encoding and one with extra zero bytes decode the same.
        # Rejecting the padded form keeps a single valid encoding per value.
        if delimiter_pos // 8 != len(data) - 1:
            raise SSZSerializationError(
                f"{cls.__name__}: non-canonical trailing zero bytes after delimiter"
            )

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
