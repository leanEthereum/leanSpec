"""
Byte array SSZ types.

This module provides two parameterized SSZ types:

- ByteVector[N]: a fixed-length byte vector of exactly N bytes.
- ByteList[L]:   a variable-length byte list with an upper bound of L bytes.
"""

from __future__ import annotations

from typing import IO, Any, ClassVar, Iterable, SupportsIndex

from pydantic import Field, field_validator
from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import core_schema
from typing_extensions import Self

from .ssz_base import SSZModel, SSZType


def _coerce_to_bytes(value: Any) -> bytes:
    """
    Coerce a variety of inputs to raw bytes.

    Accepts:
      - `bytes` / `bytearray` (returned as immutable `bytes`)
      - Iterables of integers in [0, 255]
      - Hex strings, with or without a '0x' prefix (e.g. "0xdeadbeef" or "deadbeef")

    Raises:
      ValueError / TypeError if conversion is not possible or out-of-range.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        # bytes.fromhex handles empty string and validates hex characters
        return bytes.fromhex(value.removeprefix("0x"))
    if isinstance(value, Iterable):
        # bytes(bytearray(iterable)) enforces each element is an int in 0..255
        return bytes(bytearray(value))
    # Fall back to Python's bytes() constructor (will raise if unsupported)
    return bytes(value)


class BaseBytes(bytes, SSZType):
    """
    A base class for fixed-length byte types that inherits from `bytes`.

    Subclasses set:
      - `LENGTH`: exact number of bytes the instance must contain.

    Instances are immutable byte objects with strict length checking.
    """

    LENGTH: ClassVar[int]
    """The exact number of bytes (overridden by subclasses)."""

    def __new__(cls, value: Any = b"") -> Self:
        """
        Create and validate a new Bytes instance.

        Args:
            value: Any value coercible to bytes (see `_coerce_to_bytes`).

        Raises:
            ValueError: If the resulting byte length differs from `LENGTH`.
        """
        if not hasattr(cls, "LENGTH"):
            raise TypeError(f"{cls.__name__} must define LENGTH")

        b = _coerce_to_bytes(value)
        if len(b) != cls.LENGTH:
            raise ValueError(f"{cls.__name__} expects exactly {cls.LENGTH} bytes, got {len(b)}")
        return super().__new__(cls, b)

    @classmethod
    def zero(cls) -> Self:
        """
        Create a new instance filled with zero bytes.

        Returns:
            A new instance of this class, zero-initialized.
        """
        return cls(b"\x00" * cls.LENGTH)

    @classmethod
    def is_fixed_size(cls) -> bool:
        """ByteVector is fixed-size (length known at the type level)."""
        return True

    @classmethod
    def get_byte_length(cls) -> int:
        """Get the byte length of this fixed-size type."""
        return cls.LENGTH

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Write the raw bytes to `stream`.

        Returns:
            Number of bytes written (always `LENGTH`).
        """
        stream.write(self)
        return len(self)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Read exactly `scope` bytes from `stream` and build an instance.

        For a fixed-size type, `scope` must match `LENGTH`.

        Raises:
            ValueError: if `scope` != `LENGTH`.
            IOError: if the stream ends prematurely.
        """
        if scope != cls.LENGTH:
            raise ValueError(
                f"Invalid scope for ByteVector[{cls.LENGTH}]: expected {cls.LENGTH}, got {scope}"
            )
        data = stream.read(scope)
        if len(data) != scope:
            raise IOError("Stream ended prematurely while decoding ByteVector")
        return cls(data)

    def encode_bytes(self) -> bytes:
        """Return the value's canonical SSZ byte representation."""
        return bytes(self)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Parse `data` as a value of this type.

        For a fixed-size type, the data must be exactly `LENGTH` bytes.
        """
        if len(data) != cls.LENGTH:
            raise ValueError(f"{cls.__name__} expects exactly {cls.LENGTH} bytes, got {len(data)}")
        return cls(data)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """
        Hook into Pydantic's validation system.

        This schema defines how to handle the custom Bytes type:
        1. If the input is already an instance of the class, accept it.
        2. Otherwise, validate and coerce the input to the exact LENGTH
            and then instantiate the class.
        3. For serialization (e.g., to JSON), convert to hex string.
        """
        # Validator that takes any bytes-like input and returns an instance of the class.
        from_bytes_validator = core_schema.no_info_plain_validator_function(cls)

        # Schema that validates bytes with exact length, then calls our validator.
        python_schema = core_schema.chain_schema(
            [
                core_schema.bytes_schema(min_length=cls.LENGTH, max_length=cls.LENGTH),
                from_bytes_validator,
            ]
        )

        return core_schema.union_schema(
            [
                # Case 1: The value is already the correct type.
                core_schema.is_instance_schema(cls),
                # Case 2: The value needs to be parsed and validated.
                python_schema,
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(lambda x: x.hex()),
        )

    def __repr__(self) -> str:
        """Return a string representation of the bytes."""
        tname = type(self).__name__
        return f"{tname}({self.hex()})"

    def __hash__(self) -> int:
        """Return the hash of the bytes."""
        return hash((type(self), bytes(self)))

    def hex(self, sep: str | bytes | None = None, bytes_per_sep: SupportsIndex = 1) -> str:
        """Return the hexadecimal string representation of the underlying bytes."""
        return bytes(self).hex() if sep is None else bytes(self).hex(sep, bytes_per_sep)


class Bytes1(BaseBytes):
    """Fixed-size byte array of exactly 1 byte."""

    LENGTH = 1


class Bytes4(BaseBytes):
    """Fixed-size byte array of exactly 4 bytes."""

    LENGTH = 4


class Bytes8(BaseBytes):
    """Fixed-size byte array of exactly 8 bytes."""

    LENGTH = 8


class Bytes32(BaseBytes):
    """Fixed-size byte array of exactly 32 bytes."""

    LENGTH = 32


class Bytes48(BaseBytes):
    """Fixed-size byte array of exactly 48 bytes."""

    LENGTH = 48


class Bytes52(BaseBytes):
    """Fixed-size byte array of exactly 52 bytes."""

    LENGTH = 52


class Bytes96(BaseBytes):
    """Fixed-size byte array of exactly 96 bytes."""

    LENGTH = 96


class Bytes4000(BaseBytes):
    """Fixed-size byte array of exactly 4000 bytes."""

    # TODO: this will be removed when real signature type is implemented
    LENGTH = 4000


class BaseByteList(SSZModel):
    """
    Base class for specialized `ByteList[L]`.

    Subclasses (created by `ByteList.__class_getitem__`) set:
      - `LIMIT`: maximum number of bytes the instance may contain.

    Instances are immutable byte blobs whose length can vary up to `LIMIT`.
    """

    LIMIT: ClassVar[int]
    """Maximum number of bytes the instance may contain."""

    data: bytes = Field(default=b"")
    """The raw bytes stored in this list."""

    @field_validator("data", mode="before")
    @classmethod
    def _validate_byte_list_data(cls, v: Any) -> bytes:
        """Validate and convert input to bytes with limit checking."""
        if not hasattr(cls, "LIMIT"):
            raise TypeError(f"{cls.__name__} must define LIMIT")

        b = _coerce_to_bytes(v)
        if len(b) > cls.LIMIT:
            raise ValueError(f"ByteList[{cls.LIMIT}] length {len(b)} exceeds limit {cls.LIMIT}")
        return b

    @classmethod
    def is_fixed_size(cls) -> bool:
        """ByteList is variable-size (length depends on the value)."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """ByteList is variable-size, so this should not be called."""
        raise TypeError(f"{cls.__name__} is variable-size and has no fixed byte length")

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Write the raw bytes to `stream`.

        Returns:
            Number of bytes written (the length of this instance).
        """
        stream.write(self.data)
        return len(self.data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Read exactly `scope` bytes from `stream` and build an instance.

        For variable-size values, `scope` is provided externally (the caller
        knows how many bytes belong to this value in its context).

        Raises:
            ValueError: if the decoded length exceeds `LIMIT`.
            IOError: if the stream ends prematurely.
        """
        if scope < 0:
            raise ValueError("Invalid scope for ByteList: negative")
        if scope > cls.LIMIT:
            raise ValueError(f"ByteList[{cls.LIMIT}] scope {scope} exceeds limit")
        data = stream.read(scope)
        if len(data) != scope:
            raise IOError("Stream ended prematurely while decoding ByteList")
        return cls(data=data)

    def encode_bytes(self) -> bytes:
        """Return the value's canonical SSZ byte representation."""
        return self.data

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Parse `data` as a value of this type.

        For variable-size types, the data length must be `<= LIMIT`.
        """
        if len(data) > cls.LIMIT:
            raise ValueError(f"ByteList[{cls.LIMIT}] length {len(data)} exceeds limit")
        return cls(data=data)

    def __bytes__(self) -> bytes:
        """Return the byte list as a bytes object."""
        return self.data

    def __add__(self, other: Any) -> bytes:
        """Return the concatenation of the byte list and the argument."""
        return self.data + bytes(other)

    def __radd__(self, other: Any) -> bytes:
        """Return the concatenation of the argument and the byte list."""
        return bytes(other) + self.data

    def __repr__(self) -> str:
        """Return a string representation of the byte list."""
        tname = type(self).__name__
        return f"{tname}({self.data.hex()})"

    def __eq__(self, other: object) -> bool:
        """Return whether the two byte lists are equal."""
        return isinstance(other, type(self)) and self.data == other.data

    def __hash__(self) -> int:
        """Return the hash of the byte list."""
        return hash((type(self), self.data))

    def hex(self) -> str:
        """Return the hexadecimal string representation of the underlying bytes."""
        return self.data.hex()


# Common ByteList types with explicit classes
class ByteList64(BaseByteList):
    """Variable-length byte list with a limit of 64 bytes."""

    LIMIT = 64


class ByteList256(BaseByteList):
    """Variable-length byte list with a limit of 256 bytes."""

    LIMIT = 256


class ByteList1024(BaseByteList):
    """Variable-length byte list with a limit of 1024 bytes."""

    LIMIT = 1024


class ByteList2048(BaseByteList):
    """Variable-length byte list with a limit of 2048 bytes."""

    LIMIT = 2048
