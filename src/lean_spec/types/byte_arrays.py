"""
Byte array SSZ types.

This module provides two parameterized SSZ types:

- ByteVector[N]: a fixed-length byte vector of exactly N bytes.
- ByteList[L]:   a variable-length byte list with an upper bound of L bytes.
"""

from __future__ import annotations

from typing import IO, Any, ClassVar, Iterable, Type

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema
from typing_extensions import Iterator

from .ssz_base import SSZType


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
        s = value[2:] if value.startswith("0x") else value
        # bytes.fromhex handles empty string and validates hex characters
        return bytes.fromhex(s)
    if isinstance(value, Iterable):
        # bytes(bytearray(iterable)) enforces each element is an int in 0..255
        return bytes(bytearray(value))
    # Fall back to Python's bytes() constructor (will raise if unsupported)
    return bytes(value)


class ByteVectorBase(SSZType):
    """
    Base class for specialized `ByteVector[N]`.

    Subclasses (created by `ByteVector.__class_getitem__`) set:
      - `LENGTH`: exact number of bytes the instance must contain.

    Instances are immutable byte blobs with strict length checking.
    """

    LENGTH: ClassVar[int]  # set by the specialization factory

    def __init__(self, data: Any = b"") -> None:
        """
        Build a fixed-size byte vector.

        Args:
            data: Any value coercible to bytes (see `_coerce_to_bytes`).

        Raises:
            ValueError: if the resulting byte length differs from `LENGTH`.
        """
        b = _coerce_to_bytes(data)
        if len(b) != self.LENGTH:
            raise ValueError(
                f"ByteVector[{self.LENGTH}] expects exactly {self.LENGTH} bytes, got {len(b)}"
            )
        self._b = b

    @classmethod
    def is_fixed_size(cls) -> bool:
        """ByteVector is fixed-size (length known at the type level)."""
        return True

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Write the raw bytes to `stream`.

        Returns:
            Number of bytes written (always `LENGTH`).
        """
        stream.write(self._b)
        return len(self._b)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> ByteVectorBase:
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
        return self._b

    @classmethod
    def decode_bytes(cls, data: bytes) -> ByteVectorBase:
        """
        Parse `data` as a value of this type.

        For a fixed-size type, the data must be exactly `LENGTH` bytes.
        """
        if len(data) != cls.LENGTH:
            raise ValueError(
                f"ByteVector[{cls.LENGTH}] expects exactly {cls.LENGTH} bytes, got {len(data)}"
            )
        return cls(data)

    def __len__(self) -> int:
        """Return the length of the byte vector."""
        return self.LENGTH

    def __iter__(self) -> Iterator[int]:
        """Return an iterator over the byte vector."""
        return iter(self._b)

    def __bytes__(self) -> bytes:
        """Return the byte vector as a bytes object."""
        return self._b

    def __add__(self, other: Any) -> bytes:
        """Return the concatenation of the byte vector and the argument."""
        if isinstance(other, (bytes, bytearray)):
            return self._b + bytes(other)
        return self._b + bytes(other)

    def __radd__(self, other: Any) -> bytes:
        """Return the concatenation of the argument and the byte vector."""
        if isinstance(other, (bytes, bytearray)):
            return bytes(other) + self._b
        return bytes(other) + self._b

    def __getitem__(self, i: int) -> int:
        """Return the i-th byte of the byte vector."""
        return self._b[i]

    def __repr__(self) -> str:
        """Return a string representation of the byte vector."""
        tname = type(self).__name__
        return f"{tname}({self._b.hex()})"

    def __eq__(self, other: object) -> bool:
        """Return whether the two byte vectors are equal."""
        return isinstance(other, type(self)) and self._b == other._b

    def __hash__(self) -> int:
        """Return the hash of the byte vector."""
        return hash((type(self), self._b))

    def hex(self) -> str:
        """Return the hexadecimal string representation of the underlying bytes."""
        return self._b.hex()

    def __lt__(self, other: object) -> bool:
        """Return whether the byte vector is less than the other byte vector."""
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._b < other._b

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        Pydantic schema:

        - Accept an instance of this specialized type (pass-through).
        - Or accept any value coercible to bytes with the exact `LENGTH`.

        Serialize to raw `bytes`.
        """

        def validator(v: Any) -> ByteVectorBase:
            if isinstance(v, cls):
                return v
            return cls(v)

        def serializer(x: ByteVectorBase) -> bytes:
            return x.encode_bytes()

        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.no_info_plain_validator_function(validator),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(serializer),
        )


class ByteVector(SSZType):
    """
    Factory/entry class for `ByteVector[N]` specializations.

    Usage:
        Bytes32 = ByteVector[32]
    """

    _CACHE: ClassVar[dict[int, Type[ByteVectorBase]]] = {}

    @classmethod
    def __class_getitem__(cls, length: int) -> Type[ByteVectorBase]:
        """
        Specialize the factory into a concrete ``ByteVector[length]`` class.

        Args:
            length: Exact number of bytes the specialized type must contain (N ≥ 0).

        Returns:
            A new subclass of ``ByteVectorBase`` whose ``LENGTH`` is ``length``.

        Raises:
            TypeError: If ``length`` is not a non-negative integer.
        """
        if not isinstance(length, int) or length < 0:
            raise TypeError("ByteVector[N]: N must be a non-negative int")
        cached = cls._CACHE.get(length)
        if cached is not None:
            return cached
        name = f"ByteVector[{length}]"
        bases = (ByteVectorBase,)
        attrs = {"LENGTH": length, "__module__": cls.__module__}
        typ = type(name, bases, attrs)
        cls._CACHE[length] = typ
        return typ


class Bytes1(ByteVectorBase):
    """Fixed-size byte vector of exactly 1 byte."""

    LENGTH = 1


class Bytes4(ByteVectorBase):
    """Fixed-size byte vector of exactly 4 bytes."""

    LENGTH = 4


class Bytes8(ByteVectorBase):
    """Fixed-size byte vector of exactly 8 bytes."""

    LENGTH = 8


class Bytes32(ByteVectorBase):
    """Fixed-size byte vector of exactly 32 bytes."""

    LENGTH = 32


class Bytes48(ByteVectorBase):
    """Fixed-size byte vector of exactly 48 bytes."""

    LENGTH = 48


class Bytes96(ByteVectorBase):
    """Fixed-size byte vector of exactly 96 bytes."""

    LENGTH = 96


class ByteListBase(SSZType):
    """
    Base class for specialized `ByteList[L]`.

    Subclasses (created by `ByteList.__class_getitem__`) set:
      - `LIMIT`: maximum number of bytes the instance may contain.

    Instances are immutable byte blobs whose length can vary up to `LIMIT`.
    """

    LIMIT: ClassVar[int]
    """Maximum number of bytes the instance may contain."""

    def __init__(self, data: Any = b"") -> None:
        """
        Build a byte list, enforcing the limit.

        Args:
            data: Any value coercible to bytes (see `_coerce_to_bytes`).

        Raises:
            ValueError: if the resulting length exceeds `LIMIT`.
        """
        b = _coerce_to_bytes(data)
        if len(b) > self.LIMIT:
            raise ValueError(f"ByteList[{self.LIMIT}] length {len(b)} exceeds limit {self.LIMIT}")
        self._b = b

    @classmethod
    def is_fixed_size(cls) -> bool:
        """ByteList is variable-size (length depends on the value)."""
        return False

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Write the raw bytes to `stream`.

        Returns:
            Number of bytes written (the length of this instance).
        """
        stream.write(self._b)
        return len(self._b)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> ByteListBase:
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
        data = stream.read(scope)
        if len(data) != scope:
            raise IOError("Stream ended prematurely while decoding ByteList")
        if len(data) > cls.LIMIT:
            raise ValueError(f"ByteList[{cls.LIMIT}] decoded length {len(data)} exceeds limit")
        return cls(data)

    def encode_bytes(self) -> bytes:
        """Return the value's canonical SSZ byte representation."""
        return self._b

    @classmethod
    def decode_bytes(cls, data: bytes) -> ByteListBase:
        """
        Parse `data` as a value of this type.

        For variable-size types, the data length must be `<= LIMIT`.
        """
        if len(data) > cls.LIMIT:
            raise ValueError(f"ByteList[{cls.LIMIT}] length {len(data)} exceeds limit")
        return cls(data)

    def __len__(self) -> int:
        """Return the length of the byte list."""
        return len(self._b)

    def __iter__(self) -> Iterator[int]:
        """Return an iterator over the byte list."""
        return iter(self._b)

    def __bytes__(self) -> bytes:
        """Return the byte list as a bytes object."""
        return self._b

    def __add__(self, other: Any) -> bytes:
        """Return the concatenation of the byte list and the argument."""
        if isinstance(other, (bytes, bytearray)):
            return self._b + bytes(other)
        return self._b + bytes(other)

    def __radd__(self, other: Any) -> bytes:
        """Return the concatenation of the argument and the byte list."""
        if isinstance(other, (bytes, bytearray)):
            return bytes(other) + self._b
        return bytes(other) + self._b

    def __getitem__(self, i: int) -> int:
        """Return the i-th byte of the byte list."""
        return self._b[i]

    def __repr__(self) -> str:
        """Return a string representation of the byte list."""
        tname = type(self).__name__
        return f"{tname}({self._b.hex()})"

    def __eq__(self, other: object) -> bool:
        """Return whether the two byte lists are equal."""
        return isinstance(other, type(self)) and self._b == other._b

    def __hash__(self) -> int:
        """Return the hash of the byte list."""
        return hash((type(self), self._b))

    def hex(self) -> str:
        """Return the hexadecimal string representation of the underlying bytes."""
        return self._b.hex()

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        Pydantic schema:

        - Accept an instance of this specialized type (pass-through).
        - Or accept any value coercible to bytes whose length is `<= LIMIT`.

        Serialize to raw `bytes`.
        """

        def validator(v: Any) -> ByteListBase:
            if isinstance(v, cls):
                return v
            return cls(v)

        def serializer(x: ByteListBase) -> bytes:
            return x.encode_bytes()

        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.no_info_plain_validator_function(validator),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(serializer),
        )


class ByteList(SSZType):
    """
    Factory/entry class for `ByteList[L]` specializations.

    Usage:
        Payload = ByteList[2048]
    """

    _CACHE: ClassVar[dict[int, Type[ByteListBase]]] = {}

    @classmethod
    def __class_getitem__(cls, limit: int) -> Type[ByteListBase]:
        """
        Specialize the factory into a concrete ``ByteList[limit]`` class.

        Args:
            limit: Maximum number of bytes instances may contain (L ≥ 0).

        Returns:
            A new subclass of ``ByteListBase`` whose ``LIMIT`` is ``limit``.

        Raises:
            TypeError: If ``limit`` is not a non-negative integer.
        """
        if not isinstance(limit, int) or limit < 0:
            raise TypeError("ByteList[L]: L must be a non-negative int")
        cached = cls._CACHE.get(limit)
        if cached is not None:
            return cached
        name = f"ByteList[{limit}]"
        bases = (ByteListBase,)
        attrs = {"LIMIT": limit, "__module__": cls.__module__}
        typ = type(name, bases, attrs)
        cls._CACHE[limit] = typ
        return typ
