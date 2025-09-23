"""Bitvector and Bitlist type specifications.

This module provides two SSZ (SimpleSerialize) container families:

- Bitvector[N]: fixed-length, immutable sequence of booleans.
- Bitlist[N]: variable-length, mutable sequence of booleans with max capacity N.

Both families support SSZ byte encoding/decoding:
- Bitvector packs bits little-endian within each byte (bit 0 -> LSB).
- Bitlist packs bits the same way and appends a single delimiter bit set to 1
  immediately after the last data bit (may create a new byte).

Factory types are specialized via the subscription syntax:
- Bitvector[128] produces a concrete subclass with LENGTH = 128.
- Bitlist[2048] produces a concrete subclass with LIMIT = 2048.

Specializations are cached to ensure stable identity:
Bitvector[128] is Bitvector[128].
"""

from __future__ import annotations

import abc
from typing import (
    IO,
    Any,
    ClassVar,
    Dict,
    Iterable,
    SupportsIndex,
    Tuple,
    Type,
    overload,
)

from pydantic import Field, field_validator
from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema
from typing_extensions import Iterator, List, Self

from .boolean import Boolean
from .ssz_base import SSZModel, SSZType

_BITVECTOR_CACHE: Dict[Tuple[Type[Any], int], Type["Bitvector"]] = {}
"""
Module-level cache of dynamically generated Bitvector[N] subclasses.

Cache for specialized Bitvector classes: key = (base class, length).
"""


class BitvectorType(abc.ABCMeta):
    """Metaclass that builds and caches Bitvector[N] specializations.

    Provides the `Bitvector[N]` subscription syntax by implementing __getitem__.
    Ensures each specialization is created once and reused.
    """

    def __getitem__(cls, length: int) -> Type["Bitvector"]:
        """Return a fixed-length Bitvector specialization.

        Parameters
        ----------
        length
            Exact number of bits (booleans). Must be a positive integer.

        Raises:
        ------
        TypeError
            If length is not a positive integer.

        Returns:
        -------
        Type[Bitvector]
            A subclass with LENGTH set to `length`.
        """
        # Validate the parameter early.
        if not isinstance(length, int) or length <= 0:
            raise TypeError(f"Bitvector length must be a positive integer, not {length!r}.")

        cache_key = (cls, length)
        # Reuse existing specialization if available.
        if cache_key in _BITVECTOR_CACHE:
            return _BITVECTOR_CACHE[cache_key]

        # Create a new subclass named like "Bitvector[128]".
        type_name = f"{cls.__name__}[{length}]"
        new_type = type(
            type_name,
            (cls,),
            {
                "LENGTH": length,  # attach the fixed length
                "__doc__": f"A fixed-length vector of {length} booleans.",
            },
        )

        # Cache and return.
        _BITVECTOR_CACHE[cache_key] = new_type
        return new_type


class Bitvector(tuple[Boolean, ...], SSZType, metaclass=BitvectorType):
    """Fixed-length, immutable sequence of booleans with SSZ support.

    Instances are tuples of Boolean values of exact length LENGTH.
    Use Bitvector[N] to construct a concrete class with LENGTH = N.
    """

    LENGTH: ClassVar[int]
    """Number of booleans in the vector. Set on the specialized subclass."""

    def __new__(cls, values: Iterable[bool | int]) -> Self:
        """Create and validate an instance.

        Parameters
        ----------
        values
            Iterable of booleans or 0/1 integers. Length must equal LENGTH.

        Raises:
        ------
        TypeError
            If called on the unspecialized base class.
        ValueError
            If the number of items does not match LENGTH.

        Returns:
        -------
        Self
            A validated Bitvector instance.
        """
        # Only specialized subclasses have LENGTH.
        if not hasattr(cls, "LENGTH"):
            raise TypeError(
                "Cannot instantiate raw Bitvector; specify a length, e.g., `Bitvector[128]`."
            )

        # Normalize to Boolean and freeze as a tuple.
        bool_values = tuple(Boolean(v) for v in values)

        # Enforce exact length.
        if len(bool_values) != cls.LENGTH:
            raise ValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} items, "
                f"but {len(bool_values)} were provided."
            )

        return super().__new__(cls, bool_values)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Define Pydantic v2 validation and serialization.

        Validation:
        - Accept an existing Bitvector instance (is_instance_schema).
        - Or accept a tuple of strict booleans of exact LENGTH, then coerce to Bitvector.

        Serialization:
        - Emit a plain tuple of built-in bool values.
        """
        if not hasattr(cls, "LENGTH"):
            raise TypeError(
                "Cannot use raw Bitvector in Pydantic; specify a length, e.g., `Bitvector[128]`."
            )

        # Strict boolean items (no implicit coercions by Pydantic).
        bool_schema = core_schema.bool_schema(strict=True)

        # Validate a tuple with exact LENGTH.
        tuple_validator = core_schema.tuple_variable_schema(
            items_schema=bool_schema,
            min_length=cls.LENGTH,
            max_length=cls.LENGTH,
        )

        # Convert validated tuple into a Bitvector instance.
        from_tuple_validator = core_schema.no_info_plain_validator_function(cls)

        # Union: already a Bitvector OR tuple -> Bitvector.
        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.chain_schema([tuple_validator, from_tuple_validator]),
            ],
            # Serialize as a tuple of plain bools.
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: tuple(bool(x) for x in v)
            ),
        )

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Return True. Bitvector is a fixed-size SSZ type."""
        return True

    @classmethod
    def get_byte_length(cls) -> int:
        """Return the SSZ byte length.

        Computes ceil(LENGTH / 8) using integer arithmetic.
        """
        if not hasattr(cls, "LENGTH"):
            raise TypeError("Cannot get length of raw Bitvector type.")
        return (cls.LENGTH + 7) // 8

    def serialize(self, stream: IO[bytes]) -> int:
        """Write SSZ bytes to a binary stream.

        Returns the number of bytes written.
        """
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read SSZ bytes from a stream and return an instance.

        Parameters
        ----------
        scope
            Number of bytes to read. Must equal get_byte_length().

        Raises:
        ------
        ValueError
            If scope does not match the expected byte length.
        IOError
            If the stream ends prematurely.
        """
        byte_length = cls.get_byte_length()
        if scope != byte_length:
            raise ValueError(
                f"Invalid scope for {cls.__name__}: expected {byte_length}, got {scope}"
            )
        data = stream.read(byte_length)
        if len(data) != byte_length:
            raise IOError(f"Stream ended prematurely while decoding {cls.__name__}")
        return cls.decode_bytes(data)

    def encode_bytes(self) -> bytes:
        """Encode to SSZ bytes.

        Packs bits little-endian within each byte:
        bit i goes to byte i // 8 at bit position (i % 8).
        """
        byte_len = (self.LENGTH + 7) // 8
        byte_array = bytearray(byte_len)
        for i, bit in enumerate(self):
            if bit:
                byte_index = i // 8
                bit_index_in_byte = i % 8
                byte_array[byte_index] |= 1 << bit_index_in_byte
        return bytes(byte_array)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Decode from SSZ bytes.

        Expects exactly ceil(LENGTH / 8) bytes. No delimiter bit for Bitvector.
        """
        if not hasattr(cls, "LENGTH"):
            raise TypeError(
                "Cannot decode to raw Bitvector; specify a length, e.g., `Bitvector[4]`."
            )
        expected_byte_len = (cls.LENGTH + 7) // 8
        if len(data) != expected_byte_len:
            raise ValueError(
                f"Invalid byte length for {cls.__name__}: "
                f"expected {expected_byte_len}, got {len(data)}"
            )

        # Reconstruct booleans from packed bits (little-endian per byte).
        bits: List[bool] = []
        for i in range(cls.LENGTH):
            byte_index = i // 8
            bit_index_in_byte = i % 8
            bit = (data[byte_index] >> bit_index_in_byte) & 1
            bits.append(bool(bit))
        return cls(bits)

    def __repr__(self) -> str:
        """Return a concise, informative representation."""
        return f"{type(self).__name__}({list(self)})"


_BITLIST_CACHE: Dict[Tuple[Type[Any], int], Type["Bitlist"]] = {}
"""
Module-level cache of dynamically generated Bitlist[N] subclasses.

Cache for specialized Bitlist classes: key = (base class, limit).
"""


class BitlistType(abc.ABCMeta):
    """Metaclass that builds and caches Bitlist[N] specializations.

    Provides the `Bitlist[N]` subscription syntax by implementing __getitem__.
    Ensures each specialization is created once and reused.
    """

    def __getitem__(cls, limit: int) -> Type["Bitlist"]:
        """Return a bounded-capacity Bitlist specialization.

        Parameters
        ----------
        limit
            Maximum number of booleans allowed. Must be a positive integer.

        Raises:
        ------
        TypeError
            If limit is not a positive integer.

        Returns:
        -------
        Type[Bitlist]
            A subclass with LIMIT set to `limit`.
        """
        # Validate the parameter early.
        if not isinstance(limit, int) or limit <= 0:
            raise TypeError(f"Bitlist limit must be a positive integer, not {limit!r}.")

        cache_key = (cls, limit)
        # Reuse existing specialization if available.
        if cache_key in _BITLIST_CACHE:
            return _BITLIST_CACHE[cache_key]

        # Create a new subclass named like "Bitlist[2048]".
        type_name = f"{cls.__name__}[{limit}]"
        new_type = type(
            type_name,
            (cls,),
            {
                "LIMIT": limit,  # attach the capacity limit
                "__doc__": f"A variable-length list of booleans with a limit of {limit} items.",
            },
        )

        # Cache and return.
        _BITLIST_CACHE[cache_key] = new_type
        return new_type


class Bitlist(list[Boolean], SSZType, metaclass=BitlistType):
    """Variable-length, mutable sequence of booleans with SSZ support.

    Instances are Python lists of Boolean values with length ≤ LIMIT.
    Use Bitlist[N] to construct a concrete class with LIMIT = N.
    """

    LIMIT: ClassVar[int]
    """Maximum number of booleans allowed. Set on the specialized subclass."""

    def __init__(self, values: Iterable[bool | int] = ()) -> None:
        """Create and validate an instance.

        Parameters
        ----------
        values
            Iterable of booleans or 0/1 integers. Size must be ≤ LIMIT.

        Raises:
        ------
        TypeError
            If called on the unspecialized base class.
        ValueError
            If the number of items exceeds LIMIT.
        """
        if not hasattr(self, "LIMIT"):
            raise TypeError(
                "Cannot instantiate raw Bitlist; specify a limit, e.g., `Bitlist[2048]`."
            )

        # Normalize to Boolean.
        bool_values = [Boolean(v) for v in values]

        # Enforce capacity.
        if len(bool_values) > self.LIMIT:
            raise ValueError(
                f"{type(self).__name__} has a limit of {self.LIMIT} items, "
                f"but {len(bool_values)} were provided."
            )

        super().__init__(bool_values)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Define Pydantic v2 validation and serialization.

        Validation:
        - Accept an existing Bitlist instance (is_instance_schema).
        - Or accept a list of strict booleans with length ≤ LIMIT, then coerce to Bitlist.

        Serialization:
        - Emit a plain list of built-in bool values.
        """
        if not hasattr(cls, "LIMIT"):
            raise TypeError(
                "Cannot use raw Bitlist in Pydantic; specify a limit, e.g., `Bitlist[2048]`."
            )

        # Strict boolean items.
        bool_schema = core_schema.bool_schema(strict=True)

        # Validate a list up to LIMIT elements.
        list_validator = core_schema.list_schema(
            items_schema=bool_schema,
            max_length=cls.LIMIT,
        )

        # Convert validated list into a Bitlist instance.
        from_list_validator = core_schema.no_info_plain_validator_function(cls)

        # Union: already a Bitlist OR list -> Bitlist.
        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.chain_schema([list_validator, from_list_validator]),
            ],
            # Serialize as a list of plain bools.
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: [bool(x) for x in v]
            ),
        )

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Return False. Bitlist is a variable-size SSZ type."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Bitlist is variable-size; length is not known upfront.

        Raises:
        ------
        TypeError
            Always, to signal that size is variable.
        """
        raise TypeError(f"Type {cls.__name__} is not fixed-size")

    def serialize(self, stream: IO[bytes]) -> int:
        """Write SSZ bytes to a binary stream.

        Returns the number of bytes written.
        """
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read SSZ bytes from a stream and return an instance.

        Parameters
        ----------
        scope
            Number of bytes to read. Determined externally (offset/length).

        Raises:
        ------
        IOError
            If the stream ends prematurely.
        """
        data = stream.read(scope)
        if len(data) != scope:
            raise IOError(f"Stream ended prematurely while decoding {cls.__name__}")
        return cls.decode_bytes(data)

    def encode_bytes(self) -> bytes:
        """Encode to SSZ bytes with a trailing delimiter bit.

        Data bits are packed little-endian within each byte.
        Then a single delimiter bit set to 1 is placed immediately after
        the last data bit. If the last data bit ends a byte (num_bits % 8 == 0),
        the delimiter is a new byte 0b00000001 appended at the end.
        """
        num_bits = len(self)
        if num_bits == 0:
            # Empty list: just the delimiter byte.
            return b"\x01"

        byte_len = (num_bits + 7) // 8
        byte_array = bytearray(byte_len)

        # Pack data bits.
        for i, bit in enumerate(self):
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
        """Decode from SSZ bytes with a delimiter bit.

        Rules:
        - Data cannot be empty.
        - The last byte must be nonzero (must contain the delimiter bit).
        - The delimiter is the highest set bit (most significant 1) in the last byte.
          Its zero-based position gives the offset within the last byte.
        - Total data bits = (len(data) - 1) * 8 + delimiter_pos.
        - Total data bits must be ≤ LIMIT.
        """
        if not hasattr(cls, "LIMIT"):
            raise TypeError("Cannot decode to raw Bitlist; specify a limit, e.g., `Bitlist[4]`.")
        if not data:
            raise ValueError("Invalid Bitlist encoding: data cannot be empty.")

        # Base count: all full bytes before the last contribute 8 bits each.
        num_bits = (len(data) - 1) * 8
        last_byte = data[-1]

        # Last byte must carry at least the delimiter bit.
        if last_byte == 0:
            raise ValueError("Invalid Bitlist encoding: last byte cannot be zero.")

        # Position of the delimiter is the index of the highest set bit.
        # bit_length() - 1 yields the zero-based position.
        delimiter_pos = last_byte.bit_length() - 1
        num_bits += delimiter_pos

        # Enforce capacity.
        if num_bits > cls.LIMIT:
            raise ValueError(f"Decoded bitlist length {num_bits} exceeds limit of {cls.LIMIT}")

        # Reconstruct data bits (exclude the delimiter itself).
        bits: List[bool] = []
        for i in range(num_bits):
            byte_index = i // 8
            bit_index_in_byte = i % 8
            bit = (data[byte_index] >> bit_index_in_byte) & 1
            bits.append(bool(bit))

        return cls(bits)

    def _check_capacity(self, added_count: int) -> None:
        """Validate that adding `added_count` items will not exceed LIMIT.

        Raises:
        ------
        ValueError
            If the operation would exceed LIMIT.
        """
        if len(self) + added_count > self.LIMIT:
            raise ValueError(
                f"Operation exceeds {type(self).__name__} limit of {self.LIMIT} items."
            )

    def append(self, value: bool | int) -> None:
        """Append one boolean, enforcing LIMIT."""
        self._check_capacity(1)
        super().append(Boolean(value))

    def extend(self, values: Iterable[bool | int]) -> None:
        """Extend with an iterable of booleans, enforcing LIMIT."""
        bool_values = [Boolean(v) for v in values]
        self._check_capacity(len(bool_values))
        super().extend(bool_values)

    def insert(self, index: SupportsIndex, value: bool | int) -> None:
        """Insert one boolean at a position, enforcing LIMIT."""
        self._check_capacity(1)
        super().insert(index, Boolean(value))

    @overload
    def __setitem__(self, index: SupportsIndex, value: bool | int) -> None: ...
    @overload
    def __setitem__(self, s: slice, values: Iterable[bool | int]) -> None: ...

    def __setitem__(self, key: SupportsIndex | slice, value: Any) -> None:
        """Assign an item or slice, enforcing LIMIT for slice growth.

        For slice assignment, LIMIT is checked against the net change in length.
        """
        if isinstance(key, slice):
            bool_values = [Boolean(v) for v in value]
            slice_len = len(self[key])
            change_in_len = len(bool_values) - slice_len
            self._check_capacity(change_in_len)
            super().__setitem__(key, bool_values)
        else:
            super().__setitem__(key, Boolean(value))

    def __add__(self, other: list[Boolean]) -> Bitlist:  # type: ignore[override]
        """Return a new Bitlist equal to self + other, enforcing LIMIT."""
        bool_values = [Boolean(v) for v in other]
        self._check_capacity(len(bool_values))
        new_list = list(self) + bool_values
        return type(self)(new_list)

    def __iadd__(self, other: Iterable[bool | int]) -> Self:  # type: ignore[override]
        """Extend in place with `other`, enforcing LIMIT."""
        self.extend(other)
        return self

    def __repr__(self) -> str:
        """Return a concise, informative representation."""
        return f"{type(self).__name__}({super().__repr__()})"


class BitvectorBase(SSZModel):
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

    def __len__(self) -> int:
        """Return the length of the bitvector."""
        return len(self.data)

    def __iter__(self) -> Iterator[Boolean]:  # type: ignore[override]
        """Iterate over the bitvector bits."""
        return iter(self.data)

    def __getitem__(self, i: int) -> Boolean:
        """Get a bit by index."""
        return self.data[i]

    def __repr__(self) -> str:
        """String representation of the bitvector."""
        return f"{self.__class__.__name__}(data={list(self.data)!r})"

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

        bits = []
        for i in range(cls.LENGTH):
            byte_index = i // 8
            bit_index_in_byte = i % 8
            if byte_index < len(data):
                bit_value = bool((data[byte_index] >> bit_index_in_byte) & 1)
            else:
                bit_value = False
            bits.append(bit_value)

        return cls(data=bits)


class BitlistBase(SSZModel):
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

    def __len__(self) -> int:
        """Return the number of bits in the list."""
        return len(self.data)

    def __iter__(self) -> Iterator[Boolean]:  # type: ignore[override]
        """Iterate over the list bits."""
        return iter(self.data)

    def __getitem__(self, key: int | slice) -> Boolean | list[Boolean]:
        """Get a bit by index or slice."""
        if isinstance(key, slice):
            return [self.data[i] for i in range(*key.indices(len(self.data)))]
        return self.data[key]

    def __repr__(self) -> str:
        """String representation of the bitlist."""
        return f"{self.__class__.__name__}(data={list(self.data)!r})"

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


# =============================================================================
# Concrete Bitvector Classes (Fixed-length)
# =============================================================================


class Bitvector2(BitvectorBase):
    """Fixed-length bitvector of exactly 2 bits."""

    LENGTH = 2


class Bitvector3(BitvectorBase):
    """Fixed-length bitvector of exactly 3 bits."""

    LENGTH = 3


class Bitvector4(BitvectorBase):
    """Fixed-length bitvector of exactly 4 bits."""

    LENGTH = 4


class Bitvector8(BitvectorBase):
    """Fixed-length bitvector of exactly 8 bits."""

    LENGTH = 8


class Bitvector10(BitvectorBase):
    """Fixed-length bitvector of exactly 10 bits."""

    LENGTH = 10


class Bitvector16(BitvectorBase):
    """Fixed-length bitvector of exactly 16 bits."""

    LENGTH = 16


class Bitvector512(BitvectorBase):
    """Fixed-length bitvector of exactly 512 bits."""

    LENGTH = 512


# =============================================================================
# Concrete Bitlist Classes (Variable-length)
# =============================================================================


class Bitlist3(BitlistBase):
    """Variable-length bitlist with limit of 3 bits."""

    LIMIT = 3


class Bitlist4(BitlistBase):
    """Variable-length bitlist with limit of 4 bits."""

    LIMIT = 4


class Bitlist5(BitlistBase):
    """Variable-length bitlist with limit of 5 bits."""

    LIMIT = 5


class Bitlist8(BitlistBase):
    """Variable-length bitlist with limit of 8 bits."""

    LIMIT = 8


class Bitlist10(BitlistBase):
    """Variable-length bitlist with limit of 10 bits."""

    LIMIT = 10


class Bitlist16(BitlistBase):
    """Variable-length bitlist with limit of 16 bits."""

    LIMIT = 16


class Bitlist512(BitlistBase):
    """Variable-length bitlist with limit of 512 bits."""

    LIMIT = 512
