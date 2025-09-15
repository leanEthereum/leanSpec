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

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema
from typing_extensions import List, Self

from .boolean import Boolean
from .ssz_base import SSZType

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
