"""Bitvector and Bitlist Type Specifications."""

from __future__ import annotations

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

_BITVECTOR_CACHE: Dict[Tuple[Type[Any], int], Type[Bitvector]] = {}
"""A cache to store and reuse dynamically generated Bitvector types."""


class Bitvector(tuple[Boolean, ...], SSZType):
    """A strict Bitvector type: a fixed-length, immutable sequence of booleans."""

    LENGTH: ClassVar[int]
    """
    The exact number of booleans in the vector.

    This will be populated in the dynamically created subclass.
    """

    def __class_getitem__(cls, length: int) -> Type[Bitvector]:  # type: ignore[override]
        """
        Create a specific, fixed-length Bitvector type.

        Args:
            length (int): The exact number of booleans for this vector type.

        Raises:
            TypeError: If the length is not a positive integer.

        Returns:
            Type[Bitvector]: A new, specialized Bitvector class.
        """
        # Parameter validation: ensure length is a positive integer.
        if not isinstance(length, int) or length <= 0:
            raise TypeError(f"Bitvector length must be a positive integer, not {length!r}.")

        # Use a cache to avoid recreating the same type.
        cache_key = (cls, length)
        if cache_key in _BITVECTOR_CACHE:
            return _BITVECTOR_CACHE[cache_key]

        # Dynamically create a new type with the specified length.
        #
        # This allows for `isinstance(my_vec, Bitvector[128])` checks.
        type_name = f"{cls.__name__}[{length}]"
        new_type = type(
            type_name,
            (cls,),
            {
                "LENGTH": length,
                "__doc__": f"A fixed-length vector of {length} booleans.",
            },
        )

        # Store the new type in the cache for future use.
        _BITVECTOR_CACHE[cache_key] = new_type
        return new_type

    def __new__(cls, values: Iterable[bool | int]) -> Self:
        """
        Create and validate a new Bitvector instance.

        Args:
            values (Iterable[bool | int]): An iterable of booleans or 0/1 integers.

        Raises:
            TypeError: If the class is not specialized (e.g., `Bitvector` instead of `Bitvector[N]`)
            ValueError: If the number of items in `values` does not match the required length

        Returns:
            Self: A new, validated instance of the Bitvector.
        """
        # Ensure this is a specialized class (e.g., `Bitvector[128]`) before instantiation.
        if not hasattr(cls, "LENGTH"):
            raise TypeError(
                "Cannot instantiate raw Bitvector; specify a length, e.g., `Bitvector[128]`."
            )

        # Convert all input values to our strict Boolean type for consistency.
        bool_values = tuple(Boolean(v) for v in values)

        # Enforce the fixed-length constraint.
        if len(bool_values) != cls.LENGTH:
            raise ValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} items, "
                f"but {len(bool_values)} were provided."
            )

        # Create the immutable tuple instance.
        return super().__new__(cls, bool_values)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Hook into Pydantic's validation system for strict, fixed-length validation."""
        # This method is called on specialized types, so `cls.LENGTH` is available.
        if not hasattr(cls, "LENGTH"):
            raise TypeError(
                "Cannot use raw Bitvector in Pydantic; specify a length, e.g., `Bitvector[128]`."
            )

        # Pydantic schema for a single boolean element.
        bool_schema = core_schema.bool_schema(strict=True)

        # Pydantic schema for a tuple of booleans with an exact length.
        tuple_validator = core_schema.tuple_variable_schema(
            items_schema=bool_schema,
            min_length=cls.LENGTH,
            max_length=cls.LENGTH,
        )

        # Validator function that takes the validated tuple and constructs our class.
        from_tuple_validator = core_schema.no_info_plain_validator_function(cls)

        return core_schema.union_schema(
            [
                # Case 1: The value is already the correct custom Bitvector type.
                core_schema.is_instance_schema(cls),
                # Case 2: The value is a tuple/list that needs to be validated and wrapped.
                core_schema.chain_schema([tuple_validator, from_tuple_validator]),
            ],
            # For serialization (e.g., to JSON), convert the instance to a plain tuple of bools.
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: tuple(bool(x) for x in v)
            ),
        )

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Return whether the type is fixed-size."""
        return True

    @classmethod
    def get_byte_length(cls) -> int:
        """Return the byte length of the type."""
        if not hasattr(cls, "LENGTH"):
            raise TypeError("Cannot get length of raw Bitvector type.")
        return (cls.LENGTH + 7) // 8

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize the bitvector to a binary stream."""
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a bitvector from a binary stream."""
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
        """Serializes the Bitvector into a byte string according to SSZ spec."""
        # Calculate the number of bytes required to hold all bits.
        byte_len = (self.LENGTH + 7) // 8
        # Create a mutable byte array to hold the result.
        byte_array = bytearray(byte_len)
        # Iterate through each bit and set the corresponding bit in the byte array.
        for i, bit in enumerate(self):
            if bit:
                byte_index = i // 8
                bit_index_in_byte = i % 8
                byte_array[byte_index] |= 1 << bit_index_in_byte
        return bytes(byte_array)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserializes a byte string into a Bitvector instance."""
        # Ensure this is a specialized class before decoding.
        if not hasattr(cls, "LENGTH"):
            raise TypeError(
                "Cannot decode to raw Bitvector; specify a length, e.g., `Bitvector[4]`."
            )
        # Check that the input data has the correct number of bytes.
        expected_byte_len = (cls.LENGTH + 7) // 8
        if len(data) != expected_byte_len:
            raise ValueError(
                f"Invalid byte length for {cls.__name__}: "
                f"expected {expected_byte_len}, got {len(data)}"
            )

        # Unpack the bits from the byte data.
        bits: List[bool] = []
        for i in range(cls.LENGTH):
            byte_index = i // 8
            bit_index_in_byte = i % 8
            # Check if the i-th bit is set in the byte array.
            bit = (data[byte_index] >> bit_index_in_byte) & 1
            bits.append(bool(bit))
        # Instantiate the class with the decoded bits.
        return cls(bits)

    def __repr__(self) -> str:
        """Return the official string representation of the object."""
        return f"{type(self).__name__}({list(self)})"


_BITLIST_CACHE: Dict[Tuple[Type[Any], int], Type[Bitlist]] = {}
"""A cache to store and reuse dynamically generated Bitlist types."""


class Bitlist(list[Boolean], SSZType):
    """
    A strict Bitlist type: a variable-length, mutable sequence of booleans
    with a maximum capacity.
    """

    LIMIT: ClassVar[int]
    """
    The maximum number of booleans this list can hold.

    This will be populated in the dynamically created subclass.
    """

    def __class_getitem__(cls, limit: int) -> Type[Bitlist]:  # type: ignore[override]
        """
        Create a specific, limited Bitlist type.

        Args:
            limit (int): The maximum number of booleans for this list type.

        Raises:
            TypeError: If the limit is not a positive integer.

        Returns:
            Type[Bitlist]: A new, specialized Bitlist class.
        """
        # Parameter validation: ensure limit is a positive integer.
        if not isinstance(limit, int) or limit <= 0:
            raise TypeError(f"Bitlist limit must be a positive integer, not {limit!r}.")

        # Use a cache to avoid recreating the same type.
        cache_key = (cls, limit)
        if cache_key in _BITLIST_CACHE:
            return _BITLIST_CACHE[cache_key]

        # Dynamically create a new type with the specified limit.
        type_name = f"{cls.__name__}[{limit}]"
        new_type = type(
            type_name,
            (cls,),
            {
                "LIMIT": limit,
                "__doc__": f"A variable-length list of booleans with a limit of {limit} items.",
            },
        )

        # Store the new type in the cache.
        _BITLIST_CACHE[cache_key] = new_type
        return new_type

    def __init__(self, values: Iterable[bool | int] = ()) -> None:
        """
        Create and validate a new Bitlist instance.

        Args:
            values (Iterable[bool | int]): An iterable of booleans or 0/1 integers.

        Raises:
            TypeError: If the class is not specialized (e.g., `Bitlist` instead of `Bitlist[N]`).
            ValueError: If the number of items in `values` exceeds the list's limit.
        """
        # Ensure this is a specialized class before instantiation.
        if not hasattr(self, "LIMIT"):
            raise TypeError(
                "Cannot instantiate raw Bitlist; specify a limit, e.g., `Bitlist[2048]`."
            )

        # Convert all input values to our strict Boolean type.
        bool_values = [Boolean(v) for v in values]

        # Enforce the length limit constraint.
        if len(bool_values) > self.LIMIT:
            raise ValueError(
                f"{type(self).__name__} has a limit of {self.LIMIT} items, "
                f"but {len(bool_values)} were provided."
            )

        # Initialize the mutable list.
        super().__init__(bool_values)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Hook into Pydantic's validation system for strict, max-length validation."""
        if not hasattr(cls, "LIMIT"):
            raise TypeError(
                "Cannot use raw Bitlist in Pydantic; specify a limit, e.g., `Bitlist[2048]`."
            )

        # Pydantic schema for a single boolean element.
        bool_schema = core_schema.bool_schema(strict=True)

        # Pydantic schema for a list of booleans with a maximum length.
        list_validator = core_schema.list_schema(
            items_schema=bool_schema,
            max_length=cls.LIMIT,
        )

        # Validator function that constructs our class from the validated list.
        from_list_validator = core_schema.no_info_plain_validator_function(cls)

        return core_schema.union_schema(
            [
                # Case 1: The value is already the correct custom Bitlist type.
                core_schema.is_instance_schema(cls),
                # Case 2: The value is a list that needs to be validated and wrapped.
                core_schema.chain_schema([list_validator, from_list_validator]),
            ],
            # For serialization, convert the instance to a plain list of bools.
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: [bool(x) for x in v]
            ),
        )

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Return whether the type is fixed-size."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Raise TypeError, as the type is variable-size."""
        raise TypeError(f"Type {cls.__name__} is not fixed-size")

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize the bitlist to a binary stream."""
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a bitlist from a binary stream."""
        data = stream.read(scope)
        if len(data) != scope:
            raise IOError(f"Stream ended prematurely while decoding {cls.__name__}")
        return cls.decode_bytes(data)

    def encode_bytes(self) -> bytes:
        """Serializes the Bitlist into a byte string with a trailing delimiter bit."""
        # Get the number of bits in the list.
        num_bits = len(self)
        if num_bits == 0:
            return b"\x01"

        byte_len = (num_bits + 7) // 8
        byte_array = bytearray(byte_len)

        # Pack the bits into the byte array.
        for i, bit in enumerate(self):
            if bit:
                byte_index = i // 8
                bit_index_in_byte = i % 8
                byte_array[byte_index] |= 1 << bit_index_in_byte

        # Add the mandatory delimiter bit.
        if num_bits % 8 == 0:
            # If the data perfectly fills the last byte, append a new byte for the delimiter.
            return bytes(byte_array) + b"\x01"
        else:
            # Otherwise, set the bit after the last data bit in the existing last byte.
            delimiter_byte_index = num_bits // 8
            delimiter_bit_index = num_bits % 8
            byte_array[delimiter_byte_index] |= 1 << delimiter_bit_index
            return bytes(byte_array)

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserializes a byte string with a delimiter bit into a Bitlist instance."""
        # Ensure this is a specialized class before decoding.
        if not hasattr(cls, "LIMIT"):
            raise TypeError("Cannot decode to raw Bitlist; specify a limit, e.g., `Bitlist[4]`.")
        # The encoded data must not be empty (it must at least contain the delimiter).
        if not data:
            raise ValueError("Invalid Bitlist encoding: data cannot be empty.")

        # The length in bits is determined by finding the position of the delimiter.
        num_bits = (len(data) - 1) * 8
        last_byte = data[-1]

        # The last byte must not be zero, as it must contain the delimiter.
        if last_byte == 0:
            raise ValueError("Invalid Bitlist encoding: last byte cannot be zero.")

        # The delimiter is the most significant bit. Its position tells us the length.
        delimiter_pos = last_byte.bit_length() - 1
        num_bits += delimiter_pos

        # The decoded length cannot exceed the type's limit.
        if num_bits > cls.LIMIT:
            raise ValueError(f"Decoded bitlist length {num_bits} exceeds limit of {cls.LIMIT}")

        # Unpack the bits from the byte data, up to the calculated length.
        bits: List[bool] = []
        for i in range(num_bits):
            byte_index = i // 8
            bit_index_in_byte = i % 8
            bit = (data[byte_index] >> bit_index_in_byte) & 1
            bits.append(bool(bit))

        return cls(bits)

    def _check_capacity(self, added_count: int) -> None:
        """Internal helper to check if adding items would exceed the limit."""
        if len(self) + added_count > self.LIMIT:
            raise ValueError(
                f"Operation exceeds {type(self).__name__} limit of {self.LIMIT} items."
            )

    def append(self, value: bool | int) -> None:
        """Append a boolean to the end of the list, checking the limit."""
        self._check_capacity(1)
        super().append(Boolean(value))

    def extend(self, values: Iterable[bool | int]) -> None:
        """Extend the list with an iterable of booleans, checking the limit."""
        bool_values = [Boolean(v) for v in values]
        self._check_capacity(len(bool_values))
        super().extend(bool_values)

    def insert(self, index: SupportsIndex, value: bool | int) -> None:
        """Insert a boolean at an index, checking the limit."""
        self._check_capacity(1)
        super().insert(index, Boolean(value))

    @overload
    def __setitem__(self, index: SupportsIndex, value: bool | int) -> None: ...

    @overload
    def __setitem__(self, s: slice, values: Iterable[bool | int]) -> None: ...

    def __setitem__(self, key: SupportsIndex | slice, value: Any) -> None:
        """Set an item or slice, checking the limit for slice assignments."""
        if isinstance(key, slice):
            bool_values = [Boolean(v) for v in value]
            # When replacing a slice, the change in length is the number of new
            # items minus the number of items being removed.
            slice_len = len(self[key])
            change_in_len = len(bool_values) - slice_len
            self._check_capacity(change_in_len)
            super().__setitem__(key, bool_values)
        else:
            super().__setitem__(key, Boolean(value))

    def __add__(self, other: list[Boolean]) -> Bitlist:  # type: ignore[override]
        """Concatenate with another list, checking the limit."""
        bool_values = [Boolean(v) for v in other]
        self._check_capacity(len(bool_values))
        new_list = list(self) + bool_values
        return type(self)(new_list)

    def __iadd__(self, other: Iterable[bool | int]) -> Self:  # type: ignore[override]
        """In-place concatenation (+=), checking the limit."""
        self.extend(other)
        return self

    def __repr__(self) -> str:
        """Return the official string representation of the object."""
        return f"{type(self).__name__}({super().__repr__()})"
