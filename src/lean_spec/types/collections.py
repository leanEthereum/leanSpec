"""Vector and List Type Specifications."""

from __future__ import annotations

import io
from typing import (
    IO,
    Any,
    ClassVar,
    Dict,
    Iterable,
    SupportsIndex,
    Tuple,
    Type,
    cast,
)

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema
from typing_extensions import Self

from lean_spec.types.constants import OFFSET_BYTE_LENGTH

from .ssz_base import SSZType
from .uint import Uint32

_VECTOR_CACHE: Dict[Tuple[Type[Vector], Type[SSZType], int], Type[Vector]] = {}
"""A cache to store and reuse dynamically generated Vector types."""


class Vector(tuple[SSZType, ...]):
    """A strict Vector type: a fixed-length, immutable sequence."""

    ELEMENT_TYPE: ClassVar[Type[SSZType]]
    """
    The SSZ type of the elements in the vector.

    These will be populated in the dynamically created subclass.
    """
    LENGTH: ClassVar[int]
    """
    The exact number of elements in the vector.

    These will be populated in the dynamically created subclass.
    """

    def __class_getitem__(cls, params: Tuple[Type[SSZType], int]) -> Type[Vector]:  # type: ignore[override]
        """
        Create a specific, fixed-length Vector type.

        Args:
            params (Tuple[Type[SSZType], int]): A tuple containing the element
                type and the exact vector length.

        Returns:
            Type[Vector]: A new, specialized Vector class.
        """
        # Parameter validation.
        if not isinstance(params, tuple) or len(params) != 2:
            raise TypeError("Usage: Vector[<element_type>, <length>]")
        element_type, length = params
        if not isinstance(length, int) or length <= 0:
            raise TypeError(f"Vector length must be a positive integer, not {length!r}.")

        # Use a cache to avoid recreating the same type.
        cache_key = (cls, element_type, length)
        if cache_key in _VECTOR_CACHE:
            return _VECTOR_CACHE[cache_key]

        # Dynamically create a new type.
        type_name = f"{cls.__name__}[{element_type.__name__},{length}]"
        new_type = type(
            type_name,
            (cls,),
            {
                "ELEMENT_TYPE": element_type,
                "LENGTH": length,
                "__doc__": f"A fixed-length vector of {length} {element_type.__name__} elements.",
            },
        )
        _VECTOR_CACHE[cache_key] = new_type
        return new_type

    def __new__(cls, values: Iterable[Any]) -> Self:
        """Create and validate a new Vector instance."""
        # Ensure this is a specialized class (e.g., `Vector[Uint8, 32]`).
        if not hasattr(cls, "ELEMENT_TYPE"):
            raise TypeError("Cannot instantiate raw Vector; specify element type and length.")

        # Coerce input values into the declared element type if they are not already.
        typed_values = tuple(
            v if isinstance(v, cls.ELEMENT_TYPE) else cast(Any, cls.ELEMENT_TYPE)(v) for v in values
        )

        # Enforce the fixed-length constraint.
        if len(typed_values) != cls.LENGTH:
            raise ValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} items, "
                f"but {len(typed_values)} were provided."
            )
        return super().__new__(cls, typed_values)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Hook into Pydantic for strict, fixed-length validation."""
        if not hasattr(cls, "ELEMENT_TYPE"):
            raise TypeError("Cannot use raw Vector in Pydantic models.")

        # Generate the Pydantic schema for the inner element type.
        # We use `generate_schema` to handle nested SSZ types correctly.
        element_schema = handler.generate_schema(cls.ELEMENT_TYPE)

        # Define a schema for a tuple with an exact length and specific item type.
        tuple_validator = core_schema.tuple_variable_schema(
            items_schema=element_schema,
            min_length=cls.LENGTH,
            max_length=cls.LENGTH,
        )

        # Validator function to construct our class from the validated tuple.
        from_tuple_validator = core_schema.no_info_plain_validator_function(cls)

        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.chain_schema([tuple_validator, from_tuple_validator]),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(tuple),
        )

    @classmethod
    def is_fixed_size(cls) -> bool:
        """A Vector is fixed-size if and only if its elements are fixed-size."""
        return cls.ELEMENT_TYPE.is_fixed_size()

    @classmethod
    def get_byte_length(cls) -> int:
        """Get the byte length if the Vector is fixed-size."""
        if not cls.is_fixed_size():
            raise TypeError(f"{cls.__name__} is not a fixed-size type.")
        return cls.ELEMENT_TYPE.get_byte_length() * cls.LENGTH

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize the vector to a binary stream."""
        # If elements are fixed-size, serialize them back-to-back.
        if self.is_fixed_size():
            total_bytes_written = 0
            for element in self:
                total_bytes_written += element.serialize(stream)
            return total_bytes_written
        # If elements are variable-size, serialize their offsets, then their data.
        else:
            # Use a temporary in-memory stream to hold the serialized variable data.
            variable_data_stream = io.BytesIO()
            # The first offset points to the end of all the offset data.
            offset = self.LENGTH * OFFSET_BYTE_LENGTH
            # Write the offsets to the main stream and the data to the temporary stream.
            for element in self:
                Uint32(offset).serialize(stream)
                offset += element.serialize(variable_data_stream)
            # Write the serialized variable data after the offsets.
            stream.write(variable_data_stream.getvalue())
            # The total bytes written is the final offset value.
            return offset

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a vector from a binary stream."""
        # If elements are fixed-size, read `LENGTH` elements of a fixed size.
        elements: list[SSZType] = []
        if cls.is_fixed_size():
            elem_byte_length = cls.get_byte_length() // cls.LENGTH
            if scope != cls.get_byte_length():
                raise ValueError(
                    f"Invalid scope for {cls.__name__}: "
                    f"expected {cls.get_byte_length()}, got {scope}"
                )
            elements = [
                cls.ELEMENT_TYPE.deserialize(stream, elem_byte_length) for _ in range(cls.LENGTH)
            ]
            return cls(elements)
        # If elements are variable-size, read offsets to determine element boundaries.
        else:
            # The first offset tells us where the data starts, which must be after all offsets.
            first_offset = int(Uint32.deserialize(stream, OFFSET_BYTE_LENGTH))
            if first_offset != cls.LENGTH * OFFSET_BYTE_LENGTH:
                raise ValueError("Invalid first offset in variable-size vector.")
            # Read the remaining offsets and add the total scope as the final boundary.
            offsets = [first_offset] + [
                int(Uint32.deserialize(stream, OFFSET_BYTE_LENGTH)) for _ in range(cls.LENGTH - 1)
            ]
            offsets.append(scope)
            # Read each element's data from its calculated slice.
            for i in range(cls.LENGTH):
                start, end = offsets[i], offsets[i + 1]
                if start > end:
                    raise ValueError(f"Invalid offsets: start {start} > end {end}")
                elements.append(cls.ELEMENT_TYPE.deserialize(stream, end - start))
            return cls(elements)

    def encode_bytes(self) -> bytes:
        """Serializes the Vector to a byte string."""
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserializes a byte string into a Vector instance."""
        with io.BytesIO(data) as stream:
            return cls.deserialize(stream, len(data))


_LIST_CACHE: Dict[Tuple[Type[List], Type[SSZType], int], Type[List]] = {}
"""A cache to store and reuse dynamically generated List types."""


class List(list[SSZType]):
    """A strict SSZ List type: a variable-length, mutable sequence with a maximum capacity."""

    LIMIT: ClassVar[int]
    """The maximum number of elements this list can hold."""
    ELEMENT_TYPE: ClassVar[Type[SSZType]]
    """The SSZ type of the elements in the list."""

    def __class_getitem__(cls, params: Tuple[Type[SSZType], int]) -> Type[List]:  # type: ignore[override]
        """Create a specific, limited List type."""
        if not isinstance(params, tuple) or len(params) != 2:
            raise TypeError("Usage: List[<element_type>, <limit>]")
        element_type, limit = params
        if not isinstance(limit, int) or limit <= 0:
            raise TypeError(f"List limit must be a positive integer, not {limit!r}.")

        cache_key = (cls, element_type, limit)
        if cache_key in _LIST_CACHE:
            return _LIST_CACHE[cache_key]

        type_name = f"{cls.__name__}[{element_type.__name__},{limit}]"
        new_type = type(
            type_name,
            (cls,),
            {
                "ELEMENT_TYPE": element_type,
                "LIMIT": limit,
                "__doc__": f"A variable-length list of {element_type.__name__} elements "
                f"with a limit of {limit}.",
            },
        )
        _LIST_CACHE[cache_key] = new_type
        return new_type

    def __init__(self, values: Iterable[Any] = ()) -> None:
        """Create and validate a new List instance."""
        if not hasattr(self, "LIMIT"):
            raise TypeError("Cannot instantiate raw List; specify element type and limit.")

        typed_values = [
            v if isinstance(v, self.ELEMENT_TYPE) else cast(Any, self.ELEMENT_TYPE)(v)
            for v in values
        ]

        if len(typed_values) > self.LIMIT:
            raise ValueError(
                f"Too many items for {type(self).__name__}: "
                f"provided {len(typed_values)}, limit is {self.LIMIT}"
            )

        super().__init__(typed_values)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Hook into Pydantic for strict, max-length validation."""
        if not hasattr(cls, "LIMIT"):
            raise TypeError("Cannot use raw List in Pydantic models.")

        element_schema = handler.generate_schema(cls.ELEMENT_TYPE)
        list_validator = core_schema.list_schema(items_schema=element_schema, max_length=cls.LIMIT)
        from_list_validator = core_schema.no_info_plain_validator_function(cls)

        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                core_schema.chain_schema([list_validator, from_list_validator]),
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(list),
        )

    @classmethod
    def is_fixed_size(cls) -> bool:
        """A List is always considered variable-size."""
        return False

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize the list to a binary stream."""
        # For fixed-size elements, serialize them back-to-back as per the spec.
        if self.ELEMENT_TYPE.is_fixed_size():
            total_bytes_written = 0
            for element in self:
                total_bytes_written += element.serialize(stream)
            return total_bytes_written

        # For variable-size elements, use offsets.
        variable_data_stream = io.BytesIO()
        offset = len(self) * OFFSET_BYTE_LENGTH
        for element in self:
            Uint32(offset).serialize(stream)
            offset += element.serialize(variable_data_stream)
        stream.write(variable_data_stream.getvalue())
        return offset

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a list from a binary stream."""
        elements: list[SSZType] = []
        # Handle fixed-size elements by reading them until the scope is consumed.
        if cls.ELEMENT_TYPE.is_fixed_size():
            if scope == 0:
                return cls([])
            elem_byte_length = cls.ELEMENT_TYPE.get_byte_length()
            if elem_byte_length == 0:
                raise ValueError("Cannot deserialize list of zero-sized elements.")
            if scope % elem_byte_length != 0:
                raise ValueError(
                    f"Invalid scope {scope} for list of {cls.ELEMENT_TYPE.__name__} "
                    f"with byte length {elem_byte_length}"
                )
            count = scope // elem_byte_length
            if count > cls.LIMIT:
                raise ValueError(f"Decoded list length {count} exceeds limit of {cls.LIMIT}")
            elements = [
                cls.ELEMENT_TYPE.deserialize(stream, elem_byte_length) for _ in range(count)
            ]
            return cls(elements)

        # For variable-size elements, use offsets.
        if scope == 0:
            return cls([])

        # Read the first offset to determine the number of elements.
        first_offset = int(Uint32.deserialize(stream, OFFSET_BYTE_LENGTH))
        if first_offset > scope or first_offset % OFFSET_BYTE_LENGTH != 0:
            raise ValueError("Invalid first offset in list.")

        count = first_offset // OFFSET_BYTE_LENGTH
        if count > cls.LIMIT:
            raise ValueError(f"Decoded list length {count} exceeds limit of {cls.LIMIT}")

        # Read the rest of the offsets.
        offsets = [first_offset] + [
            int(Uint32.deserialize(stream, OFFSET_BYTE_LENGTH)) for _ in range(count - 1)
        ]
        offsets.append(scope)

        # Read each element based on the calculated boundaries.
        for i in range(count):
            start, end = offsets[i], offsets[i + 1]
            if start > end:
                raise ValueError(f"Invalid offsets: start {start} > end {end}")
            elements.append(cls.ELEMENT_TYPE.deserialize(stream, end - start))
        return cls(elements)

    def encode_bytes(self) -> bytes:
        """Serializes the List to a byte string."""
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserializes a byte string into a List instance."""
        with io.BytesIO(data) as stream:
            return cls.deserialize(stream, len(data))

    def _check_capacity(self, added_count: int) -> None:
        """Internal helper to check if adding items would exceed the limit."""
        if len(self) + added_count > self.LIMIT:
            raise ValueError(
                f"Operation exceeds {type(self).__name__} limit of {self.LIMIT} items."
            )

    def append(self, value: Any) -> None:
        """Append an element to the end of the list, checking the limit."""
        self._check_capacity(1)
        super().append(cast(Any, self.ELEMENT_TYPE)(value))

    def extend(self, values: Iterable[Any]) -> None:
        """Extend the list with an iterable, checking the limit."""
        typed_values = [cast(Any, self.ELEMENT_TYPE)(v) for v in values]
        self._check_capacity(len(typed_values))
        super().extend(typed_values)

    def insert(self, index: SupportsIndex, value: Any) -> None:
        """Insert an element at an index, checking the limit."""
        self._check_capacity(1)
        super().insert(index, cast(Any, self.ELEMENT_TYPE)(value))
