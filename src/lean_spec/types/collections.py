"""Vector and List Type Specifications."""

from __future__ import annotations

import io
from typing import (
    IO,
    Any,
    ClassVar,
    Tuple,
    Type,
    cast,
)

from pydantic import Field, field_serializer, field_validator
from typing_extensions import Self

from lean_spec.types.constants import OFFSET_BYTE_LENGTH

from .byte_arrays import BaseBytes
from .ssz_base import SSZModel, SSZType
from .uint import Uint32


class SSZVector(SSZModel):
    """
    Base class for SSZ Vector types: fixed-length, immutable sequences.

    To create a specific vector type, inherit from this class and set:
    - ELEMENT_TYPE: The SSZ type of elements
    - LENGTH: The exact number of elements

    Example:
        class Uint16Vector2(SSZVector):
            ELEMENT_TYPE = Uint16
            LENGTH = 2
    """

    ELEMENT_TYPE: ClassVar[Type[SSZType]]
    """The SSZ type of the elements in the vector."""

    LENGTH: ClassVar[int]
    """The exact number of elements in the vector."""

    data: Tuple[SSZType, ...] = Field(default_factory=tuple)
    """The immutable data stored in the vector."""

    @field_serializer("data", when_used="json")
    def _serialize_data(self, value: Tuple[SSZType, ...]) -> list[Any]:
        """Serialize vector elements to JSON, preserving custom type serialization."""
        from lean_spec.subspecs.koalabear import Fp

        result: list[Any] = []
        for item in value:
            # For BaseBytes subclasses, manually add 0x prefix
            if isinstance(item, BaseBytes):
                result.append("0x" + item.hex())
            # For Fp field elements, extract the value attribute
            elif isinstance(item, Fp):
                result.append(item.value)
            else:
                # For other types (Uint, etc.), convert to int
                # BaseUint inherits from int, so this cast is safe
                result.append(item)
        return result

    @field_validator("data", mode="before")
    @classmethod
    def _validate_vector_data(cls, v: Any) -> Tuple[SSZType, ...]:
        """Validate and convert input data to typed tuple."""
        if not hasattr(cls, "ELEMENT_TYPE") or not hasattr(cls, "LENGTH"):
            raise TypeError(f"{cls.__name__} must define ELEMENT_TYPE and LENGTH")

        if not isinstance(v, (list, tuple)):
            v = tuple(v)

        # Convert each element to the declared type
        typed_values = tuple(
            item if isinstance(item, cls.ELEMENT_TYPE) else cast(Any, cls.ELEMENT_TYPE)(item)
            for item in v
        )

        if len(typed_values) != cls.LENGTH:
            raise ValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} items, "
                f"but {len(typed_values)} were provided."
            )

        return typed_values

    @classmethod
    def is_fixed_size(cls) -> bool:
        """An SSZVector is fixed-size if and only if its elements are fixed-size."""
        return cls.ELEMENT_TYPE.is_fixed_size()

    @classmethod
    def get_byte_length(cls) -> int:
        """Get the byte length if the SSZVector is fixed-size."""
        if not cls.is_fixed_size():
            raise TypeError(f"{cls.__name__} is not a fixed-size type.")
        return cls.ELEMENT_TYPE.get_byte_length() * cls.LENGTH

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize the vector to a binary stream."""
        # If elements are fixed-size, serialize them back-to-back.
        if self.is_fixed_size():
            return sum(element.serialize(stream) for element in self.data)
        # If elements are variable-size, serialize their offsets, then their data.
        else:
            # Use a temporary in-memory stream to hold the serialized variable data.
            variable_data_stream = io.BytesIO()
            # The first offset points to the end of all the offset data.
            offset = self.LENGTH * OFFSET_BYTE_LENGTH
            # Write the offsets to the main stream and the data to the temporary stream.
            for element in self.data:
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
            return cls(data=elements)
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
            return cls(data=elements)

    def encode_bytes(self) -> bytes:
        """Serializes the SSZVector to a byte string."""
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserializes a byte string into an SSZVector instance."""
        with io.BytesIO(data) as stream:
            return cls.deserialize(stream, len(data))

    def __len__(self) -> int:
        """Return the number of elements in the vector."""
        return len(self.data)

    def __getitem__(self, index: int) -> SSZType:
        """Access an element by index."""
        return self.data[index]


class SSZList(SSZModel):
    """
    Base class for SSZ List types - variable-length homogeneous collections.

    An SSZ List is a sequence that can contain between 0 and LIMIT elements,
    where all elements must be of the same SSZ type.

    Subclasses must define:
    - ELEMENT_TYPE: The SSZ type of elements in the list
    - LIMIT: Maximum number of elements allowed

    Example usage:
        class Uint64List32(SSZList):
            ELEMENT_TYPE = Uint64
            LIMIT = 32

        my_list = Uint64List32(data=[1, 2, 3])
    """

    ELEMENT_TYPE: ClassVar[Type[SSZType]]
    """The SSZ type of elements in this list."""

    LIMIT: ClassVar[int]
    """Maximum number of elements this list can contain."""

    data: Tuple[SSZType, ...] = Field(default_factory=tuple)
    """The elements in this list, stored as an immutable tuple."""

    @field_serializer("data", when_used="json")
    def _serialize_data(self, value: Tuple[SSZType, ...]) -> list[Any]:
        """Serialize list elements to JSON, preserving custom type serialization."""
        from lean_spec.subspecs.koalabear import Fp

        result: list[Any] = []
        for item in value:
            # For BaseBytes subclasses, manually add 0x prefix
            if isinstance(item, BaseBytes):
                result.append("0x" + item.hex())
            # For Fp field elements, extract the value attribute
            elif isinstance(item, Fp):
                result.append(item.value)
            else:
                # For other types (Uint, etc.), convert to int
                # BaseUint inherits from int, so this cast is safe
                result.append(item)
        return result

    @field_validator("data", mode="before")
    @classmethod
    def _validate_list_data(cls, v: Any) -> Tuple[SSZType, ...]:
        """Validate and convert input to a tuple of SSZType elements."""
        if not hasattr(cls, "ELEMENT_TYPE") or not hasattr(cls, "LIMIT"):
            raise TypeError(f"{cls.__name__} must define ELEMENT_TYPE and LIMIT")

        # Handle various input types
        if isinstance(v, (list, tuple)):
            elements = v
        elif hasattr(v, "__iter__") and not isinstance(v, (str, bytes)):
            elements = list(v)
        else:
            raise TypeError(f"List data must be iterable, got {type(v)}")

        # Check limit
        if len(elements) > cls.LIMIT:
            raise ValueError(
                f"{cls.__name__} cannot contain more than {cls.LIMIT} elements, got {len(elements)}"
            )

        # Convert and validate each element
        typed_values = []
        for i, element in enumerate(elements):
            if isinstance(element, cls.ELEMENT_TYPE):
                typed_values.append(element)
            else:
                try:
                    typed_values.append(cast(Any, cls.ELEMENT_TYPE)(element))
                except Exception as e:
                    raise ValueError(
                        f"Element {i} cannot be converted to {cls.ELEMENT_TYPE.__name__}: {e}"
                    ) from e

        return tuple(typed_values)

    def __add__(self, other: Any) -> Self:
        """Concatenate this list with another sequence."""
        if isinstance(other, SSZList):
            new_data = self.data + other.data
        elif isinstance(other, (list, tuple)):
            new_data = self.data + tuple(other)
        else:
            return NotImplemented
        return type(self)(data=new_data)

    @classmethod
    def is_fixed_size(cls) -> bool:
        """An SSZList is never fixed-size (length varies from 0 to LIMIT)."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Lists are variable-size, so this raises a TypeError."""
        raise TypeError(f"{cls.__name__} is variable-size")

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize the list to a binary stream."""
        # Lists are always variable-size, so we serialize offsets + data
        if self.ELEMENT_TYPE.is_fixed_size():
            # Fixed-size elements: serialize them back-to-back
            return sum(element.serialize(stream) for element in self.data)
        else:
            # Variable-size elements: serialize offsets, then data
            variable_data_stream = io.BytesIO()
            # The first offset points to the end of all the offset data
            offset = len(self.data) * OFFSET_BYTE_LENGTH
            # Write the offsets to the main stream and the data to the temporary stream
            for element in self.data:
                Uint32(offset).serialize(stream)
                offset += element.serialize(variable_data_stream)
            # Write the serialized variable data after the offsets
            stream.write(variable_data_stream.getvalue())
            # The total bytes written is the final offset value
            return offset

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a list from a binary stream."""
        if cls.ELEMENT_TYPE.is_fixed_size():
            # Fixed-size elements: read them back-to-back
            element_size = cls.ELEMENT_TYPE.get_byte_length()
            if scope % element_size != 0:
                raise ValueError(f"Scope {scope} is not divisible by element size {element_size}")

            num_elements = scope // element_size
            if num_elements > cls.LIMIT:
                raise ValueError(f"Too many elements: {num_elements} > {cls.LIMIT}")

            elements = [
                cls.ELEMENT_TYPE.deserialize(stream, element_size) for _ in range(num_elements)
            ]

            return cls(data=elements)
        else:
            # Variable-size elements: read offsets first, then data
            if scope == 0:
                # Empty list case
                return cls(data=[])
            if scope < OFFSET_BYTE_LENGTH:
                raise ValueError(f"Invalid scope for variable-size list: {scope}")

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
            elements = []
            for i in range(count):
                start, end = offsets[i], offsets[i + 1]
                if start > end:
                    raise ValueError(f"Invalid offsets: start {start} > end {end}")
                elements.append(cls.ELEMENT_TYPE.deserialize(stream, end - start))

            return cls(data=elements)

    def encode_bytes(self) -> bytes:
        """Return the list's canonical SSZ byte representation."""
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserializes a byte string into an SSZList instance."""
        with io.BytesIO(data) as stream:
            return cls.deserialize(stream, len(data))

    def __len__(self) -> int:
        """Return the number of elements in the list."""
        return len(self.data)

    def __getitem__(self, index: int) -> SSZType:
        """Access an element by index."""
        return self.data[index]
