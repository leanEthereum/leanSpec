"""Vector and List Type Specifications."""

from __future__ import annotations

import io
from typing import (
    IO,
    Any,
    ClassVar,
    Generic,
    Iterator,
    Self,
    Sequence,
    TypeVar,
    cast,
    overload,
)

from pydantic import Field, field_serializer, field_validator

from lean_spec.types.constants import OFFSET_BYTE_LENGTH

from .byte_arrays import BaseBytes
from .exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from .ssz_base import SSZModel, SSZType
from .uint import Uint32

T = TypeVar("T", bound=SSZType)
"""Generic type parameter for SSZ collection elements.

Bound to SSZType to ensure elements are valid SSZ types.
Enables type checkers to infer correct return types for indexed access.
"""


def _extract_element_type_from_generic(cls: type, origin_class: type) -> type[SSZType] | None:
    """Extract ELEMENT_TYPE from Pydantic's generic metadata."""
    for base in cls.__bases__:
        metadata = getattr(base, "__pydantic_generic_metadata__", None)
        if metadata and metadata.get("origin") is origin_class:
            args = metadata.get("args", ())
            if args:
                return cast(type[SSZType], args[0])
    return None


def _serialize_ssz_elements_to_json(value: Sequence[Any]) -> list[Any]:
    """Serialize SSZ collection elements to JSON-compatible format."""
    from lean_spec.subspecs.koalabear import Fp

    result: list[Any] = []
    for item in value:
        if isinstance(item, BaseBytes):
            result.append("0x" + item.hex())
        elif isinstance(item, Fp):
            result.append(item.value)
        else:
            result.append(item)
    return result


def _validate_offsets(offsets: list[int], scope: int, type_name: str) -> None:
    """Validate offset table before processing elements.

    Checks:

    - Offsets are monotonically non-decreasing
    - Final offset does not exceed scope
    """
    if not offsets:
        return

    for i in range(1, len(offsets)):
        if offsets[i] < offsets[i - 1]:
            raise SSZSerializationError(
                f"{type_name}: offsets not monotonically increasing: "
                f"{offsets[i - 1]} -> {offsets[i]}"
            )

    if offsets[-1] > scope:
        raise SSZSerializationError(
            f"{type_name}: final offset {offsets[-1]} exceeds scope {scope}"
        )


class SSZVector(SSZModel, Generic[T]):
    """Fixed-length, immutable SSZ sequence.

    Contains exactly LENGTH elements of type ELEMENT_TYPE.
    Length is fixed at the type level and cannot change at runtime.

    Subclasses must define LENGTH.
    ELEMENT_TYPE is auto-inferred from the generic parameter.

    SSZ encoding:

    - Fixed-size elements: serialized back-to-back
    - Variable-size elements: offset table followed by element data
    """

    ELEMENT_TYPE: ClassVar[type[SSZType]]
    """The SSZ type of elements in this vector (auto-inferred from generic parameter)."""

    LENGTH: ClassVar[int]
    """The exact number of elements (fixed at the type level)."""

    data: Sequence[T] = Field(default_factory=tuple)

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Automatically set ELEMENT_TYPE from the generic parameter."""
        super().__init_subclass__(**kwargs)

        # Skip if ELEMENT_TYPE is explicitly defined in this class
        if "ELEMENT_TYPE" in cls.__dict__:
            return

        element_type = _extract_element_type_from_generic(cls, SSZVector)
        if element_type is not None:
            cls.ELEMENT_TYPE = element_type

    @field_serializer("data", when_used="json")
    def _serialize_data(self, value: Sequence[T]) -> list[Any]:
        """Serialize vector elements to JSON."""
        return _serialize_ssz_elements_to_json(value)

    @field_validator("data", mode="before")
    @classmethod
    def _validate_vector_data(cls, v: Any) -> tuple[SSZType, ...]:
        """Validate and convert input to a typed tuple of exactly LENGTH elements."""
        if not hasattr(cls, "ELEMENT_TYPE") or not hasattr(cls, "LENGTH"):
            raise SSZTypeError(f"{cls.__name__} must define ELEMENT_TYPE and LENGTH")

        if not isinstance(v, (list, tuple)):
            v = tuple(v)

        # Convert each element to the declared type
        typed_values = tuple(
            item if isinstance(item, cls.ELEMENT_TYPE) else cast(Any, cls.ELEMENT_TYPE)(item)
            for item in v
        )

        if len(typed_values) != cls.LENGTH:
            raise SSZValueError(
                f"{cls.__name__} requires exactly {cls.LENGTH} elements, got {len(typed_values)}"
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
            raise SSZTypeError(f"{cls.__name__}: variable-size vector has no fixed byte length")
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
                raise SSZSerializationError(
                    f"{cls.__name__}: expected {cls.get_byte_length()} bytes, got {scope}"
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
                expected = cls.LENGTH * OFFSET_BYTE_LENGTH
                raise SSZSerializationError(
                    f"{cls.__name__}: invalid offset {first_offset}, expected {expected}"
                )
            # Read the remaining offsets and add the total scope as the final boundary.
            offsets = [first_offset] + [
                int(Uint32.deserialize(stream, OFFSET_BYTE_LENGTH)) for _ in range(cls.LENGTH - 1)
            ]
            offsets.append(scope)
            # Validate all offsets upfront before processing elements.
            _validate_offsets(offsets, scope, cls.__name__)
            # Read each element's data from its calculated slice.
            for i in range(cls.LENGTH):
                start, end = offsets[i], offsets[i + 1]
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

    def __iter__(self) -> Iterator[T]:  # type: ignore[override]
        """Iterate over vector elements."""
        return iter(self.data)

    @overload
    def __getitem__(self, index: int) -> T: ...
    @overload
    def __getitem__(self, index: slice) -> Sequence[T]: ...

    def __getitem__(self, index: int | slice) -> T | Sequence[T]:
        """
        Access element(s) by index or slice.

        Returns properly typed results:

        - `vec[0]` returns `T`
        - `vec[0:2]` returns `Sequence[T]`
        """
        return self.data[index]

    @property
    def elements(self) -> list[T]:
        """Return the elements as a typed list."""
        return list(self.data)


class SSZList(SSZModel, Generic[T]):
    """Variable-length SSZ sequence with a maximum capacity.

    Contains between 0 and LIMIT elements of type ELEMENT_TYPE.
    Unlike Vector, length can vary at runtime.

    Subclasses must define LIMIT.
    ELEMENT_TYPE is auto-inferred from the generic parameter.

    SSZ encoding:

    - Fixed-size elements: serialized back-to-back
    - Variable-size elements: offset table followed by element data
    - Hash tree root includes element count (mixed-in)
    """

    ELEMENT_TYPE: ClassVar[type[SSZType]]
    """The SSZ type of elements in this list (auto-inferred from generic parameter)."""

    LIMIT: ClassVar[int]
    """The maximum number of elements allowed."""

    data: Sequence[T] = Field(default_factory=tuple)
    """The immutable sequence of elements."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Automatically set ELEMENT_TYPE from the generic parameter."""
        super().__init_subclass__(**kwargs)

        # Skip if ELEMENT_TYPE is explicitly defined in this class
        if "ELEMENT_TYPE" in cls.__dict__:
            return

        element_type = _extract_element_type_from_generic(cls, SSZList)
        if element_type is not None:
            cls.ELEMENT_TYPE = element_type

    @field_serializer("data", when_used="json")
    def _serialize_data(self, value: Sequence[T]) -> list[Any]:
        """Serialize list elements to JSON."""
        return _serialize_ssz_elements_to_json(value)

    @field_validator("data", mode="before")
    @classmethod
    def _validate_list_data(cls, v: Any) -> tuple[SSZType, ...]:
        """Validate and convert input to a tuple of SSZType elements."""
        if not hasattr(cls, "ELEMENT_TYPE") or not hasattr(cls, "LIMIT"):
            raise SSZTypeError(f"{cls.__name__} must define ELEMENT_TYPE and LIMIT")

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

        # Convert and validate each element
        typed_values = []
        for element in elements:
            if isinstance(element, cls.ELEMENT_TYPE):
                typed_values.append(element)
            else:
                try:
                    typed_values.append(cast(Any, cls.ELEMENT_TYPE)(element))
                except Exception as e:
                    raise SSZTypeError(
                        f"Expected {cls.ELEMENT_TYPE.__name__}, got {type(element).__name__}"
                    ) from e

        return tuple(typed_values)

    def __add__(self, other: Any) -> Self:
        """Concatenate this list with another sequence."""
        if isinstance(other, SSZList):
            new_data = self.data + other.data
        elif isinstance(other, (list, tuple)):
            new_data = tuple(self.data) + tuple(other)
        else:
            return NotImplemented
        return type(self)(data=new_data)

    @classmethod
    def is_fixed_size(cls) -> bool:
        """An SSZList is never fixed-size (length varies from 0 to LIMIT)."""
        return False

    @classmethod
    def get_byte_length(cls) -> int:
        """Lists are variable-size, so this raises an SSZTypeError."""
        raise SSZTypeError(f"{cls.__name__}: variable-size list has no fixed byte length")

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
                raise SSZSerializationError(
                    f"{cls.__name__}: scope {scope} not divisible by element size {element_size}"
                )

            num_elements = scope // element_size
            if num_elements > cls.LIMIT:
                raise SSZValueError(
                    f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {num_elements}"
                )

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
                raise SSZSerializationError(
                    f"{cls.__name__}: scope {scope} too small for variable-size list"
                )

            # Read the first offset to determine the number of elements.
            first_offset = int(Uint32.deserialize(stream, OFFSET_BYTE_LENGTH))
            if first_offset > scope or first_offset % OFFSET_BYTE_LENGTH != 0:
                raise SSZSerializationError(f"{cls.__name__}: invalid offset {first_offset}")

            count = first_offset // OFFSET_BYTE_LENGTH
            if count > cls.LIMIT:
                raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {count}")

            # Read the rest of the offsets.
            offsets = [first_offset] + [
                int(Uint32.deserialize(stream, OFFSET_BYTE_LENGTH)) for _ in range(count - 1)
            ]
            offsets.append(scope)
            # Validate all offsets upfront before processing elements.
            _validate_offsets(offsets, scope, cls.__name__)
            # Read each element based on the calculated boundaries.
            elements = []
            for i in range(count):
                start, end = offsets[i], offsets[i + 1]
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

    def __iter__(self) -> Iterator[T]:  # type: ignore[override]
        """Iterate over list elements."""
        return iter(self.data)

    @overload
    def __getitem__(self, index: int) -> T: ...
    @overload
    def __getitem__(self, index: slice) -> Sequence[T]: ...

    def __getitem__(self, index: int | slice) -> T | Sequence[T]:
        """
        Access element(s) by index or slice.

        Returns properly typed results:

        - `lst[0]` returns `T`
        - `lst[0:2]` returns `Sequence[T]`
        """
        return self.data[index]

    @property
    def elements(self) -> list[T]:
        """Return the elements as a typed list."""
        return list(self.data)
