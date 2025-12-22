"""Vector and List Type Specifications."""

from __future__ import annotations

import io
from typing import (
    IO,
    Any,
    ClassVar,
    Generic,
    Iterator,
    Sequence,
    Type,
    TypeVar,
    cast,
    overload,
)

from pydantic import Field, field_serializer, field_validator
from typing_extensions import Self

from lean_spec.types.constants import OFFSET_BYTE_LENGTH

from .byte_arrays import BaseBytes
from .exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from .ssz_base import SSZModel, SSZType
from .uint import Uint32

T = TypeVar("T", bound=SSZType)
"""
Generic type parameter for SSZ collection elements.

This TypeVar enables proper static typing for collection access:

- Bound to `SSZType` to ensure elements are valid SSZ types
- Used with `Generic[T]` to parameterize `SSZVector` and `SSZList`
- Allows type checkers to infer correct return types for `__getitem__`

Example:
    class Uint64Vector4(SSZVector[Uint64]):
        ELEMENT_TYPE = Uint64
        LENGTH = 4

    vec = Uint64Vector4(data=[...])
    x = vec[0]  # Type checker infers `x: Uint64`
"""


class SSZVector(SSZModel, Generic[T]):
    """
    Fixed-length, immutable SSZ sequence.

    An SSZ Vector contains exactly `LENGTH` elements of type `ELEMENT_TYPE`.
    The length is fixed at the type level and cannot change at runtime.

    Subclasses must define:
        ELEMENT_TYPE: The SSZ type of each element
        LENGTH: The exact number of elements

    Example:
        class Uint16Vector2(SSZVector[Uint16]):
            ELEMENT_TYPE = Uint16
            LENGTH = 2

        vec = Uint16Vector2(data=[Uint16(1), Uint16(2)])
        assert len(vec) == 2
        assert vec[0] == Uint16(1)  # Properly typed as Uint16

    SSZ Encoding:
        - Fixed-size elements: Serialized back-to-back
        - Variable-size elements: Offset table followed by element data
    """

    ELEMENT_TYPE: ClassVar[Type[SSZType]]
    """The SSZ type of elements in this vector."""

    LENGTH: ClassVar[int]
    """The exact number of elements (fixed at the type level)."""

    data: Sequence[T] = Field(default_factory=tuple)
    """
    The immutable sequence of elements.

    Accepts lists or tuples on input; stored as a tuple after validation.
    """

    @field_serializer("data", when_used="json")
    def _serialize_data(self, value: Sequence[T]) -> list[Any]:
        """Serialize vector elements to JSON."""
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
            # Read each element's data from its calculated slice.
            for i in range(cls.LENGTH):
                start, end = offsets[i], offsets[i + 1]
                if start > end:
                    raise SSZSerializationError(
                        f"{cls.__name__}: invalid offsets start={start} > end={end}"
                    )
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
    """
    Variable-length SSZ sequence with a maximum capacity.

    An SSZ List contains between 0 and `LIMIT` elements of type `ELEMENT_TYPE`.
    Unlike Vector, the length can vary at runtime.

    Subclasses must define:
        ELEMENT_TYPE: The SSZ type of each element
        LIMIT: The maximum number of elements allowed

    Example:
        class Uint64List32(SSZList[Uint64]):
            ELEMENT_TYPE = Uint64
            LIMIT = 32

        my_list = Uint64List32(data=[Uint64(1), Uint64(2)])
        assert len(my_list) == 2
        assert my_list[0] == Uint64(1)  # Properly typed as Uint64

    SSZ Encoding:
        - Fixed-size elements: Serialized back-to-back
        - Variable-size elements: Offset table followed by element data
        - Hash tree root includes the element count (mixed-in)
    """

    ELEMENT_TYPE: ClassVar[Type[SSZType]]
    """The SSZ type of elements in this list."""

    LIMIT: ClassVar[int]
    """The maximum number of elements allowed."""

    data: Sequence[T] = Field(default_factory=tuple)
    """
    The immutable sequence of elements.

    Accepts lists or tuples on input; stored as a tuple after validation.
    """

    @field_serializer("data", when_used="json")
    def _serialize_data(self, value: Sequence[T]) -> list[Any]:
        """Serialize list elements to JSON."""
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

            # Read each element based on the calculated boundaries.
            elements = []
            for i in range(count):
                start, end = offsets[i], offsets[i + 1]
                if start > end:
                    raise SSZSerializationError(
                        f"{cls.__name__}: invalid offsets start={start} > end={end}"
                    )
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
