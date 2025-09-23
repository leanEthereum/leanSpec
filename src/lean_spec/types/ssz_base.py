"""Base classes and interfaces for all SSZ types."""

from __future__ import annotations

import io
from abc import ABC, abstractmethod
from typing import IO, Any

from typing_extensions import Iterator, Self

from .base import StrictBaseModel


class SSZType(ABC):
    """
    Abstract base class for all SSZ types.

    This is the minimal interface that all SSZ types must implement.
    Use SSZModel for Pydantic-based SSZ types.
    """

    @classmethod
    @abstractmethod
    def is_fixed_size(cls) -> bool:
        """
        Check if the type has a fixed size in bytes.

        Returns:
            bool: True if the size is fixed, False otherwise.
        """
        ...

    @classmethod
    @abstractmethod
    def get_byte_length(cls) -> int:
        """
        Get the byte length of the type if it is fixed-size.

        Raises:
            TypeError: If the type is not fixed-size.

        Returns:
            int: The number of bytes.
        """
        ...

    @abstractmethod
    def serialize(self, stream: IO[bytes]) -> int:
        """
        Serializes the object and writes it to a binary stream.

        Args:
            stream (IO[bytes]): The stream to write the serialized data to.

        Returns:
            int: The number of bytes written.
        """
        ...

    @classmethod
    @abstractmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Deserializes an object from a binary stream within a given scope.

        Args:
            stream (IO[bytes]): The stream to read from.
            scope (int): The number of bytes available to read for this object.

        Returns:
            Self: An instance of the class.
        """
        ...

    def encode_bytes(self) -> bytes:
        """
        Serializes the SSZ object to a byte string.

        Returns:
            bytes: The serialized byte string.
        """
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Deserializes a byte string into an SSZ object.

        Args:
            data (bytes): The byte string to deserialize.

        Returns:
            Self: An instance of the class.
        """
        with io.BytesIO(data) as stream:
            return cls.deserialize(stream, len(data))


class SSZModel(StrictBaseModel, SSZType):
    """
    Base class for SSZ types that use Pydantic validation.

    This combines StrictBaseModel (Pydantic validation + immutability) with SSZ serialization.
    Use this for containers and complex types that can benefit from Pydantic.

    For simple types that need special inheritance (like int), use SSZType directly.

    SSZModel provides natural iteration and indexing for collections with a 'data' field:
    - `for item in collection` instead of `for item in collection.data`
    - `collection[i]` instead of `collection.data[i]`
    - `len(collection)` instead of `len(collection.data)`
    """

    def __len__(self) -> int:
        """Return the length of the collection's data."""
        if hasattr(self, "data"):
            return len(self.data)
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement __len__ or have 'data' field"
        )

    def __iter__(self) -> Iterator[Any]:  # type: ignore[override]
        """
        Iterate over the collection's data if it's a collection type,
        otherwise fall back to Pydantic's field iteration.

        For SSZ collections with 'data' field, this iterates over the data contents.
        For other SSZModel types, this falls back to Pydantic's field iteration.
        """
        if hasattr(self, "data"):
            return iter(self.data)
        # Fall back to Pydantic's field iteration for non-collection types
        return super().__iter__()

    def __getitem__(self, key: Any) -> Any:
        """Get an item from the collection's data."""
        if hasattr(self, "data"):
            return self.data[key]
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement __getitem__ or have 'data' field"
        )

    def __repr__(self) -> str:
        """String representation showing the class name and data."""
        if hasattr(self, "data"):
            return f"{self.__class__.__name__}(data={list(self.data)!r})"
        return super().__repr__()
