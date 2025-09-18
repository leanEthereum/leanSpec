"""Base classes and interfaces for all SSZ types."""

from __future__ import annotations

import io
from abc import ABC, abstractmethod
from typing import IO

from typing_extensions import Self

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
    """

    ...
