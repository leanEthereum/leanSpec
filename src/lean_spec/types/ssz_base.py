"""Base classes and interfaces for all SSZ types."""

from __future__ import annotations

from typing import IO

from typing_extensions import Self


class SSZType:
    """An abstract base class for all SSZ types."""

    @classmethod
    def is_fixed_size(cls) -> bool:
        """
        Check if the type has a fixed size in bytes.

        Returns:
            bool: True if the size is fixed, False otherwise.
        """
        raise NotImplementedError

    @classmethod
    def get_byte_length(cls) -> int:
        """
        Get the byte length of the type if it is fixed-size.

        Raises:
            TypeError: If the type is not fixed-size.

        Returns:
            int: The number of bytes.
        """
        raise NotImplementedError

    def encode_bytes(self) -> bytes:
        """
        Serializes the SSZ object to a byte string.

        Returns:
            bytes: The serialized byte string.
        """
        raise NotImplementedError

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Deserializes a byte string into an SSZ object.

        Args:
            data (bytes): The byte string to deserialize.

        Returns:
            Self: An instance of the class.
        """
        raise NotImplementedError

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Serializes the object and writes it to a binary stream.

        Args:
            stream (IO[bytes]): The stream to write the serialized data to.

        Returns:
            int: The number of bytes written.
        """
        raise NotImplementedError

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Deserializes an object from a binary stream within a given scope.

        Args:
            stream (IO[bytes]): The stream to read from.
            scope (int): The number of bytes available to read for this object.

        Returns:
            Self: An instance of the class.
        """
        raise NotImplementedError
