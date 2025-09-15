"""
SSZ Container Type: Ordered heterogeneous collections with named fields.

This module implements the SSZ Container type specification.

Containers are the primary way to define structured data in
Ethereum's serialization format.
"""

from __future__ import annotations

import io
from typing import IO, Type, cast

from typing_extensions import Self

from .base import StrictBaseModel
from .constants import OFFSET_BYTE_LENGTH
from .ssz_base import SSZType
from .uint import Uint32


class Container(StrictBaseModel, SSZType):
    """
    SSZ Container: A strict, ordered collection of heterogeneous named fields.

    Containers are the fundamental composite type in SSZ, similar to structs
    in C or dataclasses in Python. Each field has a name and type, and the
    serialization preserves field order.

    Key properties:
    - Fields are serialized in definition order
    - Fixed-size fields are packed directly
    - Variable-size fields use offset pointers
    - Inherits Pydantic validation for type safety

    Example:
        >>> class Block(Container):
        ...     slot: Uint64
        ...     parent_root: Bytes32
        ...     state_root: Bytes32
        ...     body: List[Transaction, 1024]  # Variable-size field

    Serialization format:
        [fixed_field_1][fixed_field_2]...[offset_1][offset_2]...[variable_data_1][variable_data_2]...
    """

    @classmethod
    def is_fixed_size(cls) -> bool:
        """
        Check if this container has a fixed byte length.

        A container is fixed-size only when ALL its fields are fixed-size.
        This affects how the container is serialized and merkleized.

        Returns:
            True if all fields have fixed size, False if any field is variable.
        """
        # Check each field's type for fixed size property
        return all(
            cast(Type[SSZType], field.annotation).is_fixed_size()
            for field in cls.model_fields.values()
        )

    @classmethod
    def get_byte_length(cls) -> int:
        """
        Calculate the exact byte length for fixed-size containers.

        Returns:
            Total byte length of all fields summed together.

        Raises:
            TypeError: If called on a variable-size container.
        """
        # Only fixed-size containers have a deterministic byte length
        if not cls.is_fixed_size():
            raise TypeError(f"{cls.__name__} is variable-size")

        # Sum the byte lengths of all fixed-size fields
        return sum(
            cast(Type[SSZType], field.annotation).get_byte_length()
            for field in cls.model_fields.values()
        )

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Serialize container to bytes following SSZ specification.

        SSZ serialization uses a two-part format:
        1. Fixed part: Fixed-size fields and offsets for variable fields
        2. Variable part: Actual data of variable-size fields

        Args:
            stream: Binary stream to write serialized bytes to.

        Returns:
            Number of bytes written to the stream.
        """
        # Collect serialized field data
        #
        # Fixed-size field bytes or empty for variable fields
        fixed_parts = []
        # Actual data for variable-size fields
        variable_data = []

        # Process each field in definition order
        for field_name, field_info in type(self).model_fields.items():
            # Get the field value and its type
            value = getattr(self, field_name)
            field_type = cast(Type[SSZType], field_info.annotation)

            # Serialize based on field type
            if field_type.is_fixed_size():
                # Fixed fields go directly in the fixed part
                fixed_parts.append(value.encode_bytes())
            else:
                # Variable fields: placeholder in fixed part, data in variable part
                #
                # Will be replaced with offset
                fixed_parts.append(b"")
                variable_data.append(value.encode_bytes())

        # Calculate where variable data starts (after all fixed parts)
        offset = sum(len(part) if part else OFFSET_BYTE_LENGTH for part in fixed_parts)

        # Write fixed part with calculated offsets
        var_index = 0
        for part in fixed_parts:
            if part:  # Fixed-size field data
                stream.write(part)
            else:  # Variable-size field offset
                Uint32(offset).serialize(stream)
                offset += len(variable_data[var_index])
                var_index += 1

        # Append all variable data at the end
        for data in variable_data:
            stream.write(data)

        return offset  # Total bytes written

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Deserialize container from byte stream.

        Reverses the serialization process by:
        1. Reading fixed fields and offsets from the fixed part
        2. Using offsets to locate and read variable field data

        Args:
            stream: Binary stream to read from.
            scope: Total bytes available for this container.

        Returns:
            New container instance with deserialized values.

        Raises:
            IOError: If stream ends unexpectedly.
            ValueError: If offsets are invalid.
        """
        fields = {}  # Collected field values
        var_fields = []  # (name, type, offset) for variable fields
        bytes_read = 0  # Track position in fixed part

        # Phase 1: Read fixed part
        for field_name, field_info in cls.model_fields.items():
            field_type = cast(Type[SSZType], field_info.annotation)

            if field_type.is_fixed_size():
                # Read and deserialize fixed field directly
                size = field_type.get_byte_length()
                data = stream.read(size)
                if len(data) != size:
                    raise IOError(f"Unexpected EOF reading {field_name}")
                fields[field_name] = field_type.decode_bytes(data)
                bytes_read += size
            else:
                # Read offset pointer for variable field
                offset_bytes = stream.read(OFFSET_BYTE_LENGTH)
                if len(offset_bytes) != OFFSET_BYTE_LENGTH:
                    raise IOError(f"Unexpected EOF reading offset for {field_name}")
                offset = int(Uint32.decode_bytes(offset_bytes))
                var_fields.append((field_name, field_type, offset))
                bytes_read += OFFSET_BYTE_LENGTH

        # Phase 2: Read variable part if present
        if var_fields:
            # Read entire variable section at once
            var_section_size = scope - bytes_read
            var_section = stream.read(var_section_size)
            if len(var_section) != var_section_size:
                raise IOError("Unexpected EOF in variable section")

            # Extract each variable field using offsets
            offsets = [offset for _, _, offset in var_fields] + [scope]
            for i, (name, field_type, start) in enumerate(var_fields):
                # Calculate slice boundaries relative to variable section
                end = offsets[i + 1]
                rel_start = start - bytes_read
                rel_end = end - bytes_read

                # Validate offset bounds
                if rel_start < 0 or rel_start > rel_end:
                    raise ValueError(f"Invalid offsets for {name}")

                # Deserialize field from its slice
                field_data = var_section[rel_start:rel_end]
                fields[name] = field_type.decode_bytes(field_data)

        # Construct container with all fields
        return cls(**fields)

    def encode_bytes(self) -> bytes:
        """
        Encode container to bytes.

        Returns:
            Serialized container as bytes.
        """
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Decode container from bytes.

        Args:
            data: Serialized container bytes.

        Returns:
            Deserialized container instance.
        """
        with io.BytesIO(data) as stream:
            return cls.deserialize(stream, len(data))
