"""
SSZ Container Type: Ordered heterogeneous collections with named fields.

This module implements the SSZ Container type specification.

Containers are the primary way to define structured data in
Ethereum's serialization format.
"""

from __future__ import annotations

import inspect
import io
from typing import IO, Any

from typing_extensions import Self

from .constants import OFFSET_BYTE_LENGTH
from .exceptions import SSZSerializationError, SSZTypeError
from .ssz_base import SSZModel, SSZType
from .uint import Uint32


def _get_ssz_field_type(annotation: Any) -> type[SSZType]:
    """
    Extract the SSZType class from a field annotation, with validation.

    Args:
        annotation: The field type annotation.

    Returns:
        The SSZType class.

    Raises:
        SSZTypeCoercionError: If the annotation is not a valid SSZType class.
    """
    # Check if it's a class and is a subclass of SSZType
    if not (inspect.isclass(annotation) and issubclass(annotation, SSZType)):
        raise SSZTypeError(f"Expected SSZType subclass, got {annotation}")
    return annotation


class Container(SSZModel):
    """
    SSZ Container: A strict, ordered collection of heterogeneous named fields.

    Containers are the fundamental composite type in SSZ, similar to structs
    in C or dataclasses in Python. Each field has a name and type, and the
    serialization preserves field order.

    Inherits from SSZModel to get:
    - Pydantic validation and immutability (StrictBaseModel)
    - SSZ serialization interface (SSZType)
    - Collection methods that work with named fields

    Key properties:
    - Fields are serialized in definition order
    - Fixed-size fields are packed directly
    - Variable-size fields use offset pointers
    - Field iteration via inherited __iter__ method

    Example:
        >>> class Block(Container):
        ...     slot: Uint64
        ...     parent_root: Bytes32
        ...     state_root: Bytes32
        ...     body: Attestations  # Variable-size field

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
            _get_ssz_field_type(field.annotation).is_fixed_size()
            for field in cls.model_fields.values()
        )

    @classmethod
    def get_byte_length(cls) -> int:
        """
        Calculate the exact byte length for fixed-size containers.

        Returns:
            Total byte length of all fields summed together.

        Raises:
            SSZTypeDefinitionError: If called on a variable-size container.
        """
        # Only fixed-size containers have a deterministic byte length
        if not cls.is_fixed_size():
            raise SSZTypeError(f"{cls.__name__}: variable-size container has no fixed byte length")

        # Sum the byte lengths of all fixed-size fields
        return sum(
            _get_ssz_field_type(field.annotation).get_byte_length()
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
        for field_name in type(self).model_fields:
            # Get the field value and its type
            value = getattr(self, field_name)
            # Use the actual runtime type of the value, which should be an SSZType
            field_type = type(value)

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
        var_iter = iter(variable_data)
        for part in fixed_parts:
            if part:  # Fixed-size field data
                stream.write(part)
            else:  # Variable-size field offset
                stream.write(Uint32(offset).encode_bytes())
                offset += len(next(var_iter))

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
            SSZStreamError: If stream ends unexpectedly.
            SSZOffsetError: If offsets are invalid.
        """
        fields = {}  # Collected field values
        var_fields = []  # (name, type, offset) for variable fields
        bytes_read = 0  # Track position in fixed part

        # Phase 1: Read fixed part
        for field_name, field_info in cls.model_fields.items():
            field_type = _get_ssz_field_type(field_info.annotation)

            if field_type.is_fixed_size():
                # Read and deserialize fixed field directly
                size = field_type.get_byte_length()
                data = stream.read(size)
                if len(data) != size:
                    raise SSZSerializationError(
                        f"{cls.__name__}.{field_name}: expected {size} bytes, got {len(data)}"
                    )
                fields[field_name] = field_type.decode_bytes(data)
                bytes_read += size
            else:
                # Read offset pointer for variable field
                offset_bytes = stream.read(OFFSET_BYTE_LENGTH)
                if len(offset_bytes) != OFFSET_BYTE_LENGTH:
                    raise SSZSerializationError(
                        f"{cls.__name__}.{field_name}: "
                        f"expected {OFFSET_BYTE_LENGTH} offset bytes, got {len(offset_bytes)}"
                    )
                offset = int(Uint32.decode_bytes(offset_bytes))
                var_fields.append((field_name, field_type, offset))
                bytes_read += OFFSET_BYTE_LENGTH

        # Phase 2: Read variable part if present
        if var_fields:
            # Read entire variable section at once
            var_section_size = scope - bytes_read
            var_section = stream.read(var_section_size)
            if len(var_section) != var_section_size:
                raise SSZSerializationError(
                    f"{cls.__name__}: "
                    f"expected {var_section_size} variable bytes, got {len(var_section)}"
                )

            # Extract each variable field using offsets
            offsets = [offset for _, _, offset in var_fields] + [scope]
            for i, (name, field_type, start) in enumerate(var_fields):
                # Calculate slice boundaries relative to variable section
                end = offsets[i + 1]
                rel_start = start - bytes_read
                rel_end = end - bytes_read

                # Validate offset bounds
                if rel_start < 0 or rel_start > rel_end:
                    raise SSZSerializationError(
                        f"{cls.__name__}.{name}: invalid offsets start={start}, end={end}"
                    )

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
