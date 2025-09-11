"""Container Type Specification."""

from __future__ import annotations

import io
from typing import IO, Any, Dict, List, Tuple, Type, cast

from pydantic import BaseModel, ConfigDict
from typing_extensions import Self

from lean_spec.types.constants import OFFSET_BYTE_LENGTH

from .ssz_base import SSZType
from .uint import Uint32


class Container(BaseModel, SSZType):
    """
    A strict SSZ Container type: an ordered, heterogeneous collection of fields.

    Inherit from this class to define a new container structure. Field types
    must be valid SSZ types.

    Example:
        class BeaconBlockHeader(Container):
            slot: Uint64
            proposer_index: Uint64
            parent_root: Bytes32
    """

    # Configure all container subclasses to be strict and immutable by default.
    model_config = ConfigDict(strict=True, frozen=True)

    # --- SSZType Implementation ---

    @classmethod
    def is_fixed_size(cls) -> bool:
        """
        Determine if the container is a fixed-size type.

        A container is fixed-size if and only if all of its fields are fixed-size.

        Returns:
            bool: True if all fields are fixed-size, False otherwise.
        """
        # Iterate through the types of all fields defined in the model.
        for field_type in cls.model_fields.values():
            # The `annotation` attribute holds the actual type hint (e.g., `Uint64`).
            # We assume all field types are valid SSZ types and have `is_fixed_size`.
            if not cast(Type[SSZType], field_type.annotation).is_fixed_size():
                # If any field is variable-size, the container is variable-size.
                return False
        # If the loop completes, all fields are fixed-size.
        return True

    @classmethod
    def get_byte_length(cls) -> int:
        """
        Get the byte length of the container if it is fixed-size.

        Raises:
            TypeError: If the container is not fixed-size.

        Returns:
            int: The total byte length of all fields.
        """
        # A byte length can only be determined for fixed-size containers.
        if not cls.is_fixed_size():
            raise TypeError(f"{cls.__name__} is not a fixed-size type.")

        # The total length is the sum of the byte lengths of all its fields.
        return sum(
            cast(Type[SSZType], field.annotation).get_byte_length()
            for field in cls.model_fields.values()
        )

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Serialize the container to a binary stream according to SSZ rules.

        This method correctly handles the mixed serialization of fixed-size fields
        and offsets for variable-size fields.

        Args:
            stream (IO[bytes]): The stream to write the serialized data to.

        Returns:
            int: The total number of bytes written.
        """
        # Separate fields into fixed and variable parts for serialization.
        fixed_parts: List[bytes] = []
        variable_parts: List[bytes] = []

        # Iterate through all defined fields to process them in order.
        for field_name, field_info in type(self).model_fields.items():
            # Get the actual value of the field from the instance.
            value = getattr(self, field_name)
            # The field's type is its annotation (e.g., `Uint64`).
            field_type = cast(Type[SSZType], field_info.annotation)

            # Check if the field type is fixed or variable size.
            if field_type.is_fixed_size():
                # For fixed-size fields, serialize the value directly.
                fixed_parts.append(value.encode_bytes())
            else:
                # For variable-size fields, add a placeholder for the offset
                # in the fixed part and serialize the value's data into the variable part.
                fixed_parts.append(b"")  # Placeholder, will be replaced with offset.
                variable_parts.append(value.encode_bytes())

        # Calculate the starting offset for the variable data. It begins after all fixed parts.
        current_offset = sum(
            part_len if part_len > 0 else OFFSET_BYTE_LENGTH for part_len in map(len, fixed_parts)
        )

        # Write the fixed parts to the stream, replacing placeholders with calculated offsets.
        variable_part_index = 0
        for part in fixed_parts:
            # If the part is not a placeholder, write it directly.
            if part:
                stream.write(part)
            # If it is a placeholder, write the calculated offset instead.
            else:
                Uint32(current_offset).serialize(stream)
                # Update the offset for the next variable part.
                current_offset += len(variable_parts[variable_part_index])
                variable_part_index += 1

        # Write all the serialized variable data at the end of the stream.
        for part in variable_parts:
            stream.write(part)

        # The final offset value is the total number of bytes written.
        return current_offset

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Deserialize a container from a binary stream.

        Args:
            stream (IO[bytes]): The stream to read from.
            scope (int): The number of bytes available to read for this object.

        Returns:
            Self: A new instance of the container with the deserialized data.
        """
        # --- Phase 1: Read fixed data and gather variable field offsets ---
        deserialized_fields: Dict[str, Any] = {}
        variable_field_info: List[Tuple[str, Type[SSZType], int]] = []

        # Read the fixed-size portion of the data from the stream.
        fixed_data_end = 0
        for field_name, field_info in cls.model_fields.items():
            field_type = cast(Type[SSZType], field_info.annotation)

            if field_type.is_fixed_size():
                # Directly deserialize fixed-size fields.
                field_length = field_type.get_byte_length()
                field_data = stream.read(field_length)
                if len(field_data) != field_length:
                    raise IOError(f"Stream ended prematurely while decoding field '{field_name}'")
                deserialized_fields[field_name] = field_type.decode_bytes(field_data)
                fixed_data_end += field_length
            else:
                # For variable fields, read the offset and store it for later processing.
                offset_data = stream.read(OFFSET_BYTE_LENGTH)
                if len(offset_data) != OFFSET_BYTE_LENGTH:
                    raise IOError(
                        f"Stream ended prematurely while reading offset for '{field_name}'"
                    )
                offset = int(Uint32.decode_bytes(offset_data))
                variable_field_info.append((field_name, field_type, offset))
                fixed_data_end += OFFSET_BYTE_LENGTH

        # --- Phase 2: Read variable data using the collected offsets ---
        if variable_field_info:
            # Add the total scope as the final offset boundary.
            offsets = [info[2] for info in variable_field_info] + [scope]

            # Read the entire variable data block into memory.
            variable_data_length = scope - fixed_data_end
            variable_data = stream.read(variable_data_length)
            if len(variable_data) != variable_data_length:
                raise IOError("Stream ended prematurely while reading variable data block.")

            # Deserialize each variable field from its slice of the data block.
            for i in range(len(variable_field_info)):
                field_name, field_type, start_offset = variable_field_info[i]
                end_offset = offsets[i + 1]

                # The actual data slice is relative to the start of the variable block.
                slice_start = start_offset - fixed_data_end
                slice_end = end_offset - fixed_data_end

                if slice_start > slice_end or slice_start < 0:
                    raise ValueError(
                        f"Invalid offsets for field '{field_name}': start > end or start < 0"
                    )

                field_data_slice = variable_data[slice_start:slice_end]
                deserialized_fields[field_name] = field_type.decode_bytes(field_data_slice)

        # Construct the final object instance from the deserialized fields.
        return cls(**deserialized_fields)

    def encode_bytes(self) -> bytes:
        """Serializes the Container to a byte string."""
        with io.BytesIO() as stream:
            self.serialize(stream)
            return stream.getvalue()

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserializes a byte string into a Container instance."""
        with io.BytesIO(data) as stream:
            return cls.deserialize(stream, len(data))
