"""SSZ Container Type."""

import io
from itertools import pairwise
from typing import IO, Any, Self, override

from pydantic import model_validator
from pydantic.functional_validators import ModelWrapValidatorHandler

from lean_spec.spec.ssz.exceptions import SSZError, SSZSerializationError, SSZTypeError
from lean_spec.spec.ssz.ssz_base import BYTES_PER_LENGTH_OFFSET, SSZModel, SSZType
from lean_spec.spec.ssz.uint import Uint32


class Container(SSZModel):
    """Ordered struct of named heterogeneous SSZ fields."""

    @model_validator(mode="wrap")
    @classmethod
    def _accept_hex_string(cls, value: Any, handler: ModelWrapValidatorHandler[Self]) -> Self:
        """
        Reconstruct the container from a hex-encoded SSZ payload.

        - Other input shapes pass through to field-by-field validation.
        - Hex strings accept an optional 0x prefix.
        """
        if isinstance(value, str):
            try:
                return cls.from_hex(value)
            except SSZError as exception:
                raise ValueError(f"invalid {cls.__name__} hex: {exception}") from exception
        return handler(value)

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """True only when every field is fixed-size."""
        return all(f.annotation.is_fixed_size() for f in cls.model_fields.values())

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """Sum of field widths; raises for variable-size containers."""
        if not cls.is_fixed_size():
            raise SSZTypeError(f"{cls.__name__}: variable-size container has no fixed byte length")
        return sum(f.annotation.get_byte_length() for f in cls.model_fields.values())

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write the fixed part with offsets, then the variable payloads."""
        field_values = [getattr(self, name) for name in type(self).model_fields]

        # Leading-part width: each slot is either the field's byte length or one offset.
        offset = sum(
            type(v).get_byte_length() if type(v).is_fixed_size() else BYTES_PER_LENGTH_OFFSET
            for v in field_values
        )

        # Variable payloads stage in a buffer while the output takes the fixed part.
        tail = io.BytesIO()
        for field_value in field_values:
            if type(field_value).is_fixed_size():
                field_value.serialize(stream)
            else:
                Uint32(offset).serialize(stream)
                offset += field_value.serialize(tail)
        stream.write(tail.getvalue())
        return offset

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read the fixed part with offsets, then each variable payload by its offset window."""
        fields: dict[str, SSZType] = {}
        variable_fields: list[tuple[str, type[SSZType], int]] = []
        bytes_read = 0

        # Phase 1: each slot is either the field itself or an offset to its tail payload.
        for name, field_definition in cls.model_fields.items():
            field_type: type[SSZType] = field_definition.annotation
            if field_type.is_fixed_size():
                width = field_type.get_byte_length()
                fields[name] = field_type.deserialize(stream, width)
                bytes_read += width
            else:
                offset = int(Uint32.deserialize(stream, BYTES_PER_LENGTH_OFFSET))
                variable_fields.append((name, field_type, offset))
                bytes_read += BYTES_PER_LENGTH_OFFSET

        if not variable_fields:
            return cls(**fields)

        # These offset checks mirror the variable-length collection decoder.
        # The duplication is intentional: inlining keeps the per-field name in each error.
        #
        # Canonical form: the first offset must point to the end of the fixed part.
        # Any other value leaves a gap or overlap, allowing two encodings of one value.
        if variable_fields[0][2] != bytes_read:
            first_offset = variable_fields[0][2]
            raise SSZSerializationError(
                f"{cls.__name__}: first offset {first_offset} != fixed-part end {bytes_read}"
            )

        # Phase 2: each variable payload spans from its offset to the next.
        # Scope closes the final span.
        boundaries = [offset for _, _, offset in variable_fields] + [scope]
        for (name, field_type, _), (start, end) in zip(
            variable_fields, pairwise(boundaries), strict=True
        ):
            if end < start:
                raise SSZSerializationError(
                    f"{cls.__name__}.{name}: non-monotonic offsets ({start} > {end})"
                )
            fields[name] = field_type.deserialize(stream, end - start)

        return cls(**fields)

    @classmethod
    def from_hex(cls, value: str) -> Self:
        """Decode from a hex string with an optional 0x prefix."""
        return cls.decode_bytes(bytes.fromhex(value.removeprefix("0x")))
