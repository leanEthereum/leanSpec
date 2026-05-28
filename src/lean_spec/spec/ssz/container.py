"""SSZ Container Type."""

import io
from itertools import pairwise
from typing import IO, Self, override

from .exceptions import SSZSerializationError, SSZTypeError
from .ssz_base import BYTES_PER_LENGTH_OFFSET, SSZModel, SSZType
from .uint import Uint32


class Container(SSZModel):
    """Ordered struct of named heterogeneous SSZ fields."""

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
        values = [getattr(self, name) for name in type(self).model_fields]

        # Leading-part width: each slot is either the field's byte length or one offset.
        offset = sum(
            type(v).get_byte_length() if type(v).is_fixed_size() else BYTES_PER_LENGTH_OFFSET
            for v in values
        )

        # Variable payloads stage in a buffer while the output takes the fixed part.
        tail = io.BytesIO()
        for value in values:
            if type(value).is_fixed_size():
                value.serialize(stream)
            else:
                Uint32(offset).serialize(stream)
                offset += value.serialize(tail)
        stream.write(tail.getvalue())
        return offset

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Read the fixed part with offsets, then each variable payload by its offset window."""
        fields: dict[str, SSZType] = {}
        var_fields: list[tuple[str, type[SSZType], int]] = []
        bytes_read = 0

        # Phase 1: each slot is either the field itself or an offset to its tail payload.
        for name, info in cls.model_fields.items():
            ftype: type[SSZType] = info.annotation
            if ftype.is_fixed_size():
                width = ftype.get_byte_length()
                fields[name] = ftype.deserialize(stream, width)
                bytes_read += width
            else:
                offset = int(Uint32.deserialize(stream, BYTES_PER_LENGTH_OFFSET))
                var_fields.append((name, ftype, offset))
                bytes_read += BYTES_PER_LENGTH_OFFSET

        if not var_fields:
            return cls(**fields)

        # Canonical form: the first offset must point to the end of the fixed part.
        # Any other value leaves a gap or overlap, allowing two encodings of one value.
        if var_fields[0][2] != bytes_read:
            raise SSZSerializationError(
                f"{cls.__name__}: first offset {var_fields[0][2]} != fixed-part end {bytes_read}"
            )

        # Phase 2: each variable payload spans from its offset to the next.
        # Scope closes the final span.
        boundaries = [o for _, _, o in var_fields] + [scope]
        for (name, ftype, _), (start, end) in zip(var_fields, pairwise(boundaries), strict=True):
            if end < start:
                raise SSZSerializationError(
                    f"{cls.__name__}.{name}: non-monotonic offsets ({start} > {end})"
                )
            fields[name] = ftype.deserialize(stream, end - start)

        return cls(**fields)

    @classmethod
    def from_hex(cls, value: str) -> Self:
        """Decode from a hex string with an optional 0x prefix."""
        return cls.decode_bytes(bytes.fromhex(value.removeprefix("0x")))
