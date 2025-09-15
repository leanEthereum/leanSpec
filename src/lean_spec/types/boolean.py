"""Boolean Type Specification."""

from __future__ import annotations

from typing import IO, Any

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema
from typing_extensions import Self

from .ssz_base import SSZType


class Boolean(int, SSZType):
    """
    A strict SSZ Boolean type that inherits from `int` for `True`/`False` representation.

    This class provides a distinct type for SSZ booleans (`True` as `1`, `False` as `0`).

    It integrates with Pydantic for strict validation.

    It explicitly disallows standard integer arithmetic to prevent ambiguous operations.
    """

    __slots__ = ()

    def __new__(cls, value: bool | int) -> Self:
        """
        Create and validate a new Boolean instance.

        Accepts only `True`, `False`, `1`, or `0`.

        Raises:
            TypeError: If `value` is not a bool or int.
            ValueError: If `value` is an integer other than 0 or 1.
        """
        if not isinstance(value, int):
            raise TypeError(f"Expected bool or int, got {type(value).__name__}")

        int_value = int(value)
        if int_value not in (0, 1):
            raise ValueError(f"Boolean value must be 0 or 1, not {int_value}")

        return super().__new__(cls, int_value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        Hook into Pydantic's validation system for strict boolean validation.

        This schema ensures that only `True` or `False` are accepted during
        Pydantic model validation.
        """
        # Validator that takes a standard bool and returns an instance of our class.
        from_bool_validator = core_schema.no_info_plain_validator_function(cls)

        # Schema that first validates the input is a strict bool, then calls our validator.
        python_schema = core_schema.chain_schema(
            [core_schema.bool_schema(strict=True), from_bool_validator]
        )

        return core_schema.union_schema(
            [
                # Case 1: The value is already our custom Boolean type.
                core_schema.is_instance_schema(cls),
                # Case 2: The value is a standard bool and needs to be validated and wrapped.
                python_schema,
            ],
            # For serialization (e.g., to JSON), convert the instance back to a plain bool.
            serialization=core_schema.plain_serializer_function_ser_schema(bool),
        )

    @classmethod
    def is_fixed_size(cls) -> bool:
        """Return whether the type is fixed-size."""
        return True

    @classmethod
    def get_byte_length(cls) -> int:
        """Return the byte length of the type."""
        return 1

    def encode_bytes(self) -> bytes:
        r"""
        Serializes the boolean to its SSZ byte representation.
        - `True` -> `b'\\x01'`
        - `False` -> `b'\\x00'`
        """
        return b"\x01" if self else b"\x00"

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """Deserialize a single byte into a Boolean instance."""
        if len(data) != 1:
            raise ValueError(f"Expected 1 byte for Boolean, got {len(data)}")
        if data[0] not in (0, 1):
            raise ValueError(f"Boolean byte must be 0x00 or 0x01, got {data[0]:#04x}")
        return cls(data[0])

    def serialize(self, stream: IO[bytes]) -> int:
        """Serialize the boolean to a binary stream."""
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a boolean from a binary stream."""
        if scope != 1:
            raise ValueError(f"Invalid scope for Boolean: expected 1, got {scope}")
        data = stream.read(1)
        if len(data) != 1:
            raise IOError("Stream ended prematurely while decoding Boolean")
        return cls.decode_bytes(data)

    def _raise_type_error(self, other: Any, op_symbol: str) -> None:
        """Helper to raise a consistent TypeError for unsupported operations."""
        raise TypeError(
            f"Unsupported operand type(s) for {op_symbol}: "
            f"'{type(self).__name__}' and '{type(other).__name__}'"
        )

    def __add__(self, other: Any) -> Self:
        """Disable the addition operator (`+`)."""
        raise TypeError("Arithmetic operations are not supported for Boolean.")

    def __radd__(self, other: Any) -> Self:
        """Disable the reverse addition operator (`+`)."""
        raise TypeError("Arithmetic operations are not supported for Boolean.")

    def __sub__(self, other: Any) -> Self:
        """Disable the subtraction operator (`-`)."""
        raise TypeError("Arithmetic operations are not supported for Boolean.")

    def __rsub__(self, other: Any) -> Self:
        """Disable the reverse subtraction operator (`-`)."""
        raise TypeError("Arithmetic operations are not supported for Boolean.")

    def __and__(self, other: Any) -> Self:
        """Handle the bitwise AND operator (`&`) strictly."""
        if not isinstance(other, type(self)):
            self._raise_type_error(other, "&")
        return type(self)(super().__and__(other))

    def __rand__(self, other: Any) -> Self:
        """Handle the reverse bitwise AND operator (`&`) strictly."""
        return self.__and__(other)

    def __or__(self, other: Any) -> Self:
        """Handle the bitwise OR operator (`|`) strictly."""
        if not isinstance(other, type(self)):
            self._raise_type_error(other, "|")
        return type(self)(super().__or__(other))

    def __ror__(self, other: Any) -> Self:
        """Handle the reverse bitwise OR operator (`|`) strictly."""
        return self.__or__(other)

    def __xor__(self, other: Any) -> Self:
        """Handle the bitwise XOR operator (`^`) strictly."""
        if not isinstance(other, type(self)):
            self._raise_type_error(other, "^")
        return type(self)(super().__xor__(other))

    def __rxor__(self, other: Any) -> Self:
        """Handle the reverse bitwise XOR operator (`^`) strictly."""
        return self.__xor__(other)

    def __eq__(self, other: object) -> bool:
        """
        Handle the equality operator (`==`).

        Allows comparison with native `bool` and `int` types (0 or 1).

        It returns `False` for all other types.
        """
        if isinstance(other, int):
            return int(self) == int(other)
        return False

    def __ne__(self, other: object) -> bool:
        """
        Handle the inequality operator (`!=`).

        Allows comparison with native `bool` and `int` types (0 or 1).

         It returns `True` for all other types.
        """
        return not self.__eq__(other)

    def __repr__(self) -> str:
        """Return the official string representation of the object."""
        return f"Boolean({bool(self)})"

    def __str__(self) -> str:
        """Return the informal, user-friendly string representation."""
        return str(bool(self))

    def __hash__(self) -> int:
        """Return a distinct hash for the object."""
        return hash((type(self), int(self)))
