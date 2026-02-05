"""Unsigned Integer Type Specification."""

from __future__ import annotations

from typing import IO, Any, ClassVar, Literal, Self, SupportsIndex, SupportsInt

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import core_schema

from .exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from .ssz_base import SSZType


class BaseUint(int, SSZType):
    """A base class for custom unsigned integer types that inherits from `int`."""

    BITS: ClassVar[int]
    """The number of bits in the integer (overridden by subclasses)."""

    def __new__(cls, value: SupportsInt) -> Self:
        """
        Create and validate a new Uint instance.

        Raises:
            SSZTypeCoercionError: If `value` is not an int (rejects bool, string, float).
            SSZOverflowError: If `value` is outside the allowed range [0, 2**BITS - 1].
        """
        # We should accept only ints.
        if not isinstance(value, int) or isinstance(value, bool):
            raise SSZTypeError(f"Expected int, got {type(value).__name__}")

        int_value = int(value)
        max_value = 2**cls.BITS - 1
        if not (0 <= int_value <= max_value):
            raise SSZValueError(f"{int_value} out of range for {cls.__name__} [0, {max_value}]")
        return super().__new__(cls, int_value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """
        Hook into Pydantic's validation system.

        This schema defines how to handle the custom Uint type:
        1. If the input is already an instance of the class, accept it.
        2. Otherwise, validate the input as an integer within the defined bit range
            and then instantiate the class.
        3. For serialization (e.g., to JSON), convert the instance to a plain int.
        """
        # Validator that takes an integer and returns an instance of the class.
        from_int_validator = core_schema.no_info_plain_validator_function(cls)

        # Schema that first validates the input as an int, then calls our validator.
        python_schema = core_schema.chain_schema(
            [core_schema.int_schema(ge=0, lt=2**cls.BITS, strict=True), from_int_validator]
        )

        return core_schema.union_schema(
            [
                # Case 1: The value is already the correct type.
                core_schema.is_instance_schema(cls),
                # Case 2: The value needs to be parsed and validated.
                python_schema,
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(int),
        )

    @classmethod
    def is_fixed_size(cls) -> bool:
        """
        Determine if this is a fixed-size type.

        Returns:
            bool: True, as all Uint types are fixed-size.
        """
        return True

    @classmethod
    def get_byte_length(cls) -> int:
        """
        Get the number of bytes for this Uint type.

        Returns:
            int: The byte length of the integer.
        """
        return cls.BITS // 8

    def encode_bytes(self) -> bytes:
        """
        Serializes the Uint to its little-endian byte representation.

        Returns:
            bytes: The SSZ serialized bytes.
        """
        # The `to_bytes` method from `int` is used directly.
        return self.to_bytes(length=self.get_byte_length(), byteorder="little")

    @classmethod
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Deserializes a byte string into a Uint instance.

        Args:
            data (bytes): The SSZ byte string to deserialize.

        Raises:
            SSZDecodeError: If the byte string has an incorrect length.

        Returns:
            Self: A new instance of the Uint class.
        """
        # Ensure the input data has the correct number of bytes.
        expected_length = cls.get_byte_length()
        if len(data) != expected_length:
            raise SSZSerializationError(
                f"{cls.__name__}: expected {expected_length} bytes, got {len(data)}"
            )
        # The `from_bytes` class method from `int` is used to convert the data.
        return cls(int.from_bytes(data, "little"))

    def serialize(self, stream: IO[bytes]) -> int:
        """
        Serializes the Uint and writes it to a binary stream.

        Args:
            stream (IO[bytes]): The stream to write the serialized data to.

        Returns:
            int: The number of bytes written.
        """
        # Get the serialized bytes.
        encoded_data = self.encode_bytes()
        # Write the data to the stream.
        stream.write(encoded_data)
        # Return the number of bytes written.
        return len(encoded_data)

    @classmethod
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Deserializes a Uint from a binary stream within a given scope.

        Args:
            stream (IO[bytes]): The stream to read from.
            scope (int): The number of bytes available to read for this object.

        Raises:
            SSZDecodeError: If the scope does not match the type's byte length.
            SSZStreamError: If the stream ends prematurely.

        Returns:
            Self: A new instance of the Uint class.
        """
        # For a fixed-size type, the scope must exactly match the byte length.
        byte_length = cls.get_byte_length()
        if scope != byte_length:
            raise SSZSerializationError(
                f"{cls.__name__}: invalid scope, expected {byte_length} bytes, got {scope}"
            )
        # Read the required number of bytes from the stream.
        data = stream.read(byte_length)
        # Ensure the correct number of bytes was read.
        if len(data) != byte_length:
            raise SSZSerializationError(
                f"{cls.__name__}: expected {byte_length} bytes, got {len(data)}"
            )
        # Decode the bytes into a new instance.
        return cls.decode_bytes(data)

    @classmethod
    def max_value(cls) -> Self:
        """The maximum value for this unsigned integer."""
        return cls(2**cls.BITS - 1)

    def to_bytes(
        self,
        length: SupportsIndex | None = None,
        byteorder: Literal["little", "big"] = "little",
        *,
        signed: bool = False,
    ) -> bytes:
        """
        Return an array of bytes representing the integer.

        Defaults to little-endian and a fixed length based on `BITS`.
        """
        # If no length is specified, use the type's natural byte length.
        actual_length = self.BITS // 8 if length is None else int(length)
        return super().to_bytes(length=actual_length, byteorder=byteorder, signed=signed)

    def _raise_type_error(self, other: Any, op_symbol: str) -> None:
        """Helper to raise a consistent TypeError."""
        raise TypeError(
            f"Unsupported operand type(s) for {op_symbol}: "
            f"'{type(self).__name__}' and '{type(other).__name__}'"
        )

    def _validate_int_operand(self, other: Any, op_symbol: str) -> None:
        """Helper to ensure an operand is a true integer, not a bool."""
        if type(other) is not int:
            raise TypeError(
                f"Unsupported operand type for {op_symbol}: "
                f"expected 'int' but got '{type(other).__name__}'"
            )

    def __add__(self, other: Any) -> Self:
        """Handle the addition operator (`+`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "+")
        return type(self)(super().__add__(other))

    def __radd__(self, other: Any) -> Self:
        """Handle the reverse addition operator (`+`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "+")
        return type(self)(int(other) + int(self))

    def __sub__(self, other: Any) -> Self:
        """Handle the subtraction operator (`-`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "-")
        return type(self)(super().__sub__(other))

    def __rsub__(self, other: Any) -> Self:
        """Handle the reverse subtraction operator (`-`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "-")
        return type(self)(int(other) - int(self))

    def __mul__(self, other: Any) -> Self:
        """Handle the multiplication operator (`*`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "*")
        return type(self)(super().__mul__(other))

    def __rmul__(self, other: Any) -> Self:
        """Handle the reverse multiplication operator (`*`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "*")
        return type(self)(int(other) * int(self))

    def __floordiv__(self, other: Any) -> Self:
        """Handle the floor division operator (`//`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "//")
        return type(self)(super().__floordiv__(other))

    def __rfloordiv__(self, other: Any) -> Self:
        """Handle the reverse floor division operator (`//`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "//")
        return type(self)(int(other) // int(self))

    def __mod__(self, other: Any) -> Self:
        """Handle the modulo operator (`%`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "%")
        return type(self)(super().__mod__(other))

    def __rmod__(self, other: Any) -> Self:
        """Handle the reverse modulo operator (`%`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "%")
        return type(self)(int(other) % int(self))

    def __pow__(self, exponent: Any, modulo: Any | None = None) -> Any:
        """Handle the exponentiation operator (`**`) and `pow(self, exp, mod)`."""
        self._validate_int_operand(exponent, "** or pow()")
        if modulo is not None:
            self._validate_int_operand(modulo, "** or pow()")

        result = pow(int(self), int(exponent), int(modulo) if modulo is not None else None)
        return type(self)(result)

    def __rpow__(self, base: Any) -> Any:  # type: ignore[override]
        """Handle the reverse exponentiation operator (`**`)."""
        self._validate_int_operand(base, "**")
        result = pow(int(base), int(self))
        return type(self)(result)

    def __divmod__(self, other: Any) -> tuple[Self, Self]:
        """Handle `divmod(self, other)`."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "divmod")
        q, r = super().__divmod__(other)
        return type(self)(q), type(self)(r)

    def __rdivmod__(self, other: Any) -> tuple[Self, Self]:
        """Handle `divmod(other, self)`."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "divmod")
        q, r = super().__rdivmod__(other)
        return type(self)(q), type(self)(r)

    def __and__(self, other: Any) -> Self:
        """Handle the bitwise AND operator (`&`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "&")
        return type(self)(super().__and__(other))

    def __rand__(self, other: Any) -> Self:
        """Handle the reverse bitwise AND operator (`&`)."""
        return self.__and__(other)

    def __or__(self, other: Any) -> Self:
        """Handle the bitwise OR operator (`|`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "|")
        return type(self)(super().__or__(other))

    def __ror__(self, other: Any) -> Self:
        """Handle the reverse bitwise OR operator (`|`)."""
        return self.__or__(other)

    def __xor__(self, other: Any) -> Self:
        """Handle the bitwise XOR operator (`^`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "^")
        return type(self)(super().__xor__(other))

    def __rxor__(self, other: Any) -> Self:
        """Handle the reverse bitwise XOR operator (`^`)."""
        return self.__xor__(other)

    def __lshift__(self, other: Any) -> Self:
        """Handle the left bit-shift operator (`<<`)."""
        self._validate_int_operand(other, "<<")
        return type(self)(super().__lshift__(other))

    def __rlshift__(self, other: Any) -> Self:
        """Handle the reverse left bit-shift operator (`<<`)."""
        self._validate_int_operand(other, "<<")
        return type(self)(int(other) << int(self))

    def __rshift__(self, other: Any) -> Self:
        """Handle the right bit-shift operator (`>>`)."""
        self._validate_int_operand(other, ">>")
        return type(self)(super().__rshift__(other))

    def __rrshift__(self, other: Any) -> Self:
        """Handle the reverse right bit-shift operator (`>>`)."""
        self._validate_int_operand(other, ">>")
        return type(self)(int(other) >> int(self))

    def __eq__(self, other: object) -> bool:
        """Handle the equality operator (`==`)"""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "==")
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        """Handle the inequality operator (`!=`)"""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "!=")
        return super().__ne__(other)

    def __lt__(self, other: Any) -> bool:
        """Handle the less-than operator (`<`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "<")
        return super().__lt__(other)

    def __le__(self, other: Any) -> bool:
        """Handle the less-than-or-equal-to operator (`<=`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, "<=")
        return super().__le__(other)

    def __gt__(self, other: Any) -> bool:
        """Handle the greater-than operator (`>`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, ">")
        return super().__gt__(other)

    def __ge__(self, other: Any) -> bool:
        """Handle the greater-than-or-equal-to operator (`>=`)."""
        if not isinstance(other, BaseUint):
            self._raise_type_error(other, ">=")
        return super().__ge__(other)

    def __repr__(self) -> str:
        """Return the official string representation of the object."""
        return f"{type(self).__name__}({int(self)})"

    def __str__(self) -> str:
        """Return the informal, user-friendly string representation."""
        return str(int(self))

    def __hash__(self) -> int:
        """Return a hash distinct from raw int."""
        return hash((type(self), int(self)))

    def __index__(self) -> int:
        """Return self as an integer for use in slicing and indexing."""
        return int(self)


class Uint8(BaseUint):
    """A type representing an 8-bit unsigned integer (uint8)."""

    BITS = 8


class Uint16(BaseUint):
    """A type representing a 16-bit unsigned integer (uint16)."""

    BITS = 16


class Uint32(BaseUint):
    """A type representing a 32-bit unsigned integer (uint32)."""

    BITS = 32


class Uint64(BaseUint):
    """A type representing a 64-bit unsigned integer (uint64)."""

    BITS = 64
