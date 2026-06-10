"""Unsigned Integer Type Specification."""

from __future__ import annotations

from typing import IO, Any, ClassVar, NoReturn, Self, SupportsInt, overload, override

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import core_schema

from lean_spec.spec.ssz.exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from lean_spec.spec.ssz.ssz_base import SSZType


class BaseUint(int, SSZType):
    """Base class for fixed-width unsigned integer types."""

    __slots__ = ()

    BITS: ClassVar[int]
    """The number of bits in the integer (overridden by subclasses)."""

    def __new__(cls, value: SupportsInt) -> Self:
        """
        Create and range-check a new instance.

        Raises:
            SSZTypeError: If value is not an int. Bool, string, and float are rejected.
            SSZValueError: If value is outside [0, 2**BITS - 1].
        """
        # Bool subclasses int, so reject it explicitly before the value check.
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
        """Hook into Pydantic's validation system."""
        # A plain validator wraps a pre-validated int into a typed instance.
        from_int_validator = core_schema.no_info_plain_validator_function(cls)
        # Strict int validation enforces the unsigned range before construction.
        #
        # The lt bound is exclusive, so a value equal to 2**BITS is rejected.
        python_schema = core_schema.chain_schema(
            [core_schema.int_schema(ge=0, lt=2**cls.BITS, strict=True), from_int_validator]
        )
        # Existing instances bypass validation.
        #
        # Raw values flow through the strict chain instead.
        return core_schema.union_schema(
            [
                # Case 1: The value is already the correct type.
                core_schema.is_instance_schema(cls),
                # Case 2: The value needs to be parsed and validated.
                python_schema,
            ],
            # Round-trip to JSON drops the subtype back to a plain int.
            serialization=core_schema.plain_serializer_function_ser_schema(int),
        )

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """All unsigned integer types are fixed-size."""
        return True

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """Byte length derived from the bit width."""
        return cls.BITS // 8

    @override
    def encode_bytes(self) -> bytes:
        """Serialize to little-endian bytes."""
        return self.to_bytes(length=self.get_byte_length(), byteorder="little")

    @classmethod
    @override
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Deserialize from little-endian bytes.

        Raises:
            SSZSerializationError: If the byte string has the wrong length.
        """
        # Ensure the input data has the correct number of bytes.
        expected_length = cls.get_byte_length()
        if len(data) != expected_length:
            raise SSZSerializationError(
                f"{cls.__name__}: expected {expected_length} bytes, got {len(data)}"
            )
        return cls(int.from_bytes(data, "little"))

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write little-endian bytes to a stream and return the count written."""
        encoded_data = self.encode_bytes()
        # Write the data to the stream.
        stream.write(encoded_data)
        # Return the number of bytes written.
        return len(encoded_data)

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Read little-endian bytes from a stream within a fixed scope.

        Raises:
            SSZSerializationError: If the scope mismatches, or the stream ends early.
        """
        byte_length = cls.get_byte_length()
        if scope != byte_length:
            raise SSZSerializationError(
                f"{cls.__name__}: invalid scope, expected {byte_length} bytes, got {scope}"
            )
        # Read the required number of bytes from the stream.
        serialized_bytes = stream.read(byte_length)
        # Ensure the correct number of bytes was read.
        if len(serialized_bytes) != byte_length:
            raise SSZSerializationError(
                f"{cls.__name__}: expected {byte_length} bytes, got {len(serialized_bytes)}"
            )
        # Decode the bytes into a new instance.
        return cls.decode_bytes(serialized_bytes)

    @classmethod
    def max_value(cls) -> Self:
        """The maximum value for this unsigned integer."""
        return cls(2**cls.BITS - 1)

    def _raise_type_error(self, other: Any, op_symbol: str) -> NoReturn:
        """Helper to raise a consistent TypeError."""
        raise TypeError(
            f"Unsupported operand type(s) for {op_symbol}: "
            f"'{type(self).__name__}' and '{type(other).__name__}'"
        )

    def __add__(self, other: Any) -> Self:
        """Forward addition."""
        if type(other) is not type(self):
            self._raise_type_error(other, "+")
        return type(self)(super().__add__(other))

    def __radd__(self, other: Any) -> Self:
        """Reverse addition."""
        if type(other) is not type(self):
            self._raise_type_error(other, "+")
        return type(self)(int(other) + int(self))

    def __sub__(self, other: Any) -> Self:
        """Forward subtraction."""
        if type(other) is not type(self):
            self._raise_type_error(other, "-")
        return type(self)(super().__sub__(other))

    def __rsub__(self, other: Any) -> Self:
        """Reverse subtraction."""
        if type(other) is not type(self):
            self._raise_type_error(other, "-")
        return type(self)(int(other) - int(self))

    def __mul__(self, other: Any) -> Self:
        """Forward multiplication."""
        if type(other) is not type(self):
            self._raise_type_error(other, "*")
        return type(self)(super().__mul__(other))

    def __rmul__(self, other: Any) -> Self:
        """Reverse multiplication."""
        if type(other) is not type(self):
            self._raise_type_error(other, "*")
        return type(self)(int(other) * int(self))

    def __floordiv__(self, other: Any) -> Self:
        """Forward floor division."""
        if type(other) is not type(self):
            self._raise_type_error(other, "//")
        return type(self)(super().__floordiv__(other))

    def __rfloordiv__(self, other: Any) -> Self:
        """Reverse floor division."""
        if type(other) is not type(self):
            self._raise_type_error(other, "//")
        return type(self)(int(other) // int(self))

    def __mod__(self, other: Any) -> Self:
        """Forward modulo."""
        if type(other) is not type(self):
            self._raise_type_error(other, "%")
        return type(self)(super().__mod__(other))

    def __rmod__(self, other: Any) -> Self:
        """Reverse modulo."""
        if type(other) is not type(self):
            self._raise_type_error(other, "%")
        return type(self)(int(other) % int(self))

    @overload
    def __pow__(self, value: int, mod: None = None, /) -> Self: ...
    @overload
    def __pow__(self, value: int, mod: int, /) -> Self: ...
    # The parent declaration uses two stub overloads with different return types.
    #
    # Narrowing both to a single subtype is safe by Liskov substitution.
    # The strict overload-match check rejects it regardless.
    def __pow__(self, value: int, mod: int | None = None, /) -> Self:  # ty: ignore[invalid-method-override]
        """Forward exponentiation and three-argument pow."""
        if type(value) is not type(self):
            self._raise_type_error(value, "**")
        if mod is not None and type(mod) is not type(self):
            self._raise_type_error(mod, "**")
        power = pow(int(self), int(value), int(mod) if mod is not None else None)
        return type(self)(power)

    def __rpow__(self, base: int, modulo: int | None = None, /) -> Self:
        """Reverse exponentiation and three-argument pow."""
        if type(base) is not type(self):
            self._raise_type_error(base, "**")
        if modulo is not None and type(modulo) is not type(self):
            self._raise_type_error(modulo, "**")
        power = pow(int(base), int(self), int(modulo) if modulo is not None else None)
        return type(self)(power)

    def __divmod__(self, other: Any) -> tuple[Self, Self]:
        """Forward divmod."""
        if type(other) is not type(self):
            self._raise_type_error(other, "divmod")
        quotient, remainder = super().__divmod__(other)
        return type(self)(quotient), type(self)(remainder)

    def __rdivmod__(self, other: Any) -> tuple[Self, Self]:
        """Reverse divmod."""
        if type(other) is not type(self):
            self._raise_type_error(other, "divmod")
        quotient, remainder = super().__rdivmod__(other)
        return type(self)(quotient), type(self)(remainder)

    def __and__(self, other: Any) -> Self:
        """Forward bitwise AND."""
        if type(other) is not type(self):
            self._raise_type_error(other, "&")
        return type(self)(super().__and__(other))

    def __rand__(self, other: Any) -> Self:
        """Reverse bitwise AND."""
        return self.__and__(other)

    def __or__(self, other: Any) -> Self:
        """Forward bitwise OR."""
        if type(other) is not type(self):
            self._raise_type_error(other, "|")
        return type(self)(super().__or__(other))

    def __ror__(self, other: Any) -> Self:
        """Reverse bitwise OR."""
        return self.__or__(other)

    def __xor__(self, other: Any) -> Self:
        """Forward bitwise XOR."""
        if type(other) is not type(self):
            self._raise_type_error(other, "^")
        return type(self)(super().__xor__(other))

    def __rxor__(self, other: Any) -> Self:
        """Reverse bitwise XOR."""
        return self.__xor__(other)

    def __lshift__(self, other: Any) -> Self:
        """Forward left bit-shift."""
        if type(other) is not type(self):
            self._raise_type_error(other, "<<")
        return type(self)(super().__lshift__(other))

    def __rlshift__(self, other: Any) -> Self:
        """Reverse left bit-shift."""
        if type(other) is not type(self):
            self._raise_type_error(other, "<<")
        return type(self)(int(other) << int(self))

    def __rshift__(self, other: Any) -> Self:
        """Forward right bit-shift."""
        if type(other) is not type(self):
            self._raise_type_error(other, ">>")
        return type(self)(super().__rshift__(other))

    def __rrshift__(self, other: Any) -> Self:
        """Reverse right bit-shift."""
        if type(other) is not type(self):
            self._raise_type_error(other, ">>")
        return type(self)(int(other) >> int(self))

    def __eq__(self, other: object) -> bool:
        """Equality."""
        if type(other) is not type(self):
            self._raise_type_error(other, "==")
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        """Inequality."""
        if type(other) is not type(self):
            self._raise_type_error(other, "!=")
        return super().__ne__(other)

    def __lt__(self, other: Any) -> bool:
        """Less-than."""
        if type(other) is not type(self):
            self._raise_type_error(other, "<")
        return super().__lt__(other)

    def __le__(self, other: Any) -> bool:
        """Less-than-or-equal."""
        if type(other) is not type(self):
            self._raise_type_error(other, "<=")
        return super().__le__(other)

    def __gt__(self, other: Any) -> bool:
        """Greater-than."""
        if type(other) is not type(self):
            self._raise_type_error(other, ">")
        return super().__gt__(other)

    def __ge__(self, other: Any) -> bool:
        """Greater-than-or-equal."""
        if type(other) is not type(self):
            self._raise_type_error(other, ">=")
        return super().__ge__(other)

    def __repr__(self) -> str:
        """Official representation includes the subtype name."""
        return f"{type(self).__name__}({int(self)})"

    def __str__(self) -> str:
        """Informal representation matches the underlying value."""
        return str(int(self))

    def __hash__(self) -> int:
        """Hash mixes in the concrete subtype so distinct widths never collide."""
        return hash((type(self), int(self)))

    def __index__(self) -> int:
        """Return a plain integer for slicing and indexing."""
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
