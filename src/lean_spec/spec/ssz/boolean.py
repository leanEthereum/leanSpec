"""SSZ boolean type — true or false serialized as a single byte."""

from __future__ import annotations

from typing import IO, Any, Self, override

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

from lean_spec.spec.ssz.exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from lean_spec.spec.ssz.ssz_base import SSZType


class Boolean(int, SSZType):
    r"""
    Strict SSZ boolean encoded as exactly one byte.

    - Inherits from int so true/false work natively in truthiness checks.
    - Arithmetic (+ - * /) is disabled to prevent ambiguous operations.
    - Bitwise ops (& | ^) reject operands of any other type.
    - Equality rejects comparisons with anything but another boolean.

    Wire format:

        true   ->  b"\x01"
        false  ->  b"\x00"
    """

    __slots__ = ()

    def __new__(cls, value: bool | int) -> Self:
        """
        Construct and validate a new boolean.

        Only the four values true, false, 0, and 1 are accepted.

        Args:
            value: The raw value to wrap.

        Raises:
            SSZTypeError: If value is not a bool or int.
            SSZValueError: If value is an integer outside 0 or 1.
        """
        if not isinstance(value, int):
            raise SSZTypeError(f"Expected bool or int, got {type(value).__name__}")

        # Coerce to a plain int before the membership test:
        #
        #   - value in (0, 1) does value == 0 or value == 1.
        #   - For a Boolean operand, those comparisons hit strict equality and raise.
        #   - int(value) returns a plain int, so == falls back to int equality.
        if int(value) not in (0, 1):
            raise SSZValueError(f"Boolean value must be 0 or 1, not {value}")

        return super().__new__(cls, value)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """
        Provide a Pydantic core schema that enforces strict boolean validation.

        Only true or false are accepted as input at the Pydantic layer.
        Any other type — including int 0 or 1 — is rejected here, even though
        the constructor itself accepts them.
        """
        # Validator that wraps a verified bool into a typed instance.
        from_bool_validator = core_schema.no_info_plain_validator_function(cls)

        # Two-step input validation:
        #
        #   - bool_schema(strict=True)   rejects anything that is not exactly a bool.
        #   - from_bool_validator        wraps the validated bool into a Boolean.
        python_schema = core_schema.chain_schema(
            [core_schema.bool_schema(strict=True), from_bool_validator]
        )

        # Final schema accepts either branch and serializes back to a plain bool:
        #
        #   - Branch 1: input is already a typed instance, pass through.
        #   - Branch 2: input is a strict bool that needs wrapping.
        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                python_schema,
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(bool),
        )

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """Always fixed-size — every boolean encodes to one byte."""
        return True

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """Return the byte length of the encoded form."""
        return 1

    @override
    def encode_bytes(self) -> bytes:
        r"""
        Encode the boolean to its SSZ byte representation.

        - true   -> b"\x01"
        - false  -> b"\x00"
        """
        return b"\x01" if self else b"\x00"

    @classmethod
    @override
    def decode_bytes(cls, data: bytes) -> Self:
        """
        Decode a single SSZ byte into a boolean.

        Input must be exactly one byte with value 0x00 or 0x01.

        Args:
            data: SSZ-encoded byte.

        Returns:
            A boolean wrapping the decoded value.

        Raises:
            SSZSerializationError:
                - When the input length is not 1.
                - When the byte value is outside the 0x00 / 0x01 set.
        """
        if len(data) != 1:
            raise SSZSerializationError(f"Boolean: expected 1 byte, got {len(data)}")
        if data[0] not in (0, 1):
            raise SSZSerializationError(f"Boolean: byte must be 0x00 or 0x01, got {data[0]:#04x}")
        return cls(data[0])

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write the SSZ-encoded byte to a binary stream."""
        encoded_data = self.encode_bytes()
        stream.write(encoded_data)
        return len(encoded_data)

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Read one SSZ byte from a stream and decode into a boolean.

        Args:
            stream: Source binary stream.
            scope: Number of bytes the caller has allocated for this value (must be 1).

        Returns:
            A boolean wrapping the decoded value.

        Raises:
            SSZSerializationError:
                - When scope is not 1.
                - When the underlying byte decode fails.
        """
        if scope != 1:
            raise SSZSerializationError(f"Boolean: expected scope of 1, got {scope}")
        return cls.decode_bytes(stream.read(1))

    def _no_arithmetic(self, other: Any) -> Self:
        """Reject arithmetic on Boolean — use bitwise & | ^ instead."""
        raise TypeError("Arithmetic operations are not supported for Boolean.")

    __add__ = __radd__ = __sub__ = __rsub__ = _no_arithmetic

    def __and__(self, other: Any) -> Self:
        """Bitwise AND between two booleans — rejects any other operand."""
        if not isinstance(other, type(self)):
            raise TypeError(
                f"Unsupported operand type(s) for &: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return type(self)(int(self) & int(other))

    def __rand__(self, other: Any) -> Self:
        """Bitwise AND when the boolean is on the right of the operator."""
        return self.__and__(other)

    def __or__(self, other: Any) -> Self:
        """Bitwise OR between two booleans — rejects any other operand."""
        if not isinstance(other, type(self)):
            raise TypeError(
                f"Unsupported operand type(s) for |: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return type(self)(int(self) | int(other))

    def __ror__(self, other: Any) -> Self:
        """Bitwise OR when the boolean is on the right of the operator."""
        return self.__or__(other)

    def __xor__(self, other: Any) -> Self:
        """Bitwise XOR between two booleans — rejects any other operand."""
        if not isinstance(other, type(self)):
            raise TypeError(
                f"Unsupported operand type(s) for ^: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return type(self)(int(self) ^ int(other))

    def __rxor__(self, other: Any) -> Self:
        """Bitwise XOR when the boolean is on the right of the operator."""
        return self.__xor__(other)

    def __eq__(self, other: object) -> bool:
        """Strict equality — only another boolean compares; anything else raises."""
        if not isinstance(other, Boolean):
            raise TypeError(
                f"Unsupported operand type(s) for ==: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return int(self) == int(other)

    def __ne__(self, other: object) -> bool:
        """
        Strict inequality — only another boolean compares; anything else raises.

        Defined explicitly because the parent class's not-equal would otherwise
        bypass the strict equality above.
        """
        if not isinstance(other, Boolean):
            raise TypeError(
                f"Unsupported operand type(s) for !=: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return int(self) != int(other)

    def __repr__(self) -> str:
        """Return the official form: Boolean(True) or Boolean(False)."""
        return f"Boolean({bool(self)})"

    def __str__(self) -> str:
        """Return the user-facing form: True or False."""
        return str(bool(self))

    def __hash__(self) -> int:
        """Return a hash distinct from the equivalent raw bool, matching strict equality."""
        return hash((type(self), int(self)))
