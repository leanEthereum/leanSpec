"""
SSZ byte array types.

A byte array is a contiguous sequence of bytes serialized directly to the wire.

Two flavors are defined by the SSZ spec:

- Fixed-length: exactly N bytes — the byte count is part of the type.
- Variable-length: 0 to N bytes — the byte count is recovered from the surrounding context.

Both flavors serialize as the raw bytes themselves — no length prefix, no delimiter.
"""

from collections.abc import Iterable
from typing import IO, Any, ClassVar, Self, override

from pydantic import Field, field_serializer, field_validator
from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import core_schema

from .exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from .ssz_base import SSZModel, SSZType


class BaseBytes(bytes, SSZType):
    r"""
    Fixed-length SSZ byte array with exactly N bytes.

    - Inherits from bytes so the instance is usable wherever a bytes value is expected.
    - Subclasses pin the byte count by setting the class-level length.
    - Equality is strict — only another byte-array instance compares.

    For example, Bytes4 wraps four raw bytes and serializes verbatim:

        Bytes4(b"\x01\x02\x03\x04")  ->  wire bytes 01 02 03 04
    """

    __slots__ = ()

    LENGTH: ClassVar[int]
    """The exact number of bytes (overridden by subclasses)."""

    @staticmethod
    def _coerce_to_bytes(value: bytes | bytearray | str | Iterable[int]) -> bytes:
        """
        Coerce an input into a plain bytes object.

        Accepts:

        - bytes or bytearray — returned as an immutable bytes copy.
        - Iterables of integers in 0..255.
        - Hex strings, optionally prefixed with 0x.

        Args:
            value: The raw input to convert.

        Returns:
            The coerced bytes.

        Raises:
            TypeError: If the input type is not coercible.
            ValueError: If a hex string is malformed or an integer is out of range.
        """
        match value:
            case bytes() | bytearray():
                return bytes(value)
            case str():
                return bytes.fromhex(value.removeprefix("0x"))
            case Iterable():
                return bytes(bytearray(value))
            case _:
                raise TypeError(f"Cannot coerce {type(value).__name__} to bytes")

    def __new__(cls, value: bytes | bytearray | str | Iterable[int] = b"") -> Self:
        """
        Construct and validate a new byte array.

        Args:
            value: Any input coercible to bytes — bytes, bytearray, iterable of ints, or hex string.

        Raises:
            SSZTypeError: If the subclass has not declared a length.
            SSZValueError: If the coerced byte count differs from the declared length.
        """
        if not hasattr(cls, "LENGTH"):
            raise SSZTypeError(f"{cls.__name__} must define LENGTH")

        b = cls._coerce_to_bytes(value)
        if len(b) != cls.LENGTH:
            raise SSZValueError(f"{cls.__name__} requires exactly {cls.LENGTH} bytes, got {len(b)}")
        return super().__new__(cls, b)

    @classmethod
    def zero(cls) -> Self:
        """Return a new instance filled with zero bytes."""
        return cls(b"\x00" * cls.LENGTH)

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """Always fixed-size by definition."""
        return True

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """Return the declared byte length."""
        return cls.LENGTH

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write the raw bytes to a binary stream and return the number of bytes written."""
        stream.write(self)
        return len(self)

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Read the declared number of bytes from a stream.

        Args:
            stream: Source binary stream.
            scope: Number of bytes the caller has allocated for this value (must equal LENGTH).

        Returns:
            A new instance wrapping the read bytes.

        Raises:
            SSZSerializationError:
                - When scope does not equal the declared LENGTH.
                - When the stream ends before delivering scope bytes.
        """
        if scope != cls.LENGTH:
            raise SSZSerializationError(f"{cls.__name__}: expected {cls.LENGTH} bytes, got {scope}")
        data = stream.read(scope)
        if len(data) != scope:
            raise SSZSerializationError(f"{cls.__name__}: expected {scope} bytes, got {len(data)}")
        # Length already verified — bypass __new__'s coerce + revalidation.
        return bytes.__new__(cls, data)

    @override
    def encode_bytes(self) -> bytes:
        """Return the SSZ-encoded bytes as a plain bytes object."""
        return bytes(self)

    @classmethod
    @override
    def decode_bytes(cls, data: bytes) -> Self:
        """Parse SSZ bytes into an instance — the constructor enforces the declared length."""
        return cls(data)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """
        Provide a Pydantic core schema for strict byte-array validation.

        - Already-typed instances pass through.
        - Plain bytes inputs go through length-checked validation, then get wrapped.
        - JSON serialization converts the bytes to a 0x-prefixed hex string.
        """
        # Validator that wraps a verified bytes object into a typed instance.
        from_bytes_validator = core_schema.no_info_plain_validator_function(cls)

        # Two-step input validation:
        #
        #   - bytes_schema enforces the exact declared length.
        #   - wrapping validator turns the validated bytes into a typed instance.
        python_schema = core_schema.chain_schema(
            [
                core_schema.bytes_schema(min_length=cls.LENGTH, max_length=cls.LENGTH),
                from_bytes_validator,
            ]
        )

        # Final union accepts either branch and serializes back to a 0x-prefixed hex string:
        #
        #   - Branch 1: input is already a typed instance, pass through.
        #   - Branch 2: input is bytes that need length-checking and wrapping.
        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                python_schema,
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda x: "0x" + x.hex()
            ),
        )

    def __repr__(self) -> str:
        """Return the official form: ClassName(hex_string)."""
        tname = type(self).__name__
        return f"{tname}({self.hex()})"

    def __eq__(self, other: object) -> bool:
        """Strict equality — only another byte-array instance compares; anything else raises."""
        if not isinstance(other, BaseBytes):
            raise TypeError(
                f"Unsupported operand type(s) for ==: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return bytes.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        """
        Strict inequality — only another byte-array instance compares; anything else raises.

        Defined explicitly because the parent bytes class has its own not-equal
        that would otherwise bypass the strict type contract.
        """
        if not isinstance(other, BaseBytes):
            raise TypeError(
                f"Unsupported operand type(s) for !=: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return bytes.__ne__(self, other)

    def __hash__(self) -> int:
        """Return a hash distinct from raw bytes — matches the strict equality contract."""
        return hash((type(self), bytes(self)))


class Bytes4(BaseBytes):
    """Fixed-size byte array of exactly 4 bytes."""

    LENGTH = 4


class Bytes12(BaseBytes):
    """Fixed-size byte array of exactly 12 bytes (AES-GCM nonce)."""

    LENGTH = 12


class Bytes16(BaseBytes):
    """Fixed-size byte array of exactly 16 bytes (Poly1305 authentication tag)."""

    LENGTH = 16


class Bytes20(BaseBytes):
    """Fixed-size byte array of exactly 20 bytes."""

    LENGTH = 20


class Bytes32(BaseBytes):
    """Fixed-size byte array of exactly 32 bytes."""

    LENGTH = 32


class Bytes33(BaseBytes):
    """Fixed-size byte array of exactly 33 bytes (compressed secp256k1 public key)."""

    LENGTH = 33


class Bytes52(BaseBytes):
    """Fixed-size byte array of exactly 52 bytes."""

    LENGTH = 52


class Bytes64(BaseBytes):
    """Fixed-size byte array of exactly 64 bytes (secp256k1 signature)."""

    LENGTH = 64


class Bytes65(BaseBytes):
    """Fixed-size byte array of exactly 65 bytes (uncompressed secp256k1 public key)."""

    LENGTH = 65


ZERO_HASH: Bytes32 = Bytes32.zero()
"""All-zero 32-byte hash, used as a canonical empty/uninitialized root."""


class BaseByteList(SSZModel):
    r"""
    Variable-length SSZ byte array with 0 to N bytes.

    - Subclasses pin the maximum byte count by setting the class-level limit.
    - Serialization writes the raw bytes; the length is recovered from the wrapping context.
    - Equality is strict — only another byte-list instance compares.

    For example, a 4-byte payload under a limit of 10:

        instance.data = b"\xde\xad\xbe\xef"  ->  wire bytes de ad be ef
    """

    LIMIT: ClassVar[int]
    """Maximum number of bytes the instance may contain."""

    data: bytes = Field(default=b"")
    """The raw bytes stored in this list."""

    @field_validator("data", mode="before")
    @classmethod
    def _validate_byte_list_data(cls, v: Any) -> bytes:
        """Enforce the maximum byte count and coerce inputs into a plain bytes object."""
        # Subclasses must declare LIMIT before any instances can be validated.
        if not hasattr(cls, "LIMIT"):
            raise SSZTypeError(f"{cls.__name__} must define LIMIT")

        # Coerce the input first, then enforce the upper bound.
        b = BaseBytes._coerce_to_bytes(v)
        if len(b) > cls.LIMIT:
            raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {len(b)}")
        return b

    @field_serializer("data", when_used="json")
    def _serialize_data(self, value: bytes) -> str:
        """Serialize the raw bytes to a 0x-prefixed hex string for JSON output."""
        return "0x" + value.hex()

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """Variable-size by definition — the byte count depends on the value."""
        return False

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """
        Variable-size types have no fixed byte length.

        Raises:
            SSZTypeError: Always — call this only on fixed-size types.
        """
        raise SSZTypeError(f"{cls.__name__}: variable-size byte list has no fixed byte length")

    @override
    def serialize(self, stream: IO[bytes]) -> int:
        """Write the raw bytes to a binary stream and return the number of bytes written."""
        stream.write(self.data)
        return len(self.data)

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """
        Read scope bytes from a stream into a new instance.

        For variable-size values, the caller computes scope from the surrounding context.

        Args:
            stream: Source binary stream.
            scope: Number of bytes belonging to this value.

        Returns:
            A new instance wrapping the read bytes.

        Raises:
            SSZSerializationError:
                - When scope is negative.
                - When the stream ends before delivering scope bytes.
            SSZValueError: When scope exceeds the declared LIMIT.
        """
        if scope < 0:
            raise SSZSerializationError(f"{cls.__name__}: negative scope")
        if scope > cls.LIMIT:
            raise SSZValueError(f"{cls.__name__} exceeds limit of {cls.LIMIT}, got {scope}")
        data = stream.read(scope)
        if len(data) != scope:
            raise SSZSerializationError(f"{cls.__name__}: expected {scope} bytes, got {len(data)}")
        return cls(data=data)

    @override
    def encode_bytes(self) -> bytes:
        """Return the SSZ-encoded bytes — the raw payload, with no length prefix."""
        return self.data

    @classmethod
    @override
    def decode_bytes(cls, data: bytes) -> Self:
        """Parse SSZ bytes into an instance — the validator enforces the LIMIT."""
        return cls(data=data)

    def __bytes__(self) -> bytes:
        """Return the underlying raw bytes."""
        return self.data

    def __add__(self, other: Any) -> bytes:
        """Concatenate with a bytes-like value on the right, returning plain bytes."""
        return self.data + bytes(other)

    def __radd__(self, other: Any) -> bytes:
        """Concatenate with a bytes-like value on the left, returning plain bytes."""
        return bytes(other) + self.data

    def __repr__(self) -> str:
        """Return the official form: ClassName(hex_string)."""
        tname = type(self).__name__
        return f"{tname}({self.data.hex()})"

    def __eq__(self, other: object) -> bool:
        """Strict equality — only another byte-list instance compares; anything else raises."""
        if not isinstance(other, BaseByteList):
            raise TypeError(
                f"Unsupported operand type(s) for ==: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return self.data == other.data

    def __ne__(self, other: object) -> bool:
        """
        Strict inequality — only another byte-list instance compares; anything else raises.

        Mirrors the strict equality contract — both operators require a matching type.
        """
        if not isinstance(other, BaseByteList):
            raise TypeError(
                f"Unsupported operand type(s) for !=: "
                f"'{type(self).__name__}' and '{type(other).__name__}'"
            )
        return self.data != other.data

    def __hash__(self) -> int:
        """Return a hash that ties the value to its concrete type."""
        return hash((type(self), self.data))

    def hex(self) -> str:
        """Return the hexadecimal string representation of the underlying bytes."""
        return self.data.hex()


class ByteList512KiB(BaseByteList):
    """Variable-length byte list with a 512 KiB limit."""

    LIMIT = 512 * 1024
