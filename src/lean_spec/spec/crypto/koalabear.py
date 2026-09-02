"""Core definition of the KoalaBear prime field Fp."""

import math
from typing import IO, Any, Final, NoReturn, Self, cast, override

from pydantic.annotated_handlers import GetCoreSchemaHandler
from pydantic_core import core_schema
from ssz import SSZTypeError, SSZValueError, TypeFault, Uint32, ValueFault

P: Final = 2**31 - 2**24 + 1
"""
The KoalaBear Prime: P = 2^31 - 2^24 + 1

The prime is chosen because the cube map (x -> x^3) is an automorphism of the multiplicative group.
"""

P_BYTES: Final = math.ceil(P.bit_length() / 8)
"""The size of a KoalaBear field element in bytes.

The prime spans 31 bits, so a field element fits in 4 bytes.
"""


class Fp(Uint32):
    """
    An element in the KoalaBear prime field F_p.

    This is an SSZ-serializable type.

    Each field element is represented as a 4-byte little-endian unsigned integer.
    The prime spans 31 bits, so the field rides on the 32-bit unsigned integer.
    That inheritance is what packs a sequence of elements into shared chunks.
    A type outside the unsigned integers would take a 32-byte leaf per element instead.
    """

    __slots__ = ()

    def __new__(cls, value: int = 0) -> Self:
        """
        Create a field element.

        The constructor reduces the integer modulo P.
        Any integer is accepted, including negatives and values at or above P.
        The Pydantic validation path is stricter and requires the value already in [0, P).

        Args:
            value: The integer to wrap, reduced modulo P into the range [0, P).

        Raises:
            SSZTypeError: If value is not an integer.
        """
        if not isinstance(value, int) or isinstance(value, bool):
            raise SSZTypeError(TypeFault.WRONG_TYPE, expected="int", got=type(value).__name__)

        # Normalize to [0, P) - handles negative values correctly
        return super().__new__(cls, int(value) % P)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Hook into Pydantic's validation system."""
        # A plain validator wraps a pre-validated int into a typed instance.
        from_int_validator = core_schema.no_info_plain_validator_function(cls)
        # Strict int validation enforces the canonical residue range before construction.
        python_schema = core_schema.chain_schema(
            [core_schema.int_schema(ge=0, lt=P, strict=True), from_int_validator]
        )
        # Existing instances bypass validation; raw ints flow through the strict chain.
        return core_schema.union_schema(
            [
                core_schema.is_instance_schema(cls),
                python_schema,
            ],
            serialization=core_schema.plain_serializer_function_ser_schema(int),
        )

    @classmethod
    def _require_canonical_residue(cls, decoded_integer: int) -> None:
        """
        Refuse a non-canonical residue, since four bytes span more than the field holds.

        Raises:
            SSZValueError: If the decoded integer is at or above the modulus.
        """
        if decoded_integer >= P:
            raise SSZValueError(
                ValueFault.RANGE, value=decoded_integer, type=cls.__name__, max=P - 1
            )

    @classmethod
    @override
    def decode_bytes(cls, data: bytes) -> Self:
        """Decode a field element from little-endian bytes."""
        # A type checker reads the inherited classmethod as returning the class it is written on.
        element = cast(Self, super().decode_bytes(data))
        cls._require_canonical_residue(int(element))
        return element

    @classmethod
    @override
    def deserialize(cls, stream: IO[bytes], scope: int) -> Self:
        """Deserialize a field element from a binary stream."""
        element = cast(Self, super().deserialize(stream, scope))
        cls._require_canonical_residue(int(element))
        return element

    def _reject(self, other: Any, op_symbol: str) -> NoReturn:
        """Raise a consistent TypeError for a non-Fp operand."""
        raise TypeError(
            f"Unsupported operand type(s) for {op_symbol}: "
            f"'{type(self).__name__}' and '{type(other).__name__}'"
        )

    def __add__(self, other: Any) -> Self:
        """Field addition."""
        if type(other) is not type(self):
            self._reject(other, "+")
        return type(self)(int(self) + int(other))

    def __radd__(self, other: Any) -> NoReturn:
        """Reverse addition: reject non-Fp left operand to prevent silent int fallback."""
        self._reject(other, "+")

    def __sub__(self, other: Any) -> Self:
        """Field subtraction."""
        if type(other) is not type(self):
            self._reject(other, "-")
        return type(self)(int(self) - int(other))

    def __rsub__(self, other: Any) -> NoReturn:
        """Reverse subtraction: reject non-Fp left operand to prevent silent int fallback."""
        self._reject(other, "-")

    def __neg__(self) -> Self:
        """Field negation."""
        return type(self)(-int(self))

    def __mul__(self, other: Any) -> Self:
        """Field multiplication."""
        if type(other) is not type(self):
            self._reject(other, "*")
        return type(self)(int(self) * int(other))

    def __rmul__(self, other: Any) -> NoReturn:
        """Reverse multiplication: reject non-Fp left operand to prevent silent int fallback."""
        self._reject(other, "*")

    # The int base declares a three-argument pow with an optional modulus.
    #
    # The field already reduces modulo P, so the modulus argument is meaningless here.
    # Narrowing to the field type is intentional and safe by Liskov substitution.
    def __pow__(self, exponent: int) -> Self:  # ty: ignore[invalid-method-override]
        """Field exponentiation."""
        return type(self)(pow(int(self), exponent, P))

    def inverse(self) -> Self:
        """Computes the multiplicative inverse."""
        if int(self) == 0:
            raise ZeroDivisionError("Cannot invert the zero element.")
        # pow(a, -1, P) returns the modular inverse via the extended Euclidean algorithm
        return type(self)(pow(int(self), -1, P))

    def __truediv__(self, other: Any) -> Self:
        """Field division."""
        if type(other) is not type(self):
            self._reject(other, "/")
        return self * other.inverse()

    def __rtruediv__(self, other: Any) -> NoReturn:
        """Reverse division: reject non-Fp left operand to prevent silent float fallback."""
        self._reject(other, "/")

    def __eq__(self, other: object) -> bool:
        """Check equality of two field elements."""
        if type(other) is not type(self):
            return False
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        """Check inequality of two field elements."""
        return not self.__eq__(other)

    def __hash__(self) -> int:
        """Compute hash of the field element."""
        return hash((type(self), int(self)))

    def __repr__(self) -> str:
        """String representation."""
        return f"Fp(value={int(self)})"
