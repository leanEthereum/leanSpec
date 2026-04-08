"""Unsigned Integer Type Tests."""

import io
import operator
from typing import Any, Type

import pytest
from pydantic import BaseModel, ValidationError

from lean_spec.types import Uint8, Uint16, Uint32, Uint64
from lean_spec.types.exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from lean_spec.types.uint import BaseUint

ALL_UINT_TYPES = (Uint8, Uint16, Uint32, Uint64)
"""A collection of all Uint types to test against."""


# Model classes for Pydantic validation tests
class Uint8Model(BaseModel):
    value: Uint8


class Uint16Model(BaseModel):
    value: Uint16


class Uint32Model(BaseModel):
    value: Uint32


class Uint64Model(BaseModel):
    value: Uint64


UINT_MODELS: dict[Type[BaseUint], Type[BaseModel]] = {
    Uint8: Uint8Model,
    Uint16: Uint16Model,
    Uint32: Uint32Model,
    Uint64: Uint64Model,
}
"""Mapping from Uint types to their corresponding Pydantic model classes."""


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_pydantic_validation_accepts_valid_int(uint_class: Type[BaseUint]) -> None:
    """Tests that Pydantic validation correctly accepts a valid integer."""
    model = UINT_MODELS[uint_class]
    instance = model(value=10)
    value = instance.value  # type: ignore[attr-defined]
    assert isinstance(value, uint_class)
    assert value == uint_class(10)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
@pytest.mark.parametrize("invalid_value", [1.0, "1", True, False])
def test_pydantic_strict_mode_rejects_invalid_types(
    uint_class: Type[BaseUint], invalid_value: Any
) -> None:
    """Tests that Pydantic's strict mode rejects types that could be coerced to an int."""
    model = UINT_MODELS[uint_class]
    with pytest.raises(ValidationError):
        model(value=invalid_value)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
@pytest.mark.parametrize(
    "invalid_value, expected_type_name",
    [
        (1.0, "float"),
        ("1", "str"),
        (True, "bool"),
        (False, "bool"),
        (b"1", "bytes"),
        (None, "NoneType"),
    ],
)
def test_instantiation_from_invalid_types_raises_error(
    uint_class: Type[BaseUint], invalid_value: Any, expected_type_name: str
) -> None:
    """Tests that instantiating with non-integer types raises SSZTypeError."""
    expected_msg = f"Expected int, got {expected_type_name}"
    with pytest.raises(SSZTypeError, match=expected_msg):
        uint_class(invalid_value)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_instantiation_and_type(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types are instances of `int` and their own class."""
    value = uint_class(5)
    assert isinstance(value, int)
    assert isinstance(value, BaseUint)
    assert isinstance(value, uint_class)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_instantiation_negative(uint_class: Type[BaseUint]) -> None:
    """Tests that instantiating with a negative number raises SSZValueError."""
    with pytest.raises(SSZValueError):
        uint_class(-5)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_instantiation_too_large(uint_class: Type[BaseUint]) -> None:
    """Tests that instantiating with a value >= MAX raises SSZValueError."""
    max_value = 2**uint_class.BITS
    with pytest.raises(SSZValueError):
        uint_class(max_value)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_max_method_returns_correct_value(uint_class: Type[BaseUint]) -> None:
    """Tests that the max_value() class method returns the correct value."""
    expected_max_int = (2**uint_class.BITS) - 1
    assert uint_class.max_value() == uint_class(expected_max_int)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_arithmetic_operators(uint_class: Type[BaseUint]) -> None:
    """Tests all standard arithmetic operators."""
    # Use smaller values for high-bit integers to avoid massive numbers
    a_val, b_val = (100, 3) if uint_class.BITS > 8 else (20, 3)
    a = uint_class(a_val)
    b = uint_class(b_val)
    max_val = uint_class((2**uint_class.BITS) - 1)

    # Addition
    assert a + b == uint_class(a_val + b_val)
    with pytest.raises(SSZValueError):
        _ = max_val + b

    # Subtraction
    assert a - b == uint_class(a_val - b_val)
    with pytest.raises(SSZValueError):
        _ = b - a

    # Multiplication
    assert a * b == uint_class(a_val * b_val)
    with pytest.raises(SSZValueError):
        _ = max_val * b

    # Floor Division
    assert a // b == uint_class(a_val // b_val)

    # Modulo
    assert a % b == uint_class(a_val % b_val)

    # Exponentiation
    assert uint_class(b_val) ** 4 == uint_class(b_val**4)
    if uint_class.BITS <= 16:  # Pow gets too big quickly
        with pytest.raises(SSZValueError):
            _ = a ** int(b)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_reverse_arithmetic_operators_raise_error(uint_class: Type[BaseUint]) -> None:
    """Tests that reverse arithmetic operators raise a TypeError."""
    with pytest.raises(TypeError):
        _ = 100 + uint_class(3)
    with pytest.raises(TypeError):
        _ = 100 - uint_class(3)
    with pytest.raises(TypeError):
        _ = 100 * uint_class(3)
    with pytest.raises(TypeError):
        _ = 100 // uint_class(3)
    with pytest.raises(TypeError):
        _ = 100 % uint_class(3)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_divmod(uint_class: Type[BaseUint]) -> None:
    """Tests the divmod function."""
    q, r = divmod(uint_class(100), uint_class(3))
    assert q == uint_class(33)
    assert r == uint_class(1)
    assert isinstance(q, uint_class)
    assert isinstance(r, uint_class)

    with pytest.raises(TypeError):
        _ = divmod(100, uint_class(3))


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_inplace_immutability(uint_class: Type[BaseUint]) -> None:
    """Tests that in-place operators return a new instance."""
    value1 = uint_class(10)
    value2 = value1
    value1 += uint_class(5)

    assert isinstance(value1, uint_class)
    assert value1 == uint_class(15)
    # The original variable reference is unchanged
    assert value2 == uint_class(10)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_bitwise_operators(uint_class: Type[BaseUint]) -> None:
    """Tests all standard bitwise operators."""
    a = uint_class(0b1100)  # 12
    b = uint_class(0b1010)  # 10

    assert a & b == uint_class(0b1000)
    assert a | b == uint_class(0b1110)
    assert a ^ b == uint_class(0b0110)
    assert a << 2 == uint_class(0b110000)
    assert a >> 2 == uint_class(0b11)

    with pytest.raises(TypeError):
        _ = a & 1
    with pytest.raises(TypeError):
        _ = a | 1
    with pytest.raises(TypeError):
        _ = a ^ 1


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_comparison_with_same_type(uint_class: Type[BaseUint]) -> None:
    """Tests all comparison operators between two Uint instances."""
    assert uint_class(5) < uint_class(10)
    assert uint_class(5) <= uint_class(10)
    assert uint_class(10) == uint_class(10)
    assert uint_class(10) != uint_class(5)
    assert uint_class(10) > uint_class(5)
    assert uint_class(10) >= uint_class(5)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_all_comparisons_with_other_types_raise_error(
    uint_class: Type[BaseUint],
) -> None:
    """Tests that all comparisons with incompatible types raise TypeError."""
    with pytest.raises(TypeError):
        _ = uint_class(10) == 10
    with pytest.raises(TypeError):
        _ = 10 != uint_class(10)
    with pytest.raises(TypeError):
        _ = uint_class(10) > 5
    with pytest.raises(TypeError):
        _ = 5 < uint_class(10)
    with pytest.raises(TypeError):
        _ = uint_class(10) >= 10
    with pytest.raises(TypeError):
        _ = 10 <= uint_class(10)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_repr_and_str(uint_class: Type[BaseUint]) -> None:
    """Tests the string and official representations."""
    value = uint_class(42)
    assert str(value) == "42"
    assert repr(value) == f"{uint_class.__name__}(42)"


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_hash(uint_class: Type[BaseUint]) -> None:
    """Tests that the hash is distinct from a raw int."""
    assert hash(uint_class(1)) != hash(1)
    assert hash(uint_class(1)) == hash(uint_class(1))
    assert hash(uint_class(1)) != hash(uint_class(2))


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_list_access(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types can be used directly for list indexing."""
    data = ["a", "b", "c", "d", "e"]
    idx = uint_class(2)
    assert data[idx] == "c"
    assert data[uint_class(0)] == "a"
    assert data[uint_class(4)] == "e"


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_slicing(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types can be used in slice operations."""
    data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    start = uint_class(2)
    stop = uint_class(7)
    step = uint_class(2)

    assert data[start:stop] == [2, 3, 4, 5, 6]
    assert data[:stop] == [0, 1, 2, 3, 4, 5, 6]
    assert data[start:] == [2, 3, 4, 5, 6, 7, 8, 9]
    assert data[start:stop:step] == [2, 4, 6]


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_range(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types can be used in range()."""
    n = uint_class(5)
    result = list(range(n))
    assert result == [0, 1, 2, 3, 4]

    start = uint_class(2)
    stop = uint_class(8)
    step = uint_class(2)
    result = list(range(start, stop, step))
    assert result == [2, 4, 6]


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_hex_bin_oct(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types work with hex(), bin(), oct()."""
    val = uint_class(42)
    assert hex(val) == "0x2a"
    assert bin(val) == "0b101010"
    assert oct(val) == "0o52"


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_operator_index(uint_class: Type[BaseUint]) -> None:
    """Tests that operator.index() works with Uint types."""
    val = uint_class(42)
    assert operator.index(val) == 42
    assert isinstance(operator.index(val), int)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_to_bytes_default(uint_class: Type[BaseUint]) -> None:
    """Tests the default behavior of the to_bytes method."""
    byte_length = uint_class.BITS // 8
    value = uint_class(1)
    expected = b"\x01" + b"\x00" * (byte_length - 1)
    assert value.to_bytes() == expected


def test_to_bytes_specifics() -> None:
    """Tests specific byte representations."""
    assert Uint8(255).to_bytes() == b"\xff"
    assert Uint16(258).to_bytes() == b"\x02\x01"  # Little-endian
    assert Uint16(258).to_bytes(byteorder="big") == b"\x01\x02"


def test_to_bytes_overflow() -> None:
    """Tests that to_bytes raises an error if the length is too small."""
    with pytest.raises(OverflowError):
        Uint32(256).to_bytes(length=1)

    with pytest.raises(OverflowError):
        Uint32(100).to_bytes(length=0)


class TestUintSSZ:
    """A collection of tests for the SSZ interface of Uint types."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_is_fixed_size(self, uint_class: Type[BaseUint]) -> None:
        """Tests that all Uint types are correctly identified as fixed-size."""
        assert uint_class.is_fixed_size() is True

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_get_byte_length(self, uint_class: Type[BaseUint]) -> None:
        """Tests that the byte length is correctly calculated from the bit width."""
        expected_length = uint_class.BITS // 8
        assert uint_class.get_byte_length() == expected_length

    @pytest.mark.parametrize(
        "uint_class, value, expected_hex",
        [
            (Uint8, 0x00, "00"),
            (Uint8, 0x01, "01"),
            (Uint8, 0xAB, "ab"),
            (Uint16, 0x0000, "0000"),
            (Uint16, 0xABCD, "cdab"),
            (Uint32, 0x00000000, "00000000"),
            (Uint32, 0x01234567, "67452301"),
            (Uint64, 0x0000000000000000, "0000000000000000"),
            (Uint64, 0x0123456789ABCDEF, "efcdab8967452301"),
        ],
    )
    def test_encode_decode_roundtrip(
        self, uint_class: Type[BaseUint], value: int, expected_hex: str
    ) -> None:
        """Tests the roundtrip of encoding and decoding for specific values."""
        # Create an instance of the specific Uint type.
        instance = uint_class(value)

        # 1. Test encoding (serialization)
        encoded = instance.encode_bytes()
        assert encoded.hex() == expected_hex

        # 2. Test decoding (deserialization)
        decoded = uint_class.decode_bytes(encoded)
        assert decoded == instance

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_decode_bytes_invalid_length(self, uint_class: Type[BaseUint]) -> None:
        """Tests that `decode_bytes` raises SSZSerializationError for wrong length data."""
        # Create byte string that is one byte too short.
        invalid_data = b"\x00" * (uint_class.get_byte_length() - 1)
        with pytest.raises(SSZSerializationError, match="expected .* bytes, got"):
            uint_class.decode_bytes(invalid_data)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_serialize_deserialize_stream_roundtrip(self, uint_class: Type[BaseUint]) -> None:
        """Tests the round trip of serializing to and deserializing from a stream."""
        # Create a test instance with a non-zero value.
        instance = uint_class(123)
        byte_length = uint_class.get_byte_length()

        # 1. Test serialization to a stream
        stream = io.BytesIO()
        bytes_written = instance.serialize(stream)
        assert bytes_written == byte_length
        stream.seek(0)  # Rewind stream to the beginning for reading.
        assert stream.read() == instance.encode_bytes()

        # 2. Test deserialization from a stream
        stream.seek(0)  # Rewind again for the deserialization test.
        decoded = uint_class.deserialize(stream, scope=byte_length)
        assert decoded == instance

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_deserialize_invalid_scope(self, uint_class: Type[BaseUint]) -> None:
        """Tests that `deserialize` raises an SSZSerializationError if the scope is incorrect."""
        stream = io.BytesIO(b"\x00" * uint_class.get_byte_length())
        invalid_scope = uint_class.get_byte_length() - 1
        with pytest.raises(SSZSerializationError, match="invalid scope"):
            uint_class.deserialize(stream, scope=invalid_scope)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_deserialize_stream_too_short(self, uint_class: Type[BaseUint]) -> None:
        """Tests that `deserialize` raises SSZSerializationError if stream ends prematurely."""
        byte_length = uint_class.get_byte_length()
        # Create a stream that is shorter than what the type requires.
        stream = io.BytesIO(b"\x00" * (byte_length - 1))
        with pytest.raises(SSZSerializationError, match="expected .* bytes, got"):
            uint_class.deserialize(stream, scope=byte_length)


class TestForwardArithmeticTypeErrors:
    """Tests that forward arithmetic operators reject plain int operands.

    When calling e.g. Uint64(5).__add__(3), the forward operator must raise
    TypeError because 3 is a plain int, not a BaseUint subclass.
    """

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize(
        "method, op_symbol",
        [
            ("__add__", r"\+"),
            ("__sub__", r"-"),
            ("__mul__", r"\*"),
            ("__floordiv__", r"//"),
            ("__mod__", r"%"),
        ],
    )
    def test_forward_operator_rejects_plain_int(
        self, uint_class: Type[BaseUint], method: str, op_symbol: str
    ) -> None:
        """Forward arithmetic operator raises TypeError when given a plain int."""
        # Call the dunder method directly with a plain int operand.
        with pytest.raises(TypeError, match=op_symbol):
            getattr(uint_class(5), method)(3)


class TestReverseArithmeticSuccessPaths:
    """Tests that reverse arithmetic operators succeed when both operands are BaseUint.

    Calling the reverse dunder directly (e.g. Uint64(3).__radd__(Uint64(5)))
    exercises the success return path of each reverse operator.
    """

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_radd_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse add returns the correct sum when called directly."""
        # __radd__(other) computes other + self
        result = uint_class(3).__radd__(uint_class(5))
        assert result == uint_class(8)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rsub_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse sub returns the correct difference when called directly."""
        # __rsub__(other) computes other - self
        result = uint_class(3).__rsub__(uint_class(10))
        assert result == uint_class(7)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rmul_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse mul returns the correct product when called directly."""
        # __rmul__(other) computes other * self
        result = uint_class(3).__rmul__(uint_class(5))
        assert result == uint_class(15)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rfloordiv_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse floordiv returns the correct quotient when called directly."""
        # __rfloordiv__(other) computes other // self
        result = uint_class(3).__rfloordiv__(uint_class(10))
        assert result == uint_class(3)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rmod_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse mod returns the correct remainder when called directly."""
        # __rmod__(other) computes other % self
        result = uint_class(3).__rmod__(uint_class(10))
        assert result == uint_class(1)
        assert isinstance(result, uint_class)


class TestPowAndRpow:
    """Tests for exponentiation operators including modulo and reverse paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_pow_with_modulo(self, uint_class: Type[BaseUint]) -> None:
        """Three-argument pow(base, exp, mod) validates the modulo and returns correct result."""
        # pow(2, 10, 100) == 1024 % 100 == 24
        result = pow(uint_class(2), 10, 100)
        assert result == uint_class(24)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_pow_with_bool_modulo_raises(self, uint_class: Type[BaseUint]) -> None:
        """Three-argument pow rejects a bool as the modulo operand."""
        with pytest.raises(TypeError, match=r"expected 'int' but got 'bool'"):
            pow(uint_class(2), 10, True)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rpow_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse pow computes base ** self when called directly."""
        # __rpow__(base) computes base ** self => 2 ** 3 == 8
        result = uint_class(3).__rpow__(uint_class(2))
        assert result == uint_class(8)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rpow_rejects_bool(self, uint_class: Type[BaseUint]) -> None:
        """Reverse pow rejects a bool as the base operand."""
        with pytest.raises(TypeError, match=r"expected 'int' but got 'bool'"):
            uint_class(3).__rpow__(True)


class TestValidateIntOperand:
    """Tests for _validate_int_operand which rejects bools and non-ints."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_pow_rejects_bool_exponent(self, uint_class: Type[BaseUint]) -> None:
        """Exponentiation rejects a bool as the exponent."""
        with pytest.raises(TypeError, match=r"expected 'int' but got 'bool'"):
            uint_class(2) ** True

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_pow_rejects_string_exponent(self, uint_class: Type[BaseUint]) -> None:
        """Exponentiation rejects a string as the exponent."""
        with pytest.raises(TypeError, match=r"expected 'int' but got 'str'"):
            uint_class(2) ** "3"  # type: ignore[operator]

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_lshift_rejects_bool(self, uint_class: Type[BaseUint]) -> None:
        """Left shift rejects a bool as the shift amount."""
        with pytest.raises(TypeError, match=r"expected 'int' but got 'bool'"):
            uint_class(1) << True

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rshift_rejects_bool(self, uint_class: Type[BaseUint]) -> None:
        """Right shift rejects a bool as the shift amount."""
        with pytest.raises(TypeError, match=r"expected 'int' but got 'bool'"):
            uint_class(8) >> True


class TestDivmodEdgeCases:
    """Tests for divmod type error and reverse divmod paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_divmod_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Forward divmod raises TypeError when the divisor is a plain int."""
        with pytest.raises(TypeError, match="divmod"):
            divmod(uint_class(10), 3)  # type: ignore[call-overload]

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rdivmod_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse divmod returns correct (quotient, remainder) when called directly."""
        # __rdivmod__(other) computes divmod(other, self) => divmod(10, 3) == (3, 1)
        q, r = uint_class(3).__rdivmod__(uint_class(10))
        assert q == uint_class(3)
        assert r == uint_class(1)
        assert isinstance(q, uint_class)
        assert isinstance(r, uint_class)


class TestReverseBitwiseOperators:
    """Tests for reverse bitwise operator delegation paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rand_delegates_to_and(self, uint_class: Type[BaseUint]) -> None:
        """Reverse AND delegates to forward AND and returns the correct result."""
        # __rand__ delegates to __and__
        result = uint_class(0b1100).__rand__(uint_class(0b1010))
        assert result == uint_class(0b1000)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_ror_delegates_to_or(self, uint_class: Type[BaseUint]) -> None:
        """Reverse OR delegates to forward OR and returns the correct result."""
        # __ror__ delegates to __or__
        result = uint_class(0b1100).__ror__(uint_class(0b1010))
        assert result == uint_class(0b1110)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rxor_delegates_to_xor(self, uint_class: Type[BaseUint]) -> None:
        """Reverse XOR delegates to forward XOR and returns the correct result."""
        # __rxor__ delegates to __xor__
        result = uint_class(0b1100).__rxor__(uint_class(0b1010))
        assert result == uint_class(0b0110)
        assert isinstance(result, uint_class)


class TestReverseShiftOperators:
    """Tests for reverse left-shift and right-shift operator paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rlshift_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse left shift computes other << self."""
        # __rlshift__(other) computes other << self => 1 << 2 == 4
        result = uint_class(2).__rlshift__(1)
        assert result == uint_class(4)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rlshift_rejects_bool(self, uint_class: Type[BaseUint]) -> None:
        """Reverse left shift rejects a bool operand."""
        with pytest.raises(TypeError, match=r"expected 'int' but got 'bool'"):
            uint_class(2).__rlshift__(True)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rrshift_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse right shift computes other >> self."""
        # __rrshift__(other) computes other >> self => 8 >> 2 == 2
        result = uint_class(2).__rrshift__(8)
        assert result == uint_class(2)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rrshift_rejects_bool(self, uint_class: Type[BaseUint]) -> None:
        """Reverse right shift rejects a bool operand."""
        with pytest.raises(TypeError, match=r"expected 'int' but got 'bool'"):
            uint_class(2).__rrshift__(True)


class TestComparisonTypeErrors:
    """Tests that comparison operators raise TypeError when given plain int operands.

    The existing test_all_comparisons_with_other_types_raise_error uses the operator
    syntax (e.g., `uint < 10`) which for __lt__ and __le__ may be resolved by Python
    as int.__gt__ and int.__ge__ instead. Calling the dunder directly ensures the
    BaseUint implementation is exercised.
    """

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_lt_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Less-than raises TypeError when compared to a plain int directly."""
        with pytest.raises(TypeError, match="<"):
            uint_class(5).__lt__(10)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_le_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Less-than-or-equal raises TypeError when compared to a plain int directly."""
        with pytest.raises(TypeError, match="<="):
            uint_class(5).__le__(10)


class TestIndexReturnsPlainInt:
    """Tests that __index__ returns a plain int, not a BaseUint subclass."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_index_returns_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """__index__ returns a plain int so that built-in operations receive a raw integer."""
        result = uint_class(42).__index__()
        # The value must be correct.
        assert result == 42
        # The type must be plain int, not a BaseUint subclass.
        assert type(result) is int
