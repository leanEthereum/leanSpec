"""Unsigned Integer Type Tests."""

import io
import operator
import re
from itertools import permutations
from typing import Any, Type

import pytest
from pydantic import BaseModel, ValidationError

from lean_spec.types import Uint8, Uint16, Uint32, Uint64
from lean_spec.types.exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from lean_spec.types.uint import BaseUint

ALL_UINT_TYPES = (Uint8, Uint16, Uint32, Uint64)
"""A collection of all Uint types to test against."""

CROSS_UINT_TYPE_PAIRS = list(permutations(ALL_UINT_TYPES, 2))
"""Every ordered pair of distinct unsigned integer widths."""


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
    expected = f"Expected int, got {expected_type_name}"
    with pytest.raises(SSZTypeError, match=rf"^{re.escape(expected)}$"):
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
    expected = f"-5 out of range for {uint_class.__name__} [0, {2**uint_class.BITS - 1}]"
    with pytest.raises(SSZValueError, match=rf"^{re.escape(expected)}$"):
        uint_class(-5)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_instantiation_too_large(uint_class: Type[BaseUint]) -> None:
    """Tests that instantiating with a value >= MAX raises SSZValueError."""
    max_value = 2**uint_class.BITS
    expected = f"{max_value} out of range for {uint_class.__name__} [0, {max_value - 1}]"
    with pytest.raises(SSZValueError, match=rf"^{re.escape(expected)}$"):
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
    max_int = (2**uint_class.BITS) - 1
    max_val = uint_class(max_int)
    name = uint_class.__name__

    # Addition
    assert a + b == uint_class(a_val + b_val)
    expected = f"{max_int + b_val} out of range for {name} [0, {max_int}]"
    with pytest.raises(SSZValueError, match=rf"^{re.escape(expected)}$"):
        _ = max_val + b

    # Subtraction
    assert a - b == uint_class(a_val - b_val)
    expected = f"{b_val - a_val} out of range for {name} [0, {max_int}]"
    with pytest.raises(SSZValueError, match=rf"^{re.escape(expected)}$"):
        _ = b - a

    # Multiplication
    assert a * b == uint_class(a_val * b_val)
    expected = f"{max_int * b_val} out of range for {name} [0, {max_int}]"
    with pytest.raises(SSZValueError, match=rf"^{re.escape(expected)}$"):
        _ = max_val * b

    # Floor Division
    assert a // b == uint_class(a_val // b_val)

    # Modulo
    assert a % b == uint_class(a_val % b_val)

    # Exponentiation
    assert uint_class(b_val) ** uint_class(4) == uint_class(b_val**4)
    if uint_class.BITS <= 16:  # Pow gets too big quickly
        expected = f"{a_val**b_val} out of range for {name} [0, {max_int}]"
        with pytest.raises(SSZValueError, match=rf"^{re.escape(expected)}$"):
            _ = a**b


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_reverse_arithmetic_operators_raise_error(uint_class: Type[BaseUint]) -> None:
    """Tests that reverse arithmetic operators raise a TypeError."""
    name = uint_class.__name__

    expected = f"Unsupported operand type(s) for +: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = 100 + uint_class(3)

    expected = f"Unsupported operand type(s) for -: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = 100 - uint_class(3)

    expected = f"Unsupported operand type(s) for *: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = 100 * uint_class(3)

    expected = f"Unsupported operand type(s) for //: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = 100 // uint_class(3)

    expected = f"Unsupported operand type(s) for %: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = 100 % uint_class(3)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_divmod(uint_class: Type[BaseUint]) -> None:
    """Tests the divmod function."""
    q, r = divmod(uint_class(100), uint_class(3))
    assert q == uint_class(33)
    assert r == uint_class(1)
    assert isinstance(q, uint_class)
    assert isinstance(r, uint_class)

    expected = f"Unsupported operand type(s) for divmod: '{uint_class.__name__}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = divmod(100, uint_class(3))  # type: ignore[call-overload]


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
    name = uint_class.__name__

    assert a & b == uint_class(0b1000)
    assert a | b == uint_class(0b1110)
    assert a ^ b == uint_class(0b0110)
    assert a << uint_class(2) == uint_class(0b110000)
    assert a >> uint_class(2) == uint_class(0b11)

    expected = f"Unsupported operand type(s) for &: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = a & 1

    expected = f"Unsupported operand type(s) for |: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = a | 1

    expected = f"Unsupported operand type(s) for ^: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = a ^ 1

    expected = f"Unsupported operand type(s) for <<: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = a << 1

    expected = f"Unsupported operand type(s) for >>: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = a >> 1


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
    name = uint_class.__name__

    expected = f"Unsupported operand type(s) for ==: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = uint_class(10) == 10

    expected = f"Unsupported operand type(s) for !=: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = 10 != uint_class(10)

    expected = f"Unsupported operand type(s) for >: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = uint_class(10) > 5

    # 5 < uint(10) routes to uint(10).__gt__(5) because uint is a strict int subclass.
    expected = f"Unsupported operand type(s) for >: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = 5 < uint_class(10)

    expected = f"Unsupported operand type(s) for >=: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
        _ = uint_class(10) >= 10

    # 10 <= uint(10) routes to uint(10).__ge__(10) by subclass priority.
    expected = f"Unsupported operand type(s) for >=: '{name}' and 'int'"
    with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
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
        expected_length = uint_class.get_byte_length()
        invalid_data = b"\x00" * (expected_length - 1)
        expected = (
            f"{uint_class.__name__}: expected {expected_length} bytes, got {expected_length - 1}"
        )
        with pytest.raises(SSZSerializationError, match=rf"^{re.escape(expected)}$"):
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
        byte_length = uint_class.get_byte_length()
        stream = io.BytesIO(b"\x00" * byte_length)
        invalid_scope = byte_length - 1
        expected = (
            f"{uint_class.__name__}: invalid scope, "
            f"expected {byte_length} bytes, got {invalid_scope}"
        )
        with pytest.raises(SSZSerializationError, match=rf"^{re.escape(expected)}$"):
            uint_class.deserialize(stream, scope=invalid_scope)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_deserialize_stream_too_short(self, uint_class: Type[BaseUint]) -> None:
        """Tests that `deserialize` raises SSZSerializationError if stream ends prematurely."""
        byte_length = uint_class.get_byte_length()
        # Create a stream that is shorter than what the type requires.
        stream = io.BytesIO(b"\x00" * (byte_length - 1))
        expected = f"{uint_class.__name__}: expected {byte_length} bytes, got {byte_length - 1}"
        with pytest.raises(SSZSerializationError, match=rf"^{re.escape(expected)}$"):
            uint_class.deserialize(stream, scope=byte_length)


class TestForwardArithmeticTypeErrors:
    """Tests that forward arithmetic operators reject plain int operands."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize(
        "method, op_symbol",
        [
            ("__add__", "+"),
            ("__sub__", "-"),
            ("__mul__", "*"),
            ("__floordiv__", "//"),
            ("__mod__", "%"),
        ],
    )
    def test_forward_operator_rejects_plain_int(
        self, uint_class: Type[BaseUint], method: str, op_symbol: str
    ) -> None:
        """Forward arithmetic operator raises TypeError when given a plain int."""
        # Call the dunder method directly with a plain int operand.
        expected = f"Unsupported operand type(s) for {op_symbol}: '{uint_class.__name__}' and 'int'"
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            getattr(uint_class(5), method)(3)


class TestReverseArithmeticSuccessPaths:
    """Tests that reverse arithmetic operators succeed when both operands are BaseUint."""

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
        result = pow(uint_class(2), uint_class(10), uint_class(100))
        assert result == uint_class(24)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rpow_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse pow computes base ** self when called directly."""
        # __rpow__(base) computes base ** self => 2 ** 3 == 8
        result = uint_class(3).__rpow__(uint_class(2))
        assert result == uint_class(8)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rpow_with_modulo(self, uint_class: Type[BaseUint]) -> None:
        """Three-argument reverse pow validates the modulo and returns the correct result."""
        # __rpow__(base, mod) computes pow(base, self, mod) => pow(2, 10, 100) == 24
        result = uint_class(10).__rpow__(uint_class(2), uint_class(100))
        assert result == uint_class(24)
        assert isinstance(result, uint_class)


class TestPowShiftStrictOperands:
    """Pow and shift operators require same-type operands like every other binary op."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [3, True, "3", 1.5])
    def test_pow_rejects_non_uint_exponent(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Exponentiation rejects any exponent of a different type."""
        expected = (
            f"Unsupported operand type(s) for **: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            uint_class(2) ** bad  # type: ignore[operator]

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [100, True])
    def test_pow_rejects_non_uint_modulo(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Three-argument pow rejects any modulo of a different type."""
        expected = (
            f"Unsupported operand type(s) for **: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            pow(uint_class(2), uint_class(10), bad)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [2, True])
    def test_rpow_rejects_non_uint_base(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Reverse pow rejects any base of a different type."""
        expected = (
            f"Unsupported operand type(s) for **: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            uint_class(3).__rpow__(bad)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [100, True])
    def test_rpow_rejects_non_uint_modulo(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Three-argument reverse pow rejects any modulo of a different type."""
        expected = (
            f"Unsupported operand type(s) for **: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            uint_class(10).__rpow__(uint_class(2), bad)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [3, True])
    def test_lshift_rejects_non_uint(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Left shift rejects any shift amount of a different type."""
        expected = (
            f"Unsupported operand type(s) for <<: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            uint_class(1) << bad  # type: ignore[operator]

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [2, True])
    def test_rshift_rejects_non_uint(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Right shift rejects any shift amount of a different type."""
        expected = (
            f"Unsupported operand type(s) for >>: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            uint_class(8) >> bad  # type: ignore[operator]


class TestDivmodEdgeCases:
    """Tests for divmod type error and reverse divmod paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_divmod_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Forward divmod raises TypeError when the divisor is a plain int."""
        expected = f"Unsupported operand type(s) for divmod: '{uint_class.__name__}' and 'int'"
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
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
        result = uint_class(2).__rlshift__(uint_class(1))
        assert result == uint_class(4)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [1, True])
    def test_rlshift_rejects_non_uint(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Reverse left shift rejects any operand of a different type."""
        expected = (
            f"Unsupported operand type(s) for <<: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            uint_class(2).__rlshift__(bad)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rrshift_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse right shift computes other >> self."""
        # __rrshift__(other) computes other >> self => 8 >> 2 == 2
        result = uint_class(2).__rrshift__(uint_class(8))
        assert result == uint_class(2)
        assert isinstance(result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [8, True])
    def test_rrshift_rejects_non_uint(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Reverse right shift rejects any operand of a different type."""
        expected = (
            f"Unsupported operand type(s) for >>: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            uint_class(2).__rrshift__(bad)


class TestComparisonTypeErrors:
    """Tests that comparison operators raise TypeError when given plain int operands."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_lt_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Less-than raises TypeError when compared to a plain int directly."""
        expected = f"Unsupported operand type(s) for <: '{uint_class.__name__}' and 'int'"
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            uint_class(5).__lt__(10)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_le_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Less-than-or-equal raises TypeError when compared to a plain int directly."""
        expected = f"Unsupported operand type(s) for <=: '{uint_class.__name__}' and 'int'"
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
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


class TestCrossWidthEqualityIsStrict:
    """Equality across different unsigned integer widths must raise."""

    @pytest.mark.parametrize("type_a, type_b", CROSS_UINT_TYPE_PAIRS)
    def test_eq_across_widths_raises(self, type_a: Type[BaseUint], type_b: Type[BaseUint]) -> None:
        """Equality across two distinct widths raises."""
        expected = (
            f"Unsupported operand type(s) for ==: '{type_a.__name__}' and '{type_b.__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            _ = type_a(5) == type_b(5)

    @pytest.mark.parametrize("type_a, type_b", CROSS_UINT_TYPE_PAIRS)
    def test_ne_across_widths_raises(self, type_a: Type[BaseUint], type_b: Type[BaseUint]) -> None:
        """Inequality across two distinct widths raises."""
        expected = (
            f"Unsupported operand type(s) for !=: '{type_a.__name__}' and '{type_b.__name__}'"
        )
        with pytest.raises(TypeError, match=rf"^{re.escape(expected)}$"):
            _ = type_a(5) != type_b(5)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_eq_same_width_same_value_still_equal(self, uint_class: Type[BaseUint]) -> None:
        """Within a single width, equal values still compare equal."""
        assert uint_class(7) == uint_class(7)
        assert not (uint_class(7) != uint_class(7))

    @pytest.mark.parametrize("type_a, type_b", CROSS_UINT_TYPE_PAIRS)
    def test_hash_differs_across_widths(
        self, type_a: Type[BaseUint], type_b: Type[BaseUint]
    ) -> None:
        """Equal-by-value instances of different widths hash differently."""
        assert hash(type_a(5)) != hash(type_b(5))
