"""Unsigned Integer Type Tests."""

import io
import operator
from itertools import permutations
from typing import Any, Type

import pytest
from hypothesis import given, strategies as st
from pydantic import BaseModel, ValidationError

from lean_spec.spec.ssz import Uint8, Uint16, Uint32, Uint64
from lean_spec.spec.ssz.exceptions import SSZSerializationError, SSZTypeError, SSZValueError
from lean_spec.spec.ssz.uint import BaseUint

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
    validated_value = instance.value  # type: ignore[attribute-defined]
    assert isinstance(validated_value, uint_class)
    assert validated_value == uint_class(10)


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
    expected_message = f"Expected int, got {expected_type_name}"
    with pytest.raises(SSZTypeError) as exception_info:
        uint_class(invalid_value)
    assert str(exception_info.value) == expected_message


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_instantiation_and_type(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types are instances of `int` and their own class."""
    uint_instance = uint_class(5)
    assert isinstance(uint_instance, int)
    assert isinstance(uint_instance, BaseUint)
    assert isinstance(uint_instance, uint_class)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_instantiation_negative(uint_class: Type[BaseUint]) -> None:
    """Tests that instantiating with a negative number raises SSZValueError."""
    expected_message = f"-5 out of range for {uint_class.__name__} [0, {2**uint_class.BITS - 1}]"
    with pytest.raises(SSZValueError) as exception_info:
        uint_class(-5)
    assert str(exception_info.value) == expected_message


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_instantiation_too_large(uint_class: Type[BaseUint]) -> None:
    """Tests that instantiating with a value >= MAX raises SSZValueError."""
    max_value = 2**uint_class.BITS
    expected_message = f"{max_value} out of range for {uint_class.__name__} [0, {max_value - 1}]"
    with pytest.raises(SSZValueError) as exception_info:
        uint_class(max_value)
    assert str(exception_info.value) == expected_message


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_max_method_returns_correct_value(uint_class: Type[BaseUint]) -> None:
    """Tests that the max_value() class method returns the correct value."""
    expected_max_int = (2**uint_class.BITS) - 1
    assert uint_class.max_value() == uint_class(expected_max_int)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_arithmetic_operators(uint_class: Type[BaseUint]) -> None:
    """Tests all standard arithmetic operators."""
    # Use smaller values for high-bit integers to avoid massive numbers
    a_value, b_value = (100, 3) if uint_class.BITS > 8 else (20, 3)
    left = uint_class(a_value)
    right = uint_class(b_value)
    max_int = (2**uint_class.BITS) - 1
    max_value = uint_class(max_int)
    name = uint_class.__name__

    # Addition
    assert left + right == uint_class(a_value + b_value)
    expected_message = f"{max_int + b_value} out of range for {name} [0, {max_int}]"
    with pytest.raises(SSZValueError) as exception_info:
        _ = max_value + right
    assert str(exception_info.value) == expected_message

    # Subtraction
    assert left - right == uint_class(a_value - b_value)
    expected_message = f"{b_value - a_value} out of range for {name} [0, {max_int}]"
    with pytest.raises(SSZValueError) as exception_info:
        _ = right - left
    assert str(exception_info.value) == expected_message

    # Multiplication
    assert left * right == uint_class(a_value * b_value)
    expected_message = f"{max_int * b_value} out of range for {name} [0, {max_int}]"
    with pytest.raises(SSZValueError) as exception_info:
        _ = max_value * right
    assert str(exception_info.value) == expected_message

    # Floor Division
    assert left // right == uint_class(a_value // b_value)

    # Modulo
    assert left % right == uint_class(a_value % b_value)

    # Exponentiation
    assert uint_class(b_value) ** uint_class(4) == uint_class(b_value**4)
    if uint_class.BITS <= 16:  # Pow gets too big quickly
        expected_message = f"{a_value**b_value} out of range for {name} [0, {max_int}]"
        with pytest.raises(SSZValueError) as exception_info:
            _ = left**right
        assert str(exception_info.value) == expected_message


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_reverse_arithmetic_operators_raise_error(uint_class: Type[BaseUint]) -> None:
    """Tests that reverse arithmetic operators raise a TypeError."""
    name = uint_class.__name__

    expected_message = f"Unsupported operand type(s) for +: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = 100 + uint_class(3)
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for -: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = 100 - uint_class(3)
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for *: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = 100 * uint_class(3)
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for //: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = 100 // uint_class(3)
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for %: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = 100 % uint_class(3)
    assert str(exception_info.value) == expected_message


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_divmod(uint_class: Type[BaseUint]) -> None:
    """Tests the divmod function."""
    quotient, remainder = divmod(uint_class(100), uint_class(3))
    assert quotient == uint_class(33)
    assert remainder == uint_class(1)
    assert isinstance(quotient, uint_class)
    assert isinstance(remainder, uint_class)

    expected_message = f"Unsupported operand type(s) for divmod: '{uint_class.__name__}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = divmod(100, uint_class(3))
    assert str(exception_info.value) == expected_message


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
    left = uint_class(0b1100)  # 12
    right = uint_class(0b1010)  # 10
    name = uint_class.__name__

    assert left & right == uint_class(0b1000)
    assert left | right == uint_class(0b1110)
    assert left ^ right == uint_class(0b0110)
    assert left << uint_class(2) == uint_class(0b110000)
    assert left >> uint_class(2) == uint_class(0b11)

    expected_message = f"Unsupported operand type(s) for &: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = left & 1
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for |: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = left | 1
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for ^: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = left ^ 1
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for <<: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = left << 1
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for >>: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = left >> 1
    assert str(exception_info.value) == expected_message


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

    expected_message = f"Unsupported operand type(s) for ==: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = uint_class(10) == 10
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for !=: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = 10 != uint_class(10)
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for >: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = uint_class(10) > 5
    assert str(exception_info.value) == expected_message

    # 5 < uint(10) routes to uint(10).__gt__(5) because uint is a strict int subclass.
    expected_message = f"Unsupported operand type(s) for >: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = 5 < uint_class(10)
    assert str(exception_info.value) == expected_message

    expected_message = f"Unsupported operand type(s) for >=: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = uint_class(10) >= 10
    assert str(exception_info.value) == expected_message

    # 10 <= uint(10) routes to uint(10).__ge__(10) by subclass priority.
    expected_message = f"Unsupported operand type(s) for >=: '{name}' and 'int'"
    with pytest.raises(TypeError) as exception_info:
        _ = 10 <= uint_class(10)
    assert str(exception_info.value) == expected_message


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_repr_and_str(uint_class: Type[BaseUint]) -> None:
    """Tests the string and official representations."""
    uint_instance = uint_class(42)
    assert str(uint_instance) == "42"
    assert repr(uint_instance) == f"{uint_class.__name__}(42)"


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_hash(uint_class: Type[BaseUint]) -> None:
    """Tests that the hash is distinct from a raw int."""
    assert hash(uint_class(1)) != hash(1)
    assert hash(uint_class(1)) == hash(uint_class(1))
    assert hash(uint_class(1)) != hash(uint_class(2))


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_list_access(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types can be used directly for list indexing."""
    letters = ["a", "b", "c", "d", "e"]
    index = uint_class(2)
    assert letters[index] == "c"
    assert letters[uint_class(0)] == "a"
    assert letters[uint_class(4)] == "e"


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_slicing(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types can be used in slice operations."""
    numbers = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    start = uint_class(2)
    stop = uint_class(7)
    step = uint_class(2)

    assert numbers[start:stop] == [2, 3, 4, 5, 6]
    assert numbers[:stop] == [0, 1, 2, 3, 4, 5, 6]
    assert numbers[start:] == [2, 3, 4, 5, 6, 7, 8, 9]
    assert numbers[start:stop:step] == [2, 4, 6]


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_range(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types can be used in range()."""
    stop = uint_class(5)
    single_argument_range = list(range(stop))
    assert single_argument_range == [0, 1, 2, 3, 4]

    start = uint_class(2)
    stop = uint_class(8)
    step = uint_class(2)
    strided_range = list(range(start, stop, step))
    assert strided_range == [2, 4, 6]


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_hex_bin_oct(uint_class: Type[BaseUint]) -> None:
    """Tests that Uint types work with hex(), bin(), oct()."""
    uint_instance = uint_class(42)
    assert hex(uint_instance) == "0x2a"
    assert bin(uint_instance) == "0b101010"
    assert oct(uint_instance) == "0o52"


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_index_operator_index(uint_class: Type[BaseUint]) -> None:
    """Tests that operator.index() works with Uint types."""
    uint_instance = uint_class(42)
    assert operator.index(uint_instance) == 42
    assert isinstance(operator.index(uint_instance), int)


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
        expected_message = (
            f"{uint_class.__name__}: expected {expected_length} bytes, got {expected_length - 1}"
        )
        with pytest.raises(SSZSerializationError) as exception_info:
            uint_class.decode_bytes(invalid_data)
        assert str(exception_info.value) == expected_message

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
        expected_message = (
            f"{uint_class.__name__}: invalid scope, "
            f"expected {byte_length} bytes, got {invalid_scope}"
        )
        with pytest.raises(SSZSerializationError) as exception_info:
            uint_class.deserialize(stream, scope=invalid_scope)
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_deserialize_stream_too_short(self, uint_class: Type[BaseUint]) -> None:
        """Tests that `deserialize` raises SSZSerializationError if stream ends prematurely."""
        byte_length = uint_class.get_byte_length()
        # Create a stream that is shorter than what the type requires.
        stream = io.BytesIO(b"\x00" * (byte_length - 1))
        expected_message = (
            f"{uint_class.__name__}: expected {byte_length} bytes, got {byte_length - 1}"
        )
        with pytest.raises(SSZSerializationError) as exception_info:
            uint_class.deserialize(stream, scope=byte_length)
        assert str(exception_info.value) == expected_message


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
        expected_message = (
            f"Unsupported operand type(s) for {op_symbol}: '{uint_class.__name__}' and 'int'"
        )
        with pytest.raises(TypeError) as exception_info:
            getattr(uint_class(5), method)(3)
        assert str(exception_info.value) == expected_message


class TestReverseArithmeticSuccessPaths:
    """Tests that reverse arithmetic operators succeed when both operands are BaseUint."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_radd_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse add returns the correct sum when called directly."""
        # __radd__(other) computes other + self
        reverse_sum = uint_class(3).__radd__(uint_class(5))
        assert reverse_sum == uint_class(8)
        assert isinstance(reverse_sum, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rsub_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse sub returns the correct difference when called directly."""
        # __rsub__(other) computes other - self
        reverse_difference = uint_class(3).__rsub__(uint_class(10))
        assert reverse_difference == uint_class(7)
        assert isinstance(reverse_difference, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rmul_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse mul returns the correct product when called directly."""
        # __rmul__(other) computes other * self
        reverse_product = uint_class(3).__rmul__(uint_class(5))
        assert reverse_product == uint_class(15)
        assert isinstance(reverse_product, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rfloordiv_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse floordiv returns the correct quotient when called directly."""
        # __rfloordiv__(other) computes other // self
        reverse_quotient = uint_class(3).__rfloordiv__(uint_class(10))
        assert reverse_quotient == uint_class(3)
        assert isinstance(reverse_quotient, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rmod_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse mod returns the correct remainder when called directly."""
        # __rmod__(other) computes other % self
        reverse_remainder = uint_class(3).__rmod__(uint_class(10))
        assert reverse_remainder == uint_class(1)
        assert isinstance(reverse_remainder, uint_class)


class TestPowAndRpow:
    """Tests for exponentiation operators including modulo and reverse paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_pow_with_modulo(self, uint_class: Type[BaseUint]) -> None:
        """Three-argument pow(base, exp, mod) validates the modulo and returns correct result."""
        # pow(2, 10, 100) == 1024 % 100 == 24
        modular_power = pow(uint_class(2), uint_class(10), uint_class(100))
        assert modular_power == uint_class(24)
        assert isinstance(modular_power, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rpow_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse pow computes base ** self when called directly."""
        # __rpow__(base) computes base ** self => 2 ** 3 == 8
        reverse_power = uint_class(3).__rpow__(uint_class(2))
        assert reverse_power == uint_class(8)
        assert isinstance(reverse_power, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rpow_with_modulo(self, uint_class: Type[BaseUint]) -> None:
        """Three-argument reverse pow validates the modulo and returns the correct result."""
        # __rpow__(base, mod) computes pow(base, self, mod) => pow(2, 10, 100) == 24
        reverse_modular_power = uint_class(10).__rpow__(uint_class(2), uint_class(100))
        assert reverse_modular_power == uint_class(24)
        assert isinstance(reverse_modular_power, uint_class)


class TestPowShiftStrictOperands:
    """Pow and shift operators require same-type operands like every other binary op."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [3, True, "3", 1.5])
    def test_pow_rejects_non_uint_exponent(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Exponentiation rejects any exponent of a different type."""
        expected_message = (
            f"Unsupported operand type(s) for **: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            uint_class(2) ** bad
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [100, True])
    def test_pow_rejects_non_uint_modulo(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Three-argument pow rejects any modulo of a different type."""
        expected_message = (
            f"Unsupported operand type(s) for **: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            pow(uint_class(2), uint_class(10), bad)
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [2, True])
    def test_rpow_rejects_non_uint_base(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Reverse pow rejects any base of a different type."""
        expected_message = (
            f"Unsupported operand type(s) for **: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            uint_class(3).__rpow__(bad)
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [100, True])
    def test_rpow_rejects_non_uint_modulo(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Three-argument reverse pow rejects any modulo of a different type."""
        expected_message = (
            f"Unsupported operand type(s) for **: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            uint_class(10).__rpow__(uint_class(2), bad)
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [3, True])
    def test_lshift_rejects_non_uint(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Left shift rejects any shift amount of a different type."""
        expected_message = (
            f"Unsupported operand type(s) for <<: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            uint_class(1) << bad
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [2, True])
    def test_rshift_rejects_non_uint(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Right shift rejects any shift amount of a different type."""
        expected_message = (
            f"Unsupported operand type(s) for >>: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            uint_class(8) >> bad
        assert str(exception_info.value) == expected_message


class TestDivmodEdgeCases:
    """Tests for divmod type error and reverse divmod paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_divmod_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Forward divmod raises TypeError when the divisor is a plain int."""
        expected_message = (
            f"Unsupported operand type(s) for divmod: '{uint_class.__name__}' and 'int'"
        )
        with pytest.raises(TypeError) as exception_info:
            divmod(uint_class(10), 3)
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rdivmod_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse divmod returns correct (quotient, remainder) when called directly."""
        # __rdivmod__(other) computes divmod(other, self) => divmod(10, 3) == (3, 1)
        quotient, remainder = uint_class(3).__rdivmod__(uint_class(10))
        assert quotient == uint_class(3)
        assert remainder == uint_class(1)
        assert isinstance(quotient, uint_class)
        assert isinstance(remainder, uint_class)


class TestReverseBitwiseOperators:
    """Tests for reverse bitwise operator delegation paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rand_delegates_to_and(self, uint_class: Type[BaseUint]) -> None:
        """Reverse AND delegates to forward AND and returns the correct result."""
        # __rand__ delegates to __and__
        reverse_and_result = uint_class(0b1100).__rand__(uint_class(0b1010))
        assert reverse_and_result == uint_class(0b1000)
        assert isinstance(reverse_and_result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_ror_delegates_to_or(self, uint_class: Type[BaseUint]) -> None:
        """Reverse OR delegates to forward OR and returns the correct result."""
        # __ror__ delegates to __or__
        reverse_or_result = uint_class(0b1100).__ror__(uint_class(0b1010))
        assert reverse_or_result == uint_class(0b1110)
        assert isinstance(reverse_or_result, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rxor_delegates_to_xor(self, uint_class: Type[BaseUint]) -> None:
        """Reverse XOR delegates to forward XOR and returns the correct result."""
        # __rxor__ delegates to __xor__
        reverse_xor_result = uint_class(0b1100).__rxor__(uint_class(0b1010))
        assert reverse_xor_result == uint_class(0b0110)
        assert isinstance(reverse_xor_result, uint_class)


class TestReverseShiftOperators:
    """Tests for reverse left-shift and right-shift operator paths."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rlshift_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse left shift computes other << self."""
        # __rlshift__(other) computes other << self => 1 << 2 == 4
        reverse_left_shift = uint_class(2).__rlshift__(uint_class(1))
        assert reverse_left_shift == uint_class(4)
        assert isinstance(reverse_left_shift, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [1, True])
    def test_rlshift_rejects_non_uint(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Reverse left shift rejects any operand of a different type."""
        expected_message = (
            f"Unsupported operand type(s) for <<: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            uint_class(2).__rlshift__(bad)
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_rrshift_success(self, uint_class: Type[BaseUint]) -> None:
        """Reverse right shift computes other >> self."""
        # __rrshift__(other) computes other >> self => 8 >> 2 == 2
        reverse_right_shift = uint_class(2).__rrshift__(uint_class(8))
        assert reverse_right_shift == uint_class(2)
        assert isinstance(reverse_right_shift, uint_class)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    @pytest.mark.parametrize("bad", [8, True])
    def test_rrshift_rejects_non_uint(self, uint_class: Type[BaseUint], bad: Any) -> None:
        """Reverse right shift rejects any operand of a different type."""
        expected_message = (
            f"Unsupported operand type(s) for >>: "
            f"'{uint_class.__name__}' and '{type(bad).__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            uint_class(2).__rrshift__(bad)
        assert str(exception_info.value) == expected_message


class TestComparisonTypeErrors:
    """Tests that comparison operators raise TypeError when given plain int operands."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_lt_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Less-than raises TypeError when compared to a plain int directly."""
        expected_message = f"Unsupported operand type(s) for <: '{uint_class.__name__}' and 'int'"
        with pytest.raises(TypeError) as exception_info:
            uint_class(5).__lt__(10)
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_le_rejects_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """Less-than-or-equal raises TypeError when compared to a plain int directly."""
        expected_message = f"Unsupported operand type(s) for <=: '{uint_class.__name__}' and 'int'"
        with pytest.raises(TypeError) as exception_info:
            uint_class(5).__le__(10)
        assert str(exception_info.value) == expected_message


class TestIndexReturnsPlainInt:
    """Tests that __index__ returns a plain int, not a BaseUint subclass."""

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_index_returns_plain_int(self, uint_class: Type[BaseUint]) -> None:
        """__index__ returns a plain int so that built-in operations receive a raw integer."""
        index_value = uint_class(42).__index__()
        # The value must be correct.
        assert index_value == 42
        # The type must be plain int, not a BaseUint subclass.
        assert type(index_value) is int


class TestCrossWidthEqualityIsStrict:
    """Equality across different unsigned integer widths must raise."""

    @pytest.mark.parametrize("type_a, type_b", CROSS_UINT_TYPE_PAIRS)
    def test_eq_across_widths_raises(self, type_a: Type[BaseUint], type_b: Type[BaseUint]) -> None:
        """Equality across two distinct widths raises."""
        expected_message = (
            f"Unsupported operand type(s) for ==: '{type_a.__name__}' and '{type_b.__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            _ = type_a(5) == type_b(5)
        assert str(exception_info.value) == expected_message

    @pytest.mark.parametrize("type_a, type_b", CROSS_UINT_TYPE_PAIRS)
    def test_ne_across_widths_raises(self, type_a: Type[BaseUint], type_b: Type[BaseUint]) -> None:
        """Inequality across two distinct widths raises."""
        expected_message = (
            f"Unsupported operand type(s) for !=: '{type_a.__name__}' and '{type_b.__name__}'"
        )
        with pytest.raises(TypeError) as exception_info:
            _ = type_a(5) != type_b(5)
        assert str(exception_info.value) == expected_message

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


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
@given(data=st.data())
def test_encode_decode_round_trip_random_values(uint_class: Type[BaseUint], data) -> None:
    """Any in-range value survives an encode and decode round trip unchanged."""
    raw_value = data.draw(st.integers(min_value=0, max_value=2**uint_class.BITS - 1))
    instance = uint_class(raw_value)
    assert uint_class.decode_bytes(instance.encode_bytes()) == instance
