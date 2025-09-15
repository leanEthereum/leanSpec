"""Unsigned Integer Type Tests."""

import io
from typing import IO, Any, Type

import pytest
from pydantic import ValidationError, create_model

from lean_spec.types.uint import (
    BaseUint,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
)

ALL_UINT_TYPES = (Uint8, Uint16, Uint32, Uint64, Uint128, Uint256)
"""A collection of all Uint types to test against."""


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_pydantic_validation_accepts_valid_int(uint_class: Type[BaseUint]) -> None:
    """Tests that Pydantic validation correctly accepts a valid integer."""
    # Create the model dynamically
    model = create_model("Model", value=(uint_class, ...))

    # This should pass without errors
    instance: Any = model(value=10)
    assert isinstance(instance.value, uint_class)
    # This assert will also be fixed by the changes in the next section
    assert instance.value == uint_class(10)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
@pytest.mark.parametrize("invalid_value", [1.0, "1", True, False])
def test_pydantic_strict_mode_rejects_invalid_types(
    uint_class: Type[BaseUint], invalid_value: Any
) -> None:
    """
    Tests that Pydantic's strict mode rejects types that could be coerced to an int.
    """
    # Create the model dynamically
    model = create_model("Model", value=(uint_class, ...))

    # Pydantic should raise a ValidationError because of the strict=True flag
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
    """Tests that instantiating with non-integer types raises a TypeError."""
    expected_msg = f"Expected int, got {expected_type_name}"
    with pytest.raises(TypeError, match=expected_msg):
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
    """Tests that instantiating with a negative number raises OverflowError."""
    with pytest.raises(OverflowError):
        uint_class(-5)


@pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
def test_instantiation_too_large(uint_class: Type[BaseUint]) -> None:
    """Tests that instantiating with a value >= MAX raises OverflowError."""
    max_value = 2**uint_class.BITS
    with pytest.raises(OverflowError):
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
    with pytest.raises(OverflowError):
        _ = max_val + b

    # Subtraction
    assert a - b == uint_class(a_val - b_val)
    with pytest.raises(OverflowError):
        _ = b - a

    # Multiplication
    assert a * b == uint_class(a_val * b_val)
    with pytest.raises(OverflowError):
        _ = max_val * b

    # Floor Division
    assert a // b == uint_class(a_val // b_val)

    # Modulo
    assert a % b == uint_class(a_val % b_val)

    # Exponentiation
    assert uint_class(b_val) ** 4 == uint_class(b_val**4)
    if uint_class.BITS <= 16:  # Pow gets too big quickly
        with pytest.raises(OverflowError):
            _ = a ** b.as_int()


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
            (Uint128, 0x0, "00000000000000000000000000000000"),
            (Uint128, 0x11223344556677880123456789ABCDEF, "efcdab89674523018877665544332211"),
            (Uint256, 0x0, "00" * 32),
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
        """Tests that `decode_bytes` raises a ValueError for data of the wrong length."""
        # Create byte string that is one byte too short.
        invalid_data = b"\x00" * (uint_class.get_byte_length() - 1)
        with pytest.raises(ValueError, match="Invalid byte length"):
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
        """Tests that `deserialize` raises a ValueError if the scope is incorrect."""
        stream = io.BytesIO(b"\x00" * uint_class.get_byte_length())
        invalid_scope = uint_class.get_byte_length() - 1
        with pytest.raises(ValueError, match="Invalid scope"):
            uint_class.deserialize(stream, scope=invalid_scope)

    @pytest.mark.parametrize("uint_class", ALL_UINT_TYPES)
    def test_deserialize_stream_too_short(self, uint_class: Type[BaseUint]) -> None:
        """Tests that `deserialize` raises an IOError if the stream ends prematurely."""
        byte_length = uint_class.get_byte_length()
        # Create a stream that is shorter than what the type requires.
        stream = io.BytesIO(b"\x00" * (byte_length - 1))
        with pytest.raises(IOError, match="Stream ended prematurely"):
            uint_class.deserialize(stream, scope=byte_length)
