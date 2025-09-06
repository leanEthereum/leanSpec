"""Unsigned Integer Type Tests."""

from typing import Type

import pytest

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
def test_instantiation_from_float(uint_class: Type[BaseUint]) -> None:
    """Tests that floats are correctly truncated during instantiation."""
    assert uint_class(0.1) == uint_class(0)
    assert uint_class(1.9) == uint_class(1)


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
    assert uint_class(b_val) ** uint_class(4) == uint_class(b_val**4)
    if uint_class.BITS <= 16:  # Pow gets too big quickly
        with pytest.raises(OverflowError):
            _ = a**b


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
    with pytest.raises(TypeError):
        _ = 2 ** uint_class(3)


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
    assert a << uint_class(2) == uint_class(0b110000)
    assert a >> uint_class(2) == uint_class(0b11)

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
