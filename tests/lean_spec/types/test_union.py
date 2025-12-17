from __future__ import annotations

import io
from typing import Type as PyType
from typing import cast

import pytest
from pydantic import ValidationError, create_model

from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.ssz_base import SSZType
from lean_spec.types.uint import Uint8, Uint16, Uint32
from lean_spec.types.union import SSZUnion


class Uint8Vector3(SSZVector):
    """A vector of exactly 3 Uint8 values."""

    ELEMENT_TYPE = Uint8
    LENGTH = 3


class Uint16List8(SSZList):
    """A list with up to 8 Uint16 values."""

    ELEMENT_TYPE = Uint16
    LIMIT = 8


class SingleField(Container):
    """Tiny fixed-size container."""

    A: Uint8


class FixedPair(Container):
    """A pair of fixed-size values."""

    A: Uint8
    B: Uint16


# Domain-specific Union types using clean inheritance pattern
class SimpleUnion(SSZUnion):
    """Union with a single numeric type."""

    OPTIONS = (Uint16,)


class NumericUnion(SSZUnion):
    """Union of two numeric types."""

    OPTIONS = (Uint16, Uint32)


class OptionalNumericUnion(SSZUnion):
    """Nullable union with None and numeric types."""

    OPTIONS = (None, Uint16, Uint32)


class ComplexUnion(SSZUnion):
    """Union with multiple types including collections."""

    OPTIONS = (Uint16, Uint32, Uint8, Uint16List8)


class ContainerUnion(SSZUnion):
    """Union with identical container types."""

    OPTIONS = (SingleField, SingleField)


def test_specialized_union_creation() -> None:
    """Test that specialized Union types work correctly."""
    # Simple union
    u1 = SimpleUnion(selector=0, value=Uint16(0xAABB))
    assert u1.selector == 0
    assert u1.value == Uint16(0xAABB)
    assert u1.selected_type == Uint16

    # Numeric union
    u2 = NumericUnion(selector=0, value=Uint16(43707))
    assert u2.selector == 0
    assert u2.value == Uint16(43707)

    u3 = NumericUnion(selector=1, value=Uint32(0xDEADBEEF))
    assert u3.selector == 1
    assert u3.value == Uint32(0xDEADBEEF)


def test_constructor_success() -> None:
    """Test successful Union construction."""
    # None variant
    u_null = OptionalNumericUnion(selector=0, value=None)
    assert u_null.selector == 0
    assert u_null.value is None
    assert u_null.selected_type is None

    # Uint16 variant with explicit type
    u_explicit = OptionalNumericUnion(selector=1, value=Uint16(0xBEEF))
    assert u_explicit.selector == 1
    assert u_explicit.value == Uint16(0xBEEF)

    # Uint32 variant with coercion from int
    u_coerced = OptionalNumericUnion(selector=2, value=0xAABBCCDD)
    assert u_coerced.selector == 2
    assert u_coerced.value == Uint32(0xAABBCCDD)


def test_constructor_errors() -> None:
    """Test Union construction error cases."""
    # Invalid selector (out of range)
    with pytest.raises(ValueError, match="Invalid selector"):
        OptionalNumericUnion(selector=3, value=None)

    # None value for None option should work
    OptionalNumericUnion(selector=0, value=None)

    # Non-None value for None option should fail
    with pytest.raises(TypeError, match="value must be None"):
        OptionalNumericUnion(selector=0, value=Uint16(1))


def test_pydantic_validation_ok() -> None:
    """Test successful Pydantic validation."""
    # Direct construction
    u1 = OptionalNumericUnion(selector=1, value=42)
    assert u1.value == Uint16(42)

    # Model validation from dict
    u2 = OptionalNumericUnion.model_validate({"selector": 2, "value": 0xDEADBEEF})
    assert u2.selector == 2
    assert u2.value == Uint32(0xDEADBEEF)


def test_pydantic_validation_errors() -> None:
    """Test Pydantic validation error cases."""
    # Test invalid selector directly
    with pytest.raises(ValueError, match="Invalid selector"):
        OptionalNumericUnion(selector=9, value=0)

    # Test invalid value for None option directly
    with pytest.raises(TypeError, match="value must be None"):
        OptionalNumericUnion(selector=0, value=1)

    # Test with Pydantic model wrapper - should catch underlying errors
    model = create_model("M", v=(OptionalNumericUnion, ...))

    # Invalid selector in model context
    with pytest.raises((ValidationError, ValueError)):
        model(v={"selector": 9, "value": 0})

    # Invalid value for None option in model context
    with pytest.raises((ValidationError, TypeError)):
        model(v={"selector": 0, "value": 1})


def test_union_serialize_matches_reference() -> None:
    """Test serialization matches expected byte patterns."""
    test_cases = [
        (SimpleUnion(selector=0, value=Uint16(43707)), "00bbaa"),
        (NumericUnion(selector=0, value=Uint16(43707)), "00bbaa"),
        (OptionalNumericUnion(selector=0, value=None), "00"),
        (OptionalNumericUnion(selector=1, value=Uint16(43707)), "01bbaa"),
        (NumericUnion(selector=1, value=Uint32(3735928559)), "01efbeadde"),
        (ComplexUnion(selector=2, value=Uint8(170)), "02aa"),
        (ContainerUnion(selector=1, value=SingleField(A=Uint8(0xAB))), "01ab"),
    ]

    for union_instance, expected_hex in test_cases:
        encoded = union_instance.encode_bytes()
        assert encoded.hex() == expected_hex


def test_union_with_nested_composites_roundtrip() -> None:
    """Test serialization roundtrip with complex nested types."""
    # Create a union with nested container
    original = ContainerUnion(selector=0, value=SingleField(A=Uint8(42)))

    # Encode and decode
    encoded = original.encode_bytes()
    decoded = ContainerUnion.decode_bytes(encoded)

    # Verify roundtrip
    assert decoded.selector == original.selector
    assert decoded.value.A == original.value.A
    assert decoded == original


def test_deserialize_errors() -> None:
    """Test deserialization error cases."""
    # Too small scope
    with pytest.raises(ValueError, match="Scope too small"):
        SimpleUnion.deserialize(io.BytesIO(b""), 0)

    # Invalid selector
    with pytest.raises(ValueError, match="out of range"):
        SimpleUnion.deserialize(io.BytesIO(b"\x09"), 1)

    # None option with payload
    with pytest.raises(ValueError, match="no payload bytes"):
        OptionalNumericUnion.deserialize(io.BytesIO(b"\x00\xff"), 2)


def test_repr_contains_selector_and_value() -> None:
    """Test __repr__ shows selector and value."""
    u = NumericUnion(selector=1, value=Uint32(0xDEADBEEF))
    repr_str = repr(u)
    assert "selector=1" in repr_str
    assert "Uint32(3735928559)" in repr_str


def test_selected_type_sanity() -> None:
    """Test selected_type property works correctly."""
    u1 = NumericUnion(selector=0, value=Uint16(42))
    assert u1.selected_type == Uint16

    u2 = NumericUnion(selector=1, value=Uint32(42))
    assert u2.selected_type == Uint32

    u3 = OptionalNumericUnion(selector=0, value=None)
    assert u3.selected_type is None


def test_equality_and_hashing() -> None:
    """Test equality and hashing behavior."""
    u1 = NumericUnion(selector=0, value=Uint16(42))
    u2 = NumericUnion(selector=0, value=Uint16(42))
    u3 = NumericUnion(selector=1, value=Uint32(42))

    # Same data should be equal
    assert u1 == u2
    assert hash(u1) == hash(u2)

    # Different selector/value should not be equal
    assert u1 != u3
    assert hash(u1) != hash(u3)


def test_options_helper() -> None:
    """Test options() class method."""
    assert NumericUnion.options() == (Uint16, Uint32)
    assert OptionalNumericUnion.options() == (None, Uint16, Uint32)
    assert SimpleUnion.options() == (Uint16,)


def test_is_fixed_size_helper() -> None:
    """Test is_fixed_size() class method."""
    assert not NumericUnion.is_fixed_size()
    assert not OptionalNumericUnion.is_fixed_size()
    assert not SimpleUnion.is_fixed_size()


def test_get_byte_length_raises() -> None:
    """Test get_byte_length() raises for variable-size types."""
    with pytest.raises(TypeError, match="variable-size"):
        NumericUnion.get_byte_length()


def test_union_type_validation() -> None:
    """Test that Union types validate OPTIONS correctly."""

    # Valid union should work
    class ValidUnion(SSZUnion):
        OPTIONS = (Uint16, Uint32)

    instance = ValidUnion(selector=0, value=42)
    assert instance.selector == 0

    # Invalid union with None not at index 0 should fail during validation
    with pytest.raises(TypeError, match="None at index 0"):

        class InvalidUnion1(SSZUnion):
            OPTIONS = (Uint16, None)

        InvalidUnion1(selector=0, value=42)

    # Union with non-SSZ type should fail when trying to use it
    class NotSSZ:
        pass

    with pytest.raises(TypeError, match="takes no arguments"):

        class InvalidUnion2(SSZUnion):
            OPTIONS = (cast(PyType[SSZType], NotSSZ),)

        InvalidUnion2(selector=0, value=42)


def test_union_boundary_cases() -> None:
    """Test edge cases and boundary conditions."""
    # Single option union
    u = SimpleUnion(selector=0, value=Uint16(42))
    assert u.selector == 0
    assert u.value == Uint16(42)

    # None-only union should fail validation
    with pytest.raises(TypeError, match="only option"):

        class NoneOnlyUnion(SSZUnion):
            OPTIONS = (None,)

        NoneOnlyUnion(selector=0, value=None)


def test_data_tuple_construction() -> None:
    """Test construction using selector and value."""
    # Direct construction
    u = NumericUnion(selector=1, value=Uint32(42))
    assert u.selector == 1
    assert u.value == Uint32(42)

    # Model validation with dict
    u2 = NumericUnion.model_validate({"selector": 0, "value": 123})
    assert u2.selector == 0
    assert u2.value == Uint16(123)
