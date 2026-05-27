"""
Tests for the KoalaBear prime field Fp.
"""

import io
import json
import random
import re
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from lean_spec.subspecs.koalabear.field import Fp, P
from lean_spec.types.exceptions import (
    SSZSerializationError,
    SSZTypeError,
    SSZValueError,
)


def test_constants() -> None:
    """Verify field constants."""
    assert P == 2**31 - 2**24 + 1


def test_base_field_arithmetic() -> None:
    """
    Test basic arithmetic, equality, and error handling
    in the base field Fp.
    """
    a = Fp(value=5)
    b = Fp(value=10)

    # Test operations
    assert a + b == Fp(value=15)
    assert b - a == Fp(value=5)
    assert -a == Fp(value=P - 5)
    assert a * b == Fp(value=50)
    assert a / b == Fp(value=5) * Fp(value=10).inverse()

    # Test equality against the same and different types
    assert a == Fp(value=5)
    assert a != b
    assert a != 5
    assert a != "5"

    # Test error on inverting the zero element
    with pytest.raises(ZeroDivisionError, match=r"^Cannot invert the zero element\.$"):
        Fp(value=0).inverse()


def test_ssz_type_properties() -> None:
    """Test that Fp correctly implements SSZ type interface."""
    # Test is_fixed_size
    assert Fp.is_fixed_size() is True

    # Test get_byte_length
    assert Fp.get_byte_length() == 4


def test_ssz_serialize() -> None:
    """Test SSZ serialization using the serialize method."""
    fp = Fp(value=42)

    # Test serialize to stream
    stream = io.BytesIO()
    bytes_written = fp.serialize(stream)
    assert bytes_written == 4
    assert stream.getvalue() == b"\x2a\x00\x00\x00"  # 42 in LE


def test_ssz_deserialize() -> None:
    """Test SSZ deserialization using the deserialize method."""
    # Test successful deserialization
    data = b"\x2a\x00\x00\x00"  # 42 in LE
    stream = io.BytesIO(data)
    fp = Fp.deserialize(stream, 4)
    assert fp == Fp(value=42)


def test_ssz_deserialize_wrong_scope() -> None:
    """Test deserialize error when scope doesn't match P_BYTES."""
    data = b"\x2a\x00\x00\x00"
    stream = io.BytesIO(data)
    with pytest.raises(SSZSerializationError, match=r"^Expected 4 bytes for Fp, got 3$"):
        Fp.deserialize(stream, 3)


def test_ssz_deserialize_short_data() -> None:
    """Test deserialize error when stream has insufficient data."""
    stream = io.BytesIO(b"\x01\x02\x03")  # Only 3 bytes
    with pytest.raises(SSZSerializationError, match=r"^Expected 4 bytes for Fp, got 3$"):
        Fp.deserialize(stream, 4)


def test_ssz_deserialize_exceeds_modulus() -> None:
    """Test deserialize error when value exceeds field modulus."""
    # P = 2^31 - 2^24 + 1 = 2130706433
    # Encode a value >= P (use P itself)
    invalid_data = P.to_bytes(4, byteorder="little")
    stream = io.BytesIO(invalid_data)
    with pytest.raises(SSZValueError, match=rf"^Value {P} exceeds field modulus {P}$"):
        Fp.deserialize(stream, 4)


def test_ssz_encode_decode_bytes() -> None:
    """Test SSZ encode_bytes and decode_bytes methods."""
    # Test encode_bytes
    fp = Fp(value=100)
    data = fp.encode_bytes()
    assert len(data) == 4
    assert data == b"\x64\x00\x00\x00"  # 100 in LE

    # Test decode_bytes
    fp2 = Fp.decode_bytes(data)
    assert fp2 == fp

    # Test roundtrip for various values
    test_values = [0, 1, 42, 255, 256, 1000, 65535, 65536, 1000000, P - 1]
    for value in test_values:
        fp = Fp(value=value)
        data = fp.encode_bytes()
        recovered = Fp.decode_bytes(data)
        assert recovered == fp, f"Failed for value={value}"


def test_ssz_roundtrip() -> None:
    """Comprehensive SSZ roundtrip test with many values."""
    random.seed(12345)

    for _ in range(100):
        # Test with random values
        value = random.randint(0, P - 1)
        fp = Fp(value=value)

        # Test deserialization works
        data = fp.encode_bytes()
        recovered = Fp.decode_bytes(data)
        assert recovered == fp


def test_ssz_deterministic() -> None:
    """Test that SSZ serialization is deterministic."""
    fp = Fp(value=999)

    # Serialize multiple times
    data1 = fp.encode_bytes()
    data2 = fp.encode_bytes()

    # Both should be identical
    assert data1 == data2


@pytest.mark.parametrize(
    ("bad_value", "type_name"),
    [
        (3.14, "float"),
        ("5", "str"),
        (None, "NoneType"),
        (True, "bool"),
        (False, "bool"),
    ],
)
def test_new_rejects_non_int_inputs(bad_value: Any, type_name: str) -> None:
    """Constructing Fp with a non-int input raises SSZTypeError naming the offending type."""
    with pytest.raises(SSZTypeError, match=rf"^Field value must be an integer, got {type_name}$"):
        Fp(bad_value)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (P, 0),
        (P + 7, 7),
        (-1, P - 1),
        (-P, 0),
        (2 * P + 42, 42),
    ],
)
def test_new_normalizes_into_canonical_range(raw: int, expected: int) -> None:
    """Constructor reduces the input modulo P into the canonical range."""
    fp = Fp(raw)
    assert int(fp) == expected
    assert fp == Fp(expected)


@pytest.mark.parametrize("op", ["+", "-", "*", "/"])
def test_reverse_arithmetic_rejects_int_left_operand(op: str) -> None:
    """Reverse operators reject a raw int on the left to block silent int fallback."""
    a = Fp(2)
    table = {
        "+": lambda: 1 + a,
        "-": lambda: 1 - a,
        "*": lambda: 1 * a,
        "/": lambda: 1 / a,
    }
    with pytest.raises(
        TypeError,
        match=rf"^Unsupported operand type\(s\) for {re.escape(op)}: 'Fp' and 'int'$",
    ):
        table[op]()


@pytest.mark.parametrize("op", ["+", "-", "*", "/"])
def test_forward_arithmetic_rejects_raw_int_right_operand(op: str) -> None:
    """Forward operators reject a raw int on the right to enforce Fp-only arithmetic."""
    a = Fp(2)
    table = {
        "+": lambda: a + 3,
        "-": lambda: a - 3,
        "*": lambda: a * 3,
        "/": lambda: a / 3,
    }
    with pytest.raises(
        TypeError,
        match=rf"^Unsupported operand type\(s\) for {re.escape(op)}: 'Fp' and 'int'$",
    ):
        table[op]()


def test_forward_arithmetic_rejects_bool_right_operand() -> None:
    """Forward arithmetic against a bool right operand is rejected as a non-Fp type."""
    a = Fp(2)
    with pytest.raises(TypeError, match=r"^Unsupported operand type\(s\) for \+: 'Fp' and 'bool'$"):
        a + True  # noqa: B015


def test_negation_of_zero_stays_zero() -> None:
    """Negating the additive identity returns the additive identity."""
    assert -Fp(0) == Fp(0)


@pytest.mark.parametrize(
    ("base", "exponent", "expected"),
    [
        (Fp(7), 0, Fp(1)),
        (Fp(0), 0, Fp(1)),
        (Fp(2), P, Fp(2)),
        (Fp(3), 1, Fp(3)),
    ],
)
def test_pow_covers_zero_and_modular_exponents(base: Fp, exponent: int, expected: Fp) -> None:
    """Exponentiation handles zero exponent, modular exponent, and identity exponent."""
    assert base**exponent == expected


@pytest.mark.parametrize("a", [Fp(1), Fp(2), Fp(P - 1)])
def test_inverse_multiplicative_property(a: Fp) -> None:
    """The inverse satisfies a times a-inverse equals one and matches Fermat's little theorem."""
    inv = a.inverse()
    assert a * inv == Fp(1)
    assert inv == a ** (P - 2)


@pytest.mark.parametrize(("a", "b"), [(Fp(7), Fp(3)), (Fp(P - 1), Fp(2)), (Fp(1), Fp(P - 5))])
def test_truediv_inverts_multiplication(a: Fp, b: Fp) -> None:
    """Division is the inverse of multiplication for any non-zero divisor."""
    assert (a / b) * b == a


def test_truediv_by_zero_raises_zero_division() -> None:
    """Dividing by the zero element raises ZeroDivisionError."""
    with pytest.raises(ZeroDivisionError, match=r"^Cannot invert the zero element\.$"):
        Fp(5) / Fp(0)


def test_equality_matrix_covers_same_other_and_foreign_types() -> None:
    """Equality returns True only between matching Fp residues, never raises on foreign types."""
    a = Fp(5)
    assert a == Fp(5)
    assert (a == Fp(6)) is False
    assert (a == 5) is False
    assert (a == "5") is False
    assert (a == None) is False  # noqa: E711
    assert a != Fp(6)
    assert a != 5
    assert a != "5"
    assert a != None  # noqa: E711


def test_hash_mixes_in_type_and_keeps_residue_distinct_from_int() -> None:
    """Hash is stable across equal Fps, differs from a raw int's hash, and behaves in sets."""
    assert hash(Fp(5)) == hash(Fp(5))
    assert hash(Fp(5)) != hash(5)
    assert {Fp(5), Fp(5), Fp(6)} == {Fp(5), Fp(6)}
    mixed = {Fp(5), 5}
    assert len(mixed) == 2


def test_repr_uses_value_kwarg_form() -> None:
    """The repr form mirrors the kwarg constructor for round-trip readability."""
    assert repr(Fp(7)) == "Fp(value=7)"


def test_is_fixed_size_and_get_byte_length_are_classmethods() -> None:
    """The SSZ size hooks resolve through the class, not just an instance."""
    assert Fp.is_fixed_size() is True
    assert Fp.get_byte_length() == 4


def test_serialize_deserialize_round_trip_at_p_minus_one() -> None:
    """A value at the upper boundary serializes and deserializes back to itself."""
    fp = Fp(P - 1)
    stream = io.BytesIO()
    fp.serialize(stream)
    stream.seek(0)
    assert Fp.deserialize(stream, 4) == fp


def test_encode_decode_bytes_round_trip_at_p_minus_one() -> None:
    """The byte-oriented helpers round-trip the upper-boundary residue."""
    fp = Fp(P - 1)
    assert Fp.decode_bytes(fp.encode_bytes()) == fp


def test_decode_bytes_rejects_oversized_input() -> None:
    """A five-byte buffer is rejected because the scope guard fires before any read."""
    with pytest.raises(SSZSerializationError, match=r"^Expected 4 bytes for Fp, got 5$"):
        Fp.decode_bytes(b"\x00\x00\x00\x00\x01")


class _PydanticModelWithFp(BaseModel):
    """Tiny Pydantic carrier used to exercise the Fp core schema."""

    x: Fp


def test_pydantic_schema_accepts_valid_raw_int_and_lifts_to_fp() -> None:
    """A raw integer in the valid range is validated and stored as an Fp instance."""
    model = _PydanticModelWithFp(x=42)  # ty: ignore[invalid-argument-type]
    assert model.x == Fp(42)
    assert isinstance(model.x, Fp)


def test_pydantic_schema_passes_through_existing_fp_instance() -> None:
    """An existing Fp bypasses revalidation and is stored as-is."""
    existing = Fp(123)
    model = _PydanticModelWithFp(x=existing)
    assert model.x is existing


@pytest.mark.parametrize("bad", [P, P + 1, -1])
def test_pydantic_schema_rejects_out_of_range_ints(bad: int) -> None:
    """Raw integers outside the canonical range are rejected by Pydantic validation."""
    with pytest.raises(ValidationError):
        _PydanticModelWithFp(x=bad)  # ty: ignore[invalid-argument-type]


def test_pydantic_json_serialization_drops_subtype_to_plain_int() -> None:
    """JSON serialization emits a plain integer, hiding the Fp subtype."""
    model = _PydanticModelWithFp(x=Fp(99))
    payload = model.model_dump(mode="json")
    assert payload == {"x": 99}
    assert json.loads(model.model_dump_json()) == {"x": 99}
