""" "Tests for the Boolean Type."""

import io
from typing import Any, Callable

import pytest
from pydantic import BaseModel, ValidationError

from lean_spec.types.boolean import Boolean
from lean_spec.types.exceptions import SSZSerializationError, SSZTypeError, SSZValueError


class BooleanModel(BaseModel):
    """Model for testing Pydantic validation of Boolean."""

    value: Boolean


@pytest.mark.parametrize("valid_value", [True, False])
def test_pydantic_validation_accepts_valid_bool(valid_value: bool) -> None:
    """Tests that Pydantic validation correctly accepts a valid boolean."""
    instance = BooleanModel(value=valid_value)  # type: ignore[arg-type]
    assert isinstance(instance.value, Boolean)
    assert instance.value == Boolean(valid_value)


@pytest.mark.parametrize("invalid_value", [1, 0, 1.0, "True"])
def test_pydantic_strict_mode_rejects_invalid_types(invalid_value: Any) -> None:
    """Tests that Pydantic's strict mode rejects types that are not `bool`."""
    with pytest.raises(ValidationError):
        BooleanModel(value=invalid_value)


@pytest.mark.parametrize("valid_value", [True, False, 1, 0])
def test_instantiation_from_valid_types(valid_value: bool | int) -> None:
    """Tests that a Boolean can be instantiated from valid bools and ints."""
    boolean_instance = Boolean(valid_value)
    assert int(boolean_instance) == int(valid_value)


@pytest.mark.parametrize("invalid_int", [-1, 2, 100])
def test_instantiation_from_invalid_int_raises_error(invalid_int: int) -> None:
    """Tests that instantiating with an int other than 0 or 1 raises SSZValueError."""
    with pytest.raises(SSZValueError, match="Boolean value must be 0 or 1"):
        Boolean(invalid_int)


@pytest.mark.parametrize("invalid_type", [1.0, "True", b"\x01", None])
def test_instantiation_from_invalid_types_raises_error(invalid_type: Any) -> None:
    """Tests that instantiating with non-bool/non-int types raises SSZTypeError."""
    with pytest.raises(SSZTypeError, match="Expected bool or int"):
        Boolean(invalid_type)


def test_instantiation_and_type() -> None:
    """Tests that a Boolean is an instance of `int` and its own class."""
    value = Boolean(True)
    assert isinstance(value, int)
    assert isinstance(value, Boolean)


@pytest.mark.parametrize(
    "op",
    [
        lambda a, b: a + b,
        lambda a, b: a - b,
        lambda a, b: 1 + b,
        lambda a, b: 1 - b,
    ],
)
def test_arithmetic_operators_raise_error(op: Callable[[Any, Any], Any]) -> None:
    """Tests that all arithmetic operators are disabled and raise TypeError."""
    with pytest.raises(TypeError, match="Arithmetic operations are not supported"):
        op(Boolean(True), Boolean(False))


def test_bitwise_operators() -> None:
    """Tests all standard bitwise operators between Boolean instances."""
    b_true = Boolean(True)
    b_false = Boolean(False)

    assert b_true & b_true == b_true
    assert b_true & b_false == b_false
    assert b_true | b_false == b_true
    assert b_false | b_false == b_false
    assert b_true ^ b_true == b_false
    assert b_true ^ b_false == b_true


@pytest.mark.parametrize("invalid_operand", [1, True, 0.0, "a"])
def test_bitwise_operators_with_other_types_raise_error(invalid_operand: Any) -> None:
    """Tests that bitwise operations with non-Boolean types raise TypeError."""
    with pytest.raises(TypeError):
        _ = Boolean(True) & invalid_operand
    with pytest.raises(TypeError):
        _ = Boolean(True) | invalid_operand
    with pytest.raises(TypeError):
        _ = Boolean(True) ^ invalid_operand


def test_strict_equality_with_same_type() -> None:
    """Tests the strict `==` and `!=` operators between two Boolean instances."""
    assert Boolean(True) == Boolean(True)
    assert Boolean(False) == Boolean(False)
    assert Boolean(True) != Boolean(False)


@pytest.mark.parametrize(
    "left_operand, right_operand, expected_result",
    [
        # --- Comparisons between two Boolean instances ---
        (Boolean(True), Boolean(False), False),
        (Boolean(True), Boolean(True), True),
        (Boolean(False), Boolean(False), True),
        # --- Comparisons with compatible native types (Boolean on the left) ---
        (Boolean(True), True, True),
        (Boolean(True), 1, True),
        (Boolean(True), False, False),
        (Boolean(True), 0, False),
        # --- Comparisons with compatible native types (Boolean on the right) ---
        (True, Boolean(True), True),
        (1, Boolean(True), True),
        (False, Boolean(True), False),
        (0, Boolean(True), False),
        # --- Comparisons with incompatible types ---
        (Boolean(True), "a string", False),
        ("a string", Boolean(True), False),
        (Boolean(True), 1.0, False),
        (Boolean(True), None, False),
        (None, Boolean(True), False),
    ],
)
def test_equality_operator(left_operand: Any, right_operand: Any, expected_result: bool) -> None:
    """Tests the `__eq__` equality operator (`==`) for various type combinations."""
    assert (left_operand == right_operand) is expected_result


@pytest.mark.parametrize(
    "left_operand, right_operand, expected_result",
    [
        # --- Comparisons between two Boolean instances ---
        (Boolean(True), Boolean(False), True),
        (Boolean(True), Boolean(True), False),
        (Boolean(False), Boolean(False), False),
        # --- Comparisons with compatible native types (Boolean on the left) ---
        (Boolean(True), True, False),
        (Boolean(True), 1, False),
        (Boolean(True), False, True),
        (Boolean(True), 0, True),
        # --- Comparisons with compatible native types (Boolean on the right) ---
        (True, Boolean(True), False),
        (1, Boolean(True), False),
        (False, Boolean(True), True),
        (0, Boolean(True), True),
        # --- Comparisons with incompatible types ---
        (Boolean(True), "a string", True),
        ("a string", Boolean(True), True),
        (Boolean(True), 1.0, True),
        (Boolean(True), None, True),
        (None, Boolean(True), True),
    ],
)
def test_inequality_operator(left_operand: Any, right_operand: Any, expected_result: bool) -> None:
    """Tests the `__ne__` inequality operator (`!=`) for various type combinations."""
    assert (left_operand != right_operand) is expected_result


def test_repr_and_str() -> None:
    """Tests the string and official representations."""
    assert str(Boolean(True)) == "True"
    assert repr(Boolean(True)) == "Boolean(True)"
    assert str(Boolean(False)) == "False"
    assert repr(Boolean(False)) == "Boolean(False)"


def test_hash() -> None:
    """Tests that the hash is distinct from a raw bool."""
    assert hash(Boolean(True)) != hash(True)
    assert hash(Boolean(False)) != hash(False)
    assert hash(Boolean(True)) == hash(Boolean(1))
    assert hash(Boolean(True)) != hash(Boolean(False))


class TestBooleanSSZ:
    """Tests for SSZ serialization and deserialization of the Boolean type."""

    def test_ssz_properties(self) -> None:
        """Tests the static SSZ properties of the Boolean type."""
        assert Boolean.is_fixed_size() is True
        assert Boolean.get_byte_length() == 1

    @pytest.mark.parametrize(
        "value, expected_bytes",
        [
            (True, b"\x01"),
            (False, b"\x00"),
        ],
    )
    def test_encode_decode_roundtrip(self, value: bool, expected_bytes: bytes) -> None:
        """Tests the encode_bytes and decode_bytes round-trip."""
        boolean_instance = Boolean(value)

        # Test encoding
        encoded = boolean_instance.encode_bytes()
        assert encoded == expected_bytes

        # Test decoding
        decoded = Boolean.decode_bytes(encoded)
        assert decoded == boolean_instance
        assert isinstance(decoded, Boolean)

    def test_decode_invalid_length(self) -> None:
        """Tests that decode_bytes fails with incorrect byte length."""
        with pytest.raises(SSZSerializationError, match="expected 1 byte"):
            Boolean.decode_bytes(b"")
        with pytest.raises(SSZSerializationError, match="expected 1 byte"):
            Boolean.decode_bytes(b"\x00\x01")

    def test_decode_invalid_value(self) -> None:
        """Tests that decode_bytes fails with an invalid byte value."""
        with pytest.raises(SSZSerializationError, match="must be 0x00 or 0x01"):
            Boolean.decode_bytes(b"\x02")
        with pytest.raises(SSZSerializationError, match="must be 0x00 or 0x01"):
            Boolean.decode_bytes(b"\xff")

    @pytest.mark.parametrize("value", [True, False])
    def test_serialize_deserialize_roundtrip(self, value: bool) -> None:
        """Tests the serialize and deserialize round-trip."""
        boolean_instance = Boolean(value)
        stream = io.BytesIO()

        # Test serialization
        bytes_written = boolean_instance.serialize(stream)
        assert bytes_written == 1

        # Test deserialization
        stream.seek(0)
        decoded = Boolean.deserialize(stream, scope=1)
        assert decoded == boolean_instance
        assert isinstance(decoded, Boolean)

    def test_deserialize_invalid_scope(self) -> None:
        """Tests that deserialize fails with an incorrect scope."""
        stream = io.BytesIO(b"\x01")
        with pytest.raises(SSZSerializationError, match="expected scope of 1"):
            Boolean.deserialize(stream, scope=0)

        stream.seek(0)
        with pytest.raises(SSZSerializationError, match="expected scope of 1"):
            Boolean.deserialize(stream, scope=2)

    def test_deserialize_premature_stream_end(self) -> None:
        """Tests that deserialize fails if the stream ends prematurely."""
        stream = io.BytesIO(b"")  # Empty stream
        with pytest.raises(SSZSerializationError, match="expected 1 byte, got 0"):
            Boolean.deserialize(stream, scope=1)
