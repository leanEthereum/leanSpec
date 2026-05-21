"""
Tests for the KoalaBear prime field Fp.
"""

import io
import random

import pytest

from lean_spec.subspecs.koalabear.field import Fp, P


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
    with pytest.raises(ZeroDivisionError, match="Cannot invert the zero element."):
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
    with pytest.raises(ValueError, match="Expected 4 bytes for Fp, got 3"):
        Fp.deserialize(stream, 3)


def test_ssz_deserialize_short_data() -> None:
    """Test deserialize error when stream has insufficient data."""
    stream = io.BytesIO(b"\x01\x02\x03")  # Only 3 bytes
    with pytest.raises(ValueError, match="Expected 4 bytes for Fp, got 3"):
        Fp.deserialize(stream, 4)


def test_ssz_deserialize_exceeds_modulus() -> None:
    """Test deserialize error when value exceeds field modulus."""
    # P = 2^31 - 2^24 + 1 = 2130706433
    # Encode a value >= P (use P itself)
    invalid_data = P.to_bytes(4, byteorder="little")
    stream = io.BytesIO(invalid_data)
    with pytest.raises(ValueError, match="exceeds field modulus"):
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
