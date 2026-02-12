"""
Tests for the KoalaBear prime field Fp.
"""

import io
import random

import pytest

from lean_spec.subspecs.koalabear.field import (
    TWO_ADIC_GENERATORS,
    TWO_ADICITY,
    Fp,
    P,
)


def test_constants() -> None:
    """Verify field constants."""
    assert P == 2**31 - 2**24 + 1
    assert (P - 1) % (2**TWO_ADICITY) == 0
    assert (P - 1) % (2 ** (TWO_ADICITY + 1)) != 0
    assert len(TWO_ADIC_GENERATORS) == TWO_ADICITY + 1


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


def test_two_adicity() -> None:
    """Test the properties and error handling of the two-adic generators."""
    bits = 4  # 2^4 = 16
    gen = Fp.two_adic_generator(bits)
    assert gen == Fp(value=TWO_ADIC_GENERATORS[bits])

    # Check that the generator has the correct order
    assert gen ** (2**bits) == Fp(value=1)
    assert gen ** (2 ** (bits - 1)) != Fp(value=1)

    # Check relationship between generators: g_n^2 should equal g_{n-1}
    gen_n = Fp.two_adic_generator(TWO_ADICITY)
    gen_n_minus_1 = Fp.two_adic_generator(TWO_ADICITY - 1)
    assert gen_n**2 == gen_n_minus_1

    # The largest order generator should square to -1
    assert gen_n ** (2 ** (TWO_ADICITY - 1)) == Fp(value=-1)

    # Test error handling for out-of-bounds input
    with pytest.raises(ValueError, match=f"bits must be between 0 and {TWO_ADICITY}"):
        Fp.two_adic_generator(TWO_ADICITY + 1)

    with pytest.raises(ValueError, match=f"bits must be between 0 and {TWO_ADICITY}"):
        Fp.two_adic_generator(-1)


def test_bytes_protocol() -> None:
    """Test serialization using Python's bytes protocol."""
    # Test basic serialization
    fp = Fp(value=42)
    data = bytes(fp)
    assert len(data) == 4  # P_BYTES
    assert isinstance(data, bytes)

    # Test deserialization
    recovered = Fp.from_bytes(data)
    assert recovered == fp

    # Test round-trip for various values
    test_values = [0, 1, 42, 1000, P - 1]
    for value in test_values:
        fp = Fp(value=value)
        assert Fp.from_bytes(bytes(fp)) == fp

    # Test error handling for invalid data length
    with pytest.raises(ValueError, match="Expected 4 bytes for Fp, got 3"):
        Fp.from_bytes(b"\x01\x02\x03")

    with pytest.raises(ValueError, match="Expected 4 bytes for Fp, got 5"):
        Fp.from_bytes(b"\x01\x02\x03\x04\x05")

    # Test error handling for values exceeding the modulus
    invalid_data = P.to_bytes(4, byteorder="little")
    with pytest.raises(ValueError, match="exceeds field modulus"):
        Fp.from_bytes(invalid_data)


def test_serialize_list() -> None:
    """Test serialization of field element lists."""
    # Test empty list
    elements: list[Fp] = []
    data = Fp.serialize_list(elements)
    assert data == b""
    assert len(data) == 0

    # Test single element
    elements = [Fp(value=42)]
    data = Fp.serialize_list(elements)
    assert len(data) == 4
    assert data == bytes(Fp(value=42))

    # Test multiple elements
    elements = [Fp(value=1), Fp(value=2), Fp(value=3)]
    data = Fp.serialize_list(elements)
    assert len(data) == 12  # 3 * 4 bytes
    assert data == bytes(Fp(value=1)) + bytes(Fp(value=2)) + bytes(Fp(value=3))

    # Test round-trip
    recovered = Fp.deserialize_list(data, 3)
    assert recovered == elements


def test_deserialize_list() -> None:
    """Test deserialization of field element lists."""
    # Test empty list
    data = b""
    recovered = Fp.deserialize_list(data, 0)
    assert recovered == []

    # Test single element
    elements = [Fp(value=42)]
    data = Fp.serialize_list(elements)
    recovered = Fp.deserialize_list(data, 1)
    assert recovered == elements

    # Test multiple elements
    elements = [Fp(value=10), Fp(value=20), Fp(value=30), Fp(value=40)]
    data = Fp.serialize_list(elements)
    recovered = Fp.deserialize_list(data, 4)
    assert recovered == elements

    # Test error handling for incorrect length
    with pytest.raises(ValueError, match="Expected 8 bytes for 2 elements, got 4"):
        Fp.deserialize_list(b"\x01\x02\x03\x04", 2)

    with pytest.raises(ValueError, match="Expected 12 bytes for 3 elements, got 10"):
        Fp.deserialize_list(b"\x01" * 10, 3)


def test_serialize_list_roundtrip_property() -> None:
    """Property test: serialization round-trip should preserve values."""
    random.seed(42)

    for _ in range(100):
        # Generate random list of field elements
        count = random.randint(0, 20)
        elements = [Fp(value=random.randint(0, P - 1)) for _ in range(count)]

        # Round-trip
        data = Fp.serialize_list(elements)
        recovered = Fp.deserialize_list(data, count)

        assert recovered == elements
        assert len(data) == count * 4


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

        # Test all serialization methods give same result
        data1 = bytes(fp)
        data2 = fp.encode_bytes()
        assert data1 == data2

        # Test all deserialization methods work
        recovered1 = Fp.from_bytes(data1)
        recovered2 = Fp.decode_bytes(data2)
        assert recovered1 == fp
        assert recovered2 == fp


def test_ssz_deterministic() -> None:
    """Test that SSZ serialization is deterministic."""
    fp = Fp(value=999)

    # Serialize multiple times
    data1 = fp.encode_bytes()
    data2 = fp.encode_bytes()
    data3 = bytes(fp)

    # All should be identical
    assert data1 == data2
    assert data1 == data3
