"""Bincode serialization tests for Fp field elements."""

import pytest

from lean_spec.subspecs.koalabear import Fp

# Test data generated from Rust test
FP_BINCODE_TEST_CASES = [
    # Varint encoding boundaries
    {"description": "zero", "canonical_value": 0, "hex": "00"},
    {"description": "one", "canonical_value": 1, "hex": "01"},
    {"description": "small value", "canonical_value": 42, "hex": "2a"},
    {"description": "boundary < 251", "canonical_value": 100, "hex": "64"},
    {"description": "last single-byte varint", "canonical_value": 250, "hex": "fa"},
    # u16 varint (marker 0xfb + 2 bytes little-endian)
    {"description": "first u16 varint", "canonical_value": 251, "hex": "fbfb00"},
    {"description": "u16 varint", "canonical_value": 252, "hex": "fbfc00"},
    {"description": "u16 varint mid", "canonical_value": 1000, "hex": "fbe803"},
    {"description": "max u16 varint", "canonical_value": 65535, "hex": "fbffff"},
    # u32 varint (marker 0xfc + 4 bytes little-endian)
    {"description": "first u32 varint", "canonical_value": 65536, "hex": "fc00000100"},
    {"description": "u32 varint", "canonical_value": 100000, "hex": "fca0860100"},
    {"description": "large u32 varint", "canonical_value": 1000000, "hex": "fc40420f00"},
    # Field-specific values
    {"description": "two", "canonical_value": 2, "hex": "02"},
    {"description": "ten", "canonical_value": 10, "hex": "0a"},
    {"description": "byte max", "canonical_value": 255, "hex": "fbff00"},
    {"description": "byte max + 1", "canonical_value": 256, "hex": "fb0001"},
    {"description": "u16 max + 2", "canonical_value": 65537, "hex": "fc01000100"},
    {"description": "2^24", "canonical_value": 16777216, "hex": "fc00000001"},
    # KoalaBear prime: P = 2^31 - 2^24 + 1 = 2130706433 (0x7f000001)
    {"description": "P (overflows to 0)", "canonical_value": 0, "hex": "00"},
    {"description": "P - 1", "canonical_value": 2130706432, "hex": "fc0000007f"},
    {"description": "P - 2", "canonical_value": 2130706431, "hex": "fcffffff7e"},
    # Example from XMSS test
    {"description": "example from XMSS test", "canonical_value": 186736406, "hex": "fc165f210b"},
]


@pytest.mark.parametrize("test_case", FP_BINCODE_TEST_CASES)
def test_fp_bincode_serialization(test_case: dict[str, str | int]) -> None:
    """Test that Fp serializes to the expected bincode bytes."""
    fp = Fp(value=test_case["canonical_value"])
    expected_bytes = bytes.fromhex(str(test_case["hex"]))

    serialized = fp.to_bincode_bytes()

    assert serialized == expected_bytes, (
        f"Failed for {test_case['description']}: "
        f"expected {test_case['hex']}, got {serialized.hex()}"
    )


@pytest.mark.parametrize("test_case", FP_BINCODE_TEST_CASES)
def test_fp_bincode_deserialization(test_case: dict[str, str | int]) -> None:
    """Test that Fp deserializes from bincode bytes correctly."""
    expected_value = test_case["canonical_value"]
    serialized_bytes = bytes.fromhex(str(test_case["hex"]))

    fp, consumed = Fp.from_bincode_bytes(serialized_bytes)

    assert fp.value == expected_value, (
        f"Failed for {test_case['description']}: expected value {expected_value}, got {fp.value}"
    )
    assert consumed == len(serialized_bytes), (
        f"Failed for {test_case['description']}: "
        f"expected to consume {len(serialized_bytes)} bytes, consumed {consumed}"
    )


@pytest.mark.parametrize("test_case", FP_BINCODE_TEST_CASES)
def test_fp_bincode_roundtrip(test_case: dict[str, str | int]) -> None:
    """Test that Fp roundtrips correctly through bincode serialization."""
    original = Fp(value=test_case["canonical_value"])

    serialized = original.to_bincode_bytes()
    recovered, _ = Fp.from_bincode_bytes(serialized)

    assert recovered == original, (
        f"Failed for {test_case['description']}: "
        f"original={original.value}, recovered={recovered.value}"
    )


def test_fp_fixed_array_serialization() -> None:
    """Test serialization of fixed-size arrays of Fp elements."""
    elements = [
        Fp(value=0),
        Fp(value=1),
        Fp(value=250),
        Fp(value=251),
        Fp(value=65536),
    ]

    serialized = Fp.serialize_fixed_array_bincode(elements)

    # Deserialize manually
    offset = 0
    recovered = []
    for _ in range(len(elements)):
        fp, consumed = Fp.from_bincode_bytes(serialized, offset)
        recovered.append(fp)
        offset += consumed

    assert recovered == elements
    assert offset == len(serialized), "Should consume all bytes"


def test_fp_fixed_array_empty() -> None:
    """Test that empty arrays serialize to empty bytes."""
    empty_array: list[Fp] = []
    serialized = Fp.serialize_fixed_array_bincode(empty_array)
    assert serialized == b""


def test_fp_fixed_array_deserialization() -> None:
    """Test deserialization of fixed-size arrays of Fp elements."""
    elements = [
        Fp(value=0),
        Fp(value=1),
        Fp(value=250),
        Fp(value=251),
        Fp(value=65536),
    ]

    # Serialize first
    serialized = Fp.serialize_fixed_array_bincode(elements)

    # Deserialize using the new method
    recovered, consumed = Fp.deserialize_fixed_array_bincode(serialized, 0, len(elements))

    assert recovered == elements
    assert consumed == len(serialized), "Should consume all bytes"


def test_fp_fixed_array_deserialization_with_offset() -> None:
    """Test deserialization with offset into byte array."""
    # Create multiple arrays back-to-back
    array1 = [Fp(value=1), Fp(value=2)]
    array2 = [Fp(value=100), Fp(value=200), Fp(value=300)]
    array3 = [Fp(value=65536)]

    data = (
        Fp.serialize_fixed_array_bincode(array1)
        + Fp.serialize_fixed_array_bincode(array2)
        + Fp.serialize_fixed_array_bincode(array3)
    )

    # Deserialize each array
    recovered1, consumed1 = Fp.deserialize_fixed_array_bincode(data, 0, len(array1))
    assert recovered1 == array1

    recovered2, consumed2 = Fp.deserialize_fixed_array_bincode(data, consumed1, len(array2))
    assert recovered2 == array2

    recovered3, consumed3 = Fp.deserialize_fixed_array_bincode(
        data, consumed1 + consumed2, len(array3)
    )
    assert recovered3 == array3

    # Verify we consumed all bytes
    assert consumed1 + consumed2 + consumed3 == len(data)


def test_fp_fixed_array_roundtrip() -> None:
    """Test that fixed arrays roundtrip correctly."""
    elements = [
        Fp(value=0),
        Fp(value=42),
        Fp(value=250),
        Fp(value=251),
        Fp(value=1000),
        Fp(value=65536),
        Fp(value=2130706432),  # P - 1
    ]

    serialized = Fp.serialize_fixed_array_bincode(elements)
    recovered, consumed = Fp.deserialize_fixed_array_bincode(serialized, 0, len(elements))

    assert recovered == elements
    assert consumed == len(serialized)


def test_fp_fixed_array_empty_deserialization() -> None:
    """Test that empty arrays deserialize correctly."""
    data = b""
    recovered, consumed = Fp.deserialize_fixed_array_bincode(data, 0, 0)

    assert recovered == []
    assert consumed == 0


def test_fp_bincode_with_offset() -> None:
    """Test deserialization with offset into byte array."""
    # Create a byte array with multiple encoded values
    fp1 = Fp(value=42)
    fp2 = Fp(value=1000)
    fp3 = Fp(value=65536)

    data = fp1.to_bincode_bytes() + fp2.to_bincode_bytes() + fp3.to_bincode_bytes()

    # Deserialize from different offsets
    recovered1, consumed1 = Fp.from_bincode_bytes(data, offset=0)
    assert recovered1 == fp1
    assert consumed1 == len(fp1.to_bincode_bytes())

    recovered2, consumed2 = Fp.from_bincode_bytes(data, offset=consumed1)
    assert recovered2 == fp2
    assert consumed2 == len(fp2.to_bincode_bytes())

    recovered3, consumed3 = Fp.from_bincode_bytes(data, offset=consumed1 + consumed2)
    assert recovered3 == fp3
    assert consumed3 == len(fp3.to_bincode_bytes())


def test_fp_bincode_modular_reduction() -> None:
    """Test that Fp correctly reduces values modulo P during construction."""
    from lean_spec.subspecs.koalabear.field import P

    # Value larger than P should be reduced
    fp = Fp(value=P + 42)
    assert fp.value == 42

    # Serialize the reduced value
    serialized = fp.to_bincode_bytes()
    expected = Fp(value=42).to_bincode_bytes()
    assert serialized == expected
