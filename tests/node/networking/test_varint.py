"""
Tests for unsigned LEB128 varint encoding and decoding.

Test vectors sourced from:
- Protocol Buffers Encoding Guide: https://protobuf.dev/programming-guides/encoding/
- LEB128 specification: https://en.wikipedia.org/wiki/LEB128
- Go binary.PutUvarint: https://pkg.go.dev/encoding/binary#PutUvarint
"""

from __future__ import annotations

import pytest

from lean_spec.node.networking.varint import VarintError, decode_varint, encode_varint

# Hardcoded test vectors from the Protocol Buffers specification and LEB128 spec.
# Each entry is (integer_value, expected_encoded_bytes).
PROTOBUF_VECTORS: list[tuple[int, bytes]] = [
    # 1-byte varints (0-127): MSB=0 signals final byte
    (0, b"\x00"),
    (1, b"\x01"),
    (127, b"\x7f"),
    # 2-byte varints (128-16383)
    (128, b"\x80\x01"),
    (150, b"\x96\x01"),  # Protobuf documentation example
    (255, b"\xff\x01"),
    (256, b"\x80\x02"),
    (300, b"\xac\x02"),  # Protobuf documentation example
    (16383, b"\xff\x7f"),
    # 3-byte varints (16384-2097151)
    (16384, b"\x80\x80\x01"),
    (2097151, b"\xff\xff\x7f"),
    # 4-byte varints (2097152-268435455)
    (2097152, b"\x80\x80\x80\x01"),
    (268435455, b"\xff\xff\xff\x7f"),
]


class TestEncodeVarint:
    """Tests for varint encoding against reference vectors."""

    @pytest.mark.parametrize(("integer_value", "expected_encoding"), PROTOBUF_VECTORS)
    def test_encode(self, integer_value: int, expected_encoding: bytes) -> None:
        """encode_varint produces the expected wire bytes."""
        assert encode_varint(integer_value) == expected_encoding

    def test_negative_raises(self) -> None:
        """Negative values are rejected."""
        with pytest.raises(ValueError) as exception_info:
            encode_varint(-1)
        assert str(exception_info.value) == "Varint must be non-negative"


class TestDecodeVarint:
    """Tests for varint decoding against reference vectors."""

    @pytest.mark.parametrize(("expected_value", "encoded_bytes"), PROTOBUF_VECTORS)
    def test_decode(self, expected_value: int, encoded_bytes: bytes) -> None:
        """decode_varint reconstructs the original value."""
        assert decode_varint(encoded_bytes, 0) == (expected_value, len(encoded_bytes))

    def test_decode_at_offset(self) -> None:
        """Decoding respects the offset parameter."""
        encoded_bytes = b"prefix\xac\x02suffix"
        assert decode_varint(encoded_bytes, 6) == (300, 2)

    def test_truncated_raises(self) -> None:
        """Continuation bit set on last byte with no follow-up raises."""
        with pytest.raises(VarintError) as exception_info:
            decode_varint(b"\x80", 0)
        assert str(exception_info.value) == "Truncated varint"

    def test_empty_raises(self) -> None:
        """Empty input raises."""
        with pytest.raises(VarintError) as exception_info:
            decode_varint(b"", 0)
        assert str(exception_info.value) == "Truncated varint"

    def test_too_long_raises(self) -> None:
        """More than 10 continuation bytes (>64-bit) raises."""
        with pytest.raises(VarintError) as exception_info:
            decode_varint(b"\x80" * 11, 0)
        assert str(exception_info.value) == "Varint exceeds 10 bytes"


class TestVarintRoundtrip:
    """Roundtrip: decode(encode(v)) == v for all valid values."""

    @pytest.mark.parametrize(("integer_value", "_expected_encoding"), PROTOBUF_VECTORS)
    def test_roundtrip_vectors(self, integer_value: int, _expected_encoding: bytes) -> None:
        """Reference vectors survive an encode/decode cycle."""
        encoded = encode_varint(integer_value)
        assert decode_varint(encoded, 0) == (integer_value, len(encoded))

    def test_64bit_max(self) -> None:
        """Maximum 64-bit value roundtrips in exactly 10 bytes."""
        max_u64 = 2**64 - 1
        encoded = encode_varint(max_u64)
        assert len(encoded) == 10
        assert decode_varint(encoded, 0) == (max_u64, 10)

    @pytest.mark.parametrize(
        "power",
        [7, 14, 21, 28, 35, 42, 49, 56, 63],
        ids=[f"2^{power}" for power in [7, 14, 21, 28, 35, 42, 49, 56, 63]],
    )
    def test_power_of_two_boundaries(self, power: int) -> None:
        """
        Values at 7-bit group boundaries roundtrip correctly.

        Each power of 7 is a byte-size boundary: values below 2^7
        fit in 1 byte, values below 2^14 fit in 2 bytes, etc.
        """
        for integer_value in [2**power - 1, 2**power]:
            encoded = encode_varint(integer_value)
            assert decode_varint(encoded, 0) == (integer_value, len(encoded))

        # The boundary value requires one more byte than its predecessor.
        assert len(encode_varint(2**power)) == len(encode_varint(2**power - 1)) + 1

    @pytest.mark.parametrize(
        "integer_value",
        [65536, 2**20, 2**24, 2**32 - 1, 2**63],
    )
    def test_large_values(self, integer_value: int) -> None:
        """Large multi-byte values roundtrip correctly."""
        encoded = encode_varint(integer_value)
        assert decode_varint(encoded, 0) == (integer_value, len(encoded))


class TestMaxBytesParameter:
    """Tests for the max_bytes cap shared by both encode and decode."""

    @pytest.mark.parametrize(
        ("integer_value", "byte_count"),
        [
            (0, 1),
            (127, 1),
            (128, 2),
            (16383, 2),
            (16384, 3),
            (2**28 - 1, 4),
            (2**28, 5),
            (2**35 - 1, 5),
        ],
    )
    def test_five_byte_cap_accepts_values_up_to_five_bytes(
        self, integer_value: int, byte_count: int
    ) -> None:
        """A five-byte cap fits values that encode in five or fewer bytes."""
        encoded = encode_varint(integer_value, max_bytes=5)
        assert len(encoded) == byte_count
        assert decode_varint(encoded, 0, max_bytes=5) == (integer_value, byte_count)

    def test_five_byte_cap_rejects_value_needing_six_bytes(self) -> None:
        """A value past the five-byte ceiling is rejected on encode."""
        with pytest.raises(ValueError) as exception_info:
            encode_varint(2**35, max_bytes=5)
        assert str(exception_info.value) == "Varint value does not fit in 5 bytes"

    def test_five_byte_cap_rejects_six_byte_input(self) -> None:
        """A six-byte continuation run is rejected on decode."""
        with pytest.raises(VarintError) as exception_info:
            decode_varint(b"\x80" * 6, 0, max_bytes=5)
        assert str(exception_info.value) == "Varint exceeds 5 bytes"

    def test_five_byte_cap_accepts_five_bytes_at_boundary(self) -> None:
        """Five continuation bytes followed by a terminator decode successfully."""
        encoded = bytes([0x80, 0x80, 0x80, 0x80, 0x01])
        decoded_value, consumed = decode_varint(encoded, 0, max_bytes=5)
        assert (decoded_value, consumed) == (1 << 28, 5)
