"""Tests for snappy decompression, including the LEB128 length prefix."""

from __future__ import annotations

from pathlib import Path

import pytest

from lean_spec.node.networking.varint import VarintError, decode_varint, encode_varint
from lean_spec.node.snappy import (
    SnappyDecompressionError,
    compress,
    decompress,
)
from lean_spec.node.snappy.constants import SNAPPY_VARINT_MAX_BYTES

# Path to test data files
TESTDATA_DIRECTORY = Path(__file__).parent / "testdata"


def load_test_file(filename: str, size_limit: int = 0) -> bytes:
    """Load a test data file, optionally truncated to size_limit."""
    path = TESTDATA_DIRECTORY / filename
    file_bytes = path.read_bytes()
    if size_limit > 0:
        file_bytes = file_bytes[:size_limit]
    return file_bytes


class TestSnappyLengthPrefix:
    """Tests for the LEB128 length prefix used by the snappy block format."""

    def test_encode_zero(self) -> None:
        """Zero encodes to a single null byte."""
        assert encode_varint(0, max_bytes=SNAPPY_VARINT_MAX_BYTES) == b"\x00"

    def test_encode_small_values(self) -> None:
        """Values 0-127 encode to a single byte."""
        assert encode_varint(1, max_bytes=SNAPPY_VARINT_MAX_BYTES) == b"\x01"
        assert encode_varint(127, max_bytes=SNAPPY_VARINT_MAX_BYTES) == b"\x7f"

    def test_encode_two_byte_values(self) -> None:
        """Values 128-16383 encode to two bytes."""
        assert encode_varint(128, max_bytes=SNAPPY_VARINT_MAX_BYTES) == b"\x80\x01"
        assert encode_varint(300, max_bytes=SNAPPY_VARINT_MAX_BYTES) == b"\xac\x02"

    def test_encode_large_values(self) -> None:
        """Large values encode correctly."""
        for varint_value in [65536, 2**20, 2**24, 2**32 - 1]:
            encoded = encode_varint(varint_value, max_bytes=SNAPPY_VARINT_MAX_BYTES)
            decoded, _ = decode_varint(encoded, max_bytes=SNAPPY_VARINT_MAX_BYTES)
            assert decoded == varint_value

    def test_decode_roundtrip(self) -> None:
        """Encoding then decoding returns the original value."""
        test_values = [0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536, 2**20, 2**32 - 1]
        for varint_value in test_values:
            encoded = encode_varint(varint_value, max_bytes=SNAPPY_VARINT_MAX_BYTES)
            decoded, bytes_consumed = decode_varint(encoded, max_bytes=SNAPPY_VARINT_MAX_BYTES)
            assert decoded == varint_value
            assert bytes_consumed == len(encoded)

    def test_encode_negative_raises(self) -> None:
        """Negative values raise ValueError."""
        with pytest.raises(ValueError) as exception_info:
            encode_varint(-1, max_bytes=SNAPPY_VARINT_MAX_BYTES)
        assert str(exception_info.value) == "Varint must be non-negative"

    def test_encode_overflow_raises(self) -> None:
        """Values past the five-byte cap raise ValueError."""
        with pytest.raises(ValueError) as exception_info:
            encode_varint(2**35, max_bytes=SNAPPY_VARINT_MAX_BYTES)
        assert str(exception_info.value) == "Varint value does not fit in 5 bytes"

    def test_decode_truncated_raises(self) -> None:
        """Truncated varints raise a varint error."""
        with pytest.raises(VarintError) as exception_info:
            decode_varint(b"\x80", max_bytes=SNAPPY_VARINT_MAX_BYTES)
        assert str(exception_info.value) == "Truncated varint"

    def test_decode_too_long_raises(self) -> None:
        """A six-byte continuation run exceeds the snappy cap."""
        with pytest.raises(VarintError) as exception_info:
            decode_varint(b"\x80" * 6, max_bytes=SNAPPY_VARINT_MAX_BYTES)
        assert str(exception_info.value) == "Varint exceeds 5 bytes"

    def test_decode_with_offset(self) -> None:
        """Decoding at an offset works correctly."""
        prefixed_bytes = b"prefix\xac\x02suffix"
        decoded_value, bytes_consumed = decode_varint(
            prefixed_bytes, offset=6, max_bytes=SNAPPY_VARINT_MAX_BYTES
        )
        assert decoded_value == 300
        assert bytes_consumed == 2

    def test_decompress_wraps_oversize_prefix(self) -> None:
        """A length prefix that overruns the cap surfaces as a decompression error."""
        with pytest.raises(SnappyDecompressionError) as exception_info:
            decompress(b"\x80" * 6)
        assert str(exception_info.value) == "Invalid length varint: Varint exceeds 5 bytes"


class TestCorruptedData:
    """Tests for handling corrupted/malformed data."""

    def test_basic_corruption(self) -> None:
        """Test that basic corruption is detected during decompression."""
        source = b"making sure we don't crash with corrupted input"
        compressed = compress(source)

        # Mess with the data
        corrupted = bytearray(compressed)
        corrupted[1] -= 1
        corrupted[3] += 1

        # The important thing is that decompression fails gracefully.
        with pytest.raises(SnappyDecompressionError):
            decompress(bytes(corrupted))

    def test_zero_length_header(self) -> None:
        """Test data with zeroed length header."""
        source = b"A" * 100000
        compressed = compress(source)

        # Zero out the length header
        corrupted = bytearray(compressed)
        corrupted[0] = corrupted[1] = corrupted[2] = corrupted[3] = 0

        # Should either decompress to empty or raise gracefully.
        try:
            assert decompress(bytes(corrupted)) == b""
        except SnappyDecompressionError:
            pass

    def test_large_declared_length(self) -> None:
        """Test data claiming very large uncompressed size."""
        source = b"A" * 100000
        compressed = compress(source)

        # Set a very large length (about 2MB)
        corrupted = bytearray(compressed)
        corrupted[0] = corrupted[1] = corrupted[2] = 0xFF
        corrupted[3] = 0x00

        # Decompression should fail because we can't produce that many bytes.
        with pytest.raises(SnappyDecompressionError):
            decompress(bytes(corrupted))

    @pytest.mark.parametrize("bad_file", ["baddata1.snappy", "baddata2.snappy", "baddata3.snappy"])
    def test_bad_data_files(self, bad_file: str) -> None:
        """Test that bad data files from C++ test suite are rejected."""
        bad_snappy_bytes = load_test_file(bad_file)

        # Bad data must either decompress safely or raise.
        try:
            decompress(bad_snappy_bytes)
        except SnappyDecompressionError:
            pass

    def test_truncated_literal(self) -> None:
        """Test handling of truncated literal data."""
        uncompressed = b"Hello, World!"
        compressed = compress(uncompressed)

        # Truncate to remove some literal data
        truncated = compressed[:-3]
        with pytest.raises(SnappyDecompressionError):
            decompress(truncated)

    def test_invalid_copy_offset(self) -> None:
        """Test copy referencing beyond available data."""
        # Construct malformed data: length=10, then copy from invalid offset
        # Length varint: 10 = 0x0a
        # Copy-2 tag for offset 100, length 5: tag=0x12 (4<<2|2), offset=100,0
        malformed = b"\x0a\x12\x64\x00"

        with pytest.raises(SnappyDecompressionError) as exception_info:
            decompress(malformed)
        assert str(exception_info.value) == "Copy offset 100 exceeds output buffer size 0"


class TestDecompressionEdgeCases:
    """Tests for decompression edge cases and errors."""

    def test_empty_raises(self) -> None:
        """Empty input raises an error."""
        with pytest.raises(SnappyDecompressionError) as exception_info:
            decompress(b"")
        assert str(exception_info.value) == "Empty input"

    def test_invalid_varint_raises(self) -> None:
        """Invalid varint in header raises an error."""
        with pytest.raises(SnappyDecompressionError) as exception_info:
            decompress(b"\xff\xff\xff\xff\xff\xff")
        assert str(exception_info.value) == "Invalid length varint: Varint exceeds 5 bytes"
