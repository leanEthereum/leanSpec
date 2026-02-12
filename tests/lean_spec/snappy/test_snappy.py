"""Comprehensive tests for the snappy compression library."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Iterator

import pytest

from lean_spec.snappy import (
    SnappyDecompressionError,
    compress,
    decompress,
    get_uncompressed_length,
    is_valid_compressed_data,
    max_compressed_length,
)
from lean_spec.snappy.encoding import (
    decode_tag,
    decode_varint32,
    encode_copy_tag,
    encode_literal_tag,
    encode_varint32,
)

# Path to test data files
TESTDATA_DIR = Path(__file__).parent / "testdata"


def load_test_file(filename: str, size_limit: int = 0) -> bytes:
    """Load a test data file, optionally truncated to size_limit."""
    path = TESTDATA_DIR / filename
    data = path.read_bytes()
    if size_limit > 0:
        data = data[:size_limit]
    return data


# Test data files as defined in the C++ test suite
TEST_DATA_FILES = [
    ("html", "html", 0),
    ("urls", "urls.10K", 0),
    ("jpg", "fireworks.jpeg", 0),
    ("jpg_200", "fireworks.jpeg", 200),
    ("pdf", "paper-100k.pdf", 0),
    ("html4", "html_x_4", 0),
    ("txt1", "alice29.txt", 0),
    ("txt2", "asyoulik.txt", 0),
    ("txt3", "lcet10.txt", 0),
    ("txt4", "plrabn12.txt", 0),
    ("pb", "geo.protodata", 0),
    ("gaviota", "kppkn.gtb", 0),
]


def iter_test_files() -> Iterator[tuple[str, bytes]]:
    """Iterate over all test data files."""
    for label, filename, size_limit in TEST_DATA_FILES:
        yield label, load_test_file(filename, size_limit)


class TestVarintEncoding:
    """Tests for varint encoding/decoding."""

    def test_encode_zero(self) -> None:
        """Zero encodes to a single null byte."""
        assert encode_varint32(0) == b"\x00"

    def test_encode_small_values(self) -> None:
        """Values 0-127 encode to a single byte."""
        assert encode_varint32(1) == b"\x01"
        assert encode_varint32(127) == b"\x7f"

    def test_encode_two_byte_values(self) -> None:
        """Values 128-16383 encode to two bytes."""
        assert encode_varint32(128) == b"\x80\x01"
        assert encode_varint32(300) == b"\xac\x02"

    def test_encode_large_values(self) -> None:
        """Large values encode correctly."""
        for value in [65536, 2**20, 2**24, 2**32 - 1]:
            encoded = encode_varint32(value)
            decoded, _ = decode_varint32(encoded)
            assert decoded == value

    def test_decode_roundtrip(self) -> None:
        """Encoding then decoding returns the original value."""
        test_values = [0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536, 2**20, 2**32 - 1]
        for value in test_values:
            encoded = encode_varint32(value)
            decoded, bytes_consumed = decode_varint32(encoded)
            assert decoded == value
            assert bytes_consumed == len(encoded)

    def test_encode_negative_raises(self) -> None:
        """Negative values raise ValueError."""
        with pytest.raises(ValueError, match="non-negative"):
            encode_varint32(-1)

    def test_encode_overflow_raises(self) -> None:
        """Values exceeding 32 bits raise ValueError."""
        with pytest.raises(ValueError, match="32 bits"):
            encode_varint32(2**32)

    def test_decode_truncated_raises(self) -> None:
        """Truncated varints raise ValueError."""
        with pytest.raises(ValueError, match="Truncated"):
            decode_varint32(b"\x80")

    def test_decode_with_offset(self) -> None:
        """Decoding at an offset works correctly."""
        data = b"prefix\xac\x02suffix"
        value, consumed = decode_varint32(data, offset=6)
        assert value == 300
        assert consumed == 2


class TestTagEncoding:
    """Tests for literal and copy tag encoding/decoding."""

    def test_literal_inline_length(self) -> None:
        """Literal lengths 1-60 encode inline."""
        for length in [1, 30, 60]:
            tag = encode_literal_tag(length)
            assert len(tag) == 1
            tag_type, decoded_length, copy_offset, consumed = decode_tag(tag)
            assert tag_type == "literal"
            assert decoded_length == length
            assert copy_offset == 0
            assert consumed == 1

    def test_literal_extended_length(self) -> None:
        """Literal lengths > 60 use extended encoding."""
        for length in [61, 100, 256, 1000, 65536]:
            tag = encode_literal_tag(length)
            assert len(tag) > 1
            tag_type, decoded_length, copy_offset, consumed = decode_tag(tag)
            assert tag_type == "literal"
            assert decoded_length == length
            assert copy_offset == 0

    def test_copy_1_encoding(self) -> None:
        """Copy-1 encoding (2 bytes) for short offsets and lengths 4-11."""
        for length in [4, 7, 11]:
            for offset in [1, 100, 2047]:
                tag = encode_copy_tag(length, offset)
                assert len(tag) == 2
                tag_type, decoded_length, decoded_offset, consumed = decode_tag(tag)
                assert tag_type == "copy"
                assert decoded_length == length
                assert decoded_offset == offset
                assert consumed == 2

    def test_copy_2_encoding(self) -> None:
        """Copy-2 encoding (3 bytes) for medium offsets."""
        tag = encode_copy_tag(3, 100)  # Length outside [4, 11] forces copy-2
        assert len(tag) == 3

        tag = encode_copy_tag(10, 3000)  # Large offset forces copy-2
        assert len(tag) == 3

        tag_type, decoded_length, decoded_offset, consumed = decode_tag(tag)
        assert tag_type == "copy"
        assert decoded_length == 10
        assert decoded_offset == 3000

    def test_copy_4_encoding(self) -> None:
        """Copy-4 encoding (5 bytes) for large offsets."""
        tag = encode_copy_tag(10, 70000)
        assert len(tag) == 5

        tag_type, decoded_length, decoded_offset, consumed = decode_tag(tag)
        assert tag_type == "copy"
        assert decoded_length == 10
        assert decoded_offset == 70000

    def test_invalid_literal_length_raises(self) -> None:
        """Literal length < 1 raises ValueError."""
        with pytest.raises(ValueError, match=">= 1"):
            encode_literal_tag(0)

    def test_invalid_copy_params_raise(self) -> None:
        """Invalid copy parameters raise ValueError."""
        with pytest.raises(ValueError, match="length"):
            encode_copy_tag(0, 100)
        with pytest.raises(ValueError, match="offset"):
            encode_copy_tag(4, 0)


class TestSimpleCompression:
    """Simple compression tests from C++ test suite."""

    def test_empty_input(self) -> None:
        """Empty input compresses and decompresses correctly."""
        compressed = compress(b"")
        assert decompress(compressed) == b""

    def test_single_byte(self) -> None:
        """Single byte roundtrips correctly."""
        for char in [b"a", b"X", b"\x00", b"\xff"]:
            compressed = compress(char)
            assert decompress(compressed) == char

    def test_short_strings(self) -> None:
        """Short strings roundtrip correctly."""
        for s in [b"a", b"ab", b"abc"]:
            compressed = compress(s)
            assert decompress(compressed) == s

    def test_patterns_with_varying_lengths(self) -> None:
        """Test patterns similar to C++ SimpleTests."""
        patterns = [
            b"aaaaaaa" + b"b" * 16 + b"aaaaa" + b"abc",
            b"aaaaaaa" + b"b" * 256 + b"aaaaa" + b"abc",
            b"aaaaaaa" + b"b" * 2047 + b"aaaaa" + b"abc",
            b"aaaaaaa" + b"b" * 65536 + b"aaaaa" + b"abc",
            b"abcaaaaaaa" + b"b" * 65536 + b"aaaaa" + b"abc",
        ]
        for pattern in patterns:
            compressed = compress(pattern)
            assert decompress(compressed) == pattern


class TestSelfPatternExtension:
    """Tests for self-extending copy patterns (regression tests)."""

    def test_basic_self_patterns(self) -> None:
        """Test basic self-extending patterns."""
        patterns = [
            b"abcabcabcabcabcabcab",
            b"abcabcabcabcabcabcab0123456789ABCDEF",
            b"abcabcabcabcabcabcabcabcabcabcabcabc",
            b"abcabcabcabcabcabcabcabcabcabcabcabc0123456789ABCDEF",
        ]
        for pattern in patterns:
            compressed = compress(pattern)
            assert decompress(compressed) == pattern

    def test_exhaustive_self_patterns(self) -> None:
        """Exhaustive test of self-extending patterns with various sizes."""
        random.seed(42)  # Deterministic for reproducibility

        for pattern_size in range(1, 19):
            for length in range(1, 65):
                for extra_bytes in [0, 1, 15, 16, 128]:
                    size = pattern_size + length + extra_bytes
                    data = bytearray(size)

                    # Build pattern
                    for i in range(pattern_size):
                        data[i] = ord("a") + i

                    # Repeat pattern
                    for i in range(length):
                        data[pattern_size + i] = data[i % pattern_size]

                    # Random suffix
                    for i in range(extra_bytes):
                        data[pattern_size + length + i] = random.randint(0, 255)

                    compressed = compress(bytes(data))
                    assert decompress(compressed) == bytes(data)


class TestMaxBlowup:
    """Test maximum compression blowup scenario."""

    def test_max_blowup(self) -> None:
        """Test worst-case compression expansion (lots of four-byte copies)."""
        random.seed(42)

        # Build input with random bytes
        data = bytearray(random.randint(0, 255) for _ in range(80000))

        # Append four-byte sequences from the end
        for i in range(0, 80000, 4):
            four_bytes = data[-(i + 4) : -i] if i > 0 else data[-4:]
            data.extend(four_bytes)

        compressed = compress(bytes(data))
        assert decompress(compressed) == bytes(data)

        # Verify max_compressed_length bound
        assert len(compressed) <= max_compressed_length(len(data))


class TestRealDataFiles:
    """Tests using real data files from C++ test suite."""

    @pytest.mark.parametrize("label,filename,size_limit", TEST_DATA_FILES)
    def test_roundtrip(self, label: str, filename: str, size_limit: int) -> None:
        """Test compression/decompression roundtrip for each test file."""
        data = load_test_file(filename, size_limit)
        compressed = compress(data)
        decompressed = decompress(compressed)
        assert decompressed == data, f"Roundtrip failed for {label}"

    @pytest.mark.parametrize("label,filename,size_limit", TEST_DATA_FILES)
    def test_compression_bound(self, label: str, filename: str, size_limit: int) -> None:
        """Test that compressed size is within bounds."""
        data = load_test_file(filename, size_limit)
        compressed = compress(data)
        assert len(compressed) <= max_compressed_length(len(data))

    @pytest.mark.parametrize("label,filename,size_limit", TEST_DATA_FILES)
    def test_valid_compressed_check(self, label: str, filename: str, size_limit: int) -> None:
        """Test that is_valid_compressed_data returns True for valid data."""
        data = load_test_file(filename, size_limit)
        compressed = compress(data)
        assert is_valid_compressed_data(compressed)

    @pytest.mark.parametrize("label,filename,size_limit", TEST_DATA_FILES)
    def test_uncompressed_length(self, label: str, filename: str, size_limit: int) -> None:
        """Test that get_uncompressed_length returns correct value."""
        data = load_test_file(filename, size_limit)
        compressed = compress(data)
        assert get_uncompressed_length(compressed) == len(data)

    def test_text_compression_ratio(self) -> None:
        """Text files should achieve good compression."""
        for label, filename, _ in TEST_DATA_FILES:
            if filename.endswith(".txt"):
                data = load_test_file(filename)
                compressed = compress(data)
                ratio = len(compressed) / len(data)
                # Text should compress to less than 70% of original
                # (Snappy prioritizes speed over compression ratio)
                assert ratio < 0.7, f"{label} compression ratio too high: {ratio:.2%}"

    def test_jpeg_low_compression(self) -> None:
        """JPEG files (already compressed) should have low compression ratio."""
        data = load_test_file("fireworks.jpeg")
        compressed = compress(data)
        ratio = len(compressed) / len(data)
        # JPEG shouldn't compress much (already compressed)
        # Allow up to 5% expansion or minimal compression
        assert ratio > 0.95, f"JPEG compressed too much: {ratio:.2%}"


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

        # Note: is_valid_compressed_data only checks the varint header,
        # so corrupted data may still pass basic validation.
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

        # Should either fail validation or decompress to empty
        result_is_valid = is_valid_compressed_data(bytes(corrupted))
        if result_is_valid:
            # If it's "valid", decompression should give empty result
            result = decompress(bytes(corrupted))
            assert result == b""

    def test_large_declared_length(self) -> None:
        """Test data claiming very large uncompressed size."""
        source = b"A" * 100000
        compressed = compress(source)

        # Set a very large length (about 2MB)
        corrupted = bytearray(compressed)
        corrupted[0] = corrupted[1] = corrupted[2] = 0xFF
        corrupted[3] = 0x00

        # Note: is_valid_compressed_data only checks varint validity,
        # not whether the declared length is achievable.
        # Decompression should fail because we can't produce that many bytes.
        with pytest.raises(SnappyDecompressionError):
            decompress(bytes(corrupted))

    @pytest.mark.parametrize("bad_file", ["baddata1.snappy", "baddata2.snappy", "baddata3.snappy"])
    def test_bad_data_files(self, bad_file: str) -> None:
        """Test that bad data files from C++ test suite are rejected."""
        data = load_test_file(bad_file)

        # Either get_uncompressed_length should fail or return a reasonable value
        try:
            ulen = get_uncompressed_length(data)
            # If it succeeds, length should be less than 1MB (reasonable bound)
            assert ulen < (1 << 20)
        except SnappyDecompressionError:
            pass  # Expected

        # Should not validate as good data
        # Note: Some bad data might pass basic validation but fail decompression
        if is_valid_compressed_data(data):
            with pytest.raises(SnappyDecompressionError):
                decompress(data)

    def test_truncated_literal(self) -> None:
        """Test handling of truncated literal data."""
        data = b"Hello, World!"
        compressed = compress(data)

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

        with pytest.raises(SnappyDecompressionError, match="offset"):
            decompress(malformed)


class TestDecompressionEdgeCases:
    """Tests for decompression edge cases and errors."""

    def test_empty_raises(self) -> None:
        """Empty input raises an error."""
        with pytest.raises(SnappyDecompressionError, match="Empty"):
            decompress(b"")

    def test_invalid_varint_raises(self) -> None:
        """Invalid varint in header raises an error."""
        with pytest.raises(SnappyDecompressionError, match="varint"):
            decompress(b"\xff\xff\xff\xff\xff\xff")


class TestUtilities:
    """Tests for utility functions."""

    def test_get_uncompressed_length(self) -> None:
        """get_uncompressed_length returns the correct value."""
        for size in [0, 1, 100, 10000, 100000]:
            data = bytes(range(256)) * (size // 256 + 1)
            data = data[:size]
            compressed = compress(data)
            assert get_uncompressed_length(compressed) == len(data)

    def test_is_valid_compressed_data(self) -> None:
        """is_valid_compressed_data identifies valid and invalid data."""
        data = b"Test data"
        compressed = compress(data)
        assert is_valid_compressed_data(compressed) is True
        assert is_valid_compressed_data(b"") is False

    def test_max_compressed_length(self) -> None:
        """max_compressed_length returns a valid upper bound."""
        for size in [0, 100, 1000, 65536, 100000]:
            max_len = max_compressed_length(size)
            data = bytes(range(256)) * (size // 256 + 1)
            data = data[:size]
            compressed = compress(data)
            assert len(compressed) <= max_len


class TestSpecificPatterns:
    """Tests for specific compression patterns."""

    def test_overlapping_copy(self) -> None:
        """Overlapping copies (run-length encoding) work correctly."""
        data = b"AAAAAAAAAAAA"
        compressed = compress(data)
        assert decompress(compressed) == data

    def test_alternating_pattern(self) -> None:
        """Alternating patterns compress correctly."""
        data = b"ABABABABABABABAB" * 100
        compressed = compress(data)
        assert decompress(compressed) == data

    def test_long_match(self) -> None:
        """Long matches (up to 64 bytes) are handled correctly."""
        pattern = bytes(range(64))
        data = pattern * 100
        compressed = compress(data)
        assert decompress(compressed) == data

    def test_near_block_boundary(self) -> None:
        """Data near block boundaries compresses correctly."""
        for size in [65534, 65535, 65536, 65537, 65538]:
            data = b"X" * size
            compressed = compress(data)
            assert decompress(compressed) == data

    def test_repeated_data_compresses(self) -> None:
        """Repeated data achieves significant compression."""
        data = b"A" * 1000
        compressed = compress(data)
        assert len(compressed) < len(data) // 2
        assert decompress(compressed) == data

    def test_run_length_encoding(self) -> None:
        """Run-length patterns compress efficiently."""
        pattern = b"ABC" * 1000
        compressed = compress(pattern)
        assert len(compressed) < len(pattern) // 10
        assert decompress(compressed) == pattern

    def test_random_looking_data(self) -> None:
        """Data without patterns may not compress but still roundtrips."""
        data = bytes([(i * 17 + 31) % 256 for i in range(500)])
        compressed = compress(data)
        assert decompress(compressed) == data

    def test_binary_data(self) -> None:
        """Binary data roundtrips correctly."""
        data = bytes(range(256)) * 4
        compressed = compress(data)
        assert decompress(compressed) == data


class TestMultiBlock:
    """Tests for multi-block compression (inputs > 64KB)."""

    def test_large_input(self) -> None:
        """Large inputs (multi-block) roundtrip correctly."""
        data = b"Test pattern for large data compression. " * 5000
        compressed = compress(data)
        assert decompress(compressed) == data

    def test_exact_block_size(self) -> None:
        """Data exactly at block boundary."""
        data = b"X" * 65536  # Exactly one block
        compressed = compress(data)
        assert decompress(compressed) == data

    def test_multiple_blocks(self) -> None:
        """Data spanning multiple blocks."""
        data = b"Y" * (65536 * 3 + 1000)  # 3+ blocks
        compressed = compress(data)
        assert decompress(compressed) == data


class TestExpandedData:
    """Tests with expanded (repeated) data."""

    @pytest.mark.parametrize("label,filename,size_limit", TEST_DATA_FILES)
    def test_expanded_roundtrip(self, label: str, filename: str, size_limit: int) -> None:
        """Test roundtrip with data expanded to span multiple blocks."""
        data = load_test_file(filename, size_limit)

        # Expand data to at least 3x block size (196KB)
        expanded = data
        while len(expanded) < 3 * 65536:
            expanded = expanded + data

        compressed = compress(expanded)
        assert decompress(compressed) == expanded
