"""Tests for snappy compression and the compressed-length bound."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from lean_spec.node.snappy import (
    compress,
    decompress,
    max_compressed_length,
)

# Path to test data files
TESTDATA_DIRECTORY = Path(__file__).parent / "testdata"


def load_test_file(filename: str, size_limit: int = 0) -> bytes:
    """Load a test data file, optionally truncated to size_limit."""
    path = TESTDATA_DIRECTORY / filename
    file_bytes = path.read_bytes()
    if size_limit > 0:
        file_bytes = file_bytes[:size_limit]
    return file_bytes


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


class TestSimpleCompression:
    """Simple compression tests from C++ test suite."""

    def test_empty_input(self) -> None:
        """Empty input compresses and decompresses correctly."""
        compressed = compress(b"")
        assert decompress(compressed) == b""

    def test_single_byte(self) -> None:
        """Single byte roundtrips correctly."""
        for character in [b"a", b"X", b"\x00", b"\xff"]:
            compressed = compress(character)
            assert decompress(compressed) == character

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
                    uncompressed = bytearray(size)

                    # Build pattern
                    for i in range(pattern_size):
                        uncompressed[i] = ord("a") + i

                    # Repeat pattern
                    for i in range(length):
                        uncompressed[pattern_size + i] = uncompressed[i % pattern_size]

                    # Random suffix
                    for i in range(extra_bytes):
                        uncompressed[pattern_size + length + i] = random.randint(0, 255)

                    compressed = compress(bytes(uncompressed))
                    assert decompress(compressed) == bytes(uncompressed)


class TestMaxBlowup:
    """Test maximum compression blowup scenario."""

    def test_max_blowup(self) -> None:
        """Test worst-case compression expansion (lots of four-byte copies)."""
        random.seed(42)

        # Build input with random bytes
        uncompressed = bytearray(random.randint(0, 255) for _ in range(80000))

        # Append four-byte sequences from the end
        for i in range(0, 80000, 4):
            four_bytes = uncompressed[-(i + 4) : -i] if i > 0 else uncompressed[-4:]
            uncompressed.extend(four_bytes)

        compressed = compress(bytes(uncompressed))
        assert decompress(compressed) == bytes(uncompressed)

        # Verify max_compressed_length bound
        assert len(compressed) <= max_compressed_length(len(uncompressed))


class TestRealDataFiles:
    """Tests using real data files from C++ test suite."""

    @pytest.mark.parametrize("label,filename,size_limit", TEST_DATA_FILES)
    def test_roundtrip(self, label: str, filename: str, size_limit: int) -> None:
        """Test compression/decompression roundtrip for each test file."""
        uncompressed = load_test_file(filename, size_limit)
        compressed = compress(uncompressed)
        decompressed = decompress(compressed)
        assert decompressed == uncompressed, f"Roundtrip failed for {label}"

    @pytest.mark.parametrize("label,filename,size_limit", TEST_DATA_FILES)
    def test_compression_bound(self, label: str, filename: str, size_limit: int) -> None:
        """Test that compressed size is within bounds."""
        uncompressed = load_test_file(filename, size_limit)
        compressed = compress(uncompressed)
        assert len(compressed) <= max_compressed_length(len(uncompressed))

    def test_text_compression_ratio(self) -> None:
        """Text files should achieve good compression."""
        for label, filename, _ in TEST_DATA_FILES:
            if filename.endswith(".txt"):
                uncompressed = load_test_file(filename)
                compressed = compress(uncompressed)
                ratio = len(compressed) / len(uncompressed)
                # Text should compress to less than 70% of original
                # (Snappy prioritizes speed over compression ratio)
                assert ratio < 0.7, f"{label} compression ratio too high: {ratio:.2%}"

    def test_jpeg_low_compression(self) -> None:
        """JPEG files (already compressed) should have low compression ratio."""
        uncompressed = load_test_file("fireworks.jpeg")
        compressed = compress(uncompressed)
        ratio = len(compressed) / len(uncompressed)
        # JPEG shouldn't compress much (already compressed)
        # Allow up to 5% expansion or minimal compression
        assert ratio > 0.95, f"JPEG compressed too much: {ratio:.2%}"


class TestUtilities:
    """Tests for utility functions."""

    def test_max_compressed_length(self) -> None:
        """max_compressed_length returns a valid upper bound."""
        for size in [0, 100, 1000, 65536, 100000]:
            max_length = max_compressed_length(size)
            uncompressed = bytes(range(256)) * (size // 256 + 1)
            uncompressed = uncompressed[:size]
            compressed = compress(uncompressed)
            assert len(compressed) <= max_length


class TestSpecificPatterns:
    """Tests for specific compression patterns."""

    def test_overlapping_copy(self) -> None:
        """Overlapping copies (run-length encoding) work correctly."""
        uncompressed = b"AAAAAAAAAAAA"
        compressed = compress(uncompressed)
        assert decompress(compressed) == uncompressed

    def test_alternating_pattern(self) -> None:
        """Alternating patterns compress correctly."""
        uncompressed = b"ABABABABABABABAB" * 100
        compressed = compress(uncompressed)
        assert decompress(compressed) == uncompressed

    def test_long_match(self) -> None:
        """Long matches (up to 64 bytes) are handled correctly."""
        pattern = bytes(range(64))
        uncompressed = pattern * 100
        compressed = compress(uncompressed)
        assert decompress(compressed) == uncompressed

    def test_near_block_boundary(self) -> None:
        """Data near block boundaries compresses correctly."""
        for size in [65534, 65535, 65536, 65537, 65538]:
            uncompressed = b"X" * size
            compressed = compress(uncompressed)
            assert decompress(compressed) == uncompressed

    def test_repeated_data_compresses(self) -> None:
        """Repeated data achieves significant compression."""
        uncompressed = b"A" * 1000
        compressed = compress(uncompressed)
        assert len(compressed) < len(uncompressed) // 2
        assert decompress(compressed) == uncompressed

    def test_run_length_encoding(self) -> None:
        """Run-length patterns compress efficiently."""
        pattern = b"ABC" * 1000
        compressed = compress(pattern)
        assert len(compressed) < len(pattern) // 10
        assert decompress(compressed) == pattern

    def test_random_looking_data(self) -> None:
        """Data without patterns may not compress but still roundtrips."""
        uncompressed = bytes([(i * 17 + 31) % 256 for i in range(500)])
        compressed = compress(uncompressed)
        assert decompress(compressed) == uncompressed

    def test_binary_data(self) -> None:
        """Binary data roundtrips correctly."""
        uncompressed = bytes(range(256)) * 4
        compressed = compress(uncompressed)
        assert decompress(compressed) == uncompressed


class TestMultiBlock:
    """Tests for multi-block compression (inputs > 64KB)."""

    def test_large_input(self) -> None:
        """Large inputs (multi-block) roundtrip correctly."""
        uncompressed = b"Test pattern for large data compression. " * 5000
        compressed = compress(uncompressed)
        assert decompress(compressed) == uncompressed

    def test_exact_block_size(self) -> None:
        """Data exactly at block boundary."""
        uncompressed = b"X" * 65536  # Exactly one block
        compressed = compress(uncompressed)
        assert decompress(compressed) == uncompressed

    def test_multiple_blocks(self) -> None:
        """Data spanning multiple blocks."""
        uncompressed = b"Y" * (65536 * 3 + 1000)  # 3+ blocks
        compressed = compress(uncompressed)
        assert decompress(compressed) == uncompressed


class TestExpandedData:
    """Tests with expanded (repeated) data."""

    @pytest.mark.parametrize("label,filename,size_limit", TEST_DATA_FILES)
    def test_expanded_roundtrip(self, label: str, filename: str, size_limit: int) -> None:
        """Test roundtrip with data expanded to span multiple blocks."""
        uncompressed = load_test_file(filename, size_limit)

        # Expand data to at least 3x block size (196KB)
        expanded = uncompressed
        while len(expanded) < 3 * 65536:
            expanded = expanded + uncompressed

        compressed = compress(expanded)
        assert decompress(compressed) == expanded
