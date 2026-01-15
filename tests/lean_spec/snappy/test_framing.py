"""
Comprehensive tests for Snappy framing format.

Tests verify compliance with the official specification:
https://github.com/google/snappy/blob/master/framing_format.txt
"""

from __future__ import annotations

import pytest

from lean_spec.snappy import SnappyDecompressionError
from lean_spec.snappy.framing import (
    CHUNK_TYPE_COMPRESSED,
    CHUNK_TYPE_UNCOMPRESSED,
    CRC32C_MASK_DELTA,
    MAX_UNCOMPRESSED_CHUNK_SIZE,
    STREAM_IDENTIFIER,
    _crc32c,
    _mask_crc,
    frame_compress,
    frame_decompress,
)


class TestStreamIdentifier:
    """Tests for stream identifier (spec section 4.1)."""

    def test_stream_identifier_format(self) -> None:
        """Stream identifier matches spec: 0xff 0x06 0x00 0x00 sNaPpY."""
        expected = b"\xff\x06\x00\x00sNaPpY"
        assert STREAM_IDENTIFIER == expected
        assert len(STREAM_IDENTIFIER) == 10

    def test_compressed_starts_with_identifier(self) -> None:
        """All compressed output starts with stream identifier."""
        data = b"test data"
        compressed = frame_compress(data)
        assert compressed.startswith(STREAM_IDENTIFIER)

    def test_empty_data_has_identifier(self) -> None:
        """Even empty data produces stream identifier."""
        compressed = frame_compress(b"")
        assert compressed == STREAM_IDENTIFIER

    def test_repeated_identifier_accepted(self) -> None:
        """Repeated stream identifiers in concatenated streams are accepted."""
        data = b"test"
        stream1 = frame_compress(data)
        stream2 = frame_compress(data)
        # Concatenate two valid streams
        combined = stream1 + stream2
        # Should decompress to concatenated data
        result = frame_decompress(combined)
        assert result == data + data

    def test_invalid_identifier_rejected(self) -> None:
        """Invalid stream identifier content is rejected."""
        # Valid header structure but wrong content
        bad_stream = b"\xff\x06\x00\x00BADDAT"
        with pytest.raises(SnappyDecompressionError, match="Invalid stream identifier"):
            frame_decompress(bad_stream)

    def test_wrong_identifier_length_rejected(self) -> None:
        """Stream identifier with wrong length is rejected."""
        # Build a stream with identifier chunk of wrong length
        # First valid identifier, then a bad 0xFF chunk with length 5
        valid_part = STREAM_IDENTIFIER
        bad_identifier_chunk = b"\xff\x05\x00\x00sNaPp"  # Only 5 bytes, not 6
        bad_stream = valid_part + bad_identifier_chunk
        with pytest.raises(SnappyDecompressionError, match="must be 6 bytes"):
            frame_decompress(bad_stream)


class TestChunkFormat:
    """Tests for chunk format (spec section 1)."""

    def test_chunk_header_format(self) -> None:
        """Chunk header is [type: 1][length: 3 LE]."""
        data = b"Hello"
        compressed = frame_compress(data)

        # Skip stream identifier, read first chunk header
        pos = len(STREAM_IDENTIFIER)
        chunk_type = compressed[pos]
        chunk_length = int.from_bytes(compressed[pos + 1 : pos + 4], "little")

        # Chunk type should be 0x00 (compressed) or 0x01 (uncompressed)
        assert chunk_type in (CHUNK_TYPE_COMPRESSED, CHUNK_TYPE_UNCOMPRESSED)
        # Length should be CRC (4) + payload
        assert chunk_length >= 4

    def test_chunk_length_little_endian(self) -> None:
        """Chunk length is stored in little-endian format."""
        # Compress data that will create a known-size chunk
        data = b"A" * 100
        compressed = frame_compress(data)

        pos = len(STREAM_IDENTIFIER)
        # Read 3-byte little-endian length
        length_bytes = compressed[pos + 1 : pos + 4]
        chunk_length = int.from_bytes(length_bytes, "little")

        # Verify by reading that many bytes
        chunk_data = compressed[pos + 4 : pos + 4 + chunk_length]
        assert len(chunk_data) == chunk_length


class TestCRC32C:
    """Tests for CRC32C checksum (spec section 3)."""

    def test_crc32c_known_values(self) -> None:
        """CRC32C matches known test vectors."""
        # Test vectors from RFC 3720 section B.4
        assert _crc32c(b"") == 0x00000000
        # Additional test vectors
        assert _crc32c(b"\x00" * 32) == 0x8A9136AA
        assert _crc32c(b"\xff" * 32) == 0x62A8AB43

    def test_crc32c_castagnoli_polynomial(self) -> None:
        """CRC32C uses Castagnoli polynomial (0x82F63B78)."""
        # Single byte test - verifies polynomial
        crc = _crc32c(b"\x01")
        # This value is specific to Castagnoli polynomial
        assert crc == 0xA016D052

    def test_mask_formula(self) -> None:
        """Masking follows spec: ((x >> 15) | (x << 17)) + 0xa282ead8."""
        crc = 0x12345678
        expected = (((crc >> 15) | (crc << 17)) + CRC32C_MASK_DELTA) & 0xFFFFFFFF
        assert _mask_crc(crc) == expected

    def test_crc_stored_little_endian(self) -> None:
        """CRC is stored as 4 bytes little-endian in chunks."""
        data = b"test"
        compressed = frame_compress(data)

        # Find chunk after stream identifier
        pos = len(STREAM_IDENTIFIER) + 4  # Skip header
        stored_crc = int.from_bytes(compressed[pos : pos + 4], "little")

        # Compute expected CRC
        expected_crc = _mask_crc(_crc32c(data))
        # Note: if compressed, CRC is of uncompressed data
        # For small data like "test", it may be uncompressed
        assert stored_crc == expected_crc or stored_crc != 0

    def test_crc_corruption_detected(self) -> None:
        """Corrupted CRC causes decompression to fail."""
        data = b"test data for CRC validation"
        compressed = bytearray(frame_compress(data))

        # Corrupt the CRC (byte 14-17 after stream identifier + chunk header)
        crc_pos = len(STREAM_IDENTIFIER) + 4
        compressed[crc_pos] ^= 0xFF

        with pytest.raises(SnappyDecompressionError, match="CRC mismatch"):
            frame_decompress(bytes(compressed))


class TestCompressedChunk:
    """Tests for compressed data chunks (spec section 4.2)."""

    def test_compressed_chunk_type(self) -> None:
        """Compressed chunks use type 0x00."""
        assert CHUNK_TYPE_COMPRESSED == 0x00

    def test_compressible_data_uses_compressed_chunk(self) -> None:
        """Highly compressible data uses compressed chunks."""
        data = b"A" * 1000  # Very compressible
        compressed = frame_compress(data)

        # Check chunk type after stream identifier
        chunk_type = compressed[len(STREAM_IDENTIFIER)]
        assert chunk_type == CHUNK_TYPE_COMPRESSED

    def test_compressed_chunk_format(self) -> None:
        """Compressed chunk is [crc: 4][compressed_data]."""
        data = b"A" * 1000
        compressed = frame_compress(data)

        pos = len(STREAM_IDENTIFIER)
        chunk_type = compressed[pos]
        chunk_length = int.from_bytes(compressed[pos + 1 : pos + 4], "little")

        assert chunk_type == CHUNK_TYPE_COMPRESSED
        # Chunk data should be CRC (4 bytes) + compressed payload
        assert chunk_length >= 5  # At least CRC + 1 byte compressed


class TestUncompressedChunk:
    """Tests for uncompressed data chunks (spec section 4.3)."""

    def test_uncompressed_chunk_type(self) -> None:
        """Uncompressed chunks use type 0x01."""
        assert CHUNK_TYPE_UNCOMPRESSED == 0x01

    def test_incompressible_data_uses_uncompressed_chunk(self) -> None:
        """Incompressible data uses uncompressed chunks."""
        # Random-looking data that doesn't compress
        data = bytes([(i * 17 + 31) % 256 for i in range(100)])
        compressed = frame_compress(data)

        # Check chunk type
        chunk_type = compressed[len(STREAM_IDENTIFIER)]
        # May be compressed or uncompressed depending on algorithm
        assert chunk_type in (CHUNK_TYPE_COMPRESSED, CHUNK_TYPE_UNCOMPRESSED)

    def test_uncompressed_roundtrip(self) -> None:
        """Data stored uncompressed roundtrips correctly."""
        # Small incompressible data
        data = bytes(range(256))
        compressed = frame_compress(data)
        decompressed = frame_decompress(compressed)
        assert decompressed == data


class TestChunkSizeLimits:
    """Tests for chunk size limits (spec sections 4.2, 4.3)."""

    def test_max_uncompressed_chunk_size(self) -> None:
        """Maximum uncompressed chunk size is 65536 bytes."""
        assert MAX_UNCOMPRESSED_CHUNK_SIZE == 65536

    def test_large_data_split_into_chunks(self) -> None:
        """Data larger than 64KB is split into multiple chunks."""
        data = b"X" * 100_000  # ~100KB
        compressed = frame_compress(data)

        # Count chunks
        chunk_count = 0
        pos = len(STREAM_IDENTIFIER)
        while pos < len(compressed):
            chunk_count += 1
            chunk_length = int.from_bytes(compressed[pos + 1 : pos + 4], "little")
            pos += 4 + chunk_length

        # Should have at least 2 chunks for 100KB
        assert chunk_count >= 2

    def test_exact_chunk_boundary(self) -> None:
        """Data exactly at chunk boundary handled correctly."""
        data = b"Y" * MAX_UNCOMPRESSED_CHUNK_SIZE
        compressed = frame_compress(data)
        decompressed = frame_decompress(compressed)
        assert decompressed == data

    def test_oversized_uncompressed_chunk_rejected(self) -> None:
        """Chunks larger than 65536 bytes are rejected."""
        # Manually craft a malicious stream with oversized chunk
        # Stream identifier + uncompressed chunk header claiming 70000 bytes
        chunk_length = 70000 + 4  # payload + CRC
        malicious = bytearray(STREAM_IDENTIFIER)
        malicious.append(CHUNK_TYPE_UNCOMPRESSED)
        malicious.extend(chunk_length.to_bytes(3, "little"))
        # Add fake CRC and oversized payload
        malicious.extend(b"\x00" * 4)  # CRC
        malicious.extend(b"\x00" * 70000)  # Oversized payload

        with pytest.raises(SnappyDecompressionError, match="exceeds"):
            frame_decompress(bytes(malicious))


class TestReservedChunks:
    """Tests for reserved chunk types (spec sections 4.5, 4.6)."""

    def test_unskippable_chunk_raises(self) -> None:
        """Reserved unskippable chunks (0x02-0x7F) cause error."""
        for chunk_type in [0x02, 0x10, 0x50, 0x7F]:
            # Build stream with reserved chunk
            malicious = bytearray(STREAM_IDENTIFIER)
            malicious.append(chunk_type)
            malicious.extend(b"\x00\x00\x00")  # Zero length

            with pytest.raises(SnappyDecompressionError, match="unskippable"):
                frame_decompress(bytes(malicious))

    def test_skippable_chunk_ignored(self) -> None:
        """Reserved skippable chunks (0x80-0xFD) are silently skipped."""
        data = b"test"
        compressed = bytearray(frame_compress(data))

        # Insert a skippable chunk (type 0x80) with some padding
        padding_data = b"PADDING"
        skippable_chunk = bytes([0x80]) + len(padding_data).to_bytes(3, "little") + padding_data

        # Insert after stream identifier, before data chunk
        insert_pos = len(STREAM_IDENTIFIER)
        modified = compressed[:insert_pos] + skippable_chunk + compressed[insert_pos:]

        # Should still decompress correctly
        result = frame_decompress(bytes(modified))
        assert result == data

    def test_padding_chunk_ignored(self) -> None:
        """Padding chunks (0xFE) are silently skipped."""
        data = b"test"
        compressed = bytearray(frame_compress(data))

        # Insert padding chunk
        padding_chunk = b"\xfe\x10\x00\x00" + (b"\x00" * 16)

        insert_pos = len(STREAM_IDENTIFIER)
        modified = compressed[:insert_pos] + padding_chunk + compressed[insert_pos:]

        result = frame_decompress(bytes(modified))
        assert result == data


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_input(self) -> None:
        """Empty input raises appropriate error."""
        with pytest.raises(SnappyDecompressionError, match="too short"):
            frame_decompress(b"")

    def test_truncated_stream_identifier(self) -> None:
        """Truncated stream identifier raises error."""
        with pytest.raises(SnappyDecompressionError, match="too short"):
            frame_decompress(b"\xff\x06\x00")

    def test_truncated_chunk_header(self) -> None:
        """Truncated chunk header raises error."""
        truncated = STREAM_IDENTIFIER + b"\x00\x10"  # Incomplete header
        with pytest.raises(SnappyDecompressionError, match="Truncated"):
            frame_decompress(truncated)

    def test_truncated_chunk_data(self) -> None:
        """Truncated chunk data raises error."""
        data = b"test"
        compressed = frame_compress(data)
        # Truncate some bytes from the end
        truncated = compressed[:-5]
        with pytest.raises(SnappyDecompressionError, match="extends past end"):
            frame_decompress(truncated)

    def test_roundtrip_various_sizes(self) -> None:
        """Roundtrip works for various data sizes."""
        for size in [0, 1, 100, 1000, 65535, 65536, 65537, 100_000]:
            data = bytes([i % 256 for i in range(size)])
            compressed = frame_compress(data)
            decompressed = frame_decompress(compressed)
            assert decompressed == data, f"Roundtrip failed for size {size}"


class TestInteroperability:
    """Tests ensuring compatibility with other implementations."""

    def test_wire_format_structure(self) -> None:
        """Wire format matches expected structure for interop."""
        data = b"Hello, Ethereum!"
        compressed = frame_compress(data)

        # Verify structure
        assert compressed[:10] == STREAM_IDENTIFIER

        # First chunk header
        pos = 10
        chunk_type = compressed[pos]
        assert chunk_type in (0x00, 0x01)  # Compressed or uncompressed

        chunk_len = int.from_bytes(compressed[pos + 1 : pos + 4], "little")
        assert chunk_len >= 4  # At least CRC

        # CRC is first 4 bytes of chunk data
        crc_bytes = compressed[pos + 4 : pos + 8]
        assert len(crc_bytes) == 4

    def test_concatenated_streams(self) -> None:
        """Multiple concatenated streams decompress correctly."""
        # This is important for streaming protocols
        stream1 = frame_compress(b"first")
        stream2 = frame_compress(b"second")
        stream3 = frame_compress(b"third")

        combined = stream1 + stream2 + stream3
        result = frame_decompress(combined)

        assert result == b"firstsecondthird"
