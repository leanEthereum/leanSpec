"""
Tests for the req/resp codec.

Test Vector Sources
-------------------
- Varint encoding vectors: Protocol Buffers Encoding Guide
  https://protobuf.dev/programming-guides/encoding/

- Snappy framing format: Google Snappy framing_format.txt
  https://github.com/google/snappy/blob/main/framing_format.txt

- Malicious input patterns: Inspired by Lighthouse codec.rs tests
  https://github.com/sigp/lighthouse/blob/stable/beacon_node/lighthouse_network/src/rpc/codec.rs

- Wire format validation: Ethereum P2P Interface Spec
  https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
"""

from __future__ import annotations

import hashlib

import pytest

from lean_spec.node.networking.config import MAX_ERROR_MESSAGE_SIZE, MAX_PAYLOAD_SIZE
from lean_spec.node.networking.reqresp import (
    CodecError,
    ResponseCode,
    decode_request,
    encode_request,
)
from lean_spec.node.networking.varint import (
    VarintError,
    decode_varint,
    encode_varint,
)


class TestRequestCodec:
    """Tests for request encoding/decoding."""

    def test_simple_request(self) -> None:
        """Simple SSZ data encodes and decodes correctly."""
        ssz_data = b"\x01\x02\x03\x04"
        encoded = encode_request(ssz_data)
        decoded = decode_request(encoded)
        assert decoded == ssz_data

    def test_empty_request(self) -> None:
        """Empty SSZ data roundtrips correctly."""
        ssz_data = b""
        encoded = encode_request(ssz_data)
        decoded = decode_request(encoded)
        assert decoded == ssz_data

    def test_large_request(self) -> None:
        """Large request data roundtrips correctly."""
        ssz_data = b"X" * 50_000
        encoded = encode_request(ssz_data)
        decoded = decode_request(encoded)
        assert decoded == ssz_data

    def test_decode_empty_raises(self) -> None:
        """Empty input raises CodecError."""
        with pytest.raises(CodecError) as exception_info:
            decode_request(b"")
        assert str(exception_info.value) == "Empty request"

    def test_decode_invalid_varint_raises(self) -> None:
        """Invalid varint raises CodecError."""
        with pytest.raises(CodecError) as exception_info:
            decode_request(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
        assert str(exception_info.value) == "Invalid request length: Varint exceeds 10 bytes"

    def test_length_mismatch_raises(self) -> None:
        """Mismatched declared length raises CodecError."""
        # Encode valid request, then modify the length prefix
        encoded = bytearray(encode_request(b"test"))
        encoded[0] = 0x10  # Change declared length to 16
        with pytest.raises(CodecError) as exception_info:
            decode_request(bytes(encoded))
        assert str(exception_info.value) == "Length mismatch: declared 16, got 4"


class TestResponseCodec:
    """Tests for response encoding/decoding."""

    def test_success_response(self) -> None:
        """Success response encodes and decodes correctly."""
        ssz_data = b"\x01\x02\x03\x04"
        encoded = ResponseCode.SUCCESS.encode(ssz_data)
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.SUCCESS
        assert decoded == ssz_data

    def test_error_response(self) -> None:
        """Error response encodes and decodes correctly."""
        error_message = b"Block not found"
        encoded = ResponseCode.RESOURCE_UNAVAILABLE.encode(error_message)
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.RESOURCE_UNAVAILABLE
        assert decoded == error_message

    def test_all_response_codes(self) -> None:
        """All standard response codes work correctly."""
        for response_code in ResponseCode:
            ssz_data = b"test payload"
            encoded = response_code.encode(ssz_data)
            code, decoded = ResponseCode.decode(encoded)
            assert code == response_code
            assert decoded == ssz_data

    def test_response_starts_with_code(self) -> None:
        """Response wire format starts with code byte."""
        encoded = ResponseCode.SERVER_ERROR.encode(b"error")
        assert encoded[0] == ResponseCode.SERVER_ERROR

    def test_decode_empty_raises(self) -> None:
        """Empty input raises CodecError."""
        with pytest.raises(CodecError) as exception_info:
            ResponseCode.decode(b"")
        assert str(exception_info.value) == "Empty response"

    def test_decode_too_short_raises(self) -> None:
        """Too-short input raises CodecError."""
        with pytest.raises(CodecError) as exception_info:
            ResponseCode.decode(b"\x00")
        assert str(exception_info.value) == "Response too short"

    def test_unknown_code_handled(self) -> None:
        """Unknown response codes are handled gracefully."""
        # Build response with unknown code 50
        ssz_data = b"test"
        encoded = bytearray(ResponseCode.SUCCESS.encode(ssz_data))
        encoded[0] = 50  # Unknown code
        code, decoded = ResponseCode.decode(bytes(encoded))
        # Unknown codes 4-127 map to SERVER_ERROR
        assert code == ResponseCode.SERVER_ERROR
        assert decoded == ssz_data


class TestInteroperability:
    """Tests ensuring compatibility with ream/zeam wire format."""

    def test_varint_format_matches_protobuf(self) -> None:
        """Varint encoding matches protobuf/LEB128 spec."""
        # These are known protobuf varint encodings
        assert encode_varint(0) == b"\x00"
        assert encode_varint(1) == b"\x01"
        assert encode_varint(127) == b"\x7f"
        assert encode_varint(128) == b"\x80\x01"
        assert encode_varint(16384) == b"\x80\x80\x01"

    def test_request_wire_format(self) -> None:
        """Request wire format matches spec: [varint_length][snappy_payload]."""
        ssz_data = b"test"
        encoded = encode_request(ssz_data)

        # First bytes should be varint of uncompressed length
        length, varint_size = decode_varint(encoded)
        assert length == len(ssz_data)

        # Rest should be valid snappy framed data
        snappy_data = encoded[varint_size:]
        assert snappy_data.startswith(b"\xff\x06\x00\x00sNaPpY")

    def test_response_wire_format(self) -> None:
        """Response wire format matches spec: [code][varint_length][snappy_payload]."""
        ssz_data = b"test"
        encoded = ResponseCode.SUCCESS.encode(ssz_data)

        # First byte is response code
        assert encoded[0] == 0

        # Next bytes are varint of uncompressed length
        length, varint_size = decode_varint(encoded, offset=1)
        assert length == len(ssz_data)

        # Rest should be valid snappy framed data
        snappy_data = encoded[1 + varint_size :]
        assert snappy_data.startswith(b"\xff\x06\x00\x00sNaPpY")


class TestBoundaryConditions:
    """
    Tests for boundary conditions in the codec.

    Source: Ethereum P2P Interface Spec (MAX_PAYLOAD_SIZE = 10 MiB)
        https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md

    Source: Protocol Buffers varint spec (max 10 bytes for 64-bit values)
        https://protobuf.dev/programming-guides/encoding/
    """

    def test_varint_10_bytes_accepted(self) -> None:
        """A valid 10-byte varint is accepted."""
        # Construct a 10-byte varint representing 2^63
        # This is the smallest value that requires 10 bytes
        integer_value = 2**63
        encoded = encode_varint(integer_value)
        assert len(encoded) == 10

        decoded, consumed = decode_varint(encoded)
        assert decoded == integer_value
        assert consumed == 10

    def test_varint_11_bytes_rejected(self) -> None:
        """An 11-byte varint is rejected as too long."""
        # Create an artificially long varint with 11 continuation bytes
        # Each byte has the continuation bit set except the last
        malformed = bytes([0x80] * 10 + [0x01])
        assert len(malformed) == 11

        with pytest.raises(VarintError) as exception_info:
            decode_varint(malformed)
        assert str(exception_info.value) == "Varint exceeds 10 bytes"

    def test_payload_at_max_size(self) -> None:
        """Payload at exactly MAX_PAYLOAD_SIZE is accepted."""
        # Create payload at exactly MAX_PAYLOAD_SIZE
        ssz_data = b"X" * MAX_PAYLOAD_SIZE

        # Should encode without error
        encoded = encode_request(ssz_data)
        # Encoded size depends on compression; highly compressible data may be smaller
        assert len(encoded) > 0

        # Should decode back correctly
        decoded = decode_request(encoded)
        assert decoded == ssz_data

    def test_payload_over_max_size_rejected_on_encode(self) -> None:
        """Payload exceeding MAX_PAYLOAD_SIZE is rejected on encode."""
        oversized = b"X" * (MAX_PAYLOAD_SIZE + 1)

        with pytest.raises(CodecError) as exception_info:
            encode_request(oversized)
        assert str(exception_info.value) == (
            f"Payload too large: {MAX_PAYLOAD_SIZE + 1} > {MAX_PAYLOAD_SIZE}"
        )

    def test_declared_length_over_max_rejected_on_decode(self) -> None:
        """Declared length exceeding MAX_PAYLOAD_SIZE is rejected on decode."""
        # Encode a small request, then modify the length prefix
        valid_encoded = encode_request(b"test")

        # Replace the varint length with one that exceeds MAX_PAYLOAD_SIZE
        oversized_length = encode_varint(MAX_PAYLOAD_SIZE + 1)
        # Skip the original varint (which is 1 byte for "test" length 4)
        malformed = oversized_length + valid_encoded[1:]

        with pytest.raises(CodecError) as exception_info:
            decode_request(malformed)
        assert str(exception_info.value) == (
            f"Declared length too large: {MAX_PAYLOAD_SIZE + 1} > {MAX_PAYLOAD_SIZE}"
        )

    def test_response_payload_at_max_size(self) -> None:
        """Response payload at exactly MAX_PAYLOAD_SIZE is accepted."""
        ssz_data = b"Y" * MAX_PAYLOAD_SIZE

        encoded = ResponseCode.SUCCESS.encode(ssz_data)
        code, decoded = ResponseCode.decode(encoded)

        assert code == ResponseCode.SUCCESS
        assert decoded == ssz_data


class TestMaliciousInputs:
    """
    Security-focused tests for malicious input handling.

    These tests verify that the codec rejects malformed or malicious data
    without crashing, leaking information, or consuming excessive resources.

    Inspired by: Lighthouse codec.rs test patterns
        https://github.com/sigp/lighthouse/blob/stable/beacon_node/lighthouse_network/src/rpc/codec.rs

    Key patterns tested:
        - Length prefix manipulation (decompression bomb prevention)
        - Truncated snappy streams
        - Corrupted CRC checksums
        - Invalid stream identifiers
    """

    def test_length_mismatch_too_short(self) -> None:
        """Declared length larger than actual decompressed data is rejected."""
        # Encode a valid request
        valid = encode_request(b"short")

        # Modify varint to claim a larger length
        # Original encodes length 5, change to claim length 100
        malformed = encode_varint(100) + valid[1:]

        with pytest.raises(CodecError) as exception_info:
            decode_request(malformed)
        assert str(exception_info.value) == "Length mismatch: declared 100, got 5"

    def test_length_mismatch_too_long(self) -> None:
        """Declared length smaller than actual decompressed data is rejected."""
        # Encode a valid request with longer data
        valid = encode_request(b"this is longer data")

        # Modify varint to claim a smaller length
        # Change to claim length 5 instead of 19
        malformed = encode_varint(5) + valid[1:]

        with pytest.raises(CodecError) as exception_info:
            decode_request(malformed)
        assert str(exception_info.value) == "Length mismatch: declared 5, got 19"

    def test_truncated_snappy_stream(self) -> None:
        """Truncated snappy framed data is rejected."""
        valid = encode_request(b"test data")

        # Cut off the last few bytes to truncate the snappy frame
        truncated = valid[:-5]

        with pytest.raises(CodecError) as exception_info:
            decode_request(truncated)
        assert str(exception_info.value) == (
            "Decompression failed: Chunk extends past end: need 13 bytes at 14, have 8"
        )

    def test_invalid_snappy_stream_identifier(self) -> None:
        """Invalid snappy stream identifier is rejected."""
        # Create a request with corrupted snappy magic bytes
        varint_prefix = encode_varint(4)  # Claim length 4

        # Corrupted stream identifier (changed sNaPpY to XXXXXX)
        fake_snappy = b"\xff\x06\x00\x00XXXXXX"

        malformed = varint_prefix + fake_snappy

        with pytest.raises(CodecError) as exception_info:
            decode_request(malformed)
        assert str(exception_info.value) == "Decompression failed: Invalid stream identifier"

    def test_corrupted_snappy_crc(self) -> None:
        """Snappy frame with corrupted CRC is rejected."""
        # Encode a valid request
        valid = encode_request(b"test data for crc")

        # The CRC is stored after the stream identifier (10 bytes) + chunk header (4 bytes)
        # Corrupt a byte in the CRC area
        corrupted = bytearray(valid)

        # Find the start of the CRC (after varint + stream identifier + chunk type/length)
        # varint for length 17 is 1 byte, stream identifier is 10 bytes, header is 4 bytes
        crc_start = 1 + 10 + 4  # Offset to CRC
        corrupted[crc_start] ^= 0xFF  # Flip all bits in first CRC byte

        with pytest.raises(CodecError) as exception_info:
            decode_request(bytes(corrupted))
        assert str(exception_info.value) == (
            "Decompression failed: CRC mismatch: stored 0x50dac131, computed 0x50dac1ce"
        )

    def test_missing_snappy_data(self) -> None:
        """Request with varint but no snappy data is rejected."""
        # Just a varint with no payload
        malformed = encode_varint(100)

        with pytest.raises(CodecError) as exception_info:
            decode_request(malformed)
        assert str(exception_info.value) == (
            "Decompression failed: Input too short for framed snappy"
        )

    def test_response_with_truncated_payload(self) -> None:
        """Response with truncated payload is rejected."""
        valid = ResponseCode.SUCCESS.encode(b"test response data")

        # Truncate the payload
        truncated = valid[:-10]

        with pytest.raises(CodecError) as exception_info:
            ResponseCode.decode(truncated)
        assert str(exception_info.value) == (
            "Decompression failed: Chunk extends past end: need 22 bytes at 14, have 12"
        )

    def test_response_code_boundary_values(self) -> None:
        """Response codes at boundary values are handled correctly."""
        ssz_data = b"test"

        # Test boundary codes
        boundary_codes = [
            (0, ResponseCode.SUCCESS),
            (1, ResponseCode.INVALID_REQUEST),
            (2, ResponseCode.SERVER_ERROR),
            (3, ResponseCode.RESOURCE_UNAVAILABLE),
            (4, ResponseCode.SERVER_ERROR),  # First unknown, maps to SERVER_ERROR
            (127, ResponseCode.SERVER_ERROR),  # Last in 0-127 range
            (128, ResponseCode.INVALID_REQUEST),  # First in 128-255 range
            (255, ResponseCode.INVALID_REQUEST),  # Last possible code
        ]

        for raw_code, expected_mapped in boundary_codes:
            # Build a valid response with the specific code
            encoded = bytearray(ResponseCode.SUCCESS.encode(ssz_data))
            encoded[0] = raw_code

            code, decoded = ResponseCode.decode(bytes(encoded))
            assert code == expected_mapped, f"Code {raw_code} should map to {expected_mapped}"
            assert decoded == ssz_data

    def test_zero_length_varint_in_request(self) -> None:
        """Zero-length request (empty SSZ) roundtrips correctly."""
        empty_ssz = b""
        encoded = encode_request(empty_ssz)
        decoded = decode_request(encoded)
        assert decoded == empty_ssz

    def test_all_zeros_payload(self) -> None:
        """Payload of all zero bytes roundtrips correctly."""
        zeros = b"\x00" * 1000
        encoded = encode_request(zeros)
        decoded = decode_request(encoded)
        assert decoded == zeros

    def test_all_ones_payload(self) -> None:
        """Payload of all 0xFF bytes roundtrips correctly."""
        ones = b"\xff" * 1000
        encoded = encode_request(ones)
        decoded = decode_request(encoded)
        assert decoded == ones


class TestSnappyFramingEdgeCases:
    """
    Tests for snappy framing edge cases.

    These tests verify correct handling of various snappy framing scenarios
    that may occur in real-world network traffic.

    Source: Google Snappy framing_format.txt
        https://github.com/google/snappy/blob/main/framing_format.txt

    Key constraints from spec:
        - Maximum uncompressed chunk size: 64 KiB (65536 bytes)
        - Stream identifier must be present at start
        - CRC32C checksums cover uncompressed data
    """

    def test_minimum_valid_request(self) -> None:
        """Smallest possible valid request is handled."""
        # Empty SSZ data
        smallest = encode_request(b"")
        decoded = decode_request(smallest)
        assert decoded == b""

    def test_single_byte_payload(self) -> None:
        """Single-byte payload roundtrips correctly."""
        for byte_value in [0x00, 0x7F, 0x80, 0xFF]:
            ssz_data = bytes([byte_value])
            encoded = encode_request(ssz_data)
            decoded = decode_request(encoded)
            assert decoded == ssz_data

    def test_chunk_boundary_payload(self) -> None:
        """Payload at snappy chunk boundary (64 KiB) is handled."""
        # Snappy framing uses 64 KiB chunks
        chunk_size = 65536

        # Test at chunk boundary
        at_boundary = b"A" * chunk_size
        encoded = encode_request(at_boundary)
        decoded = decode_request(encoded)
        assert decoded == at_boundary

        # Test just over chunk boundary (requires 2 chunks)
        over_boundary = b"B" * (chunk_size + 1)
        encoded = encode_request(over_boundary)
        decoded = decode_request(encoded)
        assert decoded == over_boundary

    def test_multiple_chunk_payload(self) -> None:
        """Payload spanning multiple snappy chunks is handled."""
        # 3.5 chunks worth of data
        multi_chunk = b"C" * (65536 * 3 + 32768)
        encoded = encode_request(multi_chunk)
        decoded = decode_request(encoded)
        assert decoded == multi_chunk

    def test_highly_compressible_data(self) -> None:
        """Highly compressible data (repeated bytes) roundtrips correctly."""
        # This should compress very well due to Snappy's copy operations
        compressible = b"ABCD" * 25000  # 100 KB of repeated pattern
        encoded = encode_request(compressible)
        decoded = decode_request(encoded)
        assert decoded == compressible

        # Verify compression actually reduced size
        assert len(encoded) < len(compressible)

    def test_incompressible_data(self) -> None:
        """Incompressible (random-like) data roundtrips correctly."""
        # Create pseudo-random data that doesn't compress well
        incompressible = b""
        for i in range(1000):
            incompressible += hashlib.sha256(str(i).encode()).digest()

        encoded = encode_request(incompressible)
        decoded = decode_request(encoded)
        assert decoded == incompressible


class TestErrorMessageMaxSize:
    """Tests for error message size limits per Ethereum P2P spec."""

    def test_error_payload_within_limit(self) -> None:
        """Error payload at exactly MAX_ERROR_MESSAGE_SIZE roundtrips."""
        message = b"A" * MAX_ERROR_MESSAGE_SIZE
        encoded = ResponseCode.INVALID_REQUEST.encode(message)
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.INVALID_REQUEST
        assert decoded == message

    def test_max_error_message_size_is_256(self) -> None:
        """MAX_ERROR_MESSAGE_SIZE matches Ethereum spec (ErrorMessage: List[byte, 256])."""
        assert MAX_ERROR_MESSAGE_SIZE == 256
