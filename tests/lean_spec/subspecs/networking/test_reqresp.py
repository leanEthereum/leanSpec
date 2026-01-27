"""Tests for the req/resp codec."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking import ResponseCode
from lean_spec.subspecs.networking.reqresp import (
    CodecError,
    decode_request,
    encode_request,
)
from lean_spec.subspecs.networking.varint import (
    VarintError,
    decode_varint,
    encode_varint,
)


class TestVarintEncoding:
    """Tests for varint (LEB128) encoding/decoding."""

    def test_encode_zero(self) -> None:
        """Zero encodes to a single null byte."""
        assert encode_varint(0) == b"\x00"

    def test_encode_small_values(self) -> None:
        """Values 0-127 encode to a single byte."""
        assert encode_varint(1) == b"\x01"
        assert encode_varint(127) == b"\x7f"

    def test_encode_two_byte_values(self) -> None:
        """Values 128-16383 encode to two bytes."""
        assert encode_varint(128) == b"\x80\x01"
        assert encode_varint(300) == b"\xac\x02"

    def test_encode_large_values(self) -> None:
        """Large values encode and decode correctly."""
        test_values = [65536, 2**20, 2**24, 2**32 - 1, 2**63]
        for value in test_values:
            encoded = encode_varint(value)
            decoded, consumed = decode_varint(encoded)
            assert decoded == value
            assert consumed == len(encoded)

    def test_decode_with_offset(self) -> None:
        """Decoding at an offset works correctly."""
        data = b"prefix\xac\x02suffix"
        value, consumed = decode_varint(data, offset=6)
        assert value == 300
        assert consumed == 2

    def test_encode_negative_raises(self) -> None:
        """Negative values raise ValueError."""
        with pytest.raises(ValueError, match="non-negative"):
            encode_varint(-1)

    def test_decode_truncated_raises(self) -> None:
        """Truncated varints raise VarintError."""
        with pytest.raises(VarintError, match="Truncated"):
            decode_varint(b"\x80")  # Missing continuation byte

    def test_roundtrip(self) -> None:
        """Encoding then decoding returns the original value."""
        for value in [0, 1, 127, 128, 255, 16383, 16384, 65535, 2**20]:
            encoded = encode_varint(value)
            decoded, _ = decode_varint(encoded)
            assert decoded == value


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
        with pytest.raises(CodecError, match="Empty request"):
            decode_request(b"")

    def test_decode_invalid_varint_raises(self) -> None:
        """Invalid varint raises CodecError."""
        with pytest.raises(CodecError, match="length"):
            decode_request(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")

    def test_length_mismatch_raises(self) -> None:
        """Mismatched declared length raises CodecError."""
        # Encode valid request, then modify the length prefix
        encoded = bytearray(encode_request(b"test"))
        encoded[0] = 0x10  # Change declared length to 16
        with pytest.raises(CodecError, match="mismatch"):
            decode_request(bytes(encoded))


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
        error_msg = b"Block not found"
        encoded = ResponseCode.RESOURCE_UNAVAILABLE.encode(error_msg)
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.RESOURCE_UNAVAILABLE
        assert decoded == error_msg

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
        with pytest.raises(CodecError, match="Empty response"):
            ResponseCode.decode(b"")

    def test_decode_too_short_raises(self) -> None:
        """Too-short input raises CodecError."""
        with pytest.raises(CodecError, match="too short"):
            ResponseCode.decode(b"\x00")

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
        """Request wire format matches spec: [varint_len][snappy_payload]."""
        ssz_data = b"test"
        encoded = encode_request(ssz_data)

        # First bytes should be varint of uncompressed length
        length, varint_size = decode_varint(encoded)
        assert length == len(ssz_data)

        # Rest should be valid snappy framed data
        snappy_data = encoded[varint_size:]
        assert snappy_data.startswith(b"\xff\x06\x00\x00sNaPpY")

    def test_response_wire_format(self) -> None:
        """Response wire format matches spec: [code][varint_len][snappy_payload]."""
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
