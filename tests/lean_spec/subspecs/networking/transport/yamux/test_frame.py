"""
Tests for yamux frame encoding and decoding.

yamux uses fixed 12-byte headers (big-endian):
    [version:1][type:1][flags:2][stream_id:4][length:4]

Test vectors based on yamux spec:
    https://github.com/hashicorp/yamux/blob/master/spec.md
"""

from __future__ import annotations

import struct

import pytest

from lean_spec.subspecs.networking.transport.yamux.frame import (
    YAMUX_HEADER_SIZE,
    YAMUX_INITIAL_WINDOW,
    YAMUX_PROTOCOL_ID,
    YAMUX_VERSION,
    YamuxError,
    YamuxFlags,
    YamuxFrame,
    YamuxGoAwayCode,
    YamuxType,
    ack_frame,
    data_frame,
    fin_frame,
    go_away_frame,
    ping_frame,
    rst_frame,
    syn_frame,
    window_update_frame,
)


class TestYamuxType:
    """Tests for message type enumeration."""

    def test_type_values(self) -> None:
        """Message types have correct values per spec."""
        assert YamuxType.DATA == 0
        assert YamuxType.WINDOW_UPDATE == 1
        assert YamuxType.PING == 2
        assert YamuxType.GO_AWAY == 3

    def test_type_from_int(self) -> None:
        """Can create type from integer."""
        assert YamuxType(0) == YamuxType.DATA
        assert YamuxType(1) == YamuxType.WINDOW_UPDATE
        assert YamuxType(2) == YamuxType.PING
        assert YamuxType(3) == YamuxType.GO_AWAY

    def test_invalid_type(self) -> None:
        """Invalid type raises ValueError."""
        with pytest.raises(ValueError):
            YamuxType(4)

        with pytest.raises(ValueError):
            YamuxType(255)


class TestYamuxFlags:
    """Tests for flag bitfield."""

    def test_flag_values(self) -> None:
        """Flags have correct values per spec."""
        assert YamuxFlags.NONE == 0
        assert YamuxFlags.SYN == 0x01
        assert YamuxFlags.ACK == 0x02
        assert YamuxFlags.FIN == 0x04
        assert YamuxFlags.RST == 0x08

    def test_flag_combination(self) -> None:
        """Flags can be combined."""
        combined = YamuxFlags.SYN | YamuxFlags.ACK
        assert combined == 0x03

        assert bool(combined & YamuxFlags.SYN)
        assert bool(combined & YamuxFlags.ACK)
        assert not bool(combined & YamuxFlags.FIN)
        assert not bool(combined & YamuxFlags.RST)

    def test_all_flags(self) -> None:
        """All flags combined."""
        all_flags = YamuxFlags.SYN | YamuxFlags.ACK | YamuxFlags.FIN | YamuxFlags.RST
        assert all_flags == 0x0F


class TestYamuxGoAwayCode:
    """Tests for GO_AWAY error codes."""

    def test_code_values(self) -> None:
        """GO_AWAY codes have correct values."""
        assert YamuxGoAwayCode.NORMAL == 0
        assert YamuxGoAwayCode.PROTOCOL_ERROR == 1
        assert YamuxGoAwayCode.INTERNAL_ERROR == 2


class TestYamuxFrameEncoding:
    """Tests for YamuxFrame encoding."""

    def test_encode_data_frame(self) -> None:
        """Encode DATA frame."""
        frame = YamuxFrame(
            frame_type=YamuxType.DATA,
            flags=YamuxFlags.NONE,
            stream_id=1,
            length=5,
            data=b"hello",
        )
        encoded = frame.encode()

        # 12-byte header + 5-byte body
        assert len(encoded) == 17

        # Parse header
        version, ftype, flags, stream_id, length = struct.unpack(">BBHII", encoded[:12])
        assert version == 0
        assert ftype == 0  # DATA
        assert flags == 0
        assert stream_id == 1
        assert length == 5
        assert encoded[12:] == b"hello"

    def test_encode_data_frame_with_fin(self) -> None:
        """Encode DATA frame with FIN flag."""
        frame = YamuxFrame(
            frame_type=YamuxType.DATA,
            flags=YamuxFlags.FIN,
            stream_id=3,
            length=0,
        )
        encoded = frame.encode()

        assert len(encoded) == 12  # Header only, no body

        version, ftype, flags, stream_id, length = struct.unpack(">BBHII", encoded)
        assert version == 0
        assert ftype == 0  # DATA
        assert flags == 0x04  # FIN
        assert stream_id == 3
        assert length == 0

    def test_encode_window_update(self) -> None:
        """Encode WINDOW_UPDATE frame."""
        frame = YamuxFrame(
            frame_type=YamuxType.WINDOW_UPDATE,
            flags=YamuxFlags.NONE,
            stream_id=5,
            length=65536,  # 64KB window increase
        )
        encoded = frame.encode()

        assert len(encoded) == 12

        version, ftype, flags, stream_id, length = struct.unpack(">BBHII", encoded)
        assert version == 0
        assert ftype == 1  # WINDOW_UPDATE
        assert flags == 0
        assert stream_id == 5
        assert length == 65536

    def test_encode_syn_frame(self) -> None:
        """Encode WINDOW_UPDATE with SYN flag (new stream)."""
        frame = YamuxFrame(
            frame_type=YamuxType.WINDOW_UPDATE,
            flags=YamuxFlags.SYN,
            stream_id=7,
            length=YAMUX_INITIAL_WINDOW,
        )
        encoded = frame.encode()

        version, ftype, flags, stream_id, length = struct.unpack(">BBHII", encoded)
        assert version == 0
        assert ftype == 1  # WINDOW_UPDATE
        assert flags == 0x01  # SYN
        assert stream_id == 7
        assert length == 256 * 1024

    def test_encode_ping_request(self) -> None:
        """Encode PING request (no ACK)."""
        frame = YamuxFrame(
            frame_type=YamuxType.PING,
            flags=YamuxFlags.NONE,
            stream_id=0,  # Session-level
            length=12345,  # Opaque value
        )
        encoded = frame.encode()

        version, ftype, flags, stream_id, length = struct.unpack(">BBHII", encoded)
        assert version == 0
        assert ftype == 2  # PING
        assert flags == 0
        assert stream_id == 0
        assert length == 12345

    def test_encode_ping_response(self) -> None:
        """Encode PING response (with ACK)."""
        frame = YamuxFrame(
            frame_type=YamuxType.PING,
            flags=YamuxFlags.ACK,
            stream_id=0,
            length=12345,  # Echo back same opaque
        )
        encoded = frame.encode()

        version, ftype, flags, stream_id, length = struct.unpack(">BBHII", encoded)
        assert ftype == 2  # PING
        assert flags == 0x02  # ACK
        assert length == 12345

    def test_encode_go_away(self) -> None:
        """Encode GO_AWAY frame."""
        frame = YamuxFrame(
            frame_type=YamuxType.GO_AWAY,
            flags=YamuxFlags.NONE,
            stream_id=0,
            length=YamuxGoAwayCode.NORMAL,
        )
        encoded = frame.encode()

        version, ftype, flags, stream_id, length = struct.unpack(">BBHII", encoded)
        assert version == 0
        assert ftype == 3  # GO_AWAY
        assert stream_id == 0
        assert length == 0  # NORMAL

    def test_encode_go_away_error(self) -> None:
        """Encode GO_AWAY with error code."""
        frame = YamuxFrame(
            frame_type=YamuxType.GO_AWAY,
            flags=YamuxFlags.NONE,
            stream_id=0,
            length=YamuxGoAwayCode.PROTOCOL_ERROR,
        )
        encoded = frame.encode()

        version, ftype, flags, stream_id, length = struct.unpack(">BBHII", encoded)
        assert length == 1  # PROTOCOL_ERROR


class TestYamuxFrameDecoding:
    """Tests for YamuxFrame decoding."""

    def test_decode_data_frame(self) -> None:
        """Decode DATA frame."""
        header = struct.pack(">BBHII", 0, 0, 0, 1, 5)
        data = b"hello"

        frame = YamuxFrame.decode(header, data)

        assert frame.frame_type == YamuxType.DATA
        assert frame.flags == YamuxFlags.NONE
        assert frame.stream_id == 1
        assert frame.length == 5
        assert frame.data == b"hello"

    def test_decode_window_update(self) -> None:
        """Decode WINDOW_UPDATE frame."""
        header = struct.pack(">BBHII", 0, 1, 0, 5, 262144)

        frame = YamuxFrame.decode(header)

        assert frame.frame_type == YamuxType.WINDOW_UPDATE
        assert frame.stream_id == 5
        assert frame.length == 262144

    def test_decode_with_syn_flag(self) -> None:
        """Decode frame with SYN flag."""
        header = struct.pack(">BBHII", 0, 1, 0x0001, 3, YAMUX_INITIAL_WINDOW)

        frame = YamuxFrame.decode(header)

        assert frame.has_flag(YamuxFlags.SYN)
        assert not frame.has_flag(YamuxFlags.ACK)
        assert frame.stream_id == 3

    def test_decode_with_ack_flag(self) -> None:
        """Decode frame with ACK flag."""
        header = struct.pack(">BBHII", 0, 1, 0x0002, 3, YAMUX_INITIAL_WINDOW)

        frame = YamuxFrame.decode(header)

        assert frame.has_flag(YamuxFlags.ACK)
        assert not frame.has_flag(YamuxFlags.SYN)

    def test_decode_with_fin_flag(self) -> None:
        """Decode frame with FIN flag."""
        header = struct.pack(">BBHII", 0, 0, 0x0004, 5, 0)

        frame = YamuxFrame.decode(header)

        assert frame.has_flag(YamuxFlags.FIN)
        assert not frame.has_flag(YamuxFlags.RST)

    def test_decode_with_rst_flag(self) -> None:
        """Decode frame with RST flag."""
        header = struct.pack(">BBHII", 0, 0, 0x0008, 5, 0)

        frame = YamuxFrame.decode(header)

        assert frame.has_flag(YamuxFlags.RST)

    def test_decode_ping(self) -> None:
        """Decode PING frame."""
        header = struct.pack(">BBHII", 0, 2, 0, 0, 42)

        frame = YamuxFrame.decode(header)

        assert frame.frame_type == YamuxType.PING
        assert frame.stream_id == 0
        assert frame.length == 42  # opaque value

    def test_decode_go_away(self) -> None:
        """Decode GO_AWAY frame."""
        header = struct.pack(">BBHII", 0, 3, 0, 0, 1)  # PROTOCOL_ERROR

        frame = YamuxFrame.decode(header)

        assert frame.frame_type == YamuxType.GO_AWAY
        assert frame.stream_id == 0
        assert frame.length == 1

    def test_decode_invalid_header_size(self) -> None:
        """Decode with wrong header size raises error."""
        short_header = b"\x00\x00\x00\x00"  # Too short

        with pytest.raises(YamuxError, match="Invalid header size"):
            YamuxFrame.decode(short_header)

    def test_decode_invalid_version(self) -> None:
        """Decode with unsupported version raises error."""
        header = struct.pack(">BBHII", 1, 0, 0, 0, 0)  # Version 1

        with pytest.raises(YamuxError, match="Unsupported yamux version"):
            YamuxFrame.decode(header)


class TestFrameRoundtrip:
    """Tests for encode/decode roundtrip."""

    def test_roundtrip_data(self) -> None:
        """Roundtrip DATA frame."""
        original = YamuxFrame(
            frame_type=YamuxType.DATA,
            flags=YamuxFlags.NONE,
            stream_id=42,
            length=11,
            data=b"test data!",
        )

        encoded = original.encode()
        decoded = YamuxFrame.decode(encoded[:12], encoded[12:])

        assert decoded.frame_type == original.frame_type
        assert decoded.flags == original.flags
        assert decoded.stream_id == original.stream_id
        assert decoded.length == original.length
        # Note: original.data has 10 bytes but length=11, using exact data
        assert decoded.data == b"test data!"

    def test_roundtrip_window_update(self) -> None:
        """Roundtrip WINDOW_UPDATE frame."""
        original = YamuxFrame(
            frame_type=YamuxType.WINDOW_UPDATE,
            flags=YamuxFlags.SYN,
            stream_id=100,
            length=YAMUX_INITIAL_WINDOW,
        )

        encoded = original.encode()
        decoded = YamuxFrame.decode(encoded)

        assert decoded.frame_type == original.frame_type
        assert decoded.flags == original.flags
        assert decoded.stream_id == original.stream_id
        assert decoded.length == original.length

    def test_roundtrip_ping(self) -> None:
        """Roundtrip PING frame."""
        original = YamuxFrame(
            frame_type=YamuxType.PING,
            flags=YamuxFlags.ACK,
            stream_id=0,
            length=0xDEADBEEF,
        )

        encoded = original.encode()
        decoded = YamuxFrame.decode(encoded)

        assert decoded.frame_type == original.frame_type
        assert decoded.flags == original.flags
        assert decoded.stream_id == original.stream_id
        assert decoded.length == original.length


class TestFlagMethods:
    """Tests for flag checking methods."""

    def test_has_flag(self) -> None:
        """has_flag checks specific flags."""
        frame = YamuxFrame(
            frame_type=YamuxType.DATA,
            flags=YamuxFlags.SYN | YamuxFlags.FIN,
            stream_id=1,
            length=0,
        )

        assert frame.has_flag(YamuxFlags.SYN)
        assert frame.has_flag(YamuxFlags.FIN)
        assert not frame.has_flag(YamuxFlags.ACK)
        assert not frame.has_flag(YamuxFlags.RST)


class TestFrameFactoryFunctions:
    """Tests for frame factory functions."""

    def test_data_frame(self) -> None:
        """data_frame creates DATA frame."""
        frame = data_frame(stream_id=5, data=b"test payload")

        assert frame.frame_type == YamuxType.DATA
        assert frame.flags == YamuxFlags.NONE
        assert frame.stream_id == 5
        assert frame.length == 12
        assert frame.data == b"test payload"

    def test_data_frame_with_flags(self) -> None:
        """data_frame with flags."""
        frame = data_frame(stream_id=5, data=b"last", flags=YamuxFlags.FIN)

        assert frame.flags == YamuxFlags.FIN
        assert frame.data == b"last"

    def test_window_update_frame(self) -> None:
        """window_update_frame creates WINDOW_UPDATE."""
        frame = window_update_frame(stream_id=3, delta=65536)

        assert frame.frame_type == YamuxType.WINDOW_UPDATE
        assert frame.flags == YamuxFlags.NONE
        assert frame.stream_id == 3
        assert frame.length == 65536

    def test_ping_frame_request(self) -> None:
        """ping_frame creates PING request."""
        frame = ping_frame(opaque=12345)

        assert frame.frame_type == YamuxType.PING
        assert frame.flags == YamuxFlags.NONE
        assert frame.stream_id == 0
        assert frame.length == 12345

    def test_ping_frame_response(self) -> None:
        """ping_frame creates PING response with ACK."""
        frame = ping_frame(opaque=12345, is_response=True)

        assert frame.frame_type == YamuxType.PING
        assert frame.flags == YamuxFlags.ACK
        assert frame.stream_id == 0
        assert frame.length == 12345

    def test_go_away_frame_normal(self) -> None:
        """go_away_frame creates GO_AWAY with NORMAL code."""
        frame = go_away_frame()

        assert frame.frame_type == YamuxType.GO_AWAY
        assert frame.stream_id == 0
        assert frame.length == YamuxGoAwayCode.NORMAL

    def test_go_away_frame_error(self) -> None:
        """go_away_frame creates GO_AWAY with error code."""
        frame = go_away_frame(code=YamuxGoAwayCode.PROTOCOL_ERROR)

        assert frame.length == YamuxGoAwayCode.PROTOCOL_ERROR

    def test_syn_frame(self) -> None:
        """syn_frame creates SYN (new stream)."""
        frame = syn_frame(stream_id=1)

        assert frame.frame_type == YamuxType.WINDOW_UPDATE
        assert frame.flags == YamuxFlags.SYN
        assert frame.stream_id == 1
        assert frame.length == YAMUX_INITIAL_WINDOW

    def test_ack_frame(self) -> None:
        """ack_frame creates ACK."""
        frame = ack_frame(stream_id=2)

        assert frame.frame_type == YamuxType.WINDOW_UPDATE
        assert frame.flags == YamuxFlags.ACK
        assert frame.stream_id == 2
        assert frame.length == YAMUX_INITIAL_WINDOW

    def test_fin_frame(self) -> None:
        """fin_frame creates FIN (half-close)."""
        frame = fin_frame(stream_id=3)

        assert frame.frame_type == YamuxType.DATA
        assert frame.flags == YamuxFlags.FIN
        assert frame.stream_id == 3
        assert frame.length == 0

    def test_rst_frame(self) -> None:
        """rst_frame creates RST (abort)."""
        frame = rst_frame(stream_id=4)

        assert frame.frame_type == YamuxType.DATA
        assert frame.flags == YamuxFlags.RST
        assert frame.stream_id == 4
        assert frame.length == 0


class TestConstants:
    """Tests for protocol constants."""

    def test_protocol_id(self) -> None:
        """Protocol ID matches spec."""
        assert YAMUX_PROTOCOL_ID == "/yamux/1.0.0"

    def test_header_size(self) -> None:
        """Header size is 12 bytes."""
        assert YAMUX_HEADER_SIZE == 12

    def test_version(self) -> None:
        """Version is 0."""
        assert YAMUX_VERSION == 0

    def test_initial_window(self) -> None:
        """Initial window is 256KB."""
        assert YAMUX_INITIAL_WINDOW == 256 * 1024
        assert YAMUX_INITIAL_WINDOW == 262144


class TestBigEndianEncoding:
    """Tests verifying big-endian byte order."""

    def test_stream_id_big_endian(self) -> None:
        """Stream ID uses big-endian encoding."""
        frame = YamuxFrame(
            frame_type=YamuxType.DATA,
            flags=YamuxFlags.NONE,
            stream_id=0x12345678,
            length=0,
        )
        encoded = frame.encode()

        # Stream ID is at bytes 4-7 (0-indexed)
        assert encoded[4:8] == b"\x12\x34\x56\x78"

    def test_length_big_endian(self) -> None:
        """Length uses big-endian encoding."""
        frame = YamuxFrame(
            frame_type=YamuxType.DATA,
            flags=YamuxFlags.NONE,
            stream_id=0,
            length=0xAABBCCDD,
            data=b"",
        )
        encoded = frame.encode()

        # Length is at bytes 8-11 (0-indexed)
        assert encoded[8:12] == b"\xaa\xbb\xcc\xdd"

    def test_flags_big_endian(self) -> None:
        """Flags uses big-endian encoding."""
        frame = YamuxFrame(
            frame_type=YamuxType.DATA,
            flags=YamuxFlags(0x0F0F),  # All flags set in a pattern
            stream_id=0,
            length=0,
        )
        encoded = frame.encode()

        # Flags is at bytes 2-3 (0-indexed)
        assert encoded[2:4] == b"\x0f\x0f"
