"""
yamux frame encoding and decoding.

yamux uses fixed 12-byte headers (big-endian), unlike mplex's variable-length varints.
This makes parsing simpler and more predictable at the cost of slightly more bytes
for small stream IDs.

Frame format:
    [version:1][type:1][flags:2][stream_id:4][length:4][body:N]

    version: Always 0 (protocol version)
    type: Message type (0=DATA, 1=WINDOW_UPDATE, 2=PING, 3=GO_AWAY)
    flags: Bitfield for stream lifecycle (SYN, ACK, FIN, RST)
    stream_id: 32-bit stream identifier (0 for session-level messages)
    length: Payload size for DATA, window delta for WINDOW_UPDATE

Why fixed headers instead of varints like mplex?
    - Predictable parsing: know header size before reading
    - Simpler implementation: no varint state machine
    - Fast path: single struct.unpack call
    - Trade-off: 12 bytes vs ~3-5 bytes for small varints

Stream ID allocation (DIFFERENT from mplex!):
    - Client (initiator): Odd IDs (1, 3, 5, ...)
    - Server (responder): Even IDs (2, 4, 6, ...)
    - Session-level messages: ID = 0

References:
    - https://github.com/hashicorp/yamux/blob/master/spec.md
    - https://github.com/libp2p/specs/tree/master/yamux
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Final

YAMUX_VERSION: Final[int] = 0
"""yamux protocol version (always 0)."""

YAMUX_HEADER_SIZE: Final[int] = 12
"""Fixed header size in bytes."""

YAMUX_PROTOCOL_ID: Final[str] = "/yamux/1.0.0"
"""Protocol identifier for multistream-select negotiation."""

YAMUX_INITIAL_WINDOW: Final[int] = 256 * 1024  # 256KB
"""Initial receive window size per stream (matching ream/zeam defaults)."""

YAMUX_MAX_STREAM_WINDOW: Final[int] = 16 * 1024 * 1024  # 16MB
"""Maximum window size to prevent unbounded growth."""

YAMUX_MAX_FRAME_SIZE: Final[int] = 1 * 1024 * 1024  # 1MB
"""
Maximum frame payload size.

Security: Without this limit, a malicious peer could claim a massive length in the
header, causing us to allocate gigabytes of memory. This limit caps allocations
at a reasonable size while still allowing large data transfers (in multiple frames).
"""


class YamuxType(IntEnum):
    """
    yamux message types.

    Unlike mplex which has 7 message types (with separate initiator/receiver variants),
    yamux uses just 4 types and flags to indicate direction/state.

    DATA and WINDOW_UPDATE operate on streams (stream_id > 0).
    PING and GO_AWAY operate at session level (stream_id = 0).
    """

    DATA = 0
    """Stream data payload. Length field is payload size."""

    WINDOW_UPDATE = 1
    """Increase receive window. Length field is window delta (not payload size)."""

    PING = 2
    """Session keepalive. Echo back with ACK flag if received without ACK."""

    GO_AWAY = 3
    """Graceful session shutdown. Length field is error code."""


class YamuxFlags(IntFlag):
    """
    yamux header flags.

    Flags control stream lifecycle. Multiple flags can be combined:
    - SYN alone: Open new stream
    - ACK alone: Acknowledge stream opening
    - SYN|ACK: Unlikely but valid
    - FIN: Half-close (we're done sending)
    - RST: Abort stream immediately

    For PING frames:
    - No flags: Request (peer should echo back with ACK)
    - ACK: Response to a ping request
    """

    NONE = 0
    """No flags set."""

    SYN = 0x01
    """Synchronize: Start a new stream."""

    ACK = 0x02
    """Acknowledge: Confirm stream opening or respond to PING."""

    FIN = 0x04
    """Finish: Half-close the stream (no more data from this side)."""

    RST = 0x08
    """Reset: Abort the stream immediately."""


class YamuxGoAwayCode(IntEnum):
    """
    GO_AWAY error codes.

    Sent in the length field of GO_AWAY frames to indicate shutdown reason.
    """

    NORMAL = 0
    """Normal shutdown, no error."""

    PROTOCOL_ERROR = 1
    """Protocol error detected."""

    INTERNAL_ERROR = 2
    """Internal error (e.g., resource exhaustion)."""


class YamuxError(Exception):
    """Raised when yamux framing fails."""


@dataclass(frozen=True, slots=True)
class YamuxFrame:
    """
    A single yamux frame.

    yamux frames have a fixed structure making them easy to parse:
    - 12-byte header: version, type, flags, stream_id, length
    - Variable-length body (only for DATA frames)

    The frame is immutable (frozen=True) because frames represent wire data
    that shouldn't be modified after construction.

    Attributes:
        frame_type: Type of message (DATA, WINDOW_UPDATE, PING, GO_AWAY)
        flags: Lifecycle flags (SYN, ACK, FIN, RST)
        stream_id: Stream identifier (0 for session-level messages)
        length: Payload size or window delta depending on frame type
        data: Frame payload (empty except for DATA frames)
    """

    frame_type: YamuxType
    """Message type."""

    flags: YamuxFlags
    """Lifecycle flags."""

    stream_id: int
    """Stream identifier (0 for session-level messages like PING/GO_AWAY)."""

    length: int
    """Payload size (DATA) or window delta (WINDOW_UPDATE) or error code (GO_AWAY)."""

    data: bytes = b""
    """Frame payload (only present in DATA frames)."""

    def encode(self) -> bytes:
        """
        Encode frame to wire format.

        Format: [version:1][type:1][flags:2][stream_id:4][length:4][data:N]
        All multi-byte fields are big-endian.

        Returns:
            Encoded frame bytes (12-byte header + data)
        """
        # Pack header fields in big-endian order.
        #
        # struct format ">BBHII" means:
        #   > = big-endian
        #   B = unsigned char (1 byte) for version
        #   B = unsigned char (1 byte) for type
        #   H = unsigned short (2 bytes) for flags
        #   I = unsigned int (4 bytes) for stream_id
        #   I = unsigned int (4 bytes) for length
        header = struct.pack(
            ">BBHII",
            YAMUX_VERSION,
            self.frame_type,
            self.flags,
            self.stream_id,
            self.length,
        )
        return header + self.data

    @classmethod
    def decode(cls, header: bytes, data: bytes = b"") -> YamuxFrame:
        """
        Decode frame from header bytes and optional data.

        Args:
            header: 12-byte header
            data: Payload bytes (for DATA frames)

        Returns:
            Decoded YamuxFrame

        Raises:
            YamuxError: If header is malformed, version unsupported, or frame too large
        """
        if len(header) != YAMUX_HEADER_SIZE:
            raise YamuxError(f"Invalid header size: {len(header)} (expected {YAMUX_HEADER_SIZE})")

        # Unpack the fixed header.
        #
        # This is the inverse of encode(): extract version, type, flags,
        # stream_id, and length from the 12-byte header.
        version, frame_type, flags, stream_id, length = struct.unpack(">BBHII", header)

        if version != YAMUX_VERSION:
            raise YamuxError(f"Unsupported yamux version: {version}")

        # Security: Validate frame size before accepting.
        #
        # For DATA frames, length is the payload size. Without this check, a malicious
        # peer could send a header claiming 4GB of data, causing memory exhaustion when
        # we try to allocate/process it. This check catches the issue early.
        if frame_type == YamuxType.DATA and length > YAMUX_MAX_FRAME_SIZE:
            raise YamuxError(
                f"Frame payload too large: {length} bytes (max {YAMUX_MAX_FRAME_SIZE})"
            )

        return cls(
            frame_type=YamuxType(frame_type),
            flags=YamuxFlags(flags),
            stream_id=stream_id,
            length=length,
            data=data,
        )

    def has_flag(self, flag: YamuxFlags) -> bool:
        """Check if a specific flag is set."""
        return bool(self.flags & flag)


def data_frame(stream_id: int, data: bytes, flags: YamuxFlags = YamuxFlags.NONE) -> YamuxFrame:
    """
    Create a DATA frame.

    DATA frames carry stream payload. The length field equals the payload size.
    Flags can be combined with data (e.g., FIN to send last data and half-close).

    Args:
        stream_id: Target stream (must be > 0)
        data: Payload data
        flags: Optional flags (typically NONE, FIN, or RST)

    Returns:
        DATA frame ready to encode and send
    """
    return YamuxFrame(
        frame_type=YamuxType.DATA,
        flags=flags,
        stream_id=stream_id,
        length=len(data),
        data=data,
    )


def window_update_frame(stream_id: int, delta: int) -> YamuxFrame:
    """
    Create a WINDOW_UPDATE frame.

    Window updates tell the peer we've consumed data and can accept more.
    The delta is added to the peer's send window for this stream.

    Args:
        stream_id: Target stream (must be > 0)
        delta: Window size increase in bytes

    Returns:
        WINDOW_UPDATE frame ready to encode and send

    Flow control prevents fast senders from overwhelming slow receivers:
    1. Each stream starts with YAMUX_INITIAL_WINDOW (256KB) receive capacity.
    2. As we receive data, the sender's view of our window decreases.
    3. When we process received data, we send WINDOW_UPDATE to restore capacity.
    4. If the sender exhausts our window, it must pause until we update.
    """
    return YamuxFrame(
        frame_type=YamuxType.WINDOW_UPDATE,
        flags=YamuxFlags.NONE,
        stream_id=stream_id,
        length=delta,
    )


def ping_frame(opaque: int = 0, is_response: bool = False) -> YamuxFrame:
    """
    Create a PING frame.

    PING frames verify the connection is still alive. The opaque value
    should be echoed back in the response.

    Args:
        opaque: Opaque value to include (echoed in response)
        is_response: True for ping response (ACK flag), False for request

    Returns:
        PING frame ready to encode and send

    Keepalive flow:
    1. Send PING with no ACK flag and an opaque value.
    2. Peer receives PING, echoes back with ACK flag and same opaque.
    3. If no response within timeout, connection is considered dead.
    """
    flags = YamuxFlags.ACK if is_response else YamuxFlags.NONE
    return YamuxFrame(
        frame_type=YamuxType.PING,
        flags=flags,
        stream_id=0,  # Session-level, always 0
        length=opaque,
    )


def go_away_frame(code: YamuxGoAwayCode = YamuxGoAwayCode.NORMAL) -> YamuxFrame:
    """
    Create a GO_AWAY frame.

    GO_AWAY initiates graceful session shutdown. After sending:
    - No new streams should be opened.
    - Existing streams can complete.
    - Session closes after all streams finish.

    Args:
        code: Shutdown reason code

    Returns:
        GO_AWAY frame ready to encode and send

    Unlike an abrupt connection close, GO_AWAY allows in-flight requests
    to complete. This is important for request-response protocols where
    a response may be in transit when shutdown is requested.
    """
    return YamuxFrame(
        frame_type=YamuxType.GO_AWAY,
        flags=YamuxFlags.NONE,
        stream_id=0,  # Session-level, always 0
        length=code,
    )


def syn_frame(stream_id: int) -> YamuxFrame:
    """
    Create a SYN frame to open a new stream.

    SYN is sent as a WINDOW_UPDATE with the SYN flag and initial window.
    This tells the peer:
    1. A new stream is being opened.
    2. The initial receive window for this stream.

    Args:
        stream_id: ID for the new stream (odd for client, even for server)

    Returns:
        SYN frame (WINDOW_UPDATE with SYN flag)
    """
    return YamuxFrame(
        frame_type=YamuxType.WINDOW_UPDATE,
        flags=YamuxFlags.SYN,
        stream_id=stream_id,
        length=YAMUX_INITIAL_WINDOW,
    )


def ack_frame(stream_id: int) -> YamuxFrame:
    """
    Create an ACK frame to acknowledge a new stream.

    ACK is the response to SYN. It confirms stream creation and
    provides our initial receive window.

    Args:
        stream_id: ID of the stream being acknowledged

    Returns:
        ACK frame (WINDOW_UPDATE with ACK flag)
    """
    return YamuxFrame(
        frame_type=YamuxType.WINDOW_UPDATE,
        flags=YamuxFlags.ACK,
        stream_id=stream_id,
        length=YAMUX_INITIAL_WINDOW,
    )


def fin_frame(stream_id: int) -> YamuxFrame:
    """
    Create a FIN frame to half-close a stream.

    FIN signals "I'm done sending data." The other direction remains open
    until the peer also sends FIN.

    Args:
        stream_id: Stream to half-close

    Returns:
        FIN frame (DATA with FIN flag and empty payload)
    """
    return YamuxFrame(
        frame_type=YamuxType.DATA,
        flags=YamuxFlags.FIN,
        stream_id=stream_id,
        length=0,
    )


def rst_frame(stream_id: int) -> YamuxFrame:
    """
    Create a RST frame to abort a stream.

    RST immediately terminates the stream in both directions.
    Any buffered data should be discarded.

    Args:
        stream_id: Stream to abort

    Returns:
        RST frame (DATA with RST flag)
    """
    return YamuxFrame(
        frame_type=YamuxType.DATA,
        flags=YamuxFlags.RST,
        stream_id=stream_id,
        length=0,
    )
