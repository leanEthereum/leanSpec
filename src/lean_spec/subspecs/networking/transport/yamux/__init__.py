"""
yamux stream multiplexer for libp2p.

yamux is the preferred stream multiplexer providing:
    - Per-stream flow control (256KB default window)
    - WINDOW_UPDATE for backpressure
    - PING/PONG keepalive
    - GO_AWAY for graceful shutdown

Protocol ID: /yamux/1.0.0

Frame format (12-byte header + body):
    [version:1][type:1][flags:2][stream_id:4][length:4][body:N]

Types:
    0 = DATA
    1 = WINDOW_UPDATE
    2 = PING
    3 = GO_AWAY

Flags:
    SYN = 1  (start stream)
    ACK = 2  (acknowledge stream)
    FIN = 4  (half-close)
    RST = 8  (reset/abort)

Stream ID allocation (DIFFERENT from mplex!):
    - Client (initiator): Odd IDs (1, 3, 5, ...)
    - Server (responder): Even IDs (2, 4, 6, ...)

References:
    - https://github.com/hashicorp/yamux/blob/master/spec.md
    - https://github.com/libp2p/specs/tree/master/yamux
"""

from .frame import (
    YAMUX_HEADER_SIZE,
    YAMUX_INITIAL_WINDOW,
    YAMUX_MAX_FRAME_SIZE,
    YAMUX_PROTOCOL_ID,
    YAMUX_VERSION,
    YamuxError,
    YamuxFlags,
    YamuxFrame,
    YamuxGoAwayCode,
    YamuxType,
)
from .session import (
    BUFFER_SIZE,
    MAX_BUFFER_BYTES,
    MAX_STREAMS,
    YamuxSession,
    YamuxStream,
)

__all__ = [
    # Constants
    "YAMUX_HEADER_SIZE",
    "YAMUX_INITIAL_WINDOW",
    "YAMUX_MAX_FRAME_SIZE",
    "YAMUX_PROTOCOL_ID",
    "YAMUX_VERSION",
    "MAX_STREAMS",
    "MAX_BUFFER_BYTES",
    "BUFFER_SIZE",
    # Enums
    "YamuxType",
    "YamuxFlags",
    "YamuxGoAwayCode",
    # Errors
    "YamuxError",
    # Frame
    "YamuxFrame",
    # Session
    "YamuxSession",
    "YamuxStream",
]
