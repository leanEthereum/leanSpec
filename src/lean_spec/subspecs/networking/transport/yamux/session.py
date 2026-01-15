"""
yamux session and stream management with flow control.

A yamux session multiplexes streams over a single Noise connection, with per-stream
flow control to prevent fast senders from overwhelming slow receivers.

Key differences from mplex:
    - Flow control: Each stream has a receive window (default 256KB).
    - WINDOW_UPDATE: Must send updates as data is consumed.
    - PING/PONG: Session-level keepalive.
    - GO_AWAY: Graceful shutdown allowing in-flight requests to complete.
    - Stream IDs: Client=odd (1,3,5), Server=even (2,4,6) - OPPOSITE of mplex!

Stream ID allocation (CRITICAL - opposite of mplex!):
    - Client (dialer/initiator): Odd IDs (1, 3, 5, 7, ...)
    - Server (listener/responder): Even IDs (2, 4, 6, 8, ...)

Flow control prevents head-of-line blocking that plagues mplex:
    1. Each stream has a receive window (how much we can accept).
    2. As sender transmits data, receiver's window decreases.
    3. Receiver sends WINDOW_UPDATE after consuming data.
    4. If window exhausted, sender must wait for update.

Configuration (matching ream/zeam):
    - initial_window: 256KB per stream
    - max_streams: 1024 concurrent streams

References:
    - https://github.com/hashicorp/yamux/blob/master/spec.md
    - https://github.com/libp2p/specs/tree/master/yamux
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Final, Protocol

from .frame import (
    YAMUX_HEADER_SIZE,
    YAMUX_INITIAL_WINDOW,
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


class NoiseSessionProtocol(Protocol):
    """Protocol for Noise session interface used by yamux."""

    async def read(self) -> bytes:
        """Read a decrypted message from the session."""
        ...

    async def write(self, plaintext: bytes) -> None:
        """Write data to the session (will be encrypted)."""
        ...

    async def close(self) -> None:
        """Close the session."""
        ...


logger = logging.getLogger(__name__)

# Stream limits protect against resource exhaustion attacks.
#
# Without limits, a malicious peer could open thousands of streams, consuming
# memory for each stream's state and buffers. The 1024 limit balances
# concurrency needs against resource constraints.
MAX_STREAMS: Final[int] = 1024
"""Maximum number of concurrent streams."""

# Per-stream buffer size balances memory use against throughput.
#
# - Too small: frequent backpressure, reduced throughput.
# - Too large: memory exhaustion with many streams.
#
# 256 items provides reasonable queue depth for chunk count.
BUFFER_SIZE: Final[int] = 256
"""Per-stream receive buffer depth (number of data chunks)."""

# Maximum bytes buffered per stream.
#
# SECURITY: This is the critical limit for preventing memory exhaustion.
#
# The BUFFER_SIZE above limits chunk count, but a malicious peer could send
# 256 chunks of 1MB each. This byte limit caps memory per stream at a
# reasonable value (equal to the initial window size).
MAX_BUFFER_BYTES: Final[int] = YAMUX_INITIAL_WINDOW
"""Maximum bytes buffered per stream before triggering reset."""


@dataclass(slots=True)
class YamuxStream:
    """
    A single multiplexed stream with flow control.

    Unlike mplex streams, yamux streams track send and receive windows:
        - send_window: How much we can send before waiting for WINDOW_UPDATE.
        - recv_window: How much the peer can send us (we track and update).

    When we receive data, we should send WINDOW_UPDATE to allow the peer
    to continue sending. This is done automatically when reading.

    Usage:
        stream = await session.open_stream()
        await stream.write(b"request")
        response = await stream.read()
        await stream.close()
    """

    stream_id: int
    """Unique stream identifier."""

    session: YamuxSession
    """Parent session this stream belongs to."""

    is_initiator: bool
    """True if we opened this stream."""

    _send_window: int = YAMUX_INITIAL_WINDOW
    """How much data we can send before waiting for WINDOW_UPDATE."""

    _recv_window: int = YAMUX_INITIAL_WINDOW
    """How much data the peer can send us (tracks our advertised window)."""

    _recv_consumed: int = 0
    """Data consumed since last WINDOW_UPDATE (triggers update when large enough)."""

    _recv_buffer: asyncio.Queue[bytes] = field(default_factory=lambda: asyncio.Queue(BUFFER_SIZE))
    """Buffered incoming data chunks."""

    _current_buffer_bytes: int = 0
    """
    Current bytes buffered in _recv_buffer.

    SECURITY: This tracks actual memory usage, not just queue item count.

    We enforce MAX_BUFFER_BYTES to prevent memory exhaustion attacks where
    a malicious peer sends many large chunks.
    """

    _read_closed: bool = False
    """True if remote side has finished sending (received FIN)."""

    _write_closed: bool = False
    """True if we have finished sending (sent FIN)."""

    _reset: bool = False
    """True if stream was aborted (sent or received RST)."""

    _protocol_id: str = ""
    """Negotiated protocol for this stream."""

    _send_window_event: asyncio.Event = field(default_factory=asyncio.Event)
    """Event signaled when send window increases (after receiving WINDOW_UPDATE)."""

    def __post_init__(self) -> None:
        """Initialize event in signaled state (initial window > 0)."""
        if self._send_window > 0:
            self._send_window_event.set()

    @property
    def protocol_id(self) -> str:
        """The negotiated protocol for this stream."""
        return self._protocol_id

    async def write(self, data: bytes) -> None:
        """
        Write data to the stream, respecting flow control.

        If the send window is exhausted, this method will block until the peer
        sends a WINDOW_UPDATE.

        Args:
            data: Data to send

        Raises:
            YamuxError: If stream is closed or reset
        """
        if self._reset:
            raise YamuxError(f"Stream {self.stream_id} was reset")
        if self._write_closed:
            raise YamuxError(f"Stream {self.stream_id} write side closed")

        # Send data in chunks that fit within our send window.
        #
        # This respects flow control: we never send more than the peer's
        # advertised receive window.
        #
        # If window exhausted, we wait for WINDOW_UPDATE before continuing.
        offset = 0
        while offset < len(data):
            # Wait for send window to be available.
            await self._send_window_event.wait()

            if self._reset:
                raise YamuxError(f"Stream {self.stream_id} was reset while writing")

            # Calculate how much we can send.
            chunk_size = min(len(data) - offset, self._send_window)
            if chunk_size == 0:
                # Window exhausted, clear event and wait for update.
                self._send_window_event.clear()
                continue

            chunk = data[offset : offset + chunk_size]
            frame = data_frame(self.stream_id, chunk)
            await self.session._send_frame(frame)

            # Update our view of the send window.
            self._send_window -= chunk_size
            if self._send_window == 0:
                self._send_window_event.clear()

            offset += chunk_size

    async def read(self, n: int = -1) -> bytes:
        """
        Read data from the stream.

        Reads from the receive buffer. If buffer is empty and stream
        is not closed, waits for data.

        After reading, considers sending WINDOW_UPDATE to allow the peer
        to send more data.

        Args:
            n: Maximum bytes to read (-1 for all available chunk)

        Returns:
            Read data (may be less than n bytes)

        Raises:
            YamuxError: If stream was reset
        """
        if self._reset:
            raise YamuxError(f"Stream {self.stream_id} was reset")

        # If buffer is empty and read is closed, return empty.
        if self._recv_buffer.empty() and self._read_closed:
            return b""

        # Wait for data.
        try:
            data = await self._recv_buffer.get()
            result = data[:n] if n > 0 else data

            # Update buffer byte tracking.
            #
            # SECURITY: This must be decremented to allow more data to be buffered.
            # If we don't track this correctly, the stream will eventually reject
            # all incoming data once MAX_BUFFER_BYTES is reached.
            self._current_buffer_bytes -= len(data)

            # Track consumed data for window updates.
            #
            # We batch window updates rather than sending after every read.
            # This reduces overhead: instead of many small updates, we send
            # one larger update when consumption reaches a threshold.
            self._recv_consumed += len(result)

            # Send window update if we've consumed a significant amount.
            #
            # Threshold: 50% of initial window or 64KB, whichever is larger.
            #
            # This balances responsiveness (peer doesn't stall waiting for update)
            # against overhead (fewer update frames).
            threshold = max(YAMUX_INITIAL_WINDOW // 2, 64 * 1024)
            if self._recv_consumed >= threshold:
                await self._send_window_update()

            return result
        except asyncio.CancelledError:
            raise

    async def _send_window_update(self) -> None:
        """Send WINDOW_UPDATE to increase peer's send window."""
        if self._recv_consumed > 0 and not self._reset and not self._read_closed:
            frame = window_update_frame(self.stream_id, self._recv_consumed)
            await self.session._send_frame(frame)
            self._recv_window += self._recv_consumed
            self._recv_consumed = 0

    async def close(self) -> None:
        """
        Close the write side of the stream (half-close).

        Sends FIN flag. The peer can still send data.
        Use reset() to abort immediately.
        """
        if self._write_closed:
            return

        self._write_closed = True

        # Send any remaining window updates before closing.
        await self._send_window_update()

        frame = fin_frame(self.stream_id)
        await self.session._send_frame(frame)

    async def reset(self) -> None:
        """
        Reset/abort the stream immediately.

        Both directions are closed and any pending data is discarded.
        """
        if self._reset:
            return

        self._reset = True
        self._read_closed = True
        self._write_closed = True

        frame = rst_frame(self.stream_id)
        await self.session._send_frame(frame)

    def _handle_data(self, data: bytes) -> None:
        """
        Handle incoming data frame (internal).

        Security: This method enforces two critical limits:
        1. Flow control: Peer cannot send more than our advertised window.
        2. Buffer bytes: Total buffered data cannot exceed MAX_BUFFER_BYTES.

        Violating either limit results in a stream reset (protocol error).
        """
        if self._read_closed or self._reset:
            return

        # Strict flow control enforcement.
        #
        # The yamux spec states:
        # If a peer sends a frame that exceeds the window, it is a protocol error.
        #
        # We must check BEFORE accepting the data.
        #
        # A malicious peer ignoring flow control could flood us with data.
        if len(data) > self._recv_window:
            logger.warning(
                "Stream %d flow control violation: received %d bytes, window only %d",
                self.stream_id,
                len(data),
                self._recv_window,
            )
            self._handle_reset()
            return

        # Byte-bounded buffering.
        #
        # The queue has a slot limit (BUFFER_SIZE items), but a malicious peer
        # could send large chunks that fit in few slots but consume huge memory.
        #
        # This check ensures total buffered bytes stay within MAX_BUFFER_BYTES.
        if self._current_buffer_bytes + len(data) > MAX_BUFFER_BYTES:
            logger.warning(
                "Stream %d buffer overflow: would have %d bytes (max %d)",
                self.stream_id,
                self._current_buffer_bytes + len(data),
                MAX_BUFFER_BYTES,
            )
            self._handle_reset()
            return

        # Track that our receive window has decreased.
        #
        # The peer is allowed to send up to our advertised window.
        #
        # As they send, our window decreases.
        # We'll restore it with WINDOW_UPDATE when the application consumes the data.
        self._recv_window -= len(data)

        try:
            self._recv_buffer.put_nowait(data)
            self._current_buffer_bytes += len(data)
        except asyncio.QueueFull:
            # Buffer overflow triggers a stream reset.
            #
            # This should be even rare with byte-level limits above.
            # If it happens, the application is reading too slowly.
            logger.warning(
                "Stream %d queue full (%d items), resetting",
                self.stream_id,
                BUFFER_SIZE,
            )
            self._handle_reset()

    def _handle_window_update(self, delta: int) -> None:
        """Handle incoming WINDOW_UPDATE frame (internal)."""
        if not self._reset:
            # Increase our send window by the delta.
            #
            # The peer is telling us they've consumed data and can accept more.
            # This allows us to continue sending if we were blocked.
            self._send_window += delta
            if self._send_window > 0:
                self._send_window_event.set()

    def _handle_fin(self) -> None:
        """Handle incoming FIN flag (internal)."""
        self._read_closed = True

    def _handle_reset(self) -> None:
        """Handle incoming RST flag (internal)."""
        self._reset = True
        self._read_closed = True
        self._write_closed = True
        # Unblock any writers waiting for window update.
        self._send_window_event.set()

    @property
    def is_closed(self) -> bool:
        """Check if stream is fully closed (both directions)."""
        return (self._read_closed and self._write_closed) or self._reset


@dataclass(slots=True)
class YamuxSession:
    """
    Multiplexed stream session over a Noise connection with flow control.

    Manages multiple concurrent streams, each with its own ID and flow control.
    """

    noise: NoiseSessionProtocol
    """Underlying Noise-encrypted session."""

    is_initiator: bool
    """True if we dialed this connection (client)."""

    _streams: dict[int, YamuxStream] = field(default_factory=dict)
    """Active streams by ID."""

    _next_stream_id: int = field(init=False)
    """Next stream ID to allocate."""

    _incoming_streams: asyncio.Queue[YamuxStream] = field(
        default_factory=lambda: asyncio.Queue(MAX_STREAMS)
    )
    """Queue of streams opened by the remote peer."""

    _write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    """Lock for serializing writes to the underlying connection."""

    _running: bool = False
    """True while the read loop is running."""

    _closed: bool = False
    """True after session is closed."""

    _go_away_sent: bool = False
    """True after we've sent GO_AWAY."""

    _go_away_received: bool = False
    """True after we've received GO_AWAY."""

    def __post_init__(self) -> None:
        """Initialize stream ID based on role."""
        # Odd/even stream ID allocation prevents collisions without coordination.
        #
        # This is OPPOSITE of mplex!
        # - yamux: Client (initiator) uses ODD IDs (1, 3, 5, ...)
        # - mplex: Client (initiator) uses EVEN IDs (0, 2, 4, ...)
        #
        # This follows the yamux spec from HashiCorp.
        # Getting this wrong causes stream ID collisions with peers.
        self._next_stream_id = 1 if self.is_initiator else 2

    async def open_stream(self) -> YamuxStream:
        """
        Open a new outbound stream.

        Returns:
            New stream ready for use

        Raises:
            YamuxError: If too many streams, session closed, or GO_AWAY received
        """
        if self._closed:
            raise YamuxError("Session is closed")

        if self._go_away_received:
            raise YamuxError("Cannot open stream after receiving GO_AWAY")

        if len(self._streams) >= MAX_STREAMS:
            raise YamuxError(f"Too many streams: {len(self._streams)}")

        stream_id = self._next_stream_id

        # Increment by 2 to maintain odd/even parity.
        #
        # If we're:
        # - The client (starting at 1), our IDs are: 1, 3, 5, 7, ...
        # - The server (starting at 2), uses: 2, 4, 6, 8, ...
        #
        # No overlap is possible.
        self._next_stream_id += 2

        stream = YamuxStream(
            stream_id=stream_id,
            session=self,
            is_initiator=True,
        )
        self._streams[stream_id] = stream

        # Send SYN frame to open the stream.
        #
        # SYN is a WINDOW_UPDATE with SYN flag and our initial window.
        # This tells the peer both "new stream" and "my receive window".
        frame = syn_frame(stream_id)
        await self._send_frame(frame)

        return stream

    async def accept_stream(self) -> YamuxStream:
        """
        Accept an incoming stream from the peer.

        Blocks until a new stream is opened by the remote side.

        Returns:
            New stream opened by peer

        Raises:
            YamuxError: If session closed
        """
        if self._closed:
            raise YamuxError("Session is closed")

        return await self._incoming_streams.get()

    async def run(self) -> None:
        """
        Run the session's read loop.

        This must be called (typically in a background task) to process
        incoming frames. Without it, reads will block forever.

        The loop runs until the session is closed or an error occurs.
        """
        self._running = True
        try:
            while not self._closed:
                await self._read_one_frame()
        except asyncio.CancelledError:
            logger.debug("yamux session read loop cancelled")
        except Exception as e:
            logger.debug("yamux session read loop terminated: %s", e)
        finally:
            self._running = False
            self._closed = True

    async def close(self) -> None:
        """
        Close the session gracefully.

        Sends GO_AWAY to allow in-flight requests to complete, then
        resets remaining streams and closes the Noise session.
        """
        if self._closed:
            return

        self._closed = True
        logger.debug("Closing yamux session with %d streams", len(self._streams))

        # Send GO_AWAY if we haven't already.
        if not self._go_away_sent:
            try:
                frame = go_away_frame(YamuxGoAwayCode.NORMAL)
                await self._send_frame(frame)
                self._go_away_sent = True
            except Exception as e:
                logger.debug("Error sending GO_AWAY: %s", e)

        # Reset all open streams.
        for stream in list(self._streams.values()):
            if not stream.is_closed:
                try:
                    await stream.reset()
                except Exception as e:
                    logger.debug("Error resetting stream %d: %s", stream.stream_id, e)

        # Close underlying session.
        await self.noise.close()

    async def _send_frame(self, frame: YamuxFrame) -> None:
        """Send a frame over the underlying Noise session."""
        async with self._write_lock:
            await self.noise.write(frame.encode())

    async def _read_one_frame(self) -> None:
        """Read and dispatch one frame."""
        # Each Noise message contains a complete yamux frame (header + body).
        #
        # The noise.read() method:
        # - reads the 2-byte length prefix,
        # - reads the encrypted ciphertext,
        # - decrypts it, and
        # - returns the plaintext.
        #
        # For yamux, this plaintext is [12-byte header][body].
        try:
            data = await self.noise.read()
        except Exception:
            self._closed = True
            return

        if len(data) < YAMUX_HEADER_SIZE:
            raise YamuxError(f"Frame too short: {len(data)} < {YAMUX_HEADER_SIZE}")

        # Parse the 12-byte header.
        header = data[:YAMUX_HEADER_SIZE]
        body = data[YAMUX_HEADER_SIZE:]

        frame = YamuxFrame.decode(header, body)

        await self._dispatch_frame(frame)

    async def _dispatch_frame(self, frame: YamuxFrame) -> None:
        """Dispatch a frame to the appropriate handler."""
        # Session-level messages (stream_id = 0).
        if frame.stream_id == 0:
            if frame.frame_type == YamuxType.PING:
                await self._handle_ping(frame)
            elif frame.frame_type == YamuxType.GO_AWAY:
                self._handle_go_away(frame)
            return

        # Stream-level messages.
        if frame.has_flag(YamuxFlags.SYN):
            await self._handle_syn(frame)
        elif frame.stream_id in self._streams:
            stream = self._streams[frame.stream_id]
            await self._handle_stream_frame(stream, frame)
        elif frame.has_flag(YamuxFlags.ACK):
            # ACK for unknown stream - could be late ACK after we closed.
            logger.debug("ACK for unknown stream %d", frame.stream_id)
        # Ignore frames for unknown streams (they may have been reset).

    async def _handle_stream_frame(self, stream: YamuxStream, frame: YamuxFrame) -> None:
        """Handle a frame for an existing stream."""
        if frame.has_flag(YamuxFlags.RST):
            # RST takes priority - abort the stream.
            stream._handle_reset()
            del self._streams[frame.stream_id]
            return

        if frame.frame_type == YamuxType.DATA:
            if frame.data:
                stream._handle_data(frame.data)
            if frame.has_flag(YamuxFlags.FIN):
                stream._handle_fin()
        elif frame.frame_type == YamuxType.WINDOW_UPDATE:
            stream._handle_window_update(frame.length)
            if frame.has_flag(YamuxFlags.FIN):
                stream._handle_fin()

        # Clean up fully closed streams.
        if stream.is_closed:
            del self._streams[frame.stream_id]

    async def _handle_syn(self, frame: YamuxFrame) -> None:
        """Handle incoming SYN frame (new stream from peer)."""
        stream_id = frame.stream_id

        if stream_id in self._streams:
            # Duplicate stream ID - protocol error, send RST.
            rst = rst_frame(stream_id)
            await self._send_frame(rst)
            return

        if len(self._streams) >= MAX_STREAMS:
            # Too many streams - send RST.
            rst = rst_frame(stream_id)
            await self._send_frame(rst)
            return

        if self._go_away_sent:
            # We've initiated shutdown - reject new streams.
            rst = rst_frame(stream_id)
            await self._send_frame(rst)
            return

        # Create new stream (we are not the initiator of this stream).
        stream = YamuxStream(
            stream_id=stream_id,
            session=self,
            is_initiator=False,
            _send_window=frame.length,  # Peer's initial window from SYN.
        )
        self._streams[stream_id] = stream

        # Send ACK to acknowledge stream creation.
        ack = ack_frame(stream_id)
        await self._send_frame(ack)

        # Queue for accept_stream().
        try:
            self._incoming_streams.put_nowait(stream)
        except asyncio.QueueFull:
            # Too many pending incoming streams.
            stream._handle_reset()
            del self._streams[stream_id]
            rst = rst_frame(stream_id)
            await self._send_frame(rst)

    async def _handle_ping(self, frame: YamuxFrame) -> None:
        """Handle PING frame."""
        if not frame.has_flag(YamuxFlags.ACK):
            # This is a ping request - echo back with ACK.
            response = ping_frame(opaque=frame.length, is_response=True)
            await self._send_frame(response)
        # If ACK is set, this is a ping response - nothing to do.

    def _handle_go_away(self, frame: YamuxFrame) -> None:
        """Handle GO_AWAY frame."""
        self._go_away_received = True
        code = (
            YamuxGoAwayCode(frame.length) if frame.length <= 2 else YamuxGoAwayCode.INTERNAL_ERROR
        )
        logger.debug("Received GO_AWAY: %s", code.name)
        # Don't immediately close - let existing streams complete.
