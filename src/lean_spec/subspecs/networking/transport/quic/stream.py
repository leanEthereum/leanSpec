"""QUIC stream primitives for libp2p."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from aioquic.asyncio import QuicConnectionProtocol

from lean_spec.subspecs.networking.types import ProtocolId


class QuicTransportError(Exception):
    """Raised when QUIC connection operations fail."""


class QuicStreamResetError(QuicTransportError):
    """Raised when a QUIC stream is abruptly reset by the peer (RESET_STREAM).

    Per RFC 9000 Section 3.2, RESET_STREAM indicates the peer cannot guarantee
    delivery of stream data.  Outstanding data may be lost.
    """

    def __init__(self, stream_id: int, error_code: int) -> None:
        """Create a reset error with the stream ID and the peer's error code."""
        self.stream_id = stream_id
        self.error_code = error_code
        super().__init__(f"Stream {stream_id} reset by peer (error_code={error_code})")


@dataclass(slots=True)
class QuicStream:
    """
    A single QUIC stream for application data.

    QUIC streams are lightweight — opening a stream is just sending a frame,
    no handshake required.  Flow control is per-stream, preventing
    head-of-line blocking.
    """

    _protocol: QuicConnectionProtocol
    _stream_id: int
    _read_buffer: asyncio.Queue[bytes] = field(default_factory=lambda: asyncio.Queue())
    _closed: bool = False
    _write_closed: bool = False
    _read_closed: bool = False
    _reset_error: QuicStreamResetError | None = None
    _protocol_id: ProtocolId = ProtocolId("")

    @property
    def stream_id(self) -> int:
        """Stream identifier."""
        return self._stream_id

    @property
    def protocol_id(self) -> ProtocolId:
        """Negotiated protocol ID for this stream."""
        return self._protocol_id

    async def read(self) -> bytes:
        """
        Read data from the stream.

        Blocks until data is available.  Returns empty bytes when the peer
        has closed their write side (half-close via FIN).

        Raises:
            QuicStreamResetError: If the stream was reset by the peer
                (RESET_STREAM per RFC 9000 Section 3.2). Data may have been lost.

        Returns:
            Received data bytes, or empty bytes when stream is half-closed.
        """
        if self._read_closed:
            # If the stream was reset, always raise.
            if self._reset_error is not None:
                raise self._reset_error
            return b""

        data = await self._read_buffer.get()
        if data == b"":
            self._read_closed = True
            # If end-of-stream was caused by a reset, raise the error.
            # Per RFC 9000 Section 3.2, RESET_STREAM means data may have been lost.
            if self._reset_error is not None:
                raise self._reset_error
            return b""

        return data

    async def write(self, data: bytes) -> None:
        """
        Write data to the stream.

        Args:
            data: Bytes to send.

        Raises:
            QuicTransportError: If write side is closed or aioquic rejects the write.
        """
        if self._write_closed:
            raise QuicTransportError("Stream write side is closed")

        # Check aioquic's internal stream state before writing.
        #
        # aioquic tracks stream state internally and will raise an exception
        # if we try to write after FIN has been sent.  This can happen due to
        # race conditions in stream handling.  We check first to give a clearer
        # error message.
        quic = self._protocol._quic
        stream = quic._streams.get(self._stream_id)
        if stream is not None and getattr(stream, "send_fin", False):
            self._write_closed = True
            raise QuicTransportError(
                f"Stream {self._stream_id} write side is closed (aioquic FIN already sent)"
            )

        try:
            quic.send_stream_data(self._stream_id, data)
            self._protocol.transmit()
        except Exception as e:
            # If aioquic raises an exception, mark our stream as write-closed
            # to prevent further attempts.
            error_msg = str(e)
            if "FIN" in error_msg or "closed" in error_msg.lower():
                self._write_closed = True
            raise QuicTransportError(f"Write failed on stream {self._stream_id}: {e}") from e

    async def finish_write(self) -> None:
        """
        Signal end of writing (half-close).

        Sends FIN for our write direction while keeping read side open.
        Use this after sending a request to signal we're done writing.
        """
        if self._write_closed:
            return

        self._write_closed = True
        self._protocol._quic.send_stream_data(self._stream_id, b"", end_stream=True)
        self._protocol.transmit()

    async def close(self) -> None:
        """Close the stream gracefully (both directions)."""
        if self._closed:
            return

        self._closed = True
        self._write_closed = True
        self._read_closed = True
        self._protocol._quic.send_stream_data(self._stream_id, b"", end_stream=True)
        self._protocol.transmit()

    def _receive_data(self, data: bytes) -> None:
        """Internal: called when data arrives for this stream."""
        self._read_buffer.put_nowait(data)

    def _receive_end(self) -> None:
        """Internal: called when the peer sends FIN (graceful half-close)."""
        self._read_buffer.put_nowait(b"")

    def _receive_reset(self, error_code: int) -> None:
        """Internal: called when the peer sends RESET_STREAM (abrupt termination).

        Per RFC 9000 Section 3.2, RESET_STREAM indicates the sender cannot
        guarantee delivery.  Outstanding data may be lost.  This is fundamentally
        different from FIN, which guarantees all data was delivered.
        """
        self._reset_error = QuicStreamResetError(self._stream_id, error_code)
        # Queue an empty sentinel to unblock any pending read.
        self._read_buffer.put_nowait(b"")
