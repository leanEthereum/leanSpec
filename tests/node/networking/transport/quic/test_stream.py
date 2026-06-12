"""Tests for the QUIC stream wrapper, verified against RFC 9000 Section 3."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from lean_spec.node.networking.transport.quic.stream import (
    QuicStream,
    QuicStreamResetError,
    QuicTransportError,
)
from lean_spec.node.networking.types import ProtocolId


@pytest.fixture
def mock_protocol() -> MagicMock:
    """Mock aioquic protocol with stream tracking and transmit."""
    protocol = MagicMock()
    protocol._quic = MagicMock()
    protocol._quic._streams = {}
    protocol.transmit = MagicMock()
    return protocol


@pytest.fixture
def quic_stream(mock_protocol: MagicMock) -> QuicStream:
    """A QuicStream backed by the mock protocol on stream ID 0."""
    return QuicStream(_protocol=mock_protocol, _stream_id=0)


# QuicStream — read behavior per RFC 9000 Section 3
#
# - Data arrives in order per-stream.
# - FIN (end_stream=True) signals graceful half-close — all data delivered.
# - RESET_STREAM signals abrupt termination — data may be lost.


class TestQuicStreamRead:
    """Tests for reading data from a QUIC stream."""

    async def test_read_returns_buffered_data(self, quic_stream: QuicStream) -> None:
        """Data placed in the buffer is returned by read."""
        quic_stream._receive_data(b"hello")
        assert await quic_stream.read() == b"hello"

    async def test_read_returns_empty_on_fin(self, quic_stream: QuicStream) -> None:
        """FIN (graceful half-close) causes read to return empty bytes."""
        quic_stream._receive_end()
        assert await quic_stream.read() == b""
        # Per RFC 9000, stream is in "Data Read" terminal state.
        assert await quic_stream.read() == b""

    async def test_read_preserves_order(self, quic_stream: QuicStream) -> None:
        """Per RFC 9000, QUIC delivers data in order within a stream."""
        quic_stream._receive_data(b"first")
        quic_stream._receive_data(b"second")
        assert await quic_stream.read() == b"first"
        assert await quic_stream.read() == b"second"

    async def test_read_data_then_fin(self, quic_stream: QuicStream) -> None:
        """Data followed by FIN returns all data, then signals end."""
        quic_stream._receive_data(b"payload")
        quic_stream._receive_end()
        assert await quic_stream.read() == b"payload"
        assert await quic_stream.read() == b""

    async def test_read_after_close_returns_empty(self, quic_stream: QuicStream) -> None:
        """Reading a closed stream returns empty immediately."""
        await quic_stream.close()
        assert await quic_stream.read() == b""


# QuicStream — RESET_STREAM handling per RFC 9000 Section 3.2
#
# RESET_STREAM is an error/abort, NOT a clean end-of-stream.
# Data may have been lost. The application must be notified.


class TestQuicStreamReset:
    """Tests for RESET_STREAM error propagation."""

    async def test_reset_raises_on_read(self, quic_stream: QuicStream) -> None:
        """After reset, read raises an error with the error code from the peer."""
        quic_stream._receive_reset(error_code=42)
        with pytest.raises(QuicStreamResetError) as exc_info:
            await quic_stream.read()
        assert exc_info.value.stream_id == 0
        assert exc_info.value.error_code == 42

    async def test_reset_after_data_raises_after_consuming(self, quic_stream: QuicStream) -> None:
        """Data buffered before reset is delivered, then reset error is raised."""
        quic_stream._receive_data(b"partial")
        quic_stream._receive_reset(error_code=7)
        # Buffered data is still returned.
        assert await quic_stream.read() == b"partial"
        # Next read surfaces the reset error.
        with pytest.raises(QuicStreamResetError) as exc_info:
            await quic_stream.read()
        assert exc_info.value.error_code == 7

    async def test_repeated_reads_after_reset_raise(self, quic_stream: QuicStream) -> None:
        """Subsequent reads after reset continue to raise."""
        quic_stream._receive_reset(error_code=0)
        with pytest.raises(QuicStreamResetError):
            await quic_stream.read()
        with pytest.raises(QuicStreamResetError):
            await quic_stream.read()

    def test_reset_error_is_subclass_of_transport_error(self) -> None:
        """Reset error inherits from the base transport error."""
        assert issubclass(QuicStreamResetError, QuicTransportError)


# QuicStream — write behavior per RFC 9000 Section 3
#
# After FIN is sent (or stream is closed), further writes must fail.


class TestQuicStreamWrite:
    """Tests for writing data to a QUIC stream."""

    async def test_write_sends_data_and_transmits(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Writing sends data to the QUIC layer and flushes pending frames."""
        await quic_stream.write(b"hello")
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"hello")
        mock_protocol.transmit.assert_called_once()

    async def test_write_after_fin_raises(self, quic_stream: QuicStream) -> None:
        """Per RFC 9000, no data can be sent after FIN (write-side closed)."""
        quic_stream._write_closed = True
        with pytest.raises(QuicTransportError) as exception_info:
            await quic_stream.write(b"data")
        assert str(exception_info.value) == "Stream write side is closed"


# QuicStream — half-close (FIN) per RFC 9000 Section 3
#
# Sending FIN closes the write side. Read side stays open.


class TestQuicStreamFinishWrite:
    """Tests for half-close via FIN."""

    async def test_finish_write_sends_fin(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Half-close sends a STREAM frame with FIN bit (end_stream=True)."""
        await quic_stream.finish_write()
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"", end_stream=True)
        mock_protocol.transmit.assert_called_once()
        assert quic_stream._write_closed is True
        # Read side stays open (half-close per RFC 9000).
        assert quic_stream._read_closed is False

    async def test_finish_write_is_idempotent(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Sending FIN twice would be a protocol error; idempotency prevents this."""
        await quic_stream.finish_write()
        await quic_stream.finish_write()
        mock_protocol._quic.send_stream_data.assert_called_once()


# QuicStream — full close (both directions)


class TestQuicStreamClose:
    """Tests for full stream close (both directions)."""

    async def test_close_sets_all_flags_and_sends_fin(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Closing marks both directions closed and sends FIN."""
        await quic_stream.close()
        assert quic_stream._closed is True
        assert quic_stream._write_closed is True
        assert quic_stream._read_closed is True
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"", end_stream=True)
        mock_protocol.transmit.assert_called_once()

    async def test_close_is_idempotent(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Second close is a no-op — prevents double-FIN."""
        await quic_stream.close()
        await quic_stream.close()
        mock_protocol._quic.send_stream_data.assert_called_once()


class TestQuicStreamProtocolId:
    """
    Tests for the protocol_id property on QuicStream.

    Each QUIC stream carries a negotiated protocol identifier set during
    multistream-select. The default is empty until negotiation completes.
    """

    def test_protocol_id_returns_set_value(self, mock_protocol: MagicMock) -> None:
        """After negotiation, protocol_id reflects the agreed protocol."""
        stream = QuicStream(
            _protocol=mock_protocol,
            _stream_id=0,
            _protocol_id=ProtocolId("/test/1.0"),
        )
        assert stream.protocol_id == ProtocolId("/test/1.0")

    def test_protocol_id_default_empty(self, quic_stream: QuicStream) -> None:
        """Before negotiation, protocol_id is an empty string."""
        assert quic_stream.protocol_id == ProtocolId("")


class TestQuicStreamWriteFinDetection:
    """
    Tests for write detecting aioquic's internal FIN state.

    aioquic tracks per-stream state internally. If FIN was already sent
    (e.g., due to a race between close and write), the write method must
    detect this and fail early with a clear error rather than letting
    aioquic raise an opaque exception.
    """

    async def test_write_detects_aioquic_fin_sent(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """
        Write raises when aioquic has already sent FIN on this stream.

        This catches the race where close() sends FIN but write() is
        called before our _write_closed flag is set.
        """

        # Simulate aioquic's internal stream with FIN already sent.
        mock_internal_stream = MagicMock()
        mock_internal_stream.send_fin = True
        mock_protocol._quic._streams = {0: mock_internal_stream}

        with pytest.raises(QuicTransportError) as exception_info:
            await quic_stream.write(b"data")
        assert str(exception_info.value) == (
            "Stream 0 write side is closed (aioquic FIN already sent)"
        )

        # Write side is permanently closed after detecting FIN.
        assert quic_stream._write_closed is True

    async def test_write_proceeds_when_no_fin(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """Write succeeds normally when the internal stream has not sent FIN."""

        # Simulate aioquic's internal stream in normal state.
        mock_internal_stream = MagicMock()
        mock_internal_stream.send_fin = False
        mock_protocol._quic._streams = {0: mock_internal_stream}

        await quic_stream.write(b"data")
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"data")

    async def test_write_proceeds_when_stream_not_in_map(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """
        Write succeeds when aioquic has no entry for this stream ID.

        This happens for newly created streams before any data is sent.
        """
        mock_protocol._quic._streams = {}

        await quic_stream.write(b"data")
        mock_protocol._quic.send_stream_data.assert_called_once_with(0, b"data")


class TestQuicStreamWriteException:
    """
    Tests for write wrapping exceptions from aioquic.

    When aioquic raises during a write, the error is wrapped in
    QuicTransportError. If the error message indicates a terminal
    condition (FIN sent or stream closed), the write side is also
    marked closed to prevent further attempts.
    """

    async def test_write_wraps_fin_exception_and_marks_closed(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """
        An exception mentioning 'FIN' permanently closes the write side.

        This heuristic detects terminal errors from aioquic's internals.
        """

        # Simulate aioquic raising a FIN-related error.
        mock_protocol._quic.send_stream_data.side_effect = RuntimeError("FIN already sent")

        with pytest.raises(QuicTransportError) as exception_info:
            await quic_stream.write(b"data")
        assert str(exception_info.value) == "Write failed on stream 0: FIN already sent"

        # Write side is permanently closed.
        assert quic_stream._write_closed is True

    async def test_write_wraps_closed_exception_and_marks_closed(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """An exception mentioning 'closed' permanently closes the write side."""

        # Simulate aioquic raising a stream-closed error.
        mock_protocol._quic.send_stream_data.side_effect = RuntimeError("stream is closed")

        with pytest.raises(QuicTransportError) as exception_info:
            await quic_stream.write(b"data")
        assert str(exception_info.value) == "Write failed on stream 0: stream is closed"

        assert quic_stream._write_closed is True

    async def test_write_wraps_unrelated_exception_without_marking_closed(
        self, quic_stream: QuicStream, mock_protocol: MagicMock
    ) -> None:
        """
        Transient errors keep the write side open for retry.

        Only terminal conditions (FIN, closed) should permanently close.
        A buffer overflow or similar transient error should not.
        """

        # Simulate a transient error unrelated to stream state.
        mock_protocol._quic.send_stream_data.side_effect = RuntimeError("buffer overflow")

        with pytest.raises(QuicTransportError) as exception_info:
            await quic_stream.write(b"data")
        assert str(exception_info.value) == "Write failed on stream 0: buffer overflow"

        # Write side stays open — the error was transient.
        assert quic_stream._write_closed is False
