"""Tests for yamux session and stream management."""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.subspecs.networking.transport.yamux.frame import (
    YAMUX_INITIAL_WINDOW,
    YamuxError,
)
from lean_spec.subspecs.networking.transport.yamux.session import (
    BUFFER_SIZE,
    MAX_STREAMS,
    YamuxSession,
    YamuxStream,
)
from tests.lean_spec.helpers import MockNoiseSession


class TestSessionConstants:
    """Tests for session constants."""

    def test_max_streams(self) -> None:
        """Maximum streams is 1024."""
        assert MAX_STREAMS == 1024

    def test_buffer_size(self) -> None:
        """Buffer size is 256 per stream."""
        assert BUFFER_SIZE == 256

    def test_initial_window(self) -> None:
        """Initial window is 256KB."""
        assert YAMUX_INITIAL_WINDOW == 256 * 1024


class TestYamuxStreamWrite:
    """Tests for YamuxStream.write()."""

    def test_write_on_reset_stream_raises(self) -> None:
        """Writing to reset stream raises YamuxError."""

        async def run_test() -> None:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            stream._reset = True

            with pytest.raises(YamuxError, match="reset"):
                await stream.write(b"data")

        asyncio.run(run_test())

    def test_write_on_closed_stream_raises(self) -> None:
        """Writing to write-closed stream raises YamuxError."""

        async def run_test() -> None:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            stream._write_closed = True

            with pytest.raises(YamuxError, match="closed"):
                await stream.write(b"data")

        asyncio.run(run_test())


class TestYamuxStreamRead:
    """Tests for YamuxStream.read()."""

    def test_read_on_reset_stream_raises(self) -> None:
        """Reading from reset stream raises YamuxError."""

        async def run_test() -> None:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            stream._reset = True

            with pytest.raises(YamuxError, match="reset"):
                await stream.read()

        asyncio.run(run_test())

    def test_read_returns_empty_when_closed_and_buffer_empty(self) -> None:
        """Reading from closed stream with empty buffer returns empty bytes."""

        async def run_test() -> bytes:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            stream._read_closed = True

            return await stream.read()

        result = asyncio.run(run_test())
        assert result == b""

    def test_read_returns_buffered_data(self) -> None:
        """Reading returns data from buffer."""

        async def run_test() -> bytes:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            stream._handle_data(b"test data")

            return await stream.read()

        result = asyncio.run(run_test())
        assert result == b"test data"

    def test_read_with_limit(self) -> None:
        """Reading with limit returns at most n bytes."""

        async def run_test() -> bytes:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            stream._handle_data(b"hello world")

            return await stream.read(5)

        result = asyncio.run(run_test())
        assert result == b"hello"


class TestYamuxStreamClose:
    """Tests for YamuxStream.close()."""

    def test_close_sets_write_closed(self) -> None:
        """Close sets the _write_closed flag."""

        async def run_test() -> bool:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            assert stream._write_closed is False

            await stream.close()
            return stream._write_closed

        assert asyncio.run(run_test()) is True

    def test_close_is_idempotent(self) -> None:
        """Closing twice is safe."""

        async def run_test() -> None:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)

            await stream.close()
            await stream.close()  # Should not raise

        asyncio.run(run_test())


class TestYamuxStreamReset:
    """Tests for YamuxStream.reset()."""

    def test_reset_sets_flag(self) -> None:
        """Reset sets the _reset flag."""

        async def run_test() -> bool:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            assert stream._reset is False

            await stream.reset()
            return stream._reset

        assert asyncio.run(run_test()) is True

    def test_reset_is_idempotent(self) -> None:
        """Resetting twice is safe."""

        async def run_test() -> None:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)

            await stream.reset()
            await stream.reset()  # Should not raise

        asyncio.run(run_test())

    def test_reset_sets_all_closed_flags(self) -> None:
        """Reset sets all closed flags."""

        async def run_test() -> tuple[bool, bool, bool]:
            stream = _create_mock_stream(stream_id=1, is_initiator=True)
            await stream.reset()
            return stream._reset, stream._read_closed, stream._write_closed

        reset, read_closed, write_closed = asyncio.run(run_test())
        assert reset is True
        assert read_closed is True
        assert write_closed is True


class TestYamuxStreamHandlers:
    """Tests for YamuxStream internal handlers."""

    def test_handle_data_queues_data(self) -> None:
        """_handle_data adds data to receive buffer."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        assert stream._recv_buffer.empty()

        stream._handle_data(b"test data")

        assert not stream._recv_buffer.empty()

    def test_handle_data_decreases_recv_window(self) -> None:
        """_handle_data decreases receive window."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        initial_window = stream._recv_window

        assert stream._recv_window == initial_window

        stream._handle_data(b"test data")

        assert stream._recv_window == initial_window - len(b"test data")

    def test_handle_data_ignored_when_read_closed(self) -> None:
        """_handle_data ignores data when read side is closed."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        stream._read_closed = True

        stream._handle_data(b"test data")

        assert stream._recv_buffer.empty()

    def test_handle_data_ignored_when_reset(self) -> None:
        """_handle_data ignores data when stream is reset."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        stream._reset = True

        stream._handle_data(b"test data")

        assert stream._recv_buffer.empty()

    def test_handle_window_update_increases_send_window(self) -> None:
        """_handle_window_update increases send window."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        initial_window = stream._send_window

        assert stream._send_window == initial_window

        stream._handle_window_update(10000)

        assert stream._send_window == initial_window + 10000

    def test_handle_fin_sets_flag(self) -> None:
        """_handle_fin sets read_closed flag."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        assert stream._read_closed is False

        stream._handle_fin()

        assert stream._read_closed is True

    def test_handle_reset_sets_all_flags(self) -> None:
        """_handle_reset sets all closed flags."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        assert stream._reset is False
        assert stream._read_closed is False
        assert stream._write_closed is False

        stream._handle_reset()

        assert stream._reset is True
        assert stream._read_closed is True
        assert stream._write_closed is True


class TestYamuxStreamIsClosed:
    """Tests for YamuxStream.is_closed property."""

    def test_not_closed_initially(self) -> None:
        """Stream is not closed initially."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        assert stream.is_closed is False

    def test_not_closed_when_read_only_closed(self) -> None:
        """Stream is not closed when only read side is closed."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        stream._read_closed = True

        assert stream.is_closed is False

    def test_not_closed_when_write_only_closed(self) -> None:
        """Stream is not closed when only write side is closed."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        stream._write_closed = True

        assert stream.is_closed is False

    def test_closed_when_both_directions_closed(self) -> None:
        """Stream is closed when both directions are closed."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        assert stream.is_closed is False

        stream._read_closed = True
        stream._write_closed = True

        assert stream.is_closed is True

    def test_closed_when_reset(self) -> None:
        """Stream is closed when reset."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)

        assert stream.is_closed is False

        stream._reset = True

        assert stream.is_closed is True


class TestYamuxStreamFlowControl:
    """Tests for yamux flow control."""

    def test_initial_send_window(self) -> None:
        """Stream starts with initial send window."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        assert stream._send_window == YAMUX_INITIAL_WINDOW

    def test_initial_recv_window(self) -> None:
        """Stream starts with initial recv window."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        assert stream._recv_window == YAMUX_INITIAL_WINDOW

    def test_send_window_event_set_initially(self) -> None:
        """Send window event is set initially (window > 0)."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        assert stream._send_window_event.is_set()


class TestYamuxSessionInit:
    """Tests for YamuxSession initialization."""

    def test_initiator_starts_with_odd_id(self) -> None:
        """Initiator (client) session starts stream IDs at 1 (odd).

        NOTE: This is OPPOSITE of mplex which uses even IDs for initiator!
        """
        session = _create_mock_session(is_initiator=True)
        assert session._next_stream_id == 1

    def test_responder_starts_with_even_id(self) -> None:
        """Responder (server) session starts stream IDs at 2 (even).

        NOTE: This is OPPOSITE of mplex which uses odd IDs for responder!
        """
        session = _create_mock_session(is_initiator=False)
        assert session._next_stream_id == 2

    def test_session_starts_not_running(self) -> None:
        """Session starts with _running = False."""
        session = _create_mock_session(is_initiator=True)
        assert session._running is False

    def test_session_starts_not_closed(self) -> None:
        """Session starts with _closed = False."""
        session = _create_mock_session(is_initiator=True)
        assert session._closed is False

    def test_session_starts_no_go_away(self) -> None:
        """Session starts without GO_AWAY sent or received."""
        session = _create_mock_session(is_initiator=True)
        assert session._go_away_sent is False
        assert session._go_away_received is False


class TestYamuxSessionOpenStream:
    """Tests for YamuxSession.open_stream()."""

    def test_open_stream_on_closed_session_raises(self) -> None:
        """Opening stream on closed session raises YamuxError."""

        async def run_test() -> None:
            session = _create_mock_session(is_initiator=True)
            session._closed = True

            with pytest.raises(YamuxError, match="closed"):
                await session.open_stream()

        asyncio.run(run_test())

    def test_open_stream_after_go_away_raises(self) -> None:
        """Opening stream after receiving GO_AWAY raises YamuxError."""

        async def run_test() -> None:
            session = _create_mock_session(is_initiator=True)
            session._go_away_received = True

            with pytest.raises(YamuxError, match="GO_AWAY"):
                await session.open_stream()

        asyncio.run(run_test())

    def test_open_stream_allocates_odd_id_for_initiator(self) -> None:
        """Initiator (client) allocates odd stream IDs."""

        async def run_test() -> list[int]:
            session = _create_mock_session(is_initiator=True)

            stream1 = await session.open_stream()
            stream2 = await session.open_stream()
            stream3 = await session.open_stream()

            return [stream1.stream_id, stream2.stream_id, stream3.stream_id]

        ids = asyncio.run(run_test())
        assert ids == [1, 3, 5]

    def test_open_stream_allocates_even_id_for_responder(self) -> None:
        """Responder (server) allocates even stream IDs."""

        async def run_test() -> list[int]:
            session = _create_mock_session(is_initiator=False)

            stream1 = await session.open_stream()
            stream2 = await session.open_stream()
            stream3 = await session.open_stream()

            return [stream1.stream_id, stream2.stream_id, stream3.stream_id]

        ids = asyncio.run(run_test())
        assert ids == [2, 4, 6]

    def test_open_stream_tracks_stream(self) -> None:
        """Opening stream adds it to _streams dict."""

        async def run_test() -> bool:
            session = _create_mock_session(is_initiator=True)

            stream = await session.open_stream()
            return stream.stream_id in session._streams

        assert asyncio.run(run_test()) is True

    def test_open_stream_returns_initiator_stream(self) -> None:
        """Opened stream has is_initiator=True."""

        async def run_test() -> bool:
            session = _create_mock_session(is_initiator=True)

            stream = await session.open_stream()
            return stream.is_initiator

        assert asyncio.run(run_test()) is True


class TestYamuxSessionAcceptStream:
    """Tests for YamuxSession.accept_stream()."""

    def test_accept_stream_on_closed_session_raises(self) -> None:
        """Accepting stream on closed session raises YamuxError."""

        async def run_test() -> None:
            session = _create_mock_session(is_initiator=True)
            session._closed = True

            with pytest.raises(YamuxError, match="closed"):
                await session.accept_stream()

        asyncio.run(run_test())


class TestYamuxSessionClose:
    """Tests for YamuxSession.close()."""

    def test_close_sets_closed_flag(self) -> None:
        """Close sets the _closed flag."""

        async def run_test() -> bool:
            session = _create_mock_session(is_initiator=True)

            await session.close()
            return session._closed

        assert asyncio.run(run_test()) is True

    def test_close_is_idempotent(self) -> None:
        """Closing twice is safe."""

        async def run_test() -> None:
            session = _create_mock_session(is_initiator=True)

            await session.close()
            await session.close()  # Should not raise

        asyncio.run(run_test())

    def test_close_resets_open_streams(self) -> None:
        """Close resets all open streams."""

        async def run_test() -> bool:
            session = _create_mock_session(is_initiator=True)

            stream = await session.open_stream()
            await session.close()

            return stream._reset

        assert asyncio.run(run_test()) is True

    def test_close_sets_go_away_sent(self) -> None:
        """Close sets _go_away_sent flag."""

        async def run_test() -> bool:
            session = _create_mock_session(is_initiator=True)

            await session.close()
            return session._go_away_sent

        assert asyncio.run(run_test()) is True


class TestYamuxStreamProtocolId:
    """Tests for stream protocol_id property."""

    def test_protocol_id_initially_empty(self) -> None:
        """Protocol ID is empty string initially."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        assert stream.protocol_id == ""

    def test_protocol_id_can_be_set(self) -> None:
        """Protocol ID can be set via _protocol_id."""
        stream = _create_mock_stream(stream_id=1, is_initiator=True)
        stream._protocol_id = "/test/1.0"

        assert stream.protocol_id == "/test/1.0"


class TestStreamIdAllocationDifference:
    """Tests highlighting the critical difference from mplex.

    yamux: Client=odd (1,3,5...), Server=even (2,4,6...)
    mplex: Client=even (0,2,4...), Server=odd (1,3,5...)
    """

    def test_client_uses_odd_ids(self) -> None:
        """Client (initiator) uses odd IDs in yamux."""
        session = _create_mock_session(is_initiator=True)

        # First ID should be 1 (odd)
        assert session._next_stream_id == 1
        assert session._next_stream_id % 2 == 1  # Odd

    def test_server_uses_even_ids(self) -> None:
        """Server (responder) uses even IDs in yamux."""
        session = _create_mock_session(is_initiator=False)

        # First ID should be 2 (even)
        assert session._next_stream_id == 2
        assert session._next_stream_id % 2 == 0  # Even

    def test_client_ids_remain_odd(self) -> None:
        """All client stream IDs are odd."""

        async def run_test() -> list[int]:
            session = _create_mock_session(is_initiator=True)
            ids = []
            for _ in range(5):
                stream = await session.open_stream()
                ids.append(stream.stream_id)
            return ids

        ids = asyncio.run(run_test())
        assert ids == [1, 3, 5, 7, 9]
        assert all(i % 2 == 1 for i in ids)

    def test_server_ids_remain_even(self) -> None:
        """All server stream IDs are even."""

        async def run_test() -> list[int]:
            session = _create_mock_session(is_initiator=False)
            ids = []
            for _ in range(5):
                stream = await session.open_stream()
                ids.append(stream.stream_id)
            return ids

        ids = asyncio.run(run_test())
        assert ids == [2, 4, 6, 8, 10]
        assert all(i % 2 == 0 for i in ids)


# Helper functions for testing


def _create_mock_stream(stream_id: int, is_initiator: bool) -> YamuxStream:
    """Create a mock YamuxStream for testing."""
    session = _create_mock_session(is_initiator=is_initiator)
    return YamuxStream(
        stream_id=stream_id,
        session=session,
        is_initiator=is_initiator,
    )


def _create_mock_session(is_initiator: bool) -> YamuxSession:
    """Create a mock YamuxSession for testing."""
    noise = MockNoiseSession()
    return YamuxSession(noise=noise, is_initiator=is_initiator)
