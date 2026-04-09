"""
Tests for multistream-select 1.0 protocol negotiation.

Wire format:
    Message = [varint length][payload + '\\n']
    - Length includes the trailing newline
    - Maximum message size: 1024 bytes

Protocol flow:
    1. Both sides send multistream header: /multistream/1.0.0
    2. Client proposes a protocol
    3. Server echoes (accept) or sends "na" (reject)

Reference: https://github.com/multiformats/multistream-select
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import cast
from unittest.mock import AsyncMock, patch

import pytest

from lean_spec.subspecs.networking.transport.quic import QuicStream
from lean_spec.subspecs.networking.transport.quic.stream_adapter import (
    MAX_MESSAGE_SIZE,
    MAX_NEGOTIATION_ATTEMPTS,
    MULTISTREAM_PROTOCOL_ID,
    NA,
    NegotiationError,
    QuicStreamAdapter,
)
from lean_spec.subspecs.networking.types import ProtocolId
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint

GOSSIPSUB_ID = ProtocolId("/meshsub/1.1.0")
GOSSIPSUB_V12_ID = ProtocolId("/meshsub/1.2.0")
STATUS_ID = ProtocolId("/leanconsensus/req/status/1/ssz_snappy")
BLOCKS_BY_ROOT_ID = ProtocolId("/leanconsensus/req/blocks_by_root/1/ssz_snappy")


class TestConstants:
    """Tests for protocol constants."""

    def test_protocol_id(self) -> None:
        """Protocol ID matches spec."""
        assert MULTISTREAM_PROTOCOL_ID == "/multistream/1.0.0"

    def test_na_constant(self) -> None:
        """NA rejection string."""
        assert NA == "na"


class TestNegotiateClient:
    """Tests for client-side negotiation."""

    async def test_client_accepts_first_protocol(self) -> None:
        """Client successfully negotiates first proposed protocol."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            protocol = await _read_message(server)
            await _write_message(server, protocol)

        task = asyncio.create_task(server_task())
        result = await client.negotiate_client([GOSSIPSUB_ID])
        await task
        assert result == GOSSIPSUB_ID

    async def test_client_tries_multiple_protocols(self) -> None:
        """Client tries protocols until one is accepted."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _read_message(server)
            await _write_message(server, NA)
            protocol = await _read_message(server)
            await _write_message(server, protocol)

        task = asyncio.create_task(server_task())
        result = await client.negotiate_client([GOSSIPSUB_V12_ID, GOSSIPSUB_ID])
        await task
        assert result == GOSSIPSUB_ID

    async def test_client_all_rejected(self) -> None:
        """Client raises error when all protocols rejected."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _read_message(server)
            await _write_message(server, NA)
            await _read_message(server)
            await _write_message(server, NA)

        task = asyncio.create_task(server_task())
        with pytest.raises(NegotiationError, match="No protocols accepted"):
            await client.negotiate_client([ProtocolId("/proto1"), ProtocolId("/proto2")])
        await task

    async def test_client_empty_protocols(self) -> None:
        """Client raises error when no protocols provided."""
        stream, _ = _create_stream_pair()
        with pytest.raises(NegotiationError, match="No protocols to negotiate"):
            await stream.negotiate_client([])

    async def test_client_invalid_header(self) -> None:
        """Client raises error on invalid header."""
        client, server = _create_stream_pair()
        await _write_message(server, "/wrong/1.0.0")

        with pytest.raises(NegotiationError, match="Invalid multistream header"):
            await client.negotiate_client([GOSSIPSUB_ID])

    async def test_client_unexpected_response(self) -> None:
        """Client gets neither protocol nor na"""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _read_message(server)
            await _write_message(server, "/unexpected/response")
            await _write_message(server, "<><><>")

        task = asyncio.create_task(server_task())
        with pytest.raises(NegotiationError, match="Unexpected response"):
            await client.negotiate_client([GOSSIPSUB_ID])
        await task


class TestNegotiateServer:
    """Tests for server-side negotiation."""

    async def test_server_accepts_supported_protocol(self) -> None:
        """Server accepts protocol it supports."""
        server, client = _create_stream_pair()

        async def client_task() -> None:
            await _write_message(client, MULTISTREAM_PROTOCOL_ID)
            await _read_message(client)
            await _write_message(client, GOSSIPSUB_ID)
            await _read_message(client)

        task = asyncio.create_task(client_task())
        result = await server.negotiate_server({GOSSIPSUB_ID, STATUS_ID})
        await task
        assert result == GOSSIPSUB_ID

    async def test_server_rejects_unsupported_then_accepts(self) -> None:
        """Server rejects unsupported protocols."""
        server, client = _create_stream_pair()

        async def client_task() -> None:
            await _write_message(client, MULTISTREAM_PROTOCOL_ID)
            await _read_message(client)
            await _write_message(client, GOSSIPSUB_V12_ID)
            response1 = await _read_message(client)
            assert response1 == NA
            await _write_message(client, GOSSIPSUB_ID)
            response2 = await _read_message(client)
            assert response2 == GOSSIPSUB_ID

        task = asyncio.create_task(client_task())
        result = await server.negotiate_server({GOSSIPSUB_ID})
        await task
        assert result == GOSSIPSUB_ID

    async def test_server_empty_supported(self) -> None:
        """Server raises error when no supported protocols."""
        stream, _ = _create_stream_pair()
        with pytest.raises(NegotiationError, match="No supported protocols"):
            await stream.negotiate_server(set())

    async def test_server_invalid_header(self) -> None:
        """Server raises error on invalid client header."""
        server, client = _create_stream_pair()
        await _write_message(client, "/wrong/1.0.0")

        with pytest.raises(NegotiationError, match="Invalid multistream header"):
            await server.negotiate_server({GOSSIPSUB_ID})

    async def test_server_client_unsupported_server_supported(self) -> None:
        """Client proposes unsupported, then supported protocol"""
        server, client = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _read_message(server)
            await _write_message(server, NA)
            protocol = await _read_message(server)
            await _write_message(server, protocol)

        task = asyncio.create_task(server_task())
        result = await client.negotiate_client([ProtocolId("/unsupported"), GOSSIPSUB_ID])
        await task
        assert result == GOSSIPSUB_ID

    async def test_server_too_many_attempts(self) -> None:
        """Client uses too many attempts"""
        server, client = _create_stream_pair()

        async def client_task() -> None:
            await _write_message(client, MULTISTREAM_PROTOCOL_ID)
            header = await _read_message(client)
            assert header == MULTISTREAM_PROTOCOL_ID

            for i in range(MAX_NEGOTIATION_ATTEMPTS):
                await _write_message(client, ProtocolId(f"/proto{i}"))
                resp = await _read_message(client)
                assert resp == NA

        task = asyncio.create_task(client_task())

        with pytest.raises(NegotiationError, match="Too many negotiation attempts"):
            await server.negotiate_server({GOSSIPSUB_ID})
        await task

    @pytest.mark.anyio
    async def test_server_timeout(self) -> None:
        """Server raises error when negotiation times out."""
        server, _ = _create_stream_pair()

        async def slow_read() -> bytes:
            await asyncio.sleep(1000)
            return b""

        server._stream.read = slow_read  # type: ignore[method-assign]

        with pytest.raises(NegotiationError, match="Negotiation timed out"):
            await server.negotiate_server({GOSSIPSUB_ID}, timeout=0.1)


class TestLazyClient:
    """Tests for lazy client negotiation."""

    async def test_lazy_client_single_protocol(self) -> None:
        """Lazy client sends header and proposal together."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            header = await _read_message(server)
            assert header == MULTISTREAM_PROTOCOL_ID
            protocol = await _read_message(server)
            assert protocol == GOSSIPSUB_ID
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _write_message(server, protocol)

        task = asyncio.create_task(server_task())
        result = await client.negotiate_lazy_client(GOSSIPSUB_ID)
        await task
        assert result == GOSSIPSUB_ID

    async def test_lazy_client_rejected(self) -> None:
        """Lazy client raises error when protocol rejected."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _write_message(server, NA)

        task = asyncio.create_task(server_task())
        with pytest.raises(NegotiationError, match="Protocol rejected"):
            await client.negotiate_lazy_client(ProtocolId("/unsupported"))
        await task

    async def test_lazy_client_invalid_header(self) -> None:
        """Lazy client raises error on invalid server header."""
        client, server = _create_stream_pair()
        await _write_message(server, "/wrong/1.0.0")

        with pytest.raises(NegotiationError, match="Invalid multistream header"):
            await client.negotiate_lazy_client(GOSSIPSUB_ID)

    @pytest.mark.anyio
    async def test_lazy_client_unexpected_response(self) -> None:
        """Lazy client raises error on unexpected response."""
        client, server = _create_stream_pair()

        async def server_task() -> None:
            await _read_message(server)
            await _read_message(server)
            await _write_message(server, MULTISTREAM_PROTOCOL_ID)
            await _write_message(server, "/unexpected")

        task = asyncio.create_task(server_task())
        with pytest.raises(NegotiationError, match="Unexpected response"):
            await client.negotiate_lazy_client(GOSSIPSUB_ID)
        await task


class TestMessageFormat:
    """Tests for wire message format."""

    async def test_message_format(self) -> None:
        """Messages are length-prefixed with trailing newline."""
        stream, peer = _create_stream_pair()
        await _write_message(peer, STATUS_ID)

        raw = await stream.read(100)
        expected_payload = STATUS_ID.encode("utf-8") + b"\n"
        expected_len = len(expected_payload)
        assert raw[0] == expected_len
        assert raw[1:] == expected_payload

    async def test_message_roundtrip(self) -> None:
        """Write then read returns original message."""
        stream, peer = _create_stream_pair()
        await _write_message(peer, BLOCKS_BY_ROOT_ID)
        received = await _read_message(stream)
        assert received == BLOCKS_BY_ROOT_ID

    async def test_read_returns_buffered_data_first(self) -> None:
        """Data already in buffer returned first"""
        stream, peer = _create_stream_pair()
        peer.write(b"ABCDEFG")
        await peer.drain()
        first = await stream.read(1)
        assert first == b"A"
        rest = await stream.read(100)
        assert rest == b"BCDEFG"

    async def test_read_buffer_overflow(self) -> None:
        """Buffer has more than n bytes, leftover stays"""
        stream, peer = _create_stream_pair()
        peer.write(b"ABCDEFG")
        await peer.drain()

        first = await stream.read(1)
        second = await stream.read(5)
        await peer.finish_write()
        third = await stream.read(10)
        empty = await stream.read(1)

        assert first == b"A"
        assert second == b"BCDEF"
        assert third == b"G"
        assert empty == b""

    async def test_read_buffer_no_limit(self) -> None:
        """Returns all available data from buffer, then stream"""
        stream, peer = _create_stream_pair()
        peer.write(b"ABCDEFG")
        await peer.drain()

        first = await stream.read()
        assert first == b"ABCDEFG"

    async def test_read_buffer_empty_stream(self) -> None:
        """Return b"" when stream is closed"""
        stream, peer = _create_stream_pair()
        await peer.finish_write()
        empty = await stream.read()
        assert empty == b""

    async def test_read_buffer_partial_data(self) -> None:
        """Stream returns less than n bytes"""
        stream, peer = _create_stream_pair()
        peer.write(b"ABCDEFG")
        await peer.drain()
        await peer.finish_write()

        first = await stream.read(10)
        leftover = await stream.read()
        assert first == b"ABCDEFG"
        assert leftover == b""

    async def test_readexactly_accumulates_chunks(self) -> None:
        """Accumulates chunks until n bytes available"""
        stream, peer = _create_stream_pair()
        peer.write(b"AB")
        peer.write(b"CDE")
        peer.write(b"FG")
        await peer.drain()
        result = await stream.readexactly(6)
        assert result == b"ABCDEF"
        assert await stream.read() == b"G"

    async def test_readexactly_eof_error(self) -> None:
        """Stream closes before n bytes received"""
        stream, peer = _create_stream_pair()
        peer.write(b"ABC")
        await peer.finish_write()
        await peer.drain()
        with pytest.raises(EOFError):
            await stream.readexactly(6)

    async def test_write_drain_buffers(self) -> None:
        """Write accumulates, drain flushes to stream"""
        stream, peer = _create_stream_pair()
        stream.write(b"A")
        stream.write(b"B")

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(peer.read(), timeout=0.01)
        await stream.drain()
        assert await peer.read() == b"AB"

    async def test_empty_drain(self) -> None:
        """Drain with no buffered data is no-op"""
        stream, peer = _create_stream_pair()
        await stream.drain()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(peer.read(), timeout=0.01)

    async def test_finish_write(self) -> None:
        """Flushes buffer before sending FIN"""
        stream, peer = _create_stream_pair()
        stream.write(b"HELLO")
        await stream.finish_write()
        first = await peer.read()
        second = await peer.read()
        assert first == b"HELLO"
        assert second == b""

    async def test_finish_write_no_data(self) -> None:
        """Finish write without buffered data just sends FIN"""
        stream, peer = _create_stream_pair()
        await stream.finish_write()
        first = await peer.read()
        assert first == b""

    async def test_read_negotiation_message_valid(self) -> None:
        """Valid message is Varint length + payload + newline"""
        stream, peer = _create_stream_pair()

        payload = b"/my/proto/1.0.0\n"
        length_prefix = encode_varint(len(payload))
        framed = length_prefix + payload

        peer.write(framed)
        await peer.drain()

        result = await stream._read_negotiation_message()
        assert result == "/my/proto/1.0.0"

    async def test_read_negotiation_message_connection_closed(self) -> None:
        """Connection closed"""
        stream, peer = _create_stream_pair()
        await peer.finish_write()
        await peer.drain()
        with pytest.raises(NegotiationError, match="Connection closed while reading length"):
            await stream._read_negotiation_message()

    async def test_read_negotiation_message_varint_too_long(self) -> None:
        """Varint too long"""
        stream, peer = _create_stream_pair()
        peer.write(b"\x80\x80\x80\x80\x80\x80")
        await peer.drain()
        with pytest.raises(NegotiationError, match="Varint too long"):
            await stream._read_negotiation_message()

    async def test_read_negotiation_message_message_too_long(self) -> None:
        """Message too long"""
        stream, peer = _create_stream_pair()
        too_big_len = MAX_MESSAGE_SIZE + 1
        payload = b"A" * too_big_len
        length_prefix = encode_varint(len(payload))
        peer.write(length_prefix)
        await peer.drain()

        with pytest.raises(NegotiationError, match="Message too large"):
            await stream._read_negotiation_message()

    async def test_read_negotiation_message_empty_message(self) -> None:
        """Empty message"""
        stream, peer = _create_stream_pair()
        peer.write(encode_varint(0))
        await peer.drain()
        with pytest.raises(NegotiationError, match="Empty message"):
            await stream._read_negotiation_message()

    async def test_read_negotiation_message_no_trailing_newline(self) -> None:
        """No trailing newline"""
        stream, peer = _create_stream_pair()
        payload = b"/my/proto/1.0.0"
        length_prefix = encode_varint(len(payload))
        peer.write(length_prefix + payload)
        await peer.drain()

        with pytest.raises(NegotiationError, match="Message must end with newline"):
            await stream._read_negotiation_message()

    async def test_read_negotiation_message_invalid_varint(self, monkeypatch) -> None:
        """Invalid varint"""
        stream, peer = _create_stream_pair()
        peer.write(b"\x01")
        await peer.drain()
        import lean_spec.subspecs.networking.transport.quic.stream_adapter as module

        def fake_decode_varint(_):
            raise ValueError("bad varint")

        monkeypatch.setattr(module, "decode_varint", fake_decode_varint)

        with pytest.raises(NegotiationError, match="Invalid varint: bad varint"):
            await stream._read_negotiation_message()

    async def test_write_negotiation_message_format(self) -> None:
        """Write negotiation message with correct varint"""
        stream, peer = _create_stream_pair()
        await stream._write_negotiation_message("/my/proto/1.0.0")
        raw = await peer.read()
        expected_payload = b"/my/proto/1.0.0\n"
        expected = encode_varint(len(expected_payload)) + expected_payload

        assert raw == expected


class TestBufferedIO:
    """Tests for buffered read/write operations."""

    async def test_read_n_none_returns_buffer(self) -> None:
        """read(n=None) returns buffered data."""
        stream, _ = _create_stream_pair()
        stream._buffer = b"already buffered"
        result = await stream.read()
        assert result == b"already buffered"
        assert stream._buffer == b""

    async def test_read_n_none_empty_buffer(self) -> None:
        """read(n=None) with empty buffer reads from stream."""
        stream, peer = _create_stream_pair()
        stream._stream._read_queue.put_nowait(b"from stream")  # type: ignore[attr-defined]
        result = await stream.read()
        assert result == b"from stream"

    async def test_read_partial_buffer(self) -> None:
        """read(n) returns from buffer when buffer has less than n."""
        stream, _ = _create_stream_pair()
        stream._buffer = b"abc"
        result = await stream.read(5)
        assert result == b"abc"
        assert stream._buffer == b""

    async def test_read_buffer_overflow(self) -> None:
        """read(n) keeps leftover when buffer exceeds n."""
        stream, _ = _create_stream_pair()
        stream._buffer = b"abcdef"
        result = await stream.read(3)
        assert result == b"abc"
        assert stream._buffer == b"def"

    async def test_read_empty_stream(self) -> None:
        """read(n) returns empty bytes when stream is closed."""
        stream, _ = _create_stream_pair()
        stream._buffer = b""
        stream._stream._read_queue.put_nowait(b"")  # type: ignore[attr-defined]
        result = await stream.read(10)
        assert result == b""

    async def test_readexactly_accumulates_chunks(self) -> None:
        """readexactly accumulates chunks until n bytes."""
        stream, peer = _create_stream_pair()
        stream._stream._read_queue.put_nowait(b"ab")  # type: ignore[attr-defined]
        stream._stream._read_queue.put_nowait(b"cd")  # type: ignore[attr-defined]
        result = await stream.readexactly(4)
        assert result == b"abcd"
        assert stream._buffer == b""

    async def test_readexactly_eof_error(self) -> None:
        """readexactly raises EOFError when stream closes early."""
        stream, peer = _create_stream_pair()
        stream._stream._read_queue.put_nowait(b"partial")  # type: ignore[attr-defined]
        stream._stream._read_queue.put_nowait(b"")  # type: ignore[attr-defined]
        with pytest.raises(EOFError, match="Stream closed"):
            await stream.readexactly(100)

    async def test_drain_empty_buffer(self) -> None:
        """drain() with no buffered data is a no-op."""
        stream, _ = _create_stream_pair()
        stream._write_buffer = b""
        await stream.drain()
        assert stream._write_buffer == b""

    async def test_drain_flushes_buffer(self) -> None:
        """drain() flushes buffered data to stream."""
        stream, peer = _create_stream_pair()
        stream.write(b"data to flush")
        await stream.drain()
        assert stream._write_buffer == b""
        received = await peer.read()
        assert received == b"data to flush"

    async def test_close_delegates_to_stream(self) -> None:
        """close() calls underlying stream's close."""
        stream, _ = _create_stream_pair()
        close_called = False

        async def mock_close() -> None:
            nonlocal close_called
            close_called = True

        stream._stream.close = mock_close  # type: ignore[method-assign]
        await stream.close()
        assert close_called

    async def test_finish_write_with_buffer(self) -> None:
        """finish_write() flushes buffer then sends FIN."""
        stream, peer = _create_stream_pair()
        stream.write(b"buffered")
        await stream.finish_write()
        assert stream._write_buffer == b""
        received = await peer.read()
        assert received == b"buffered"

    async def test_finish_write_without_buffer(self) -> None:
        """finish_write() just sends FIN when no buffered data."""
        stream, _ = _create_stream_pair()
        stream._write_buffer = b""
        await stream.finish_write()


class TestReadNegotiationMessage:
    """Tests for _read_negotiation_message edge cases."""

    async def test_message_connection_closed(self) -> None:
        """Raises error when connection closes while reading length."""
        stream, peer = _create_stream_pair()
        stream._stream._read_queue.put_nowait(b"")  # type: ignore[attr-defined]
        with pytest.raises(NegotiationError, match="Connection closed"):
            await stream._read_negotiation_message()

    async def test_message_varint_too_long(self) -> None:
        """Raises error when varint has more than 5 continuation bytes."""
        stream, peer = _create_stream_pair()
        stream._stream._read_queue.put_nowait(bytes([0x80, 0x80, 0x80, 0x80, 0x80, 0x80]))  # type: ignore[attr-defined]
        with pytest.raises(NegotiationError, match="Varint too long"):
            await stream._read_negotiation_message()

    @pytest.mark.anyio
    async def test_message_invalid_varint(self) -> None:
        """Raises error when varint decoding fails."""
        stream, _ = _create_stream_pair()
        with patch(
            "lean_spec.subspecs.networking.transport.quic.stream_adapter.decode_varint",
            side_effect=ValueError("Invalid varint encoding"),
        ):
            stream._stream.read = AsyncMock(return_value=bytes([0x7F]))  # type: ignore[method-assign]
            with pytest.raises(NegotiationError, match="Invalid varint"):
                await stream._read_negotiation_message()

    async def test_message_too_large(self) -> None:
        """Raises error when message exceeds MAX_MESSAGE_SIZE."""
        stream, peer = _create_stream_pair()
        stream._buffer = bytes([0x80, 0x10])
        with pytest.raises(NegotiationError, match="Message too large"):
            await stream._read_negotiation_message()

    async def test_message_empty(self) -> None:
        """Raises error when message length is zero."""
        stream, peer = _create_stream_pair()
        stream._buffer = bytes([0])
        with pytest.raises(NegotiationError, match="Empty message"):
            await stream._read_negotiation_message()

    async def test_message_no_trailing_newline(self) -> None:
        """Raises error when message doesn't end with newline."""
        stream, peer = _create_stream_pair()
        payload = b"no newline"
        length_prefix = encode_varint(len(payload))
        stream._buffer = length_prefix + payload
        with pytest.raises(NegotiationError, match="Message must end with newline"):
            await stream._read_negotiation_message()


class TestFullNegotiation:
    """Integration tests for full negotiation scenarios."""

    async def test_bidirectional_negotiation(self) -> None:
        """Client and server negotiate successfully."""
        client, server = _create_stream_pair()

        async def client_task() -> str:
            return await client.negotiate_client([GOSSIPSUB_ID, STATUS_ID])

        async def server_task() -> str:
            return await server.negotiate_server({GOSSIPSUB_ID, BLOCKS_BY_ROOT_ID})

        client_result, server_result = await asyncio.gather(
            client_task(),
            server_task(),
        )
        assert client_result == GOSSIPSUB_ID
        assert server_result == GOSSIPSUB_ID

    async def test_negotiate_status(self) -> None:
        """Negotiate status protocol."""
        client, server = _create_stream_pair()

        async def client_task() -> str:
            return await client.negotiate_client([STATUS_ID])

        async def server_task() -> str:
            return await server.negotiate_server({STATUS_ID})

        client_result, server_result = await asyncio.gather(
            client_task(),
            server_task(),
        )
        assert client_result == STATUS_ID
        assert server_result == STATUS_ID

    async def test_negotiate_with_fallback(self) -> None:
        """Client falls back to second option when first rejected."""
        client, server = _create_stream_pair()

        async def client_task() -> str:
            return await client.negotiate_client([GOSSIPSUB_V12_ID, GOSSIPSUB_ID])

        async def server_task() -> str:
            return await server.negotiate_server({GOSSIPSUB_ID})

        client_result, server_result = await asyncio.gather(
            client_task(),
            server_task(),
        )
        assert client_result == GOSSIPSUB_ID
        assert server_result == GOSSIPSUB_ID


@dataclass
class _MockStream:
    """In-memory stream for testing.

    Two instances cross-connected via asyncio queues simulate a
    bidirectional QUIC stream pair.
    """

    _read_queue: asyncio.Queue[bytes] = field(default_factory=asyncio.Queue)
    _write_queue: asyncio.Queue[bytes] | None = None
    close_called: bool = False

    async def read(self) -> bytes:
        """Read next chunk from the queue."""
        return await self._read_queue.get()

    async def write(self, data: bytes) -> None:
        """Write data to the peer's read queue."""
        if self._write_queue is not None:
            self._write_queue.put_nowait(data)

    async def finish_write(self) -> None:
        """Signal end of writing."""
        if self._write_queue is not None:
            self._write_queue.put_nowait(b"")

    async def close(self) -> None:
        """Close the stream."""
        self.close_called = True
        if self._write_queue is not None:
            self._write_queue.put_nowait(b"")


class TestClose:
    """Integration test for calling underlying stream's close"""

    async def test_close_delegates_to_underlying(self) -> None:
        """Close delegates to stream"""
        mock = _MockStream(_read_queue=asyncio.Queue(), _write_queue=None)
        await QuicStreamAdapter(cast(QuicStream, mock)).close()
        assert mock.close_called is True


def _create_stream_pair() -> tuple[QuicStreamAdapter, QuicStreamAdapter]:
    """Create a cross-connected pair of QuicStreamAdapters for testing.

    Data written to one adapter is readable from the other.
    """
    a_to_b: asyncio.Queue[bytes] = asyncio.Queue()
    b_to_a: asyncio.Queue[bytes] = asyncio.Queue()

    stream_a = _MockStream(_read_queue=b_to_a, _write_queue=a_to_b)
    stream_b = _MockStream(_read_queue=a_to_b, _write_queue=b_to_a)

    return QuicStreamAdapter(stream_a), QuicStreamAdapter(stream_b)  # type: ignore[arg-type]


async def _write_message(stream: QuicStreamAdapter, message: str) -> None:
    """Write a multistream message to a stream."""
    payload = message.encode("utf-8") + b"\n"
    length_prefix = encode_varint(len(payload))
    stream.write(length_prefix + payload)
    await stream.drain()


async def _read_message(stream: QuicStreamAdapter) -> str:
    """Read a multistream message from a stream."""
    length_bytes = bytearray()
    while True:
        byte = await stream.read(1)
        if not byte:
            raise NegotiationError("Connection closed")
        length_bytes.append(byte[0])
        if byte[0] & 0x80 == 0:
            break

    length, _ = decode_varint(bytes(length_bytes))
    payload = await stream.readexactly(length)

    if not payload.endswith(b"\n"):
        raise NegotiationError("Message must end with newline")

    return payload[:-1].decode("utf-8")
