"""Tests for outbound ReqResp protocol client."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from lean_spec.subspecs.containers import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.networking.client.reqresp_client import (
    REQUEST_TIMEOUT_SECONDS,
    ReqRespClient,
)
from lean_spec.subspecs.networking.reqresp.codec import (
    ResponseCode,
    encode_request,
)
from lean_spec.subspecs.networking.reqresp.message import (
    BLOCKS_BY_ROOT_PROTOCOL_V1,
    STATUS_PROTOCOL_V1,
    Status,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import make_test_block, make_test_status


@dataclass
class MockStream:
    """Mock stream for testing ReqRespClient."""

    stream_id: int = 0
    """Mock stream ID."""

    protocol_id: str = STATUS_PROTOCOL_V1
    """The negotiated protocol ID."""

    response_chunks: list[bytes] = field(default_factory=list)
    """Response chunks to return on successive read() calls."""

    written: list[bytes] = field(default_factory=list)
    """Data written to the stream."""

    closed: bool = False
    """Whether close() has been called."""

    finish_write_called: bool = False
    """Whether finish_write() has been called."""

    _read_index: int = 0
    """Index into response_chunks for next read()."""

    _fail_on_read: bool = False
    """If True, raise ConnectionError on read()."""

    _fail_on_write: bool = False
    """If True, raise ConnectionError on write()."""

    async def read(self) -> bytes:
        """Return next response chunk, or empty if exhausted."""
        if self._fail_on_read:
            raise ConnectionError("Read failed")
        if self._read_index >= len(self.response_chunks):
            return b""
        chunk = self.response_chunks[self._read_index]
        self._read_index += 1
        return chunk

    async def write(self, data: bytes) -> None:
        """Accumulate written data."""
        if self._fail_on_write:
            raise ConnectionError("Write failed")
        self.written.append(data)

    async def finish_write(self) -> None:
        """Signal half-close."""
        self.finish_write_called = True

    async def close(self) -> None:
        """Mark stream as closed."""
        self.closed = True


@dataclass
class MockConnection:
    """Mock connection for testing ReqRespClient."""

    streams: list[MockStream] = field(default_factory=list)
    """Pre-configured streams to return on open_stream()."""

    opened_protocols: list[str] = field(default_factory=list)
    """Protocols requested via open_stream()."""

    _stream_index: int = 0
    """Index into streams for next open_stream()."""

    _fail_on_open: bool = False
    """If True, raise ConnectionError on open_stream()."""

    async def open_stream(self, protocol: str) -> MockStream:
        """Return next configured stream."""
        if self._fail_on_open:
            raise ConnectionError("Failed to open stream")
        self.opened_protocols.append(protocol)
        if self._stream_index >= len(self.streams):
            return MockStream(protocol_id=protocol)
        stream = self.streams[self._stream_index]
        stream.protocol_id = protocol
        self._stream_index += 1
        return stream


def make_client() -> ReqRespClient:
    """Create a ReqRespClient with a mock connection manager."""
    # Tests use mock connections directly, not the connection manager.
    # We just need something to satisfy the type.
    return ReqRespClient(connection_manager=None)  # type: ignore[arg-type]


class TestReqRespClientConnectionManagement:
    """Tests for connection registration and management."""

    def test_register_connection(self) -> None:
        """Connections can be registered for a peer."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")
        conn = MockConnection()

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        assert peer_id in client._connections
        assert client._connections[peer_id] is conn

    def test_unregister_connection(self) -> None:
        """Connections can be unregistered."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")
        conn = MockConnection()

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]
        client.unregister_connection(peer_id)

        assert peer_id not in client._connections

    def test_unregister_nonexistent_connection(self) -> None:
        """Unregistering nonexistent connection doesn't raise."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # Should not raise
        client.unregister_connection(peer_id)

    def test_register_overwrites_existing(self) -> None:
        """New registration overwrites old connection."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")
        conn1 = MockConnection()
        conn2 = MockConnection()

        client.register_connection(peer_id, conn1)  # type: ignore[arg-type]
        client.register_connection(peer_id, conn2)  # type: ignore[arg-type]

        assert client._connections[peer_id] is conn2


class TestReqRespClientStatusExchange:
    """Tests for Status request/response exchange."""

    async def test_send_status_success(self) -> None:
        """Successfully exchange status with a peer."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # Prepare peer's status response
        peer_status = Status(
            finalized=Checkpoint(root=Bytes32(b"\xaa" * 32), slot=Slot(50)),
            head=Checkpoint(root=Bytes32(b"\xbb" * 32), slot=Slot(150)),
        )
        response_bytes = ResponseCode.SUCCESS.encode(peer_status.encode_bytes())

        stream = MockStream(response_chunks=[response_bytes])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        our_status = make_test_status()
        result = await client.send_status(peer_id, our_status)

        assert result is not None
        assert result.head.slot == Slot(150)
        assert result.finalized.slot == Slot(50)

    async def test_send_status_no_connection(self) -> None:
        """Request to unconnected peer returns None."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # No connection registered
        our_status = make_test_status()
        result = await client.send_status(peer_id, our_status)

        assert result is None

    async def test_send_status_server_error_response(self) -> None:
        """SERVER_ERROR response returns None."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        response_bytes = ResponseCode.SERVER_ERROR.encode(b"Internal error")
        stream = MockStream(response_chunks=[response_bytes])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        result = await client.send_status(peer_id, make_test_status())

        assert result is None

    async def test_send_status_stream_closed(self) -> None:
        """Empty response (closed stream) returns None."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # Empty response simulates closed stream
        stream = MockStream(response_chunks=[])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        result = await client.send_status(peer_id, make_test_status())

        assert result is None

    async def test_send_status_writes_request(self) -> None:
        """Request is properly encoded and sent."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        peer_status = make_test_status()
        response_bytes = ResponseCode.SUCCESS.encode(peer_status.encode_bytes())

        stream = MockStream(response_chunks=[response_bytes])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        our_status = make_test_status()
        await client.send_status(peer_id, our_status)

        assert len(stream.written) == 1
        # Should be properly encoded request (varint + snappy)
        expected_wire = encode_request(make_test_status().encode_bytes())
        assert stream.written[0] == expected_wire

    async def test_send_status_closes_stream(self) -> None:
        """Stream is closed after exchange."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        peer_status = make_test_status()
        response_bytes = ResponseCode.SUCCESS.encode(peer_status.encode_bytes())

        stream = MockStream(response_chunks=[response_bytes])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        await client.send_status(peer_id, make_test_status())

        assert stream.closed is True
        assert stream.finish_write_called is True


class TestReqRespClientBlocksByRoot:
    """Tests for BlocksByRoot request handling."""

    async def test_request_single_block_success(self) -> None:
        """Successfully request a single block."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        block = make_test_block(slot=10, seed=10)
        response_bytes = ResponseCode.SUCCESS.encode(block.encode_bytes())

        stream = MockStream(response_chunks=[response_bytes])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        assert len(blocks) == 1
        assert blocks[0].block.slot == Slot(10)

    async def test_request_multiple_blocks_success(self) -> None:
        """Successfully request multiple blocks."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        block1 = make_test_block(slot=10, seed=10)
        block2 = make_test_block(slot=20, seed=20)
        response1 = ResponseCode.SUCCESS.encode(block1.encode_bytes())
        response2 = ResponseCode.SUCCESS.encode(block2.encode_bytes())

        stream = MockStream(response_chunks=[response1, response2])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        assert len(blocks) == 2
        slots = {b.block.slot for b in blocks}
        assert Slot(10) in slots
        assert Slot(20) in slots

    async def test_request_blocks_partial_response(self) -> None:
        """Handle partial response (some blocks unavailable)."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        block = make_test_block(slot=10, seed=10)
        success_response = ResponseCode.SUCCESS.encode(block.encode_bytes())
        unavailable_response = ResponseCode.RESOURCE_UNAVAILABLE.encode(b"Not found")

        stream = MockStream(response_chunks=[success_response, unavailable_response])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        # Only one block returned, RESOURCE_UNAVAILABLE continues reading
        assert len(blocks) == 1
        assert blocks[0].block.slot == Slot(10)

    async def test_request_blocks_empty_request(self) -> None:
        """Empty root list returns empty without request."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        conn = MockConnection()
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_root(peer_id, [])

        assert len(blocks) == 0
        # No stream should be opened for empty request
        assert len(conn.opened_protocols) == 0

    async def test_request_blocks_no_connection(self) -> None:
        """Request to unconnected peer returns empty."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # No connection registered
        roots = [Bytes32(b"\x11" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        assert len(blocks) == 0

    async def test_request_blocks_stream_closed_early(self) -> None:
        """Handle stream closing before all blocks."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        block = make_test_block(slot=10, seed=10)
        response = ResponseCode.SUCCESS.encode(block.encode_bytes())

        # Only one response, but we request two blocks
        stream = MockStream(response_chunks=[response])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        # Only one block received before stream closed
        assert len(blocks) == 1

    async def test_request_blocks_server_error_stops_reading(self) -> None:
        """SERVER_ERROR stops reading more blocks."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        block = make_test_block(slot=10, seed=10)
        success_response = ResponseCode.SUCCESS.encode(block.encode_bytes())
        error_response = ResponseCode.SERVER_ERROR.encode(b"Database error")

        # Error response should stop reading (not continue like RESOURCE_UNAVAILABLE)
        stream = MockStream(response_chunks=[success_response, error_response])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32), Bytes32(b"\x33" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        # Only block before SERVER_ERROR is returned
        assert len(blocks) == 1


class TestReqRespClientTimeouts:
    """Tests for request timeout handling."""

    async def test_status_timeout_returns_none(self) -> None:
        """Status request timing out returns None."""
        client = make_client()
        client.timeout = 0.01  # Very short timeout
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        async def slow_read() -> bytes:
            await asyncio.sleep(1.0)  # Longer than timeout
            return b""

        stream = MockStream()
        stream.read = slow_read  # type: ignore[method-assign]
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        result = await client.send_status(peer_id, make_test_status())

        assert result is None

    async def test_blocks_by_root_timeout_returns_empty(self) -> None:
        """BlocksByRoot timeout returns empty list."""
        client = make_client()
        client.timeout = 0.01  # Very short timeout
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        async def slow_read() -> bytes:
            await asyncio.sleep(1.0)  # Longer than timeout
            return b""

        stream = MockStream()
        stream.read = slow_read  # type: ignore[method-assign]
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        assert len(blocks) == 0

    def test_default_timeout_is_reasonable(self) -> None:
        """Timeout constant is within reasonable bounds."""
        # Should be at least a few seconds for network latency
        assert REQUEST_TIMEOUT_SECONDS >= 1.0
        # Should not be excessively long
        assert REQUEST_TIMEOUT_SECONDS <= 60.0


class TestReqRespClientErrorHandling:
    """Tests for error handling and recovery."""

    async def test_write_failure_returns_gracefully(self) -> None:
        """Write failure during request handled gracefully."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        stream = MockStream(_fail_on_write=True)
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        result = await client.send_status(peer_id, make_test_status())

        assert result is None

    async def test_read_failure_returns_gracefully(self) -> None:
        """Read failure during response handled gracefully."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        stream = MockStream(_fail_on_read=True)
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        result = await client.send_status(peer_id, make_test_status())

        assert result is None

    async def test_open_stream_failure_returns_gracefully(self) -> None:
        """Failure to open stream handled gracefully."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        conn = MockConnection(_fail_on_open=True)
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        result = await client.send_status(peer_id, make_test_status())

        assert result is None

    async def test_malformed_response_handled(self) -> None:
        """Malformed response data handled gracefully."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # Invalid response: wrong response code format
        malformed = b"\xff\xff\xff\xff"
        stream = MockStream(response_chunks=[malformed])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        result = await client.send_status(peer_id, make_test_status())

        assert result is None

    async def test_blocks_codec_error_stops_reading(self) -> None:
        """CodecError during block response stops reading."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        block = make_test_block(slot=10, seed=10)
        valid_response = ResponseCode.SUCCESS.encode(block.encode_bytes())
        # Malformed response triggers CodecError
        malformed = b"\x00\xff\xff\xff"

        stream = MockStream(response_chunks=[valid_response, malformed])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        # Only block before codec error is returned
        assert len(blocks) == 1
        assert blocks[0].block.slot == Slot(10)


class TestReqRespClientConcurrency:
    """Tests for concurrent request handling."""

    async def test_concurrent_status_to_different_peers(self) -> None:
        """Concurrent requests to different peers work."""
        client = make_client()
        peer1 = PeerId.from_base58("16Uiu2HAmTestPeer123")
        peer2 = PeerId.from_base58("16Uiu2HAmTestPeer456")

        status1 = Status(
            finalized=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(100)),
            head=Checkpoint(root=Bytes32(b"\x12" * 32), slot=Slot(200)),
        )
        status2 = Status(
            finalized=Checkpoint(root=Bytes32(b"\x21" * 32), slot=Slot(300)),
            head=Checkpoint(root=Bytes32(b"\x22" * 32), slot=Slot(400)),
        )

        response1 = ResponseCode.SUCCESS.encode(status1.encode_bytes())
        response2 = ResponseCode.SUCCESS.encode(status2.encode_bytes())

        stream1 = MockStream(response_chunks=[response1])
        stream2 = MockStream(response_chunks=[response2])

        conn1 = MockConnection(streams=[stream1])
        conn2 = MockConnection(streams=[stream2])

        client.register_connection(peer1, conn1)  # type: ignore[arg-type]
        client.register_connection(peer2, conn2)  # type: ignore[arg-type]

        our_status = make_test_status()
        results = list(
            await asyncio.gather(
                client.send_status(peer1, our_status),
                client.send_status(peer2, our_status),
            )
        )

        assert len(results) == 2
        assert results[0] is not None
        assert results[1] is not None
        # Verify we got different responses
        assert results[0].head.slot == Slot(200)
        assert results[1].head.slot == Slot(400)

    async def test_concurrent_mixed_requests(self) -> None:
        """Concurrent Status and BlocksByRoot work."""
        client = make_client()
        peer1 = PeerId.from_base58("16Uiu2HAmTestPeer123")
        peer2 = PeerId.from_base58("16Uiu2HAmTestPeer456")

        peer_status = Status(
            finalized=Checkpoint(root=Bytes32(b"\x11" * 32), slot=Slot(100)),
            head=Checkpoint(root=Bytes32(b"\x12" * 32), slot=Slot(200)),
        )
        block = make_test_block(slot=42, seed=42)

        status_response = ResponseCode.SUCCESS.encode(peer_status.encode_bytes())
        block_response = ResponseCode.SUCCESS.encode(block.encode_bytes())

        stream1 = MockStream(response_chunks=[status_response])
        stream2 = MockStream(response_chunks=[block_response])

        conn1 = MockConnection(streams=[stream1])
        conn2 = MockConnection(streams=[stream2])

        client.register_connection(peer1, conn1)  # type: ignore[arg-type]
        client.register_connection(peer2, conn2)  # type: ignore[arg-type]

        status, blocks = await asyncio.gather(
            client.send_status(peer1, make_test_status()),
            client.request_blocks_by_root(peer2, [Bytes32(b"\x42" * 32)]),
        )

        assert status is not None
        assert status.head.slot == Slot(200)
        assert len(blocks) == 1
        assert blocks[0].block.slot == Slot(42)


class TestReqRespClientStreamLifecycle:
    """Tests for stream lifecycle management."""

    async def test_stream_closed_on_success(self) -> None:
        """Stream closed after successful request."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        peer_status = make_test_status()
        response = ResponseCode.SUCCESS.encode(peer_status.encode_bytes())

        stream = MockStream(response_chunks=[response])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        await client.send_status(peer_id, make_test_status())

        assert stream.closed is True

    async def test_stream_closed_on_error(self) -> None:
        """Stream closed even when request fails."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # Error response
        response = ResponseCode.SERVER_ERROR.encode(b"Error")
        stream = MockStream(response_chunks=[response])
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        await client.send_status(peer_id, make_test_status())

        assert stream.closed is True

    async def test_stream_closed_on_timeout(self) -> None:
        """Stream closed when request times out."""
        client = make_client()
        client.timeout = 0.01  # Very short timeout
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        closed_flag = {"closed": False}

        async def slow_read() -> bytes:
            await asyncio.sleep(1.0)
            return b""

        async def track_close() -> None:
            closed_flag["closed"] = True

        stream = MockStream()
        stream.read = slow_read  # type: ignore[method-assign]
        stream.close = track_close  # type: ignore[method-assign]
        conn = MockConnection(streams=[stream])

        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        await client.send_status(peer_id, make_test_status())

        assert closed_flag["closed"] is True

    async def test_correct_protocol_negotiated(self) -> None:
        """Requests use correct protocol ID."""
        client = make_client()
        peer1 = PeerId.from_base58("16Uiu2HAmTestPeer123")
        peer2 = PeerId.from_base58("16Uiu2HAmTestPeer456")

        status = make_test_status()
        block = make_test_block(slot=1, seed=1)

        status_response = ResponseCode.SUCCESS.encode(status.encode_bytes())
        block_response = ResponseCode.SUCCESS.encode(block.encode_bytes())

        status_stream = MockStream(response_chunks=[status_response])
        block_stream = MockStream(response_chunks=[block_response])

        status_conn = MockConnection(streams=[status_stream])
        block_conn = MockConnection(streams=[block_stream])

        client.register_connection(peer1, status_conn)  # type: ignore[arg-type]
        client.register_connection(peer2, block_conn)  # type: ignore[arg-type]

        await client.send_status(peer1, make_test_status())
        await client.request_blocks_by_root(peer2, [Bytes32(b"\x11" * 32)])

        assert status_conn.opened_protocols == [STATUS_PROTOCOL_V1]
        assert block_conn.opened_protocols == [BLOCKS_BY_ROOT_PROTOCOL_V1]
