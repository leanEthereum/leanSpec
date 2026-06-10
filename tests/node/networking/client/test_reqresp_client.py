"""Tests for outbound ReqResp protocol client."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from consensus_testing import make_test_block, make_test_status
from lean_spec.node.networking.client.reqresp_client import (
    REQUEST_TIMEOUT_SECONDS,
    ReqRespClient,
)
from lean_spec.node.networking.config import MAX_REQUEST_BLOCKS
from lean_spec.node.networking.reqresp.codec import (
    CodecError,
    ResponseCode,
    encode_request,
)
from lean_spec.node.networking.reqresp.message import (
    BLOCKS_BY_RANGE_PROTOCOL_V1,
    BLOCKS_BY_ROOT_PROTOCOL_V1,
    STATUS_PROTOCOL_V1,
    Status,
)
from lean_spec.node.networking.transport import PeerId
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    Block,
    BlockBody,
    MultiMessageAggregate,
    SignedBlock,
)
from lean_spec.spec.ssz import ByteList512KiB, Bytes32, Uint64


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
        connection = MockConnection()

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        assert peer_id in client._connections
        assert client._connections[peer_id] is connection

    def test_unregister_connection(self) -> None:
        """Connections can be unregistered."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")
        connection = MockConnection()

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]
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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        our_status = make_test_status()
        received_status = await client.send_status(peer_id, our_status)

        assert received_status is not None
        assert received_status.head.slot == Slot(150)
        assert received_status.finalized.slot == Slot(50)

    async def test_send_status_no_connection(self) -> None:
        """Request to unconnected peer returns None."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # No connection registered
        our_status = make_test_status()
        received_status = await client.send_status(peer_id, our_status)

        assert received_status is None

    async def test_send_status_server_error_response(self) -> None:
        """SERVER_ERROR response returns None."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        response_bytes = ResponseCode.SERVER_ERROR.encode(b"Internal error")
        stream = MockStream(response_chunks=[response_bytes])
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        received_status = await client.send_status(peer_id, make_test_status())

        assert received_status is None

    async def test_send_status_stream_closed(self) -> None:
        """Empty response (closed stream) returns None."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # Empty response simulates closed stream
        stream = MockStream(response_chunks=[])
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        received_status = await client.send_status(peer_id, make_test_status())

        assert received_status is None

    async def test_send_status_writes_request(self) -> None:
        """Request is properly encoded and sent."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        peer_status = make_test_status()
        response_bytes = ResponseCode.SUCCESS.encode(peer_status.encode_bytes())

        stream = MockStream(response_chunks=[response_bytes])
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        assert len(blocks) == 2
        slots = {signed_block.block.slot for signed_block in blocks}
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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        roots = [Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)]
        blocks = await client.request_blocks_by_root(peer_id, roots)

        # Only one block returned, RESOURCE_UNAVAILABLE continues reading
        assert len(blocks) == 1
        assert blocks[0].block.slot == Slot(10)

    async def test_request_blocks_empty_request(self) -> None:
        """Empty root list returns empty without request."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        connection = MockConnection()
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_root(peer_id, [])

        assert len(blocks) == 0
        # No stream should be opened for empty request
        assert len(connection.opened_protocols) == 0

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        received_status = await client.send_status(peer_id, make_test_status())

        assert received_status is None

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        received_status = await client.send_status(peer_id, make_test_status())

        assert received_status is None

    async def test_read_failure_returns_gracefully(self) -> None:
        """Read failure during response handled gracefully."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        stream = MockStream(_fail_on_read=True)
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        received_status = await client.send_status(peer_id, make_test_status())

        assert received_status is None

    async def test_open_stream_failure_returns_gracefully(self) -> None:
        """Failure to open stream handled gracefully."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        connection = MockConnection(_fail_on_open=True)
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        received_status = await client.send_status(peer_id, make_test_status())

        assert received_status is None

    async def test_malformed_response_handled(self) -> None:
        """Malformed response data handled gracefully."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # Invalid response: wrong response code format
        malformed = b"\xff\xff\xff\xff"
        stream = MockStream(response_chunks=[malformed])
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        received_status = await client.send_status(peer_id, make_test_status())

        assert received_status is None

    async def test_blocks_codec_error_stops_reading(self) -> None:
        """CodecError during block response stops reading."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        block = make_test_block(slot=10, seed=10)
        valid_response = ResponseCode.SUCCESS.encode(block.encode_bytes())
        # Malformed response triggers CodecError
        malformed = b"\x00\xff\xff\xff"

        stream = MockStream(response_chunks=[valid_response, malformed])
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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
        received_statuses = list(
            await asyncio.gather(
                client.send_status(peer1, our_status),
                client.send_status(peer2, our_status),
            )
        )

        assert len(received_statuses) == 2
        assert received_statuses[0] is not None
        assert received_statuses[1] is not None
        # Verify we got different responses
        assert received_statuses[0].head.slot == Slot(200)
        assert received_statuses[1].head.slot == Slot(400)

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        await client.send_status(peer_id, make_test_status())

        assert stream.closed is True

    async def test_stream_closed_on_error(self) -> None:
        """Stream closed even when request fails."""
        client = make_client()
        peer_id = PeerId.from_base58("16Uiu2HAmTestPeer123")

        # Error response
        response = ResponseCode.SERVER_ERROR.encode(b"Error")
        stream = MockStream(response_chunks=[response])
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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
        connection = MockConnection(streams=[stream])

        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

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

        status_connection = MockConnection(streams=[status_stream])
        block_connection = MockConnection(streams=[block_stream])

        client.register_connection(peer1, status_connection)  # type: ignore[arg-type]
        client.register_connection(peer2, block_connection)  # type: ignore[arg-type]

        await client.send_status(peer1, make_test_status())
        await client.request_blocks_by_root(peer2, [Bytes32(b"\x11" * 32)])

        assert status_connection.opened_protocols == [STATUS_PROTOCOL_V1]
        assert block_connection.opened_protocols == [BLOCKS_BY_ROOT_PROTOCOL_V1]


@dataclass
class MockRangeStream:
    """Mock stream feeding a queue of pre-encoded response chunks."""

    stream_id: int = 0
    """Mock stream ID."""

    protocol_id: str = BLOCKS_BY_RANGE_PROTOCOL_V1
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

    async def read(self) -> bytes:
        """Return the next response chunk, or empty bytes when exhausted."""
        if self._read_index >= len(self.response_chunks):
            return b""
        chunk = self.response_chunks[self._read_index]
        self._read_index += 1
        return chunk

    async def write(self, data: bytes) -> None:
        """Accumulate written request bytes."""
        self.written.append(data)

    async def finish_write(self) -> None:
        """Signal half-close."""
        self.finish_write_called = True

    async def close(self) -> None:
        """Mark the stream as closed."""
        self.closed = True


@dataclass
class MockRangeConnection:
    """Mock QUIC connection that exposes a peer_id and a single canned stream."""

    peer_id: PeerId
    """Identity reported on protocol-violation logs."""

    streams: list[MockRangeStream] = field(default_factory=list)
    """Pre-configured streams to return on successive open_stream() calls."""

    opened_protocols: list[str] = field(default_factory=list)
    """Protocols requested via open_stream()."""

    _stream_index: int = 0
    """Index into streams for next open_stream()."""

    async def open_stream(self, protocol: str) -> MockRangeStream:
        """Return the next preconfigured stream, recording the protocol."""
        self.opened_protocols.append(protocol)
        if self._stream_index >= len(self.streams):
            return MockRangeStream(protocol_id=protocol)
        stream = self.streams[self._stream_index]
        stream.protocol_id = protocol
        self._stream_index += 1
        return stream


def empty_signed_block(slot: Slot, parent_root: Bytes32, state_seed: int) -> SignedBlock:
    """Build a SignedBlock with the requested slot and parent_root."""
    block = Block(
        slot=slot,
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        state_root=Bytes32(bytes([state_seed]) * 32),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    return SignedBlock(block=block, proof=MultiMessageAggregate(proof=ByteList512KiB(data=b"")))


def build_chain(start_slot: int, count: int, root_seed: int = 0xAA) -> list[SignedBlock]:
    """
    Return a chain of strictly-increasing-slot blocks starting at start_slot.

    Each child links to its predecessor via the previous block's tree-hash root.
    The root of the first slot is derived from the seed parameter.
    """
    parent_root = Bytes32(bytes([root_seed]) * 32)
    blocks: list[SignedBlock] = []
    for i in range(count):
        block = empty_signed_block(
            slot=Slot(start_slot + i),
            parent_root=parent_root,
            state_seed=(root_seed + i + 1) & 0xFF,
        )
        blocks.append(block)
        parent_root = hash_tree_root(block.block)
    return blocks


def encode_success(block: SignedBlock) -> bytes:
    """Encode a SignedBlock as a SUCCESS response chunk."""
    return ResponseCode.SUCCESS.encode(block.encode_bytes())


class TestReqRespClientBlocksByRange:
    """Tests for the outbound blocks-by-range request flow."""

    async def test_zero_count_returns_empty_without_opening_stream(self, peer_id: PeerId) -> None:
        """A count of zero short-circuits without opening a stream."""
        client = make_client()
        connection = MockRangeConnection(peer_id=peer_id)
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(0), Uint64(0))

        assert blocks == []
        assert connection.opened_protocols == []

    async def test_count_above_max_returns_empty_without_opening_stream(
        self, peer_id: PeerId
    ) -> None:
        """A count strictly larger than MAX_REQUEST_BLOCKS is rejected locally."""
        client = make_client()
        connection = MockRangeConnection(peer_id=peer_id)
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(
            peer_id, Slot(0), Uint64(MAX_REQUEST_BLOCKS + 1)
        )

        assert blocks == []
        assert connection.opened_protocols == []

    async def test_overflow_range_returns_empty_without_opening_stream(
        self, peer_id: PeerId
    ) -> None:
        """A start_slot+count overflow above 2**64-1 is rejected locally."""
        client = make_client()
        connection = MockRangeConnection(peer_id=peer_id)
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        max_slot = int(Uint64.max_value())
        blocks = await client.request_blocks_by_range(peer_id, Slot(max_slot - 4), Uint64(10))

        assert blocks == []
        assert connection.opened_protocols == []

    async def test_no_connection_returns_empty(self, peer_id: PeerId) -> None:
        """A request with no registered connection returns an empty list."""
        client = make_client()

        blocks = await client.request_blocks_by_range(peer_id, Slot(1), Uint64(3))

        assert blocks == []

    async def test_full_range_success(self, peer_id: PeerId) -> None:
        """A clean response of count blocks is returned in order."""
        client = make_client()
        chain = build_chain(start_slot=10, count=4)

        stream = MockRangeStream(
            response_chunks=[encode_success(signed_block) for signed_block in chain]
        )
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(10), Uint64(4))

        assert blocks == chain
        assert connection.opened_protocols == [BLOCKS_BY_RANGE_PROTOCOL_V1]
        assert stream.closed is True
        assert stream.finish_write_called is True

    async def test_partial_response_when_stream_closes_early(self, peer_id: PeerId) -> None:
        """Stream closing before count is reached returns the partial list."""
        client = make_client()
        chain = build_chain(start_slot=20, count=2)

        stream = MockRangeStream(
            response_chunks=[encode_success(signed_block) for signed_block in chain]
        )
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(20), Uint64(5))

        assert blocks == chain

    async def test_resource_unavailable_chunks_are_skipped(self, peer_id: PeerId) -> None:
        """RESOURCE_UNAVAILABLE chunks do not raise and the remaining blocks are returned."""
        client = make_client()
        chain = build_chain(start_slot=30, count=2)
        unavailable = ResponseCode.RESOURCE_UNAVAILABLE.encode(b"missing")

        stream = MockRangeStream(
            response_chunks=[
                unavailable,
                encode_success(chain[0]),
                unavailable,
                encode_success(chain[1]),
            ],
        )
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(30), Uint64(4))

        assert blocks == chain

    async def test_non_monotonic_slots_raise_codec_error(self, peer_id: PeerId) -> None:
        """A response with two blocks at the same slot is rejected as a protocol violation."""
        client = make_client()
        first = empty_signed_block(Slot(40), Bytes32(b"\xaa" * 32), state_seed=1)
        # Reuses the same slot as the first block. Parent root is irrelevant because
        # the slot check fires before the parent-root check.
        duplicate = empty_signed_block(Slot(40), hash_tree_root(first.block), state_seed=2)

        stream = MockRangeStream(response_chunks=[encode_success(first), encode_success(duplicate)])
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        with pytest.raises(CodecError) as exception_info:
            await client.request_blocks_by_range(peer_id, Slot(40), Uint64(2))
        assert str(exception_info.value) == "Non-monotonic slot: 40 <= 40"

    async def test_out_of_range_slot_raises_codec_error(self, peer_id: PeerId) -> None:
        """A block whose slot falls outside the requested range is rejected."""
        client = make_client()
        # Request [50, 53). Peer responds with a block at slot 60.
        out_of_range = empty_signed_block(Slot(60), Bytes32(b"\xaa" * 32), state_seed=1)

        stream = MockRangeStream(response_chunks=[encode_success(out_of_range)])
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        with pytest.raises(CodecError) as exception_info:
            await client.request_blocks_by_range(peer_id, Slot(50), Uint64(3))
        assert str(exception_info.value) == "Block slot 60 outside requested range"

    async def test_parent_root_continuity_violation_across_skipped_slot(
        self, peer_id: PeerId
    ) -> None:
        """
        A wrong parent root after a skipped empty slot is rejected as a protocol violation.

        The responder serves canonical blocks only and skips empty slots.
        So a block following an empty slot must still chain off the previous
        non-empty block's root.
        """
        client = make_client()
        # Request [70, 75). Peer responds with slot 70 then slot 73.
        # The slot 73 block's parent_root is wrong (zero root) instead of slot 70's root.
        first = empty_signed_block(Slot(70), Bytes32(b"\xaa" * 32), state_seed=1)
        # Wrong parent: should equal the tree-hash root of the first block.
        bad = empty_signed_block(Slot(73), Bytes32.zero(), state_seed=2)

        stream = MockRangeStream(response_chunks=[encode_success(first), encode_success(bad)])
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        expected_parent_root = hash_tree_root(first.block).hex()
        with pytest.raises(CodecError) as exception_info:
            await client.request_blocks_by_range(peer_id, Slot(70), Uint64(5))
        assert str(exception_info.value) == (
            f"Parent root mismatch at slot 73: "
            f"expected {expected_parent_root}, "
            f"got {bad.block.parent_root.hex()}"
        )

    async def test_parent_root_continuity_holds_across_skipped_slots(self, peer_id: PeerId) -> None:
        """A correct parent_root linkage across empty slots is accepted."""
        client = make_client()
        # Request [80, 90). Peer responds with slot 80 and slot 85, where the
        # slot 85 block chains correctly off the slot 80 block.
        first = empty_signed_block(Slot(80), Bytes32(b"\xaa" * 32), state_seed=1)
        second = empty_signed_block(Slot(85), parent_root=hash_tree_root(first.block), state_seed=2)

        stream = MockRangeStream(response_chunks=[encode_success(first), encode_success(second)])
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(80), Uint64(10))

        assert blocks == [first, second]

    async def test_more_than_count_chunks_raises_codec_error(self, peer_id: PeerId) -> None:
        """An extra chunk past the requested count is rejected as a protocol violation."""
        client = make_client()
        chain = build_chain(start_slot=100, count=2)
        # An extra third chunk that the peer is not allowed to send.
        extra = empty_signed_block(
            Slot(102), parent_root=hash_tree_root(chain[1].block), state_seed=99
        )

        stream = MockRangeStream(
            response_chunks=[
                encode_success(chain[0]),
                encode_success(chain[1]),
                encode_success(extra),
            ],
        )
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        with pytest.raises(CodecError) as exception_info:
            await client.request_blocks_by_range(peer_id, Slot(100), Uint64(2))
        assert str(exception_info.value) == "Peer sent more than count BlocksByRange chunks"

    async def test_timeout_returns_empty_list(self, peer_id: PeerId) -> None:
        """A request that times out returns an empty list rather than raising."""
        client = make_client()
        client.timeout = 0.01
        connection = MockRangeConnection(peer_id=peer_id, streams=[MockRangeStream()])

        async def slow_read() -> bytes:
            await asyncio.sleep(1.0)
            return b""

        connection.streams[0].read = slow_read  # type: ignore[method-assign]
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(0), Uint64(3))

        assert blocks == []

    async def test_server_error_stops_reading_and_returns_partial(self, peer_id: PeerId) -> None:
        """A SERVER_ERROR chunk halts reading and returns blocks received so far."""
        client = make_client()
        chain = build_chain(start_slot=200, count=1)
        error_chunk = ResponseCode.SERVER_ERROR.encode(b"db boom")

        stream = MockRangeStream(response_chunks=[encode_success(chain[0]), error_chunk])
        connection = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, connection)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(200), Uint64(3))

        assert blocks == chain
