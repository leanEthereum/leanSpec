"""Tests for inbound ReqResp protocol handlers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Final

import pytest

from lean_spec.forks.lstar.containers import Checkpoint, SignedBlock
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.subspecs.networking.config import MAX_ERROR_MESSAGE_SIZE, MAX_REQUEST_BLOCKS
from lean_spec.subspecs.networking.reqresp.codec import (
    ResponseCode,
    encode_request,
)
from lean_spec.subspecs.networking.reqresp.handler import (
    REQRESP_PROTOCOL_IDS,
    AsyncBlockBySlotLookup,
    ReqRespServer,
    RequestHandler,
    StreamResponseAdapter,
)
from lean_spec.subspecs.networking.reqresp.message import (
    BLOCKS_BY_RANGE_PROTOCOL_V1,
    BLOCKS_BY_ROOT_PROTOCOL_V1,
    STATUS_PROTOCOL_V1,
    BlocksByRangeRequest,
    BlocksByRootRequest,
    RequestedBlockRoots,
    Status,
)
from lean_spec.subspecs.networking.types import ProtocolId
from lean_spec.subspecs.networking.varint import encode_varint
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.exceptions import SSZSerializationError
from tests.lean_spec.helpers import make_test_block, make_test_status


@dataclass
class MockStream:
    """Mock QUIC stream for testing ReqRespServer."""

    request_data: bytes = b""
    """Data to return when read() is called."""

    written: list[bytes] = field(default_factory=list)
    """Accumulator for data written to the stream."""

    closed: bool = False
    """Whether close() has been called."""

    _read_offset: int = 0
    """Internal offset for simulating chunked reads."""

    _stream_id: int = 0
    """Mock stream identifier."""

    @property
    def stream_id(self) -> int:
        """Mock stream ID."""
        return self._stream_id

    @property
    def protocol_id(self) -> str:
        """Mock protocol ID."""
        return STATUS_PROTOCOL_V1

    async def read(self) -> bytes:
        """
        Return request data in a single chunk, then empty bytes.

        Simulates the stream EOF behavior.
        """
        if self._read_offset >= len(self.request_data):
            return b""
        chunk = self.request_data[self._read_offset :]
        self._read_offset = len(self.request_data)
        return chunk

    def write(self, data: bytes) -> None:
        """Buffer written data for inspection."""
        self.written.append(data)

    async def drain(self) -> None:
        """No-op flush."""

    async def close(self) -> None:
        """Mark stream as closed."""
        self.closed = True

    async def reset(self) -> None:
        """Abort the stream."""
        self.closed = True


@dataclass
class MockResponseStream:
    """Mock ResponseStream for testing handlers in isolation."""

    successes: list[bytes] = field(default_factory=list)
    """SSZ data sent via send_success."""

    errors: list[tuple[ResponseCode, str]] = field(default_factory=list)
    """Errors sent via send_error as (code, message) tuples."""

    finished: bool = False
    """Whether finish() was called."""

    async def send_success(self, ssz_data: bytes) -> None:
        """Record a success response."""
        self.successes.append(ssz_data)

    async def send_error(self, code: ResponseCode, message: str) -> None:
        """Record an error response."""
        self.errors.append((code, message))

    async def finish(self) -> None:
        """Mark stream as finished."""
        self.finished = True


class TestStreamResponseAdapter:
    """Tests for StreamResponseAdapter wire format encoding."""

    async def test_send_success_encodes_correctly(self) -> None:
        """Success response uses SUCCESS code and encodes SSZ data."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        ssz_data = b"\x01\x02\x03\x04"
        await response.send_success(ssz_data)

        written = stream.written

        assert len(written) == 1
        encoded = written[0]

        # First byte should be SUCCESS (0)
        assert encoded[0] == ResponseCode.SUCCESS

        # Should decode back to original data
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.SUCCESS
        assert decoded == b"\x01\x02\x03\x04"

    async def test_send_error_encodes_correctly(self) -> None:
        """Error response uses specified code and UTF-8 message."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        await response.send_error(ResponseCode.INVALID_REQUEST, "Bad request")

        written = stream.written

        assert len(written) == 1
        encoded = written[0]

        # First byte should be INVALID_REQUEST (1)
        assert encoded[0] == ResponseCode.INVALID_REQUEST

        # Should decode back to UTF-8 message
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.INVALID_REQUEST
        assert decoded == b"Bad request"

    async def test_send_error_server_error(self) -> None:
        """SERVER_ERROR code encodes correctly."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        await response.send_error(ResponseCode.SERVER_ERROR, "Internal error")

        encoded = stream.written[0]

        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.SERVER_ERROR
        assert decoded == b"Internal error"

    async def test_send_error_resource_unavailable(self) -> None:
        """RESOURCE_UNAVAILABLE code encodes correctly."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        await response.send_error(ResponseCode.RESOURCE_UNAVAILABLE, "Block not found")

        encoded = stream.written[0]

        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.RESOURCE_UNAVAILABLE
        assert decoded == b"Block not found"

    async def test_finish_closes_stream(self) -> None:
        """Finish closes the underlying stream."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        assert not stream.closed
        await response.finish()
        assert stream.closed is True


class TestRequestHandlerStatus:
    """Tests for RequestHandler.handle_status."""

    async def test_handle_status_returns_our_status(self) -> None:
        """Returns our configured status on valid request."""
        our_status = make_test_status()
        handler = RequestHandler(our_status=our_status)
        response = MockResponseStream()

        await handler.handle_status(response)  # type: ignore[arg-type]

        assert len(response.errors) == 0
        assert len(response.successes) == 1

        # Decode the SSZ response
        returned_status = Status.decode_bytes(response.successes[0])
        assert returned_status.head.slot == Slot(200)
        assert returned_status.finalized.slot == Slot(100)

    async def test_handle_status_no_status_returns_error(self) -> None:
        """Returns SERVER_ERROR when no status is configured."""
        handler = RequestHandler()  # No our_status set
        response = MockResponseStream()

        await handler.handle_status(response)  # type: ignore[arg-type]

        assert len(response.successes) == 0
        assert len(response.errors) == 1
        assert response.errors[0][0] == ResponseCode.SERVER_ERROR
        assert "not available" in response.errors[0][1]

    async def test_handle_status_ignores_peer_status(self) -> None:
        """Peer's status does not affect our response."""
        our_status = make_test_status()
        handler = RequestHandler(our_status=our_status)
        response = MockResponseStream()

        await handler.handle_status(response)  # type: ignore[arg-type]

        returned_status = Status.decode_bytes(response.successes[0])
        assert returned_status.head.slot == Slot(200)
        assert returned_status.finalized.slot == Slot(100)


class TestRequestHandlerBlocksByRoot:
    """Tests for RequestHandler.handle_blocks_by_root."""

    async def test_handle_blocks_by_root_returns_found_blocks(self) -> None:
        """Sends SUCCESS response for each found block."""
        block1 = make_test_block(slot=1, seed=1)
        block2 = make_test_block(slot=2, seed=2)

        # Create lookup that returns blocks for specific roots
        block_roots: dict[bytes, SignedBlock] = {
            b"\x11" * 32: block1,
            b"\x22" * 32: block2,
        }

        async def lookup(root: Bytes32) -> SignedBlock | None:
            return block_roots.get(bytes(root))

        handler = RequestHandler(block_lookup=lookup)
        response = MockResponseStream()

        request = BlocksByRootRequest(
            roots=RequestedBlockRoots(data=[Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)])
        )

        await handler.handle_blocks_by_root(request, response)  # type: ignore[arg-type]

        assert len(response.errors) == 0
        assert len(response.successes) == 2

        # Both blocks should be decodable
        decoded1 = SignedBlock.decode_bytes(response.successes[0])
        decoded2 = SignedBlock.decode_bytes(response.successes[1])

        assert decoded1.block.slot == Slot(1)
        assert decoded2.block.slot == Slot(2)

    async def test_handle_blocks_by_root_skips_missing_blocks(self) -> None:
        """Missing blocks are silently skipped."""
        block1 = make_test_block(slot=1, seed=1)

        # Only block1 exists
        async def lookup(root: Bytes32) -> SignedBlock | None:
            if bytes(root) == b"\x11" * 32:
                return block1
            return None

        handler = RequestHandler(block_lookup=lookup)
        response = MockResponseStream()

        # Request two blocks, only one exists
        request = BlocksByRootRequest(
            roots=RequestedBlockRoots(
                data=[
                    Bytes32(b"\x11" * 32),  # exists
                    Bytes32(b"\x99" * 32),  # missing
                ]
            )
        )

        await handler.handle_blocks_by_root(request, response)  # type: ignore[arg-type]

        # Only one block returned, no errors
        assert len(response.errors) == 0
        assert len(response.successes) == 1

    async def test_handle_blocks_by_root_no_lookup_returns_error(self) -> None:
        """Returns SERVER_ERROR when no lookup callback is configured."""
        handler = RequestHandler()  # No block_lookup set
        response = MockResponseStream()

        request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[Bytes32(b"\x11" * 32)]))

        await handler.handle_blocks_by_root(request, response)  # type: ignore[arg-type]

        assert len(response.successes) == 0
        assert len(response.errors) == 1
        assert response.errors[0][0] == ResponseCode.SERVER_ERROR
        assert "not available" in response.errors[0][1]

    async def test_handle_blocks_by_root_empty_request(self) -> None:
        """Empty request returns no blocks and no errors."""

        async def lookup(root: Bytes32) -> SignedBlock | None:
            return None

        handler = RequestHandler(block_lookup=lookup)
        response = MockResponseStream()

        request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[]))

        await handler.handle_blocks_by_root(request, response)  # type: ignore[arg-type]

        assert len(response.errors) == 0
        assert len(response.successes) == 0

    async def test_handle_blocks_by_root_lookup_error_continues(self) -> None:
        """Lookup exceptions are caught and processing continues."""
        block2 = make_test_block(slot=2, seed=2)

        async def lookup(root: Bytes32) -> SignedBlock | None:
            if bytes(root) == b"\x11" * 32:
                raise RuntimeError("Database error")
            if bytes(root) == b"\x22" * 32:
                return block2
            return None

        handler = RequestHandler(block_lookup=lookup)
        response = MockResponseStream()

        # First block causes error, second succeeds
        request = BlocksByRootRequest(
            roots=RequestedBlockRoots(data=[Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)])
        )

        await handler.handle_blocks_by_root(request, response)  # type: ignore[arg-type]

        # Second block still returned despite first lookup failing
        assert len(response.errors) == 0
        assert len(response.successes) == 1

        decoded = SignedBlock.decode_bytes(response.successes[0])
        assert decoded.block.slot == Slot(2)


class TestReqRespServer:
    """Tests for ReqRespServer request handling."""

    async def test_handle_status_request(self) -> None:
        """Full Status request/response flow through ReqRespServer."""
        our_status = make_test_status()
        handler = RequestHandler(our_status=our_status)
        server = ReqRespServer(handler=handler)

        # Build wire-format request
        peer_status = Status(
            finalized=Checkpoint(root=Bytes32(b"\xaa" * 32), slot=Slot(50)),
            head=Checkpoint(root=Bytes32(b"\xbb" * 32), slot=Slot(150)),
        )
        request_bytes = encode_request(peer_status.encode_bytes())

        stream = MockStream(request_data=request_bytes)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        # Stream should be closed after handling
        assert stream.closed is True

        # Should have received a success response
        assert len(stream.written) >= 1

        # Decode the response
        code, ssz_data = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.SUCCESS

        returned_status = Status.decode_bytes(ssz_data)
        assert returned_status.head.slot == Slot(200)

    async def test_handle_blocks_by_root_request(self) -> None:
        """Full BlocksByRoot request/response flow through ReqRespServer."""
        block1 = make_test_block(slot=1, seed=1)
        root1 = Bytes32(b"\x11" * 32)

        async def lookup(root: Bytes32) -> SignedBlock | None:
            if bytes(root) == bytes(root1):
                return block1
            return None

        handler = RequestHandler(block_lookup=lookup)
        server = ReqRespServer(handler=handler)

        # Build wire-format request
        request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[root1]))
        request_bytes = encode_request(request.encode_bytes())

        stream = MockStream(request_data=request_bytes)

        await server.handle_stream(stream, BLOCKS_BY_ROOT_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, ssz_data = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.SUCCESS

        returned_block = SignedBlock.decode_bytes(ssz_data)
        assert returned_block.block.slot == Slot(1)

    async def test_empty_request_returns_error(self) -> None:
        """Empty request data returns INVALID_REQUEST error."""
        handler = RequestHandler(our_status=make_test_status())
        server = ReqRespServer(handler=handler)

        stream = MockStream(request_data=b"")

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, message = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.INVALID_REQUEST
        assert b"Empty" in message

    async def test_decode_error_returns_invalid_request(self) -> None:
        """Malformed wire data returns INVALID_REQUEST error."""
        handler = RequestHandler(our_status=make_test_status())
        server = ReqRespServer(handler=handler)

        # Invalid snappy data after length prefix
        malformed_data = b"\x10\x00\x00\x00invalid snappy data here"
        stream = MockStream(request_data=malformed_data)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, _ = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.INVALID_REQUEST

    async def test_invalid_ssz_returns_invalid_request(self) -> None:
        """Valid wire format but invalid SSZ returns INVALID_REQUEST."""
        handler = RequestHandler(our_status=make_test_status())
        server = ReqRespServer(handler=handler)

        # Valid wire format but SSZ is too short for Status (needs 80 bytes)
        invalid_ssz = b"\x01\x02\x03\x04"
        request_bytes = encode_request(invalid_ssz)
        stream = MockStream(request_data=request_bytes)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, message = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.INVALID_REQUEST
        assert b"Invalid Status" in message or b"Status" in message

    async def test_unknown_protocol_returns_error(self) -> None:
        """Unknown protocol ID returns SERVER_ERROR."""
        handler = RequestHandler(our_status=make_test_status())
        server = ReqRespServer(handler=handler)

        # Valid request data but unknown protocol
        status = make_test_status()
        request_bytes = encode_request(status.encode_bytes())
        stream = MockStream(request_data=request_bytes)

        unknown_protocol = ProtocolId("/unknown/protocol/1/ssz_snappy")
        await server.handle_stream(stream, unknown_protocol)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, message = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.SERVER_ERROR
        assert b"Unknown" in message or b"protocol" in message.lower()

    async def test_stream_closed_on_completion(self) -> None:
        """Stream is always closed after handling, even on success."""
        handler = RequestHandler(our_status=make_test_status())
        server = ReqRespServer(handler=handler)

        status = make_test_status()
        request_bytes = encode_request(status.encode_bytes())
        stream = MockStream(request_data=request_bytes)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True

    async def test_stream_closed_on_error(self) -> None:
        """Stream is closed even when handling fails."""
        handler = RequestHandler()  # No status configured
        server = ReqRespServer(handler=handler)

        status = make_test_status()
        request_bytes = encode_request(status.encode_bytes())
        stream = MockStream(request_data=request_bytes)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True


class TestReqRespProtocolConstants:
    """Tests for protocol ID constants."""

    def test_protocol_ids_contains_status(self) -> None:
        """REQRESP_PROTOCOL_IDS includes status protocol."""
        assert STATUS_PROTOCOL_V1 in REQRESP_PROTOCOL_IDS

    def test_protocol_ids_contains_blocks_by_root(self) -> None:
        """REQRESP_PROTOCOL_IDS includes blocks_by_root protocol."""
        assert BLOCKS_BY_ROOT_PROTOCOL_V1 in REQRESP_PROTOCOL_IDS

    def test_protocol_ids_is_frozenset(self) -> None:
        """REQRESP_PROTOCOL_IDS is immutable."""
        assert isinstance(REQRESP_PROTOCOL_IDS, frozenset)

    def test_status_protocol_format(self) -> None:
        """Status protocol ID follows expected format."""
        assert STATUS_PROTOCOL_V1.startswith("/leanconsensus/req/")
        assert STATUS_PROTOCOL_V1.endswith("/ssz_snappy")
        assert "status" in STATUS_PROTOCOL_V1

    def test_blocks_by_root_protocol_format(self) -> None:
        """BlocksByRoot protocol ID follows expected format."""
        assert BLOCKS_BY_ROOT_PROTOCOL_V1.startswith("/leanconsensus/req/")
        assert BLOCKS_BY_ROOT_PROTOCOL_V1.endswith("/ssz_snappy")
        assert "blocks_by_root" in BLOCKS_BY_ROOT_PROTOCOL_V1


class TestIntegration:
    """Integration tests for full request/response roundtrips."""

    async def test_roundtrip_status_request(self) -> None:
        """Full encode -> server -> decode roundtrip for Status."""
        our_status = make_test_status()
        handler = RequestHandler(our_status=our_status)
        server = ReqRespServer(handler=handler)

        # Client side: encode request
        peer_status = Status(
            finalized=Checkpoint(root=Bytes32(b"\xcc" * 32), slot=Slot(300)),
            head=Checkpoint(root=Bytes32(b"\xdd" * 32), slot=Slot(400)),
        )
        request_wire = encode_request(peer_status.encode_bytes())

        # Server side: handle request
        stream = MockStream(request_data=request_wire)
        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        # Client side: decode response
        response_wire = stream.written[0]
        code, ssz_bytes = ResponseCode.decode(response_wire)

        assert code == ResponseCode.SUCCESS
        returned = Status.decode_bytes(ssz_bytes)

        # Verify we got our status back
        assert returned.head.slot == Slot(200)
        assert returned.finalized.slot == Slot(100)

    async def test_roundtrip_blocks_by_root_request(self) -> None:
        """Full encode -> server -> decode roundtrip for BlocksByRoot."""
        block1 = make_test_block(slot=10, seed=10)
        block2 = make_test_block(slot=20, seed=20)

        root1 = Bytes32(b"\xaa" * 32)
        root2 = Bytes32(b"\xbb" * 32)

        blocks_by_root: dict[bytes, SignedBlock] = {
            bytes(root1): block1,
            bytes(root2): block2,
        }

        async def lookup(root: Bytes32) -> SignedBlock | None:
            return blocks_by_root.get(bytes(root))

        handler = RequestHandler(block_lookup=lookup)
        server = ReqRespServer(handler=handler)

        # Client side: encode request
        request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[root1, root2]))
        request_wire = encode_request(request.encode_bytes())

        # Server side: handle request
        stream = MockStream(request_data=request_wire)
        await server.handle_stream(stream, BLOCKS_BY_ROOT_PROTOCOL_V1)

        # Client side: decode responses
        blocks = []
        for response_wire in stream.written:
            code, ssz_bytes = ResponseCode.decode(response_wire)
            if code == ResponseCode.SUCCESS:
                blocks.append(SignedBlock.decode_bytes(ssz_bytes))

        assert len(blocks) == 2
        slots = {b.block.slot for b in blocks}
        assert Slot(10) in slots
        assert Slot(20) in slots

    async def test_roundtrip_blocks_by_root_partial_response(self) -> None:
        """BlocksByRoot returns only available blocks."""
        block1 = make_test_block(slot=10, seed=10)

        root1 = Bytes32(b"\xaa" * 32)
        root_missing = Bytes32(b"\x00" * 32)

        async def lookup(root: Bytes32) -> SignedBlock | None:
            if bytes(root) == bytes(root1):
                return block1
            return None

        handler = RequestHandler(block_lookup=lookup)
        server = ReqRespServer(handler=handler)

        # Request two blocks, only one exists
        request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[root1, root_missing]))
        request_wire = encode_request(request.encode_bytes())

        stream = MockStream(request_data=request_wire)
        await server.handle_stream(stream, BLOCKS_BY_ROOT_PROTOCOL_V1)

        blocks = []
        for response_wire in stream.written:
            code, ssz_bytes = ResponseCode.decode(response_wire)
            if code == ResponseCode.SUCCESS:
                blocks.append(SignedBlock.decode_bytes(ssz_bytes))

        # Only one block returned
        assert len(blocks) == 1
        assert blocks[0].block.slot == Slot(10)


class TestStreamResponseAdapterMultipleResponses:
    """Tests for StreamResponseAdapter with multiple responses in sequence."""

    async def test_send_multiple_success_responses(self) -> None:
        """Multiple SUCCESS responses are written independently."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        await response.send_success(b"\x01\x02")
        await response.send_success(b"\x03\x04")
        await response.send_success(b"\x05\x06")

        written = stream.written

        assert len(written) == 3

        # Each response should be independently decodable
        for i, data in enumerate(written):
            code, decoded = ResponseCode.decode(data)
            assert code == ResponseCode.SUCCESS
            expected = bytes([i * 2 + 1, i * 2 + 2])
            assert decoded == expected

    async def test_send_success_then_error(self) -> None:
        """Success response followed by error response."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        await response.send_success(b"\xaa\xbb")
        await response.send_error(ResponseCode.RESOURCE_UNAVAILABLE, "Done")

        written = stream.written

        assert len(written) == 2

        code1, data1 = ResponseCode.decode(written[0])
        assert code1 == ResponseCode.SUCCESS
        assert data1 == b"\xaa\xbb"

        code2, data2 = ResponseCode.decode(written[1])
        assert code2 == ResponseCode.RESOURCE_UNAVAILABLE
        assert data2 == b"Done"

    async def test_send_empty_success_response(self) -> None:
        """Empty SUCCESS response payload is handled."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        await response.send_success(b"")

        written = stream.written

        assert len(written) == 1
        code, decoded = ResponseCode.decode(written[0])
        assert code == ResponseCode.SUCCESS
        assert decoded == b""


class MockChunkedStream:
    """Mock stream that returns data in multiple chunks."""

    def __init__(self, chunks: list[bytes]) -> None:
        """Initialize with a list of chunks to return."""
        self.chunks = chunks
        self.chunk_index = 0
        self.written: list[bytes] = []
        self.closed = False
        self._stream_id = 0

    @property
    def stream_id(self) -> int:
        """Mock stream ID."""
        return self._stream_id

    @property
    def protocol_id(self) -> str:
        """Mock protocol ID."""
        return STATUS_PROTOCOL_V1

    async def read(self) -> bytes:
        """Return chunks one at a time."""
        if self.chunk_index >= len(self.chunks):
            return b""
        chunk = self.chunks[self.chunk_index]
        self.chunk_index += 1
        return chunk

    def write(self, data: bytes) -> None:
        """Buffer written data."""
        self.written.append(data)

    async def drain(self) -> None:
        """No-op flush."""

    async def close(self) -> None:
        """Mark stream as closed."""
        self.closed = True

    async def reset(self) -> None:
        """Abort the stream."""
        self.closed = True


class TestReqRespServerChunkedRead:
    """Tests for ReqRespServer handling chunked request data."""

    async def test_handle_chunked_status_request(self) -> None:
        """Request data arriving in multiple chunks is assembled correctly."""
        our_status = make_test_status()
        handler = RequestHandler(our_status=our_status)
        server = ReqRespServer(handler=handler)

        # Build wire-format request
        peer_status = make_test_status()
        request_bytes = encode_request(peer_status.encode_bytes())

        # Split into multiple chunks
        mid = len(request_bytes) // 2
        chunks = [request_bytes[:mid], request_bytes[mid:]]

        stream = MockChunkedStream(chunks=chunks)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, ssz_data = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.SUCCESS

    async def test_handle_single_byte_chunks(self) -> None:
        """Request data arriving one byte at a time is handled."""
        our_status = make_test_status()
        handler = RequestHandler(our_status=our_status)
        server = ReqRespServer(handler=handler)

        peer_status = make_test_status()
        request_bytes = encode_request(peer_status.encode_bytes())

        # Split into single-byte chunks
        chunks = [bytes([b]) for b in request_bytes]

        stream = MockChunkedStream(chunks=chunks)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, _ = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.SUCCESS


class TestReqRespServerEdgeCases:
    """Edge cases for ReqRespServer."""

    async def test_invalid_blocks_by_root_ssz(self) -> None:
        """Invalid SSZ for BlocksByRoot returns INVALID_REQUEST."""

        async def lookup(root: Bytes32) -> SignedBlock | None:
            return None

        handler = RequestHandler(block_lookup=lookup)
        server = ReqRespServer(handler=handler)

        # Valid wire format but wrong SSZ structure for BlocksByRootRequest
        # BlocksByRootRequest expects list of Bytes32, not arbitrary bytes
        invalid_ssz = b"\xff" * 10
        request_bytes = encode_request(invalid_ssz)
        stream = MockStream(request_data=request_bytes)

        await server.handle_stream(stream, BLOCKS_BY_ROOT_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, message = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.INVALID_REQUEST

    async def test_truncated_varint_returns_error(self) -> None:
        """Truncated varint in request returns INVALID_REQUEST."""
        handler = RequestHandler(our_status=make_test_status())
        server = ReqRespServer(handler=handler)

        # Varint with continuation bit set but no following byte
        truncated_varint = b"\x80"
        stream = MockStream(request_data=truncated_varint)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, _ = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.INVALID_REQUEST


class TestRequestHandlerEdgeCases:
    """Edge cases for RequestHandler."""

    async def test_blocks_by_root_single_block(self) -> None:
        """Single block request returns correctly."""
        block = make_test_block(slot=999, seed=99)
        root = Bytes32(b"\x99" * 32)

        async def lookup(r: Bytes32) -> SignedBlock | None:
            if bytes(r) == bytes(root):
                return block
            return None

        handler = RequestHandler(block_lookup=lookup)
        response = MockResponseStream()

        request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[root]))

        await handler.handle_blocks_by_root(request, response)  # type: ignore[arg-type]

        assert len(response.errors) == 0
        assert len(response.successes) == 1

        decoded = SignedBlock.decode_bytes(response.successes[0])
        assert decoded.block.slot == Slot(999)

    async def test_blocks_by_root_all_missing(self) -> None:
        """Request where all blocks are missing returns no success responses."""

        async def lookup(root: Bytes32) -> SignedBlock | None:
            return None

        handler = RequestHandler(block_lookup=lookup)
        response = MockResponseStream()

        request = BlocksByRootRequest(
            roots=RequestedBlockRoots(
                data=[
                    Bytes32(b"\x11" * 32),
                    Bytes32(b"\x22" * 32),
                    Bytes32(b"\x33" * 32),
                ]
            )
        )

        await handler.handle_blocks_by_root(request, response)  # type: ignore[arg-type]

        assert len(response.errors) == 0
        assert len(response.successes) == 0

    async def test_blocks_by_root_mixed_found_missing(self) -> None:
        """Mixed found/missing blocks returns only found blocks."""
        block1 = make_test_block(slot=1, seed=1)
        block3 = make_test_block(slot=3, seed=3)

        blocks: dict[bytes, SignedBlock] = {
            b"\x11" * 32: block1,
            # \x22 missing
            b"\x33" * 32: block3,
        }

        async def lookup(root: Bytes32) -> SignedBlock | None:
            return blocks.get(bytes(root))

        handler = RequestHandler(block_lookup=lookup)
        response = MockResponseStream()

        request = BlocksByRootRequest(
            roots=RequestedBlockRoots(
                data=[
                    Bytes32(b"\x11" * 32),
                    Bytes32(b"\x22" * 32),
                    Bytes32(b"\x33" * 32),
                ]
            )
        )

        await handler.handle_blocks_by_root(request, response)  # type: ignore[arg-type]

        assert len(response.errors) == 0
        assert len(response.successes) == 2

        # Verify order is preserved
        decoded1 = SignedBlock.decode_bytes(response.successes[0])
        decoded2 = SignedBlock.decode_bytes(response.successes[1])

        assert decoded1.block.slot == Slot(1)
        assert decoded2.block.slot == Slot(3)

    async def test_status_update_after_initialization(self) -> None:
        """Status can be updated after handler creation."""
        handler = RequestHandler()
        response1 = MockResponseStream()

        # First request with no status
        await handler.handle_status(response1)  # type: ignore[arg-type]

        # Update status
        handler.our_status = make_test_status()

        response2 = MockResponseStream()
        await handler.handle_status(response2)  # type: ignore[arg-type]

        # First request should fail
        assert len(response1.successes) == 0

        # Second request should succeed
        assert len(response2.successes) == 1


class TestConcurrentRequestHandling:
    """Tests for concurrent request handling."""

    async def test_concurrent_status_requests(self) -> None:
        """Multiple concurrent status requests are handled independently."""
        our_status = make_test_status()
        handler = RequestHandler(our_status=our_status)
        server = ReqRespServer(handler=handler)

        # Create multiple streams with requests
        streams: list[MockStream] = []
        for i in range(3):
            peer_status = Status(
                finalized=Checkpoint(root=Bytes32(bytes([i]) * 32), slot=Slot(i * 10)),
                head=Checkpoint(root=Bytes32(bytes([i + 10]) * 32), slot=Slot(i * 20)),
            )
            request_bytes = encode_request(peer_status.encode_bytes())
            streams.append(MockStream(request_data=request_bytes))

        # Handle all requests concurrently
        await asyncio.gather(*[server.handle_stream(s, STATUS_PROTOCOL_V1) for s in streams])

        # Decode all responses
        results = []
        for stream in streams:
            assert stream.closed
            assert len(stream.written) >= 1
            code, ssz_data = ResponseCode.decode(stream.written[0])
            assert code == ResponseCode.SUCCESS
            results.append(Status.decode_bytes(ssz_data))

        # All responses should be our status
        for status in results:
            assert status.head.slot == Slot(200)
            assert status.finalized.slot == Slot(100)

    async def test_concurrent_mixed_requests(self) -> None:
        """Concurrent Status and BlocksByRoot requests."""
        block = make_test_block(slot=42, seed=42)
        root = Bytes32(b"\x42" * 32)

        async def lookup(r: Bytes32) -> SignedBlock | None:
            if bytes(r) == bytes(root):
                return block
            return None

        our_status = make_test_status()
        handler = RequestHandler(our_status=our_status, block_lookup=lookup)
        server = ReqRespServer(handler=handler)

        # Status request
        status_request = encode_request(make_test_status().encode_bytes())
        status_stream = MockStream(request_data=status_request)

        # BlocksByRoot request
        blocks_request = encode_request(
            BlocksByRootRequest(roots=RequestedBlockRoots(data=[root])).encode_bytes()
        )
        blocks_stream = MockStream(request_data=blocks_request)

        # Handle concurrently
        await asyncio.gather(
            server.handle_stream(status_stream, STATUS_PROTOCOL_V1),
            server.handle_stream(blocks_stream, BLOCKS_BY_ROOT_PROTOCOL_V1),
        )

        # Decode status response
        code, ssz_data = ResponseCode.decode(status_stream.written[0])
        assert code == ResponseCode.SUCCESS
        status_result = Status.decode_bytes(ssz_data)

        # Decode block response
        code, ssz_data = ResponseCode.decode(blocks_stream.written[0])
        assert code == ResponseCode.SUCCESS
        block_result = SignedBlock.decode_bytes(ssz_data)

        assert status_result.head.slot == Slot(200)
        assert block_result.block.slot == Slot(42)


class MockFailingStream:
    """Mock stream that raises exceptions on specific operations."""

    def __init__(
        self,
        request_data: bytes = b"",
        fail_on_write: bool = False,
        fail_on_close: bool = False,
    ) -> None:
        """Initialize with failure modes."""
        self.request_data = request_data
        self.fail_on_write = fail_on_write
        self.fail_on_close = fail_on_close
        self._read_offset = 0
        self.written: list[bytes] = []
        self.closed = False
        self.close_attempts = 0
        self._stream_id = 0

    @property
    def stream_id(self) -> int:
        """Mock stream ID."""
        return self._stream_id

    @property
    def protocol_id(self) -> str:
        """Mock protocol ID."""
        return STATUS_PROTOCOL_V1

    async def read(self) -> bytes:
        """Return request data."""
        if self._read_offset >= len(self.request_data):
            return b""
        chunk = self.request_data[self._read_offset :]
        self._read_offset = len(self.request_data)
        return chunk

    def write(self, data: bytes) -> None:
        """Buffer written data (may fail if configured)."""
        if self.fail_on_write:
            raise ConnectionError("Write failed")
        self.written.append(data)

    async def drain(self) -> None:
        """No-op flush."""

    async def close(self) -> None:
        """Optionally fail on close."""
        self.close_attempts += 1
        if self.fail_on_close:
            raise ConnectionError("Close failed")
        self.closed = True

    async def reset(self) -> None:
        """Abort the stream."""
        self.closed = True


class TestHandlerExceptionRecovery:
    """Tests for exception handling and recovery."""

    async def test_stream_closed_despite_close_exception(self) -> None:
        """Stream close is attempted even if it raises an exception."""
        handler = RequestHandler(our_status=make_test_status())
        server = ReqRespServer(handler=handler)

        request_bytes = encode_request(make_test_status().encode_bytes())
        stream = MockFailingStream(
            request_data=request_bytes,
            fail_on_close=True,
        )

        # Should not raise, exception is caught
        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        # Close should be attempted
        assert stream.close_attempts >= 1

    async def test_error_response_sent_despite_write_exception(self) -> None:
        """Error handling continues even when write fails."""
        handler = RequestHandler()  # No status
        server = ReqRespServer(handler=handler)

        request_bytes = encode_request(make_test_status().encode_bytes())
        stream = MockFailingStream(
            request_data=request_bytes,
            fail_on_write=True,
        )

        # Should not raise, writes that fail are caught
        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        # Close should still be attempted after write failure
        assert stream.close_attempts >= 1


class TestStreamResponseAdapterErrorTruncation:
    """Tests for error message truncation in StreamResponseAdapter."""

    async def test_send_error_truncates_long_messages(self) -> None:
        """Error messages exceeding 256 bytes are truncated."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        long_message = "X" * 500
        await response.send_error(ResponseCode.INVALID_REQUEST, long_message)

        encoded = stream.written[0]
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.INVALID_REQUEST
        assert len(decoded) == MAX_ERROR_MESSAGE_SIZE

    async def test_send_error_short_message_unchanged(self) -> None:
        """Short error messages are not truncated."""
        stream = MockStream()
        response = StreamResponseAdapter(_stream=stream)

        short_message = "Bad request"
        await response.send_error(ResponseCode.INVALID_REQUEST, short_message)

        encoded = stream.written[0]
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.INVALID_REQUEST
        assert decoded == b"Bad request"


class TestReadRequestBufferLimit:
    """Tests for buffer size limits in _read_request."""

    async def test_read_request_rejects_oversized_compressed_data(self) -> None:
        """Unbounded compressed data stream is rejected."""
        handler = RequestHandler(our_status=make_test_status())
        server = ReqRespServer(handler=handler)

        # Send a small varint claiming length 10, then flood with garbage data
        # exceeding the max compressed size limit
        declared_length = 10
        varint_bytes = encode_varint(declared_length)
        max_compressed = declared_length + declared_length // 6 + 1024

        # Create a stream with varint + way more data than max_compressed
        oversized_data = varint_bytes + b"\x00" * (max_compressed + 5000)
        stream = MockStream(request_data=oversized_data)

        await server.handle_stream(stream, STATUS_PROTOCOL_V1)

        assert stream.closed is True
        assert len(stream.written) >= 1

        code, _ = ResponseCode.decode(stream.written[0])
        assert code == ResponseCode.INVALID_REQUEST


class TestBlocksByRangeRequestRoundTrip:
    """SSZ encode/decode round-trip tests."""

    def test_basic_roundtrip(self) -> None:
        """Encode then decode yields identical container."""
        req = BlocksByRangeRequest(start_slot=Slot(100), count=Uint64(10))
        encoded = req.encode_bytes()
        assert len(encoded) == 16  # 8 (Slot) + 8 (Uint64)

        decoded = BlocksByRangeRequest.decode_bytes(encoded)
        assert decoded.start_slot == Slot(100)
        assert decoded.count == Uint64(10)

    def test_roundtrip_preserves_equality(self) -> None:
        """Decoded request equals original."""
        original = BlocksByRangeRequest(start_slot=Slot(42), count=Uint64(1024))
        decoded = BlocksByRangeRequest.decode_bytes(original.encode_bytes())
        assert original == decoded

    def test_roundtrip_various_values(self) -> None:
        """Round-trip works for diverse value combinations."""
        cases = [
            (Slot(0), Uint64(1)),
            (Slot(1), Uint64(1)),
            (Slot(0), Uint64(MAX_REQUEST_BLOCKS)),
            (Slot(999_999), Uint64(512)),
        ]
        for start_slot, count in cases:
            req = BlocksByRangeRequest(start_slot=start_slot, count=count)
            decoded = BlocksByRangeRequest.decode_bytes(req.encode_bytes())
            assert decoded.start_slot == start_slot
            assert decoded.count == count


class TestBlocksByRangeRequestHashTreeRoot:
    """hash_tree_root stability tests."""

    def test_hash_tree_root_stable_across_reencodings(self) -> None:
        """hash_tree_root is identical for equal requests re-encoded."""
        req1 = BlocksByRangeRequest(start_slot=Slot(100), count=Uint64(10))
        req2 = BlocksByRangeRequest(start_slot=Slot(100), count=Uint64(10))

        root1 = hash_tree_root(req1)
        root2 = hash_tree_root(req2)
        assert root1 == root2

    def test_hash_tree_root_after_decode(self) -> None:
        """hash_tree_root matches between original and decoded copy."""
        original = BlocksByRangeRequest(start_slot=Slot(500), count=Uint64(64))
        decoded = BlocksByRangeRequest.decode_bytes(original.encode_bytes())

        assert hash_tree_root(original) == hash_tree_root(decoded)

    def test_hash_tree_root_differs_for_different_values(self) -> None:
        """Different requests produce different roots."""
        req_a = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(10))
        req_b = BlocksByRangeRequest(start_slot=Slot(1), count=Uint64(10))
        req_c = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(11))

        assert hash_tree_root(req_a) != hash_tree_root(req_b)
        assert hash_tree_root(req_a) != hash_tree_root(req_c)


class TestBlocksByRangeRequestBoundaryValues:
    """Boundary and edge-case value tests."""

    def test_start_slot_zero_decodes_cleanly(self) -> None:
        """start_slot at Slot(0) encodes and decodes correctly."""
        req = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(1))
        decoded = BlocksByRangeRequest.decode_bytes(req.encode_bytes())
        assert decoded.start_slot == Slot(0)

    def test_large_start_slot_decodes_cleanly(self) -> None:
        """Large start_slot values encode and decode correctly."""
        large_slot = Slot(2**63 - 1)  # Very large but valid
        req = BlocksByRangeRequest(start_slot=large_slot, count=Uint64(1))
        decoded = BlocksByRangeRequest.decode_bytes(req.encode_bytes())
        assert decoded.start_slot == large_slot

    def test_max_uint64_start_slot_decodes_cleanly(self) -> None:
        """start_slot at Uint64 max boundary decodes cleanly."""
        max_slot = Slot(2**64 - 1)
        req = BlocksByRangeRequest(start_slot=max_slot, count=Uint64(1))
        decoded = BlocksByRangeRequest.decode_bytes(req.encode_bytes())
        assert decoded.start_slot == max_slot

    def test_count_one(self) -> None:
        """Minimum meaningful count (1) round-trips correctly."""
        req = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(1))
        decoded = BlocksByRangeRequest.decode_bytes(req.encode_bytes())
        assert decoded.count == Uint64(1)

    def test_count_max_request_blocks(self) -> None:
        """count == MAX_REQUEST_BLOCKS round-trips correctly."""
        req = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(MAX_REQUEST_BLOCKS))
        decoded = BlocksByRangeRequest.decode_bytes(req.encode_bytes())
        assert decoded.count == Uint64(MAX_REQUEST_BLOCKS)

    def test_count_zero_encodes_and_decodes(self) -> None:
        """count == 0 encodes/decodes at SSZ layer (validation is handler-level)."""
        req = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(0))
        decoded = BlocksByRangeRequest.decode_bytes(req.encode_bytes())
        assert decoded.count == Uint64(0)

    def test_count_above_max_encodes_and_decodes(self) -> None:
        """count > MAX_REQUEST_BLOCKS encodes/decodes at SSZ layer.

        Enforcement of MAX_REQUEST_BLOCKS is the handler's job, not SSZ's.
        """
        req = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(MAX_REQUEST_BLOCKS + 1))
        decoded = BlocksByRangeRequest.decode_bytes(req.encode_bytes())
        assert decoded.count == Uint64(MAX_REQUEST_BLOCKS + 1)


class TestBlocksByRangeRequestMalformedPayloads:
    """Truncated and oversized payload rejection tests."""

    def test_truncated_payload_rejected(self) -> None:
        """Payload shorter than 16 bytes is rejected."""
        truncated = b"\x01" * 15  # 15 bytes, need 16
        with pytest.raises(SSZSerializationError):
            BlocksByRangeRequest.decode_bytes(truncated)

    def test_empty_payload_rejected(self) -> None:
        """Zero-length payload is rejected."""
        with pytest.raises(SSZSerializationError):
            BlocksByRangeRequest.decode_bytes(b"")

    def test_single_byte_rejected(self) -> None:
        """Single byte payload is rejected."""
        with pytest.raises(SSZSerializationError):
            BlocksByRangeRequest.decode_bytes(b"\x00")

    def test_eight_byte_payload_rejected(self) -> None:
        """8 bytes (half-payload, single field) is rejected."""
        partial = (100).to_bytes(8, "little")
        with pytest.raises(SSZSerializationError):
            BlocksByRangeRequest.decode_bytes(partial)


class TestBlocksByRangeProtocolId:
    """Protocol ID format tests."""

    def test_protocol_id_format(self) -> None:
        """Protocol ID follows lean namespace convention."""
        assert BLOCKS_BY_RANGE_PROTOCOL_V1.startswith("/leanconsensus/req/")
        assert BLOCKS_BY_RANGE_PROTOCOL_V1.endswith("/ssz_snappy")
        assert "blocks_by_range" in BLOCKS_BY_RANGE_PROTOCOL_V1

    def test_protocol_id_version_is_v1(self) -> None:
        """Protocol ID is version 1."""
        assert "/1/" in BLOCKS_BY_RANGE_PROTOCOL_V1

    def test_protocol_id_distinct_from_blocks_by_root(self) -> None:
        """BlocksByRange and BlocksByRoot have distinct protocol IDs."""
        assert BLOCKS_BY_RANGE_PROTOCOL_V1 != BLOCKS_BY_ROOT_PROTOCOL_V1


def _slot_lookup_from(blocks: dict[int, SignedBlock]) -> AsyncBlockBySlotLookup:
    """Build an AsyncBlockBySlotLookup that returns blocks from the given dict."""

    async def _lookup(slot: Slot) -> SignedBlock | None:
        return blocks.get(int(slot))

    return _lookup


_DEFAULT_CURRENT_SLOT: Final[Slot] = Slot(5000)
"""Default current slot used by `_make_range_handler`.

With MIN_SLOTS_FOR_BLOCK_REQUESTS=3600 the window floor is 1400.
Tests with start_slot below 1400 must override the current slot explicitly.
"""


def _make_range_handler(
    blocks: dict[int, SignedBlock] | None = None,
    current_slot: Slot = _DEFAULT_CURRENT_SLOT,
    block_by_slot_lookup: AsyncBlockBySlotLookup | None = None,
) -> RequestHandler:
    """Build a RequestHandler wired for BlocksByRange tests."""
    lookup = block_by_slot_lookup or _slot_lookup_from(blocks or {})
    return RequestHandler(
        block_by_slot_lookup=lookup,
        current_slot_lookup=lambda: current_slot,
    )


class TestRequestHandlerBlocksByRange:
    """Tests for RequestHandler.handle_blocks_by_range."""

    async def test_returns_exactly_count_consecutive_blocks(self) -> None:
        """Returns exactly `count` consecutive blocks from start_slot when all retained."""
        blocks_db = {4000 + i: make_test_block(slot=4000 + i, seed=40 + i) for i in range(5)}
        handler = _make_range_handler(blocks=blocks_db)
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(5))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        decoded_slots = [SignedBlock.decode_bytes(s).block.slot for s in response.successes]
        assert response.errors == []
        assert decoded_slots == [Slot(4000 + i) for i in range(5)]

    async def test_returns_fewer_when_range_overruns_head(self) -> None:
        """Returns fewer than count when range overruns head, no error."""
        blocks_db = {4000 + i: make_test_block(slot=4000 + i, seed=40 + i) for i in range(3)}
        handler = _make_range_handler(blocks=blocks_db)
        response = MockResponseStream()

        # Request 10 blocks but only 3 exist
        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(10))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        decoded_slots = [SignedBlock.decode_bytes(s).block.slot for s in response.successes]
        assert response.errors == []
        assert decoded_slots == [Slot(4000), Slot(4001), Slot(4002)]

    async def test_skips_empty_slots_preserves_monotonicity(self) -> None:
        """Skips empty slots, preserves slot monotonicity."""
        # Blocks at slots 4000, 4002, 4004 (4001 and 4003 are empty)
        blocks_db = {
            4000: make_test_block(slot=4000, seed=40),
            4002: make_test_block(slot=4002, seed=42),
            4004: make_test_block(slot=4004, seed=44),
        }
        handler = _make_range_handler(blocks=blocks_db)
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(5))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        decoded_slots = [SignedBlock.decode_bytes(s).block.slot for s in response.successes]
        assert response.errors == []
        assert decoded_slots == [Slot(4000), Slot(4002), Slot(4004)]

    async def test_resource_unavailable_when_start_slot_predates_window(self) -> None:
        """RESOURCE_UNAVAILABLE when start_slot is older than the sliding window.

        With current_slot=5000 and MIN_SLOTS_FOR_BLOCK_REQUESTS=3600 the floor is
        slot 1400; start_slot=0 falls outside it.
        """
        handler = _make_range_handler(current_slot=Slot(5000))
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(10))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        assert response.successes == []
        assert len(response.errors) == 1
        assert response.errors[0][0] == ResponseCode.RESOURCE_UNAVAILABLE

    async def test_genesis_request_allowed_before_window_extends_below_zero(self) -> None:
        """At genesis (current_slot < MIN_SLOTS_FOR_BLOCK_REQUESTS) start_slot=0 is in window."""
        block_zero = make_test_block(slot=0, seed=0)
        handler = _make_range_handler(blocks={0: block_zero}, current_slot=Slot(100))
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(0), count=Uint64(1))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        decoded_slots = [SignedBlock.decode_bytes(s).block.slot for s in response.successes]
        assert response.errors == []
        assert decoded_slots == [Slot(0)]

    async def test_invalid_request_on_count_zero(self) -> None:
        """INVALID_REQUEST when count == 0."""
        handler = _make_range_handler()
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(0))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        assert response.successes == []
        assert len(response.errors) == 1
        assert response.errors[0][0] == ResponseCode.INVALID_REQUEST

    async def test_invalid_request_on_count_exceeds_max(self) -> None:
        """INVALID_REQUEST when count > MAX_REQUEST_BLOCKS."""
        handler = _make_range_handler()
        response = MockResponseStream()

        request = BlocksByRangeRequest(
            start_slot=Slot(4000),
            count=Uint64(MAX_REQUEST_BLOCKS + 1),
        )
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        assert response.successes == []
        assert len(response.errors) == 1
        assert response.errors[0][0] == ResponseCode.INVALID_REQUEST

    async def test_count_at_max_boundary_succeeds(self) -> None:
        """count == MAX_REQUEST_BLOCKS is valid (boundary case)."""
        handler = _make_range_handler()
        response = MockResponseStream()

        request = BlocksByRangeRequest(
            start_slot=Slot(4000),
            count=Uint64(MAX_REQUEST_BLOCKS),
        )
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        assert response.errors == []
        assert response.successes == []

    async def test_no_block_by_slot_lookup_returns_error(self) -> None:
        """SERVER_ERROR when no block_by_slot_lookup callback is configured."""
        handler = RequestHandler()  # no lookups
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(5))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        assert response.successes == []
        assert len(response.errors) == 1
        assert response.errors[0][0] == ResponseCode.SERVER_ERROR
        assert "Block lookup not available" in response.errors[0][1]

    async def test_no_current_slot_lookup_returns_error(self) -> None:
        """SERVER_ERROR when current_slot_lookup is missing — window cannot be bounded."""
        handler = RequestHandler(block_by_slot_lookup=_slot_lookup_from({}))
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(5))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        assert response.successes == []
        assert len(response.errors) == 1
        assert response.errors[0][0] == ResponseCode.SERVER_ERROR
        assert "Current slot not available" in response.errors[0][1]

    async def test_lookup_error_continues(self) -> None:
        """Lookup exceptions are caught and processing continues."""
        block_at_4001 = make_test_block(slot=4001, seed=41)

        async def slot_lookup(slot: Slot) -> SignedBlock | None:
            if int(slot) == 4000:
                raise RuntimeError("Database error")
            if int(slot) == 4001:
                return block_at_4001
            return None

        handler = _make_range_handler(block_by_slot_lookup=slot_lookup)
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(3))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        decoded_slots = [SignedBlock.decode_bytes(s).block.slot for s in response.successes]
        assert response.errors == []
        assert decoded_slots == [Slot(4001)]

    async def test_empty_range_returns_no_blocks(self) -> None:
        """Range with no blocks at all returns empty (no error)."""
        handler = _make_range_handler()
        response = MockResponseStream()

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(5))
        await handler.handle_blocks_by_range(request, response)  # type: ignore[arg-type]

        assert response.errors == []
        assert response.successes == []


class TestReqRespServerBlocksByRange:
    """Full ReqRespServer integration tests for BlocksByRange."""

    async def test_handle_blocks_by_range_request(self) -> None:
        """Full BlocksByRange request/response flow through ReqRespServer."""
        block = make_test_block(slot=4000, seed=40)
        handler = _make_range_handler(blocks={4000: block})
        server = ReqRespServer(handler=handler)

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(1))
        request_bytes = encode_request(request.encode_bytes())

        stream = MockStream(request_data=request_bytes)
        await server.handle_stream(stream, BLOCKS_BY_RANGE_PROTOCOL_V1)

        assert stream.closed is True
        success_blocks = []
        for chunk in stream.written:
            code, ssz_bytes = ResponseCode.decode(chunk)
            if code == ResponseCode.SUCCESS:
                success_blocks.append(SignedBlock.decode_bytes(ssz_bytes))
        assert [b.block.slot for b in success_blocks] == [Slot(4000)]

    async def test_invalid_ssz_returns_invalid_request(self) -> None:
        """Invalid SSZ for BlocksByRange returns INVALID_REQUEST."""
        handler = _make_range_handler()
        server = ReqRespServer(handler=handler)

        invalid_ssz = b"\xff" * 10
        request_bytes = encode_request(invalid_ssz)
        stream = MockStream(request_data=request_bytes)

        await server.handle_stream(stream, BLOCKS_BY_RANGE_PROTOCOL_V1)

        assert stream.closed is True
        codes = [ResponseCode.decode(chunk)[0] for chunk in stream.written]
        assert codes == [ResponseCode.INVALID_REQUEST]

    async def test_protocol_id_in_reqresp_set(self) -> None:
        """BlocksByRange protocol ID is in REQRESP_PROTOCOL_IDS."""
        assert BLOCKS_BY_RANGE_PROTOCOL_V1 in REQRESP_PROTOCOL_IDS

    async def test_roundtrip_blocks_by_range_multiple(self) -> None:
        """Full encode -> server -> decode roundtrip for multiple blocks."""
        blocks_db = {4000 + i: make_test_block(slot=4000 + i, seed=40 + i) for i in range(3)}
        handler = _make_range_handler(blocks=blocks_db)
        server = ReqRespServer(handler=handler)

        request = BlocksByRangeRequest(start_slot=Slot(4000), count=Uint64(3))
        request_wire = encode_request(request.encode_bytes())
        stream = MockStream(request_data=request_wire)

        await server.handle_stream(stream, BLOCKS_BY_RANGE_PROTOCOL_V1)

        success_blocks = []
        for response_wire in stream.written:
            code, ssz_bytes = ResponseCode.decode(response_wire)
            if code == ResponseCode.SUCCESS:
                success_blocks.append(SignedBlock.decode_bytes(ssz_bytes))
        assert [b.block.slot for b in success_blocks] == [Slot(4000 + i) for i in range(3)]
