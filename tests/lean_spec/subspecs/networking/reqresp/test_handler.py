"""Tests for inbound ReqResp protocol handlers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from lean_spec.subspecs.containers import Checkpoint, SignedBlockWithAttestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.networking.reqresp.codec import (
    ResponseCode,
    encode_request,
)
from lean_spec.subspecs.networking.reqresp.handler import (
    REQRESP_PROTOCOL_IDS,
    BlockLookup,
    DefaultRequestHandler,
    ReqRespServer,
    YamuxResponseStream,
)
from lean_spec.subspecs.networking.reqresp.message import (
    BLOCKS_BY_ROOT_PROTOCOL_V1,
    STATUS_PROTOCOL_V1,
    BlocksByRootRequest,
    RequestedBlockRoots,
    Status,
)
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import make_test_block, make_test_status, run_async

# -----------------------------------------------------------------------------
# Mock Classes
# -----------------------------------------------------------------------------


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

    async def read(self, n: int = -1) -> bytes:
        """
        Return request data in a single chunk, then empty bytes.

        Simulates the stream EOF behavior.
        """
        if self._read_offset >= len(self.request_data):
            return b""
        chunk = self.request_data[self._read_offset :]
        self._read_offset = len(self.request_data)
        return chunk

    async def write(self, data: bytes) -> None:
        """Accumulate written data for inspection."""
        self.written.append(data)

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


# -----------------------------------------------------------------------------
# TestYamuxResponseStream
# -----------------------------------------------------------------------------


class TestYamuxResponseStream:
    """Tests for YamuxResponseStream wire format encoding."""

    def test_send_success_encodes_correctly(self) -> None:
        """Success response uses SUCCESS code and encodes SSZ data."""

        async def run_test() -> tuple[list[bytes], bool]:
            stream = MockStream()
            response = YamuxResponseStream(_stream=stream)

            ssz_data = b"\x01\x02\x03\x04"
            await response.send_success(ssz_data)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert len(written) == 1
        encoded = written[0]

        # First byte should be SUCCESS (0)
        assert encoded[0] == ResponseCode.SUCCESS

        # Should decode back to original data
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.SUCCESS
        assert decoded == b"\x01\x02\x03\x04"

    def test_send_error_encodes_correctly(self) -> None:
        """Error response uses specified code and UTF-8 message."""

        async def run_test() -> list[bytes]:
            stream = MockStream()
            response = YamuxResponseStream(_stream=stream)

            await response.send_error(ResponseCode.INVALID_REQUEST, "Bad request")

            return stream.written

        written = run_async(run_test())

        assert len(written) == 1
        encoded = written[0]

        # First byte should be INVALID_REQUEST (1)
        assert encoded[0] == ResponseCode.INVALID_REQUEST

        # Should decode back to UTF-8 message
        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.INVALID_REQUEST
        assert decoded == b"Bad request"

    def test_send_error_server_error(self) -> None:
        """SERVER_ERROR code encodes correctly."""

        async def run_test() -> list[bytes]:
            stream = MockStream()
            response = YamuxResponseStream(_stream=stream)

            await response.send_error(ResponseCode.SERVER_ERROR, "Internal error")

            return stream.written

        written = run_async(run_test())
        encoded = written[0]

        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.SERVER_ERROR
        assert decoded == b"Internal error"

    def test_send_error_resource_unavailable(self) -> None:
        """RESOURCE_UNAVAILABLE code encodes correctly."""

        async def run_test() -> list[bytes]:
            stream = MockStream()
            response = YamuxResponseStream(_stream=stream)

            await response.send_error(ResponseCode.RESOURCE_UNAVAILABLE, "Block not found")

            return stream.written

        written = run_async(run_test())
        encoded = written[0]

        code, decoded = ResponseCode.decode(encoded)
        assert code == ResponseCode.RESOURCE_UNAVAILABLE
        assert decoded == b"Block not found"

    def test_finish_closes_stream(self) -> None:
        """Finish closes the underlying stream."""

        async def run_test() -> bool:
            stream = MockStream()
            response = YamuxResponseStream(_stream=stream)

            assert not stream.closed
            await response.finish()
            return stream.closed

        closed = run_async(run_test())
        assert closed is True


# -----------------------------------------------------------------------------
# TestDefaultRequestHandler - Status
# -----------------------------------------------------------------------------


class TestDefaultRequestHandlerStatus:
    """Tests for DefaultRequestHandler.handle_status."""

    def test_handle_status_returns_our_status(self) -> None:
        """Returns our configured status on valid request."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            our_status = make_test_status()
            handler = DefaultRequestHandler(our_status=our_status)
            response = MockResponseStream()

            peer_status = Status(
                finalized=Checkpoint(root=Bytes32(b"\xaa" * 32), slot=Slot(50)),
                head=Checkpoint(root=Bytes32(b"\xbb" * 32), slot=Slot(150)),
            )

            await handler.handle_status(peer_status, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        assert len(errors) == 0
        assert len(successes) == 1

        # Decode the SSZ response
        returned_status = Status.decode_bytes(successes[0])
        assert returned_status.head.slot == Slot(200)
        assert returned_status.finalized.slot == Slot(100)

    def test_handle_status_no_status_returns_error(self) -> None:
        """Returns SERVER_ERROR when no status is configured."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            handler = DefaultRequestHandler()  # No our_status set
            response = MockResponseStream()

            peer_status = make_test_status()
            await handler.handle_status(peer_status, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        assert len(successes) == 0
        assert len(errors) == 1
        assert errors[0][0] == ResponseCode.SERVER_ERROR
        assert "not available" in errors[0][1]

    def test_handle_status_ignores_peer_status(self) -> None:
        """Peer's status does not affect our response."""

        async def run_test() -> bytes:
            our_status = make_test_status()
            handler = DefaultRequestHandler(our_status=our_status)
            response = MockResponseStream()

            # Peer claims different chain state
            peer_status = Status(
                finalized=Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(9999)),
                head=Checkpoint(root=Bytes32(b"\xee" * 32), slot=Slot(10000)),
            )

            await handler.handle_status(peer_status, response)

            return response.successes[0]

        ssz_data = run_async(run_test())

        # Our response is independent of peer's status
        returned_status = Status.decode_bytes(ssz_data)
        assert returned_status.head.slot == Slot(200)
        assert returned_status.finalized.slot == Slot(100)


# -----------------------------------------------------------------------------
# TestDefaultRequestHandler - BlocksByRoot
# -----------------------------------------------------------------------------


class TestDefaultRequestHandlerBlocksByRoot:
    """Tests for DefaultRequestHandler.handle_blocks_by_root."""

    def test_handle_blocks_by_root_returns_found_blocks(self) -> None:
        """Sends SUCCESS response for each found block."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            block1 = make_test_block(slot=1, seed=1)
            block2 = make_test_block(slot=2, seed=2)

            # Create lookup that returns blocks for specific roots
            block_roots: dict[bytes, SignedBlockWithAttestation] = {
                b"\x11" * 32: block1,
                b"\x22" * 32: block2,
            }

            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                return block_roots.get(bytes(root))

            handler = DefaultRequestHandler(block_lookup=lookup)
            response = MockResponseStream()

            request = BlocksByRootRequest(
                roots=RequestedBlockRoots(data=[Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)])
            )

            await handler.handle_blocks_by_root(request, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        assert len(errors) == 0
        assert len(successes) == 2

        # Both blocks should be decodable
        decoded1 = SignedBlockWithAttestation.decode_bytes(successes[0])
        decoded2 = SignedBlockWithAttestation.decode_bytes(successes[1])

        assert decoded1.message.block.slot == Slot(1)
        assert decoded2.message.block.slot == Slot(2)

    def test_handle_blocks_by_root_skips_missing_blocks(self) -> None:
        """Missing blocks are silently skipped."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            block1 = make_test_block(slot=1, seed=1)

            # Only block1 exists
            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                if bytes(root) == b"\x11" * 32:
                    return block1
                return None

            handler = DefaultRequestHandler(block_lookup=lookup)
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

            await handler.handle_blocks_by_root(request, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        # Only one block returned, no errors
        assert len(errors) == 0
        assert len(successes) == 1

    def test_handle_blocks_by_root_no_lookup_returns_error(self) -> None:
        """Returns SERVER_ERROR when no lookup callback is configured."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            handler = DefaultRequestHandler()  # No block_lookup set
            response = MockResponseStream()

            request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[Bytes32(b"\x11" * 32)]))

            await handler.handle_blocks_by_root(request, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        assert len(successes) == 0
        assert len(errors) == 1
        assert errors[0][0] == ResponseCode.SERVER_ERROR
        assert "not available" in errors[0][1]

    def test_handle_blocks_by_root_empty_request(self) -> None:
        """Empty request returns no blocks and no errors."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                return None

            handler = DefaultRequestHandler(block_lookup=lookup)
            response = MockResponseStream()

            request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[]))

            await handler.handle_blocks_by_root(request, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        assert len(errors) == 0
        assert len(successes) == 0

    def test_handle_blocks_by_root_lookup_error_continues(self) -> None:
        """Lookup exceptions are caught and processing continues."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            block2 = make_test_block(slot=2, seed=2)

            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                if bytes(root) == b"\x11" * 32:
                    raise RuntimeError("Database error")
                if bytes(root) == b"\x22" * 32:
                    return block2
                return None

            handler = DefaultRequestHandler(block_lookup=lookup)
            response = MockResponseStream()

            # First block causes error, second succeeds
            request = BlocksByRootRequest(
                roots=RequestedBlockRoots(data=[Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)])
            )

            await handler.handle_blocks_by_root(request, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        # Second block still returned despite first lookup failing
        assert len(errors) == 0
        assert len(successes) == 1

        decoded = SignedBlockWithAttestation.decode_bytes(successes[0])
        assert decoded.message.block.slot == Slot(2)


# -----------------------------------------------------------------------------
# TestReqRespServer
# -----------------------------------------------------------------------------


class TestReqRespServer:
    """Tests for ReqRespServer request handling."""

    def test_handle_status_request(self) -> None:
        """Full Status request/response flow through ReqRespServer."""

        async def run_test() -> tuple[list[bytes], bool]:
            our_status = make_test_status()
            handler = DefaultRequestHandler(our_status=our_status)
            server = ReqRespServer(handler=handler)

            # Build wire-format request
            peer_status = Status(
                finalized=Checkpoint(root=Bytes32(b"\xaa" * 32), slot=Slot(50)),
                head=Checkpoint(root=Bytes32(b"\xbb" * 32), slot=Slot(150)),
            )
            request_bytes = encode_request(peer_status.encode_bytes())

            stream = MockStream(request_data=request_bytes)

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        # Stream should be closed after handling
        assert closed is True

        # Should have received a success response
        assert len(written) >= 1

        # Decode the response
        code, ssz_data = ResponseCode.decode(written[0])
        assert code == ResponseCode.SUCCESS

        returned_status = Status.decode_bytes(ssz_data)
        assert returned_status.head.slot == Slot(200)

    def test_handle_blocks_by_root_request(self) -> None:
        """Full BlocksByRoot request/response flow through ReqRespServer."""

        async def run_test() -> tuple[list[bytes], bool]:
            block1 = make_test_block(slot=1, seed=1)
            root1 = Bytes32(b"\x11" * 32)

            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                if bytes(root) == bytes(root1):
                    return block1
                return None

            handler = DefaultRequestHandler(block_lookup=lookup)
            server = ReqRespServer(handler=handler)

            # Build wire-format request
            request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[root1]))
            request_bytes = encode_request(request.encode_bytes())

            stream = MockStream(request_data=request_bytes)

            await server.handle_stream(stream, BLOCKS_BY_ROOT_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, ssz_data = ResponseCode.decode(written[0])
        assert code == ResponseCode.SUCCESS

        returned_block = SignedBlockWithAttestation.decode_bytes(ssz_data)
        assert returned_block.message.block.slot == Slot(1)

    def test_empty_request_returns_error(self) -> None:
        """Empty request data returns INVALID_REQUEST error."""

        async def run_test() -> tuple[list[bytes], bool]:
            handler = DefaultRequestHandler(our_status=make_test_status())
            server = ReqRespServer(handler=handler)

            stream = MockStream(request_data=b"")

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, message = ResponseCode.decode(written[0])
        assert code == ResponseCode.INVALID_REQUEST
        assert b"Empty" in message

    def test_decode_error_returns_invalid_request(self) -> None:
        """Malformed wire data returns INVALID_REQUEST error."""

        async def run_test() -> tuple[list[bytes], bool]:
            handler = DefaultRequestHandler(our_status=make_test_status())
            server = ReqRespServer(handler=handler)

            # Invalid snappy data after length prefix
            malformed_data = b"\x10\x00\x00\x00invalid snappy data here"
            stream = MockStream(request_data=malformed_data)

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, _ = ResponseCode.decode(written[0])
        assert code == ResponseCode.INVALID_REQUEST

    def test_invalid_ssz_returns_invalid_request(self) -> None:
        """Valid wire format but invalid SSZ returns INVALID_REQUEST."""

        async def run_test() -> tuple[list[bytes], bool]:
            handler = DefaultRequestHandler(our_status=make_test_status())
            server = ReqRespServer(handler=handler)

            # Valid wire format but SSZ is too short for Status (needs 80 bytes)
            invalid_ssz = b"\x01\x02\x03\x04"
            request_bytes = encode_request(invalid_ssz)
            stream = MockStream(request_data=request_bytes)

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, message = ResponseCode.decode(written[0])
        assert code == ResponseCode.INVALID_REQUEST
        assert b"Invalid Status" in message or b"Status" in message

    def test_unknown_protocol_returns_error(self) -> None:
        """Unknown protocol ID returns SERVER_ERROR."""

        async def run_test() -> tuple[list[bytes], bool]:
            handler = DefaultRequestHandler(our_status=make_test_status())
            server = ReqRespServer(handler=handler)

            # Valid request data but unknown protocol
            status = make_test_status()
            request_bytes = encode_request(status.encode_bytes())
            stream = MockStream(request_data=request_bytes)

            unknown_protocol = "/unknown/protocol/1/ssz_snappy"
            await server.handle_stream(stream, unknown_protocol)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, message = ResponseCode.decode(written[0])
        assert code == ResponseCode.SERVER_ERROR
        assert b"Unknown" in message or b"protocol" in message.lower()

    def test_stream_closed_on_completion(self) -> None:
        """Stream is always closed after handling, even on success."""

        async def run_test() -> bool:
            handler = DefaultRequestHandler(our_status=make_test_status())
            server = ReqRespServer(handler=handler)

            status = make_test_status()
            request_bytes = encode_request(status.encode_bytes())
            stream = MockStream(request_data=request_bytes)

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.closed

        closed = run_async(run_test())
        assert closed is True

    def test_stream_closed_on_error(self) -> None:
        """Stream is closed even when handling fails."""

        async def run_test() -> bool:
            handler = DefaultRequestHandler()  # No status configured
            server = ReqRespServer(handler=handler)

            status = make_test_status()
            request_bytes = encode_request(status.encode_bytes())
            stream = MockStream(request_data=request_bytes)

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.closed

        closed = run_async(run_test())
        assert closed is True


# -----------------------------------------------------------------------------
# TestReqRespProtocolConstants
# -----------------------------------------------------------------------------


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


# -----------------------------------------------------------------------------
# TestIntegration - Roundtrip Tests
# -----------------------------------------------------------------------------


class TestIntegration:
    """Integration tests for full request/response roundtrips."""

    def test_roundtrip_status_request(self) -> None:
        """Full encode -> server -> decode roundtrip for Status."""

        async def run_test() -> Status:
            our_status = make_test_status()
            handler = DefaultRequestHandler(our_status=our_status)
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
            return Status.decode_bytes(ssz_bytes)

        returned = run_async(run_test())

        # Verify we got our status back
        assert returned.head.slot == Slot(200)
        assert returned.finalized.slot == Slot(100)

    def test_roundtrip_blocks_by_root_request(self) -> None:
        """Full encode -> server -> decode roundtrip for BlocksByRoot."""

        async def run_test() -> list[SignedBlockWithAttestation]:
            block1 = make_test_block(slot=10, seed=10)
            block2 = make_test_block(slot=20, seed=20)

            root1 = Bytes32(b"\xaa" * 32)
            root2 = Bytes32(b"\xbb" * 32)

            blocks_by_root: dict[bytes, SignedBlockWithAttestation] = {
                bytes(root1): block1,
                bytes(root2): block2,
            }

            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                return blocks_by_root.get(bytes(root))

            handler = DefaultRequestHandler(block_lookup=lookup)
            server = ReqRespServer(handler=handler)

            # Client side: encode request
            request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[root1, root2]))
            request_wire = encode_request(request.encode_bytes())

            # Server side: handle request
            stream = MockStream(request_data=request_wire)
            await server.handle_stream(stream, BLOCKS_BY_ROOT_PROTOCOL_V1)

            # Client side: decode responses
            results = []
            for response_wire in stream.written:
                code, ssz_bytes = ResponseCode.decode(response_wire)
                if code == ResponseCode.SUCCESS:
                    results.append(SignedBlockWithAttestation.decode_bytes(ssz_bytes))

            return results

        blocks = run_async(run_test())

        assert len(blocks) == 2
        slots = {b.message.block.slot for b in blocks}
        assert Slot(10) in slots
        assert Slot(20) in slots

    def test_roundtrip_blocks_by_root_partial_response(self) -> None:
        """BlocksByRoot returns only available blocks."""

        async def run_test() -> list[SignedBlockWithAttestation]:
            block1 = make_test_block(slot=10, seed=10)

            root1 = Bytes32(b"\xaa" * 32)
            root_missing = Bytes32(b"\x00" * 32)

            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                if bytes(root) == bytes(root1):
                    return block1
                return None

            handler = DefaultRequestHandler(block_lookup=lookup)
            server = ReqRespServer(handler=handler)

            # Request two blocks, only one exists
            request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[root1, root_missing]))
            request_wire = encode_request(request.encode_bytes())

            stream = MockStream(request_data=request_wire)
            await server.handle_stream(stream, BLOCKS_BY_ROOT_PROTOCOL_V1)

            results = []
            for response_wire in stream.written:
                code, ssz_bytes = ResponseCode.decode(response_wire)
                if code == ResponseCode.SUCCESS:
                    results.append(SignedBlockWithAttestation.decode_bytes(ssz_bytes))

            return results

        blocks = run_async(run_test())

        # Only one block returned
        assert len(blocks) == 1
        assert blocks[0].message.block.slot == Slot(10)


# -----------------------------------------------------------------------------
# TestResponseStreamProtocol
# -----------------------------------------------------------------------------


class TestResponseStreamProtocol:
    """Tests verifying ResponseStream protocol compliance."""

    def test_mock_response_stream_is_protocol_compliant(self) -> None:
        """MockResponseStream implements ResponseStream protocol."""
        # This test verifies our mock is usable with the handler
        mock = MockResponseStream()

        # Should have the required methods
        assert hasattr(mock, "send_success")
        assert hasattr(mock, "send_error")
        assert hasattr(mock, "finish")

        # Methods should be callable
        assert callable(mock.send_success)
        assert callable(mock.send_error)
        assert callable(mock.finish)

    def test_yamux_response_stream_is_protocol_compliant(self) -> None:
        """YamuxResponseStream implements ResponseStream protocol."""
        stream = MockStream()
        yamux = YamuxResponseStream(_stream=stream)

        assert hasattr(yamux, "send_success")
        assert hasattr(yamux, "send_error")
        assert hasattr(yamux, "finish")


# -----------------------------------------------------------------------------
# TestBlockLookupTypeAlias
# -----------------------------------------------------------------------------


class TestBlockLookupTypeAlias:
    """Tests for BlockLookup type alias usage."""

    def test_async_function_matches_block_lookup_signature(self) -> None:
        """Verify async function can be used as BlockLookup."""

        async def my_lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
            return None

        # Should type-check as BlockLookup
        lookup: BlockLookup = my_lookup

        async def run_test() -> SignedBlockWithAttestation | None:
            return await lookup(Bytes32(b"\x00" * 32))

        result = run_async(run_test())
        assert result is None

    def test_block_lookup_returning_block(self) -> None:
        """BlockLookup returning a block works correctly."""
        block = make_test_block(slot=42, seed=42)

        async def my_lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
            return block

        async def run_test() -> SignedBlockWithAttestation | None:
            return await my_lookup(Bytes32(b"\x00" * 32))

        result = run_async(run_test())
        assert result is not None
        assert result.message.block.slot == Slot(42)


# -----------------------------------------------------------------------------
# TestYamuxResponseStreamMultipleResponses
# -----------------------------------------------------------------------------


class TestYamuxResponseStreamMultipleResponses:
    """Tests for YamuxResponseStream with multiple responses in sequence."""

    def test_send_multiple_success_responses(self) -> None:
        """Multiple SUCCESS responses are written independently."""

        async def run_test() -> list[bytes]:
            stream = MockStream()
            response = YamuxResponseStream(_stream=stream)

            await response.send_success(b"\x01\x02")
            await response.send_success(b"\x03\x04")
            await response.send_success(b"\x05\x06")

            return stream.written

        written = run_async(run_test())

        assert len(written) == 3

        # Each response should be independently decodable
        for i, data in enumerate(written):
            code, decoded = ResponseCode.decode(data)
            assert code == ResponseCode.SUCCESS
            expected = bytes([i * 2 + 1, i * 2 + 2])
            assert decoded == expected

    def test_send_success_then_error(self) -> None:
        """Success response followed by error response."""

        async def run_test() -> list[bytes]:
            stream = MockStream()
            response = YamuxResponseStream(_stream=stream)

            await response.send_success(b"\xaa\xbb")
            await response.send_error(ResponseCode.RESOURCE_UNAVAILABLE, "Done")

            return stream.written

        written = run_async(run_test())

        assert len(written) == 2

        code1, data1 = ResponseCode.decode(written[0])
        assert code1 == ResponseCode.SUCCESS
        assert data1 == b"\xaa\xbb"

        code2, data2 = ResponseCode.decode(written[1])
        assert code2 == ResponseCode.RESOURCE_UNAVAILABLE
        assert data2 == b"Done"

    def test_send_empty_success_response(self) -> None:
        """Empty SUCCESS response payload is handled."""

        async def run_test() -> list[bytes]:
            stream = MockStream()
            response = YamuxResponseStream(_stream=stream)

            await response.send_success(b"")

            return stream.written

        written = run_async(run_test())

        assert len(written) == 1
        code, decoded = ResponseCode.decode(written[0])
        assert code == ResponseCode.SUCCESS
        assert decoded == b""


# -----------------------------------------------------------------------------
# TestMockStreamChunkedRead
# -----------------------------------------------------------------------------


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

    async def read(self, n: int = -1) -> bytes:
        """Return chunks one at a time."""
        if self.chunk_index >= len(self.chunks):
            return b""
        chunk = self.chunks[self.chunk_index]
        self.chunk_index += 1
        return chunk

    async def write(self, data: bytes) -> None:
        """Accumulate written data."""
        self.written.append(data)

    async def close(self) -> None:
        """Mark stream as closed."""
        self.closed = True

    async def reset(self) -> None:
        """Abort the stream."""
        self.closed = True


class TestReqRespServerChunkedRead:
    """Tests for ReqRespServer handling chunked request data."""

    def test_handle_chunked_status_request(self) -> None:
        """Request data arriving in multiple chunks is assembled correctly."""

        async def run_test() -> tuple[list[bytes], bool]:
            our_status = make_test_status()
            handler = DefaultRequestHandler(our_status=our_status)
            server = ReqRespServer(handler=handler)

            # Build wire-format request
            peer_status = make_test_status()
            request_bytes = encode_request(peer_status.encode_bytes())

            # Split into multiple chunks
            mid = len(request_bytes) // 2
            chunks = [request_bytes[:mid], request_bytes[mid:]]

            stream = MockChunkedStream(chunks=chunks)

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, ssz_data = ResponseCode.decode(written[0])
        assert code == ResponseCode.SUCCESS

    def test_handle_single_byte_chunks(self) -> None:
        """Request data arriving one byte at a time is handled."""

        async def run_test() -> tuple[list[bytes], bool]:
            our_status = make_test_status()
            handler = DefaultRequestHandler(our_status=our_status)
            server = ReqRespServer(handler=handler)

            peer_status = make_test_status()
            request_bytes = encode_request(peer_status.encode_bytes())

            # Split into single-byte chunks
            chunks = [bytes([b]) for b in request_bytes]

            stream = MockChunkedStream(chunks=chunks)

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, _ = ResponseCode.decode(written[0])
        assert code == ResponseCode.SUCCESS


# -----------------------------------------------------------------------------
# TestReqRespServerEdgeCases
# -----------------------------------------------------------------------------


class TestReqRespServerEdgeCases:
    """Edge cases for ReqRespServer."""

    def test_invalid_blocks_by_root_ssz(self) -> None:
        """Invalid SSZ for BlocksByRoot returns INVALID_REQUEST."""

        async def run_test() -> tuple[list[bytes], bool]:
            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                return None

            handler = DefaultRequestHandler(block_lookup=lookup)
            server = ReqRespServer(handler=handler)

            # Valid wire format but wrong SSZ structure for BlocksByRootRequest
            # BlocksByRootRequest expects list of Bytes32, not arbitrary bytes
            invalid_ssz = b"\xff" * 10
            request_bytes = encode_request(invalid_ssz)
            stream = MockStream(request_data=request_bytes)

            await server.handle_stream(stream, BLOCKS_BY_ROOT_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, message = ResponseCode.decode(written[0])
        assert code == ResponseCode.INVALID_REQUEST

    def test_truncated_varint_returns_error(self) -> None:
        """Truncated varint in request returns INVALID_REQUEST."""

        async def run_test() -> tuple[list[bytes], bool]:
            handler = DefaultRequestHandler(our_status=make_test_status())
            server = ReqRespServer(handler=handler)

            # Varint with continuation bit set but no following byte
            truncated_varint = b"\x80"
            stream = MockStream(request_data=truncated_varint)

            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.written, stream.closed

        written, closed = run_async(run_test())

        assert closed is True
        assert len(written) >= 1

        code, _ = ResponseCode.decode(written[0])
        assert code == ResponseCode.INVALID_REQUEST


# -----------------------------------------------------------------------------
# TestDefaultRequestHandlerEdgeCases
# -----------------------------------------------------------------------------


class TestDefaultRequestHandlerEdgeCases:
    """Edge cases for DefaultRequestHandler."""

    def test_blocks_by_root_single_block(self) -> None:
        """Single block request returns correctly."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            block = make_test_block(slot=999, seed=99)
            root = Bytes32(b"\x99" * 32)

            async def lookup(r: Bytes32) -> SignedBlockWithAttestation | None:
                if bytes(r) == bytes(root):
                    return block
                return None

            handler = DefaultRequestHandler(block_lookup=lookup)
            response = MockResponseStream()

            request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[root]))

            await handler.handle_blocks_by_root(request, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        assert len(errors) == 0
        assert len(successes) == 1

        decoded = SignedBlockWithAttestation.decode_bytes(successes[0])
        assert decoded.message.block.slot == Slot(999)

    def test_blocks_by_root_all_missing(self) -> None:
        """Request where all blocks are missing returns no success responses."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                return None

            handler = DefaultRequestHandler(block_lookup=lookup)
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

            await handler.handle_blocks_by_root(request, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        assert len(errors) == 0
        assert len(successes) == 0

    def test_blocks_by_root_mixed_found_missing(self) -> None:
        """Mixed found/missing blocks returns only found blocks."""

        async def run_test() -> tuple[list[bytes], list[tuple[ResponseCode, str]]]:
            block1 = make_test_block(slot=1, seed=1)
            block3 = make_test_block(slot=3, seed=3)

            blocks: dict[bytes, SignedBlockWithAttestation] = {
                b"\x11" * 32: block1,
                # \x22 missing
                b"\x33" * 32: block3,
            }

            async def lookup(root: Bytes32) -> SignedBlockWithAttestation | None:
                return blocks.get(bytes(root))

            handler = DefaultRequestHandler(block_lookup=lookup)
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

            await handler.handle_blocks_by_root(request, response)

            return response.successes, response.errors

        successes, errors = run_async(run_test())

        assert len(errors) == 0
        assert len(successes) == 2

        # Verify order is preserved
        decoded1 = SignedBlockWithAttestation.decode_bytes(successes[0])
        decoded2 = SignedBlockWithAttestation.decode_bytes(successes[1])

        assert decoded1.message.block.slot == Slot(1)
        assert decoded2.message.block.slot == Slot(3)

    def test_status_update_after_initialization(self) -> None:
        """Status can be updated after handler creation."""

        async def run_test() -> tuple[list[bytes], list[bytes]]:
            handler = DefaultRequestHandler()
            response1 = MockResponseStream()

            # First request with no status
            await handler.handle_status(make_test_status(), response1)

            # Update status
            handler.our_status = make_test_status()

            response2 = MockResponseStream()
            await handler.handle_status(make_test_status(), response2)

            return response1.successes, response2.successes

        successes1, successes2 = run_async(run_test())

        # First request should fail
        assert len(successes1) == 0

        # Second request should succeed
        assert len(successes2) == 1


# -----------------------------------------------------------------------------
# TestConcurrentRequestHandling
# -----------------------------------------------------------------------------


class TestConcurrentRequestHandling:
    """Tests for concurrent request handling."""

    def test_concurrent_status_requests(self) -> None:
        """Multiple concurrent status requests are handled independently."""

        async def run_test() -> list[Status]:
            our_status = make_test_status()
            handler = DefaultRequestHandler(our_status=our_status)
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

            return results

        results = run_async(run_test())

        # All responses should be our status
        for status in results:
            assert status.head.slot == Slot(200)
            assert status.finalized.slot == Slot(100)

    def test_concurrent_mixed_requests(self) -> None:
        """Concurrent Status and BlocksByRoot requests."""

        async def run_test() -> tuple[list[Status], list[SignedBlockWithAttestation]]:
            block = make_test_block(slot=42, seed=42)
            root = Bytes32(b"\x42" * 32)

            async def lookup(r: Bytes32) -> SignedBlockWithAttestation | None:
                if bytes(r) == bytes(root):
                    return block
                return None

            our_status = make_test_status()
            handler = DefaultRequestHandler(our_status=our_status, block_lookup=lookup)
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
            block_result = SignedBlockWithAttestation.decode_bytes(ssz_data)

            return [status_result], [block_result]

        statuses, blocks = run_async(run_test())

        assert len(statuses) == 1
        assert statuses[0].head.slot == Slot(200)

        assert len(blocks) == 1
        assert blocks[0].message.block.slot == Slot(42)


# -----------------------------------------------------------------------------
# TestHandlerExceptionRecovery
# -----------------------------------------------------------------------------


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

    async def read(self, n: int = -1) -> bytes:
        """Return request data."""
        if self._read_offset >= len(self.request_data):
            return b""
        chunk = self.request_data[self._read_offset :]
        self._read_offset = len(self.request_data)
        return chunk

    async def write(self, data: bytes) -> None:
        """Optionally fail on write."""
        if self.fail_on_write:
            raise ConnectionError("Write failed")
        self.written.append(data)

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

    def test_stream_closed_despite_close_exception(self) -> None:
        """Stream close is attempted even if it raises an exception."""

        async def run_test() -> int:
            handler = DefaultRequestHandler(our_status=make_test_status())
            server = ReqRespServer(handler=handler)

            request_bytes = encode_request(make_test_status().encode_bytes())
            stream = MockFailingStream(
                request_data=request_bytes,
                fail_on_close=True,
            )

            # Should not raise, exception is caught
            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.close_attempts

        close_attempts = run_async(run_test())

        # Close should be attempted
        assert close_attempts >= 1

    def test_error_response_sent_despite_write_exception(self) -> None:
        """Error handling continues even when write fails."""

        async def run_test() -> int:
            handler = DefaultRequestHandler()  # No status
            server = ReqRespServer(handler=handler)

            request_bytes = encode_request(make_test_status().encode_bytes())
            stream = MockFailingStream(
                request_data=request_bytes,
                fail_on_write=True,
            )

            # Should not raise, writes that fail are caught
            await server.handle_stream(stream, STATUS_PROTOCOL_V1)

            return stream.close_attempts

        close_attempts = run_async(run_test())

        # Close should still be attempted after write failure
        assert close_attempts >= 1


# -----------------------------------------------------------------------------
# TestRequestHandlerConstant
# -----------------------------------------------------------------------------


class TestRequestTimeoutConstant:
    """Tests for REQUEST_TIMEOUT_SECONDS constant."""

    def test_timeout_is_positive(self) -> None:
        """Request timeout is a positive number."""
        from lean_spec.subspecs.networking.reqresp.handler import REQUEST_TIMEOUT_SECONDS

        assert REQUEST_TIMEOUT_SECONDS > 0

    def test_timeout_is_reasonable(self) -> None:
        """Request timeout is within reasonable bounds."""
        from lean_spec.subspecs.networking.reqresp.handler import REQUEST_TIMEOUT_SECONDS

        # Should be at least a few seconds
        assert REQUEST_TIMEOUT_SECONDS >= 1.0
        # Should not be excessively long
        assert REQUEST_TIMEOUT_SECONDS <= 60.0


# -----------------------------------------------------------------------------
# TestMockStreamProtocolCompliance
# -----------------------------------------------------------------------------


class TestMockStreamProtocolCompliance:
    """Tests verifying mock streams match the Stream protocol."""

    def test_mock_stream_has_protocol_id(self) -> None:
        """MockStream has protocol_id property."""
        stream = MockStream()
        assert hasattr(stream, "protocol_id")
        assert isinstance(stream.protocol_id, str)

    def test_mock_stream_has_read_method(self) -> None:
        """MockStream has read method."""
        stream = MockStream()
        assert hasattr(stream, "read")
        assert callable(stream.read)

    def test_mock_stream_has_write_method(self) -> None:
        """MockStream has write method."""
        stream = MockStream()
        assert hasattr(stream, "write")
        assert callable(stream.write)

    def test_mock_stream_has_close_method(self) -> None:
        """MockStream has close method."""
        stream = MockStream()
        assert hasattr(stream, "close")
        assert callable(stream.close)

    def test_mock_stream_has_reset_method(self) -> None:
        """MockStream has reset method."""
        stream = MockStream()
        assert hasattr(stream, "reset")
        assert callable(stream.reset)

    def test_mock_stream_reset_closes_stream(self) -> None:
        """MockStream reset marks stream as closed."""

        async def run_test() -> bool:
            stream = MockStream()
            await stream.reset()
            return stream.closed

        closed = run_async(run_test())
        assert closed is True
