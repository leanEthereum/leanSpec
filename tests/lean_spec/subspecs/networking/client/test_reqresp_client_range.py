"""Tests for the outbound BlocksByRange protocol on the ReqResp client."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from lean_spec.forks.lstar.containers import Block, BlockBody, SignedBlock
from lean_spec.forks.lstar.containers.block import BlockSignatures
from lean_spec.forks.lstar.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking.client.reqresp_client import ReqRespClient
from lean_spec.subspecs.networking.config import MAX_REQUEST_BLOCKS
from lean_spec.subspecs.networking.reqresp.codec import (
    CodecError,
    ResponseCode,
)
from lean_spec.subspecs.networking.reqresp.message import (
    BLOCKS_BY_RANGE_PROTOCOL_V1,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import make_mock_signature


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


def make_client() -> ReqRespClient:
    """Create a ReqRespClient that bypasses the connection manager."""
    return ReqRespClient(connection_manager=None)  # type: ignore[arg-type]


def empty_signed_block(slot: Slot, parent_root: Bytes32, state_seed: int) -> SignedBlock:
    """Build a SignedBlock with the requested slot and parent_root."""
    block = Block(
        slot=slot,
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        state_root=Bytes32(bytes([state_seed]) * 32),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    return SignedBlock(
        block=block,
        signature=BlockSignatures(
            attestation_signatures=AttestationSignatures(data=[]),
            proposer_signature=make_mock_signature(),
        ),
    )


def build_chain(start_slot: int, count: int, root_seed: int = 0xAA) -> list[SignedBlock]:
    """Return a chain of strictly-increasing-slot blocks starting at start_slot.

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
        conn = MockRangeConnection(peer_id=peer_id)
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(0), Uint64(0))

        assert blocks == []
        assert conn.opened_protocols == []

    async def test_count_above_max_returns_empty_without_opening_stream(
        self, peer_id: PeerId
    ) -> None:
        """A count strictly larger than MAX_REQUEST_BLOCKS is rejected locally."""
        client = make_client()
        conn = MockRangeConnection(peer_id=peer_id)
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(
            peer_id, Slot(0), Uint64(MAX_REQUEST_BLOCKS + 1)
        )

        assert blocks == []
        assert conn.opened_protocols == []

    async def test_overflow_range_returns_empty_without_opening_stream(
        self, peer_id: PeerId
    ) -> None:
        """A start_slot+count overflow above 2**64-1 is rejected locally."""
        client = make_client()
        conn = MockRangeConnection(peer_id=peer_id)
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        max_slot = int(Uint64.max_value())
        blocks = await client.request_blocks_by_range(peer_id, Slot(max_slot - 4), Uint64(10))

        assert blocks == []
        assert conn.opened_protocols == []

    async def test_no_connection_returns_empty(self, peer_id: PeerId) -> None:
        """A request with no registered connection returns an empty list."""
        client = make_client()

        blocks = await client.request_blocks_by_range(peer_id, Slot(1), Uint64(3))

        assert blocks == []

    async def test_full_range_success(self, peer_id: PeerId) -> None:
        """A clean response of count blocks is returned in order."""
        client = make_client()
        chain = build_chain(start_slot=10, count=4)

        stream = MockRangeStream(response_chunks=[encode_success(b) for b in chain])
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(10), Uint64(4))

        assert blocks == chain
        assert conn.opened_protocols == [BLOCKS_BY_RANGE_PROTOCOL_V1]
        assert stream.closed is True
        assert stream.finish_write_called is True

    async def test_partial_response_when_stream_closes_early(self, peer_id: PeerId) -> None:
        """Stream closing before count is reached returns the partial list."""
        client = make_client()
        chain = build_chain(start_slot=20, count=2)

        stream = MockRangeStream(response_chunks=[encode_success(b) for b in chain])
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

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
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

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
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        with pytest.raises(CodecError, match=r"Non-monotonic slot"):
            await client.request_blocks_by_range(peer_id, Slot(40), Uint64(2))

    async def test_out_of_range_slot_raises_codec_error(self, peer_id: PeerId) -> None:
        """A block whose slot falls outside the requested range is rejected."""
        client = make_client()
        # Request [50, 53). Peer responds with a block at slot 60.
        out_of_range = empty_signed_block(Slot(60), Bytes32(b"\xaa" * 32), state_seed=1)

        stream = MockRangeStream(response_chunks=[encode_success(out_of_range)])
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        with pytest.raises(CodecError, match=r"outside requested range"):
            await client.request_blocks_by_range(peer_id, Slot(50), Uint64(3))

    async def test_parent_root_continuity_violation_across_skipped_slot(
        self, peer_id: PeerId
    ) -> None:
        """A wrong parent root after a skipped empty slot is rejected as a protocol violation.

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
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        with pytest.raises(CodecError, match=r"Parent root mismatch"):
            await client.request_blocks_by_range(peer_id, Slot(70), Uint64(5))

    async def test_parent_root_continuity_holds_across_skipped_slots(self, peer_id: PeerId) -> None:
        """A correct parent_root linkage across empty slots is accepted."""
        client = make_client()
        # Request [80, 90). Peer responds with slot 80 and slot 85, where the
        # slot 85 block chains correctly off the slot 80 block.
        first = empty_signed_block(Slot(80), Bytes32(b"\xaa" * 32), state_seed=1)
        second = empty_signed_block(Slot(85), parent_root=hash_tree_root(first.block), state_seed=2)

        stream = MockRangeStream(response_chunks=[encode_success(first), encode_success(second)])
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

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
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        with pytest.raises(CodecError, match=r"more than count"):
            await client.request_blocks_by_range(peer_id, Slot(100), Uint64(2))

    async def test_timeout_returns_empty_list(self, peer_id: PeerId) -> None:
        """A request that times out returns an empty list rather than raising."""
        client = make_client()
        client.timeout = 0.01
        conn = MockRangeConnection(peer_id=peer_id, streams=[MockRangeStream()])

        async def slow_read() -> bytes:
            await asyncio.sleep(1.0)
            return b""

        conn.streams[0].read = slow_read  # type: ignore[method-assign]
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(0), Uint64(3))

        assert blocks == []

    async def test_server_error_stops_reading_and_returns_partial(self, peer_id: PeerId) -> None:
        """A SERVER_ERROR chunk halts reading and returns blocks received so far."""
        client = make_client()
        chain = build_chain(start_slot=200, count=1)
        error_chunk = ResponseCode.SERVER_ERROR.encode(b"db boom")

        stream = MockRangeStream(response_chunks=[encode_success(chain[0]), error_chunk])
        conn = MockRangeConnection(peer_id=peer_id, streams=[stream])
        client.register_connection(peer_id, conn)  # type: ignore[arg-type]

        blocks = await client.request_blocks_by_range(peer_id, Slot(200), Uint64(3))

        assert blocks == chain
