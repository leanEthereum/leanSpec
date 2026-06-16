"""Tests for the req/resp domain message types."""

from __future__ import annotations

import pytest

from lean_spec.node.networking.config import MAX_REQUEST_BLOCKS
from lean_spec.node.networking.reqresp.message import (
    BLOCKS_BY_RANGE_PROTOCOL_V1,
    BLOCKS_BY_ROOT_PROTOCOL_V1,
    STATUS_PROTOCOL_V1,
    BlocksByRangeRequest,
    BlocksByRootRequest,
    RequestedBlockRoots,
    Status,
)
from lean_spec.node.networking.types import ProtocolId
from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.ssz import Bytes32, Uint64
from lean_spec.spec.ssz.exceptions import SSZValueError


class TestProtocolIdentifiers:
    """Tests for the request/response protocol identifiers."""

    def test_status_protocol_identifier(self) -> None:
        """The Status v1 protocol identifier matches the leanconsensus wire string."""
        assert STATUS_PROTOCOL_V1 == ProtocolId("/leanconsensus/req/status/1/ssz_snappy")

    def test_blocks_by_root_protocol_identifier(self) -> None:
        """The BlocksByRoot v1 protocol identifier matches the leanconsensus wire string."""
        assert BLOCKS_BY_ROOT_PROTOCOL_V1 == ProtocolId(
            "/leanconsensus/req/blocks_by_root/1/ssz_snappy"
        )

    def test_blocks_by_range_protocol_identifier(self) -> None:
        """The BlocksByRange v1 protocol identifier matches the leanconsensus wire string."""
        assert BLOCKS_BY_RANGE_PROTOCOL_V1 == ProtocolId(
            "/leanconsensus/req/blocks_by_range/1/ssz_snappy"
        )


class TestStatus:
    """Tests for the Status handshake message."""

    def test_construction_preserves_checkpoints(self) -> None:
        """Status holds the finalized and head checkpoints it was built with."""
        finalized_checkpoint = Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(7))
        head_checkpoint = Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(9))
        status = Status(finalized=finalized_checkpoint, head=head_checkpoint)
        assert status == Status(finalized=finalized_checkpoint, head=head_checkpoint)

    def test_ssz_encoding_is_eighty_bytes(self) -> None:
        """Status serializes to the fixed 80-byte layout of two checkpoints."""
        status = Status(
            finalized=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(7)),
            head=Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(9)),
        )
        assert len(status.encode_bytes()) == 80

    def test_ssz_roundtrip(self) -> None:
        """Encoding then decoding a Status yields the original message."""
        status = Status(
            finalized=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(7)),
            head=Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(9)),
        )
        assert Status.decode_bytes(status.encode_bytes()) == status


class TestRequestedBlockRoots:
    """Tests for the bounded list of requested block roots."""

    def test_limit_matches_max_request_blocks(self) -> None:
        """The list limit equals the configured maximum block request size."""
        assert RequestedBlockRoots.LIMIT == MAX_REQUEST_BLOCKS

    def test_accepts_list_at_limit(self) -> None:
        """A list filled to exactly the limit is accepted."""
        roots = RequestedBlockRoots(data=[Bytes32(b"\x00" * 32)] * MAX_REQUEST_BLOCKS)
        assert len(roots) == MAX_REQUEST_BLOCKS

    def test_rejects_list_over_limit(self) -> None:
        """A list one element over the limit is rejected with the full message."""
        with pytest.raises(SSZValueError) as exception_info:
            RequestedBlockRoots(data=[Bytes32(b"\x00" * 32)] * (MAX_REQUEST_BLOCKS + 1))
        assert str(exception_info.value) == (
            f"RequestedBlockRoots exceeds limit of {MAX_REQUEST_BLOCKS}, "
            f"got {MAX_REQUEST_BLOCKS + 1}"
        )


class TestBlocksByRootRequest:
    """Tests for the blocks-by-root request message."""

    def test_construction_preserves_roots(self) -> None:
        """The request holds the roots it was built with."""
        roots = RequestedBlockRoots(data=[Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)])
        assert BlocksByRootRequest(roots=roots) == BlocksByRootRequest(roots=roots)

    def test_ssz_roundtrip(self) -> None:
        """Encoding then decoding a blocks-by-root request yields the original."""
        request = BlocksByRootRequest(
            roots=RequestedBlockRoots(data=[Bytes32(b"\x11" * 32), Bytes32(b"\x22" * 32)])
        )
        assert BlocksByRootRequest.decode_bytes(request.encode_bytes()) == request

    def test_ssz_roundtrip_empty(self) -> None:
        """An empty blocks-by-root request roundtrips correctly."""
        request = BlocksByRootRequest(roots=RequestedBlockRoots(data=[]))
        assert BlocksByRootRequest.decode_bytes(request.encode_bytes()) == request


class TestBlocksByRangeRequest:
    """Tests for the blocks-by-range request message."""

    def test_construction_preserves_fields(self) -> None:
        """The request holds the start slot and count it was built with."""
        request = BlocksByRangeRequest(start_slot=Slot(3), count=Uint64(5))
        assert request == BlocksByRangeRequest(start_slot=Slot(3), count=Uint64(5))

    def test_ssz_roundtrip(self) -> None:
        """Encoding then decoding a blocks-by-range request yields the original."""
        request = BlocksByRangeRequest(start_slot=Slot(3), count=Uint64(5))
        assert BlocksByRangeRequest.decode_bytes(request.encode_bytes()) == request
