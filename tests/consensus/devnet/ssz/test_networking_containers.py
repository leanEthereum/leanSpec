"""SSZ conformance tests for networking containers."""

import pytest
from consensus_testing import SSZTestFiller

from lean_spec.subspecs.containers import Checkpoint, Slot
from lean_spec.subspecs.networking.reqresp.message import (
    BlocksByRootRequest,
    RequestedBlockRoots,
    Status,
)
from lean_spec.types import Bytes32

pytestmark = pytest.mark.valid_until("Devnet")


# --- Status ---


def test_status_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Status with zero values."""
    ssz(
        type_name="Status",
        value=Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        ),
    )


def test_status_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Status with typical values."""
    ssz(
        type_name="Status",
        value=Status(
            finalized=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(100)),
            head=Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(150)),
        ),
    )


# --- BlocksByRootRequest ---


def test_blocks_by_root_request_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlocksByRootRequest with no roots."""
    ssz(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(roots=RequestedBlockRoots(data=[])),
    )


def test_blocks_by_root_request_single(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlocksByRootRequest with single root."""
    ssz(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(roots=RequestedBlockRoots(data=[Bytes32(b"\xab" * 32)])),
    )


def test_blocks_by_root_request_multiple(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlocksByRootRequest with multiple roots."""
    ssz(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(
            roots=RequestedBlockRoots(
                data=[Bytes32(b"\x01" * 32), Bytes32(b"\x02" * 32), Bytes32(b"\x03" * 32)]
            )
        ),
    )
