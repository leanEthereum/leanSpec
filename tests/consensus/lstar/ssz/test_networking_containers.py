"""SSZ conformance tests for networking containers."""

import pytest

from consensus_testing import SSZTestFiller
from lean_spec.node.networking.reqresp.message import (
    BlocksByRootRequest,
    RequestedBlockRoots,
    Status,
)
from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_status_zero(ssz_test: SSZTestFiller) -> None:
    """
    A status message with zero checkpoints round-trips unchanged.

    Given
    -----
    - a status message whose finalized and head checkpoints are both zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Status",
        value=Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        ),
    )


def test_status_typical(ssz_test: SSZTestFiller) -> None:
    """
    A status message with distinct checkpoints round-trips unchanged.

    Given
    -----
    - a status message with a finalized checkpoint at slot 100.
    - a head checkpoint at slot 150.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Status",
        value=Status(
            finalized=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(100)),
            head=Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(150)),
        ),
    )


def test_blocks_by_root_request_empty(ssz_test: SSZTestFiller) -> None:
    """
    A blocks-by-root request with no roots round-trips unchanged.

    Given
    -----
    - a request whose root list is empty.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(roots=RequestedBlockRoots(data=[])),
    )


def test_blocks_by_root_request_single(ssz_test: SSZTestFiller) -> None:
    """
    A blocks-by-root request with one root round-trips unchanged.

    Given
    -----
    - a request carrying a single block root.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(roots=RequestedBlockRoots(data=[Bytes32(b"\xab" * 32)])),
    )


def test_blocks_by_root_request_multiple(ssz_test: SSZTestFiller) -> None:
    """
    A blocks-by-root request with three roots round-trips unchanged.

    Given
    -----
    - a request carrying three distinct block roots.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(
            roots=RequestedBlockRoots(
                data=[Bytes32(b"\x01" * 32), Bytes32(b"\x02" * 32), Bytes32(b"\x03" * 32)]
            )
        ),
    )


def test_blocks_by_root_request_max_roots(ssz_test: SSZTestFiller) -> None:
    """
    A blocks-by-root request with ten roots round-trips unchanged.

    Given
    -----
    - a request carrying ten distinct block roots.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="BlocksByRootRequest",
        value=BlocksByRootRequest(
            roots=RequestedBlockRoots(data=[Bytes32(bytes([i]) * 32) for i in range(1, 11)])
        ),
    )
