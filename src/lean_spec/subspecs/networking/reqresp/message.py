"""
Request/Response Domain Message Types.

This module defines the data structures for the peer-to-peer request/response
domain. All messages are SSZ-encoded and then compressed with Snappy frames.
"""

from typing import ClassVar

from lean_spec.subspecs.containers import Checkpoint
from lean_spec.types import Bytes32, SSZList
from lean_spec.types.container import Container

from ..config import MAX_REQUEST_BLOCKS
from ..types import ProtocolId

# --- Status v1 ---

STATUS_PROTOCOL_V1: ProtocolId = "/leanconsensus/req/status/1/ssz_snappy"
"""The protocol ID for the Status v1 request/response message."""


class Status(Container):
    """
    The Status message, used by clients to share their chain state.

    This is the first message sent upon a new connection and is essential for
    the peer-to-peer handshake. It allows nodes to verify compatibility and
    determine if they are on the same chain.

    SSZ encoding produces 80 bytes:
        - finalized.root (32 bytes)
        - finalized.slot (8 bytes)
        - head.root (32 bytes)
        - head.slot (8 bytes)
    """

    finalized: Checkpoint
    """The client's latest finalized checkpoint."""

    head: Checkpoint
    """The client's current head checkpoint."""


# --- BlocksByRoot v1 ---

BLOCKS_BY_ROOT_PROTOCOL_V1: ProtocolId = "/leanconsensus/req/blocks_by_root/1/ssz_snappy"
"""The protocol ID for the BlocksByRoot v1 request/response message."""


class BlocksByRootRequestRoots(SSZList[Bytes32]):
    """List of requested root hashes."""

    LIMIT: ClassVar[int] = MAX_REQUEST_BLOCKS


class BlocksByRootRequest(Container):
    """
    A request for one or more blocks by their root hashes.

    This is primarily used to recover recent or missing blocks from a peer.
    """

    roots: BlocksByRootRequestRoots
    """List of requested root hashes."""
