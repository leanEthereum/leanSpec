"""
Request/Response Domain Message Types.

This module defines the data structures for the peer-to-peer request/response
domain. All messages are SSZ-encoded and then compressed with Snappy frames.
"""

from pydantic import Field
from typing_extensions import Annotated

from lean_spec.subspecs.containers import Checkpoint, SignedBlock
from lean_spec.types import Bytes32, StrictBaseModel

from .config import MAX_REQUEST_BLOCKS
from .types import ProtocolId

# --- Status v1 ---

STATUS_PROTOCOL_V1: ProtocolId = "/leanconsensus/req/status/1/"
"""The protocol ID for the Status v1 request/response message."""


class Status(StrictBaseModel):
    """
    The Status message, used by clients to share their chain state.

    This is the first message sent upon a new connection and is essential for
    the peer-to-peer handshake. It allows nodes to verify compatibility and
    determine if they are on the same chain.
    """

    finalized: Checkpoint
    """The client's latest finalized checkpoint."""

    head: Checkpoint
    """The client's current head checkpoint."""


# --- BlocksByRoot v1 ---

BLOCKS_BY_ROOT_PROTOCOL_V1: ProtocolId = "/leanconsensus/req/blocks_by_root/1/"
"""The protocol ID for the BlocksByRoot v1 request/response message."""

BlocksByRootRequest = Annotated[
    list[Bytes32],
    Field(max_length=MAX_REQUEST_BLOCKS),
]
"""
A request for one or more blocks by their root hashes.

This is primarily used to recover recent or missing blocks from a peer.
"""

BlocksByRootResponse = Annotated[
    list[SignedBlock],
    Field(max_length=MAX_REQUEST_BLOCKS),
]
"""
A response containing the requested `SignedBlock` objects.

The length of the list may be less than the number of requested blocks if
the responding peer does not have all of them. Each block is sent in a
separate `response_chunk`.
"""
