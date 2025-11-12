"""
Request/Response Domain Message Types.

This module defines the data structures for the peer-to-peer request/response
domain. All messages are SSZ-encoded and then compressed with Snappy frames.
"""

from pydantic import Field
from typing_extensions import Annotated

from lean_spec.subspecs.containers import Checkpoint, SignedBlockWithAttestation
from lean_spec.types import Bytes32, StrictBaseModel

from ..config import MAX_REQUEST_BLOCKS
from ..types import ProtocolId

# --- Status v1 ---

STATUS_PROTOCOL_V1: ProtocolId = "/leanconsensus/req/status/1/"
"""The protocol ID for the Status v1 request/response message."""


class Status(StrictBaseModel):
    """
    The Status message, used by clients to share their chain state.

    This is the first message sent upon a new connection and is essential for
    the peer-to-peer handshake. It allows nodes to verify compatibility and
    determine if they are on the same chain.

    The dialing client MUST send a `Status` request upon connection.

    The request/response MUST be encoded as an SSZ-container.

    The response MUST consist of a single `response_chunk`.

    Clients SHOULD immediately disconnect from one another following the handshake
    above under the following conditions:

    1. If the (`finalized_root`, `finalized_epoch`) shared by the peer is not in the
    client's chain at the expected epoch. For example, if Peer 1 sends (root,
    epoch) of (A, 5) and Peer 2 sends (B, 3) but Peer 1 has root C at epoch 3,
    then Peer 1 would disconnect because it knows that their chains are
    irreparably disjoint.

    Once the handshake completes, the client with the lower `finalized_epoch` or
    `head_slot` (if the clients have equal `finalized_epoch`s) SHOULD request blocks
    from its counterparty via the `BlocksByRoot` request.

    *Note*: Under abnormal network condition or after some rounds of
    `BlocksByRoot` requests, the client might need to send `Status` request
    again to learn if the peer has a higher head. Implementers are free to implement
    such behavior in their own way.
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
    list[SignedBlockWithAttestation],
    Field(max_length=MAX_REQUEST_BLOCKS),
]
"""
A response containing the requested `SignedBlockWithAttestation` objects.

The length of the list may be less than the number of requested blocks if
the responding peer does not have all of them. Each block is sent in a
separate `response_chunk`.
"""
