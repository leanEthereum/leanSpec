"""Abstract event-source contract and shared protocol-id allow-list."""

from __future__ import annotations

from typing import Final, Protocol, Self

from lean_spec.node.networking.config import (
    GOSSIPSUB_DEFAULT_PROTOCOL_ID,
    GOSSIPSUB_PROTOCOL_ID_V12,
)
from lean_spec.node.networking.gossipsub.types import TopicId
from lean_spec.node.networking.reqresp.handler import REQRESP_PROTOCOL_IDS
from lean_spec.node.networking.service.events import NetworkEvent
from lean_spec.node.networking.types import ProtocolId


class EventSource(Protocol):
    """
    Protocol for network event sources.

    Defines the minimal interface needed by the network service.
    One implementation uses real network I/O.
    Another is used for testing with controlled inputs.
    """

    def __aiter__(self) -> Self:
        """Return self as async iterator."""
        ...

    async def __anext__(self) -> NetworkEvent:
        """Yield the next network event."""
        ...

    async def publish(self, topic: TopicId, data: bytes) -> None:
        """Broadcast a message to all peers on a topic."""
        ...


class GossipMessageError(Exception):
    """Raised when a gossip message cannot be processed."""


SUPPORTED_PROTOCOLS: Final[frozenset[ProtocolId]] = (
    frozenset({GOSSIPSUB_DEFAULT_PROTOCOL_ID, GOSSIPSUB_PROTOCOL_ID_V12}) | REQRESP_PROTOCOL_IDS
)
"""Protocols supported for incoming stream negotiation.

Includes:

- GossipSub v1.2
- Request/response protocols (Status, BlocksByRoot)
"""
