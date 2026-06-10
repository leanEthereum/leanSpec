"""Network event source bridging transport to sync service."""

from lean_spec.node.networking.client.event_source.gossip import GossipHandler, read_gossip_message
from lean_spec.node.networking.client.event_source.live import LiveNetworkEventSource
from lean_spec.node.networking.client.event_source.protocol import (
    SUPPORTED_PROTOCOLS,
    EventSource,
    GossipMessageError,
)

__all__ = [
    "SUPPORTED_PROTOCOLS",
    "EventSource",
    "GossipHandler",
    "GossipMessageError",
    "LiveNetworkEventSource",
    "read_gossip_message",
]
