"""
Network service module.

This module provides the event routing layer between libp2p and consensus.
"""

from .events import (
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    NetworkEventSource,
    PeerConnectedEvent,
    PeerDisconnectedEvent,
    PeerStatusEvent,
)
from .service import NetworkService

__all__ = [
    # Service
    "NetworkService",
    # Protocol
    "NetworkEventSource",
    # Events
    "GossipAttestationEvent",
    "GossipBlockEvent",
    "NetworkEvent",
    "PeerConnectedEvent",
    "PeerDisconnectedEvent",
    "PeerStatusEvent",
]
