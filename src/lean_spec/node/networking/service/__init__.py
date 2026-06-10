"""
Network service module.

This module provides the event routing layer between libp2p and consensus.
"""

from lean_spec.node.networking.service.events import (
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    PeerConnectedEvent,
    PeerDisconnectedEvent,
    PeerStatusEvent,
)
from lean_spec.node.networking.service.service import NetworkService

__all__ = [
    # Service
    "NetworkService",
    # Events
    "GossipAttestationEvent",
    "GossipBlockEvent",
    "NetworkEvent",
    "PeerConnectedEvent",
    "PeerDisconnectedEvent",
    "PeerStatusEvent",
]
