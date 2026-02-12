"""
Network Event Types.

Event types that flow from the network layer to the sync service.

Event Flow
----------
The network layer produces events as an async stream.
The network service consumes these events and routes them to sync handlers.

::

    LiveNetworkEventSource (async iterator)
           |
    Network Service (pattern matching dispatch)
           |
           +-- Gossip block events          --> Sync block handler
           +-- Gossip attestation events    --> Sync attestation handler
           +-- Peer status events           --> Sync peer tracker
"""

from __future__ import annotations

from dataclasses import dataclass

from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.containers.attestation import SignedAggregatedAttestation, SignedAttestation
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.transport import PeerId


@dataclass(frozen=True, slots=True)
class GossipBlockEvent:
    """
    Block received via gossip subscription.

    Fired when a signed block arrives from the gossipsub network.
    The block may or may not have a known parent in the store.
    """

    block: SignedBlockWithAttestation
    """The signed block with attestation proof."""

    peer_id: PeerId
    """Peer that propagated this block to us."""

    topic: GossipTopic
    """Topic the block was received on (includes fork digest)."""


@dataclass(frozen=True, slots=True)
class GossipAttestationEvent:
    """
    Attestation received via gossip subscription.

    Fired when a signed attestation arrives from the gossipsub network.
    """

    attestation: SignedAttestation
    """The signed attestation."""

    peer_id: PeerId
    """Peer that propagated this attestation to us."""

    topic: GossipTopic
    """Topic the attestation was received on (includes fork digest)."""


@dataclass(frozen=True, slots=True)
class GossipAggregatedAttestationEvent:
    """
    Aggregated attestation received via gossip subscription.

    Fired when a signed aggregated attestation arrives from the gossipsub network.
    Aggregates contain multiple validator votes combined into a single proof.
    """

    signed_attestation: SignedAggregatedAttestation
    """The signed aggregated attestation."""

    peer_id: PeerId
    """Peer that propagated this aggregated attestation to us."""

    topic: GossipTopic
    """Topic the aggregated attestation was received on."""


@dataclass(frozen=True, slots=True)
class PeerStatusEvent:
    """
    Peer sent their chain status.

    Fired when a peer responds to or initiates a Status request.
    Contains the peer's view of the chain (head, finalized checkpoint).
    """

    peer_id: PeerId
    """Peer that sent their status."""

    status: Status
    """The peer's chain status (finalized checkpoint and head)."""


@dataclass(frozen=True, slots=True)
class PeerConnectedEvent:
    """
    New peer connection established.

    Fired when the transport layer establishes a new connection.
    The peer has not yet exchanged Status messages at this point.
    """

    peer_id: PeerId
    """Peer that connected."""


@dataclass(frozen=True, slots=True)
class PeerDisconnectedEvent:
    """
    Peer disconnected.

    Fired when a peer connection is closed:
        - either gracefully (Goodbye message) or
        - due to transport failure.
    """

    peer_id: PeerId
    """Peer that disconnected."""


NetworkEvent = (
    GossipBlockEvent
    | GossipAttestationEvent
    | GossipAggregatedAttestationEvent
    | PeerStatusEvent
    | PeerConnectedEvent
    | PeerDisconnectedEvent
)
"""Union of all network event types for pattern matching dispatch."""
