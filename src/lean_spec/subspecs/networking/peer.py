"""Peer Information"""

from __future__ import annotations

from dataclasses import dataclass

from .enr import ENR
from .reqresp import Status
from .transport import PeerId
from .types import ConnectionState, Direction, Multiaddr


@dataclass(slots=True)
class PeerInfo:
    """
    Information about a known peer.

    Tracks identity, connection state, and cached protocol data.

    The enr and status fields cache fork data from peer configuration and handshake:

    - enr: Populated from bootnode/peer configuration, contains eth2 fork_digest
    - status: Populated after Status handshake, contains finalized/head checkpoints

    These cached values enable fork compatibility checks at multiple layers.
    """

    peer_id: PeerId
    """The libp2p peer identifier."""

    state: ConnectionState = ConnectionState.DISCONNECTED
    """Current connection state."""

    direction: Direction = Direction.OUTBOUND
    """Connection direction (inbound/outbound)."""

    address: Multiaddr | None = None
    """Last known network address for this peer."""

    enr: ENR | None = None
    """Cached ENR from peer configuration. Contains eth2 fork_digest for compatibility checks."""

    status: Status | None = None
    """Cached Status from handshake. Contains finalized/head checkpoints."""

    def is_connected(self) -> bool:
        """Check if peer has an active connection."""
        return self.state == ConnectionState.CONNECTED
