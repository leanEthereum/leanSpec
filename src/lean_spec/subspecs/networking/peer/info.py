"""Peer Information"""

from dataclasses import dataclass, field
from enum import IntEnum, auto
from time import time

from ..transport import PeerId
from ..types import ConnectionState, Multiaddr


class Direction(IntEnum):
    """
    Direction of a peer connection.

    Indicates whether:
        - we initiated the connection (outbound) or
        - the peer connected to us (inbound).
    """

    INBOUND = auto()
    """Peer initiated the connection to us."""

    OUTBOUND = auto()
    """We initiated the connection to the peer."""


@dataclass
class PeerInfo:
    """
    Minimal information about a known peer.

    Tracks only the essential data needed to manage peer connections:
    identity, connection state, direction, and last activity timestamp.

    This is intentionally minimal - additional fields (scoring, subnet
    subscriptions, protocol metadata) can be added as features are
    implemented.
    """

    peer_id: PeerId
    """The libp2p peer identifier."""

    state: ConnectionState = ConnectionState.DISCONNECTED
    """Current connection state."""

    direction: Direction = Direction.OUTBOUND
    """Connection direction (inbound/outbound)."""

    address: Multiaddr | None = None
    """Last known network address for this peer."""

    last_seen: float = field(default_factory=time)
    """Unix timestamp of last successful interaction."""

    def is_connected(self) -> bool:
        """Check if peer has an active connection."""
        return self.state == ConnectionState.CONNECTED

    def update_last_seen(self) -> None:
        """Update the last seen timestamp to now."""
        self.last_seen = time()
