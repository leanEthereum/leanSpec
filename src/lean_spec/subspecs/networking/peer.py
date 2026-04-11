"""Peer Information"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import time

from .enr import ENR
from .reqresp import Status
from .transport import PeerId
from .types import ConnectionState, Direction, ForkDigest, Multiaddr


@dataclass(slots=True)
class PeerInfo:
    """
    Information about a known peer.

    Tracks identity, connection state, and cached protocol data.

    The enr and status fields cache fork data from discovery and handshake:

    - enr: Populated from discovery, contains eth2 fork_digest
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

    last_seen: float = field(default_factory=time)
    """Unix timestamp of last successful interaction."""

    enr: ENR | None = None
    """Cached ENR from discovery. Contains eth2 fork_digest for compatibility checks."""

    status: Status | None = None
    """Cached Status from handshake. Contains finalized/head checkpoints."""

    def is_connected(self) -> bool:
        """Check if peer has an active connection."""
        return self.state == ConnectionState.CONNECTED

    def update_last_seen(self) -> None:
        """Update the last seen timestamp to now."""
        self.last_seen = time()

    @property
    def fork_digest(self) -> ForkDigest | None:
        """
        Get the peer's fork_digest from cached ENR.

        Returns:
            4-byte fork_digest or None if ENR/eth2 data unavailable.
        """
        if self.enr is None:
            return None
        eth2_data = self.enr.eth2_data
        if eth2_data is None:
            return None
        return eth2_data.fork_digest
