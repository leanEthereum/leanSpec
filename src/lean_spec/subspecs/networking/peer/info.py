"""Peer Information"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, auto
from time import time
from typing import TYPE_CHECKING

from ..transport import PeerId
from ..types import ConnectionState, Multiaddr

if TYPE_CHECKING:
    from ..enr import ENR
    from ..reqresp import Status


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
    def fork_digest(self) -> bytes | None:
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
        return bytes(eth2_data.fork_digest)
