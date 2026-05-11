"""
Peer manager for sync operations.

Tracks peer chain status and selects peers for block requests.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Final

from lean_spec.subspecs.networking.peer import PeerInfo
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.transport.peer_id import PeerId
from lean_spec.types import Slot

from .config import MAX_CONCURRENT_REQUESTS

INITIAL_PEER_SCORE: Final = 100
"""Starting score for newly added peers."""

MIN_PEER_SCORE: Final = 0
"""Minimum peer score (floor)."""

MAX_PEER_SCORE: Final = 200
"""Maximum peer score (ceiling)."""

SCORE_SUCCESS_BONUS: Final = 10
"""Score increase for a successful request."""

SCORE_FAILURE_PENALTY: Final = 20
"""Score decrease for a failed request."""


@dataclass(slots=True)
class SyncPeer:
    """
    Peer information for sync operations.

    Wraps PeerInfo with sync-specific state: chain status and request tracking.
    """

    info: PeerInfo
    """Base peer information from the networking layer."""

    status: Status | None = None
    """Chain status from the last Status message exchange."""

    requests_in_flight: int = 0
    """Number of active requests to this peer."""

    score: int = INITIAL_PEER_SCORE
    """Peer reputation score. Higher means more reliable."""

    @property
    def peer_id(self) -> PeerId:
        """Get the peer's ID."""
        return self.info.peer_id

    def is_connected(self) -> bool:
        """Check if peer is currently connected."""
        return self.info.is_connected()

    def is_available(self) -> bool:
        """Check if peer can accept new requests."""
        return self.is_connected() and self.requests_in_flight < MAX_CONCURRENT_REQUESTS

    def has_slot(self, slot: Slot) -> bool:
        """Check if peer likely has data for given slot."""
        return self.status is not None and self.status.head.slot >= slot

    def on_request_start(self) -> None:
        """Mark that a request has been sent to this peer."""
        self.requests_in_flight += 1

    def on_request_complete(self) -> None:
        """Mark that a request has completed."""
        self.requests_in_flight = max(0, self.requests_in_flight - 1)


@dataclass(slots=True)
class PeerManager:
    """
    Manages peers for sync operations.

    Tracks peer chain status and provides peer selection for block requests.
    """

    _peers: dict[PeerId, SyncPeer] = field(default_factory=dict)
    """Mapping of peer ID to SyncPeer."""

    def __len__(self) -> int:
        """Return the number of tracked peers."""
        return len(self._peers)

    def __contains__(self, peer_id: PeerId) -> bool:
        """Check if a peer is being tracked."""
        return peer_id in self._peers

    def add_peer(self, info: PeerInfo) -> SyncPeer:
        """Register a new peer or update existing."""
        if info.peer_id in self._peers:
            self._peers[info.peer_id].info = info
            return self._peers[info.peer_id]

        sync_peer = SyncPeer(info=info)
        self._peers[info.peer_id] = sync_peer
        return sync_peer

    def remove_peer(self, peer_id: PeerId) -> SyncPeer | None:
        """Remove a peer from tracking."""
        return self._peers.pop(peer_id, None)

    def get_peer(self, peer_id: PeerId) -> SyncPeer | None:
        """Get a tracked peer by ID."""
        return self._peers.get(peer_id)

    def update_status(self, peer_id: PeerId, status: Status) -> None:
        """Update a peer's chain status."""
        peer = self._peers.get(peer_id)
        if peer is not None:
            peer.status = status

    def select_peer_for_request(self, min_slot: Slot | None = None) -> SyncPeer | None:
        """
        Select an available peer for a request using weighted random selection.

        Peers with higher scores are more likely to be selected. This avoids
        concentrating all load on one peer and naturally prefers reliable peers.

        Args:
            min_slot: Optional minimum slot the peer must have.

        Returns:
            An available SyncPeer, or None if no suitable peer exists.
        """
        candidates: list[SyncPeer] = []
        for peer in self._peers.values():
            if not peer.is_available():
                continue
            if min_slot is not None and not peer.has_slot(min_slot):
                continue
            candidates.append(peer)

        if not candidates:
            return None

        # Weight by score. A score of 0 still gets weight 1 to avoid exclusion.
        weights = [max(peer.score, 1) for peer in candidates]
        return random.choices(candidates, weights=weights, k=1)[0]

    def get_network_finalized_slot(self) -> Slot | None:
        """
        Determine network consensus finalized slot.

        Returns the mode (most common) finalized slot reported by connected peers.
        """
        slots = (
            peer.status.finalized.slot
            for peer in self._peers.values()
            if peer.status is not None and peer.is_connected()
        )
        counter = Counter(slots)
        if not counter:
            return None
        return counter.most_common(1)[0][0]

    def on_request_success(self, peer_id: PeerId) -> None:
        """Record a successful request to a peer."""
        peer = self._peers.get(peer_id)
        if peer is not None:
            peer.on_request_complete()
            peer.score = min(peer.score + SCORE_SUCCESS_BONUS, MAX_PEER_SCORE)

    def on_request_failure(self, peer_id: PeerId) -> None:
        """Record a failed request to a peer."""
        peer = self._peers.get(peer_id)
        if peer is not None:
            peer.on_request_complete()
            peer.score = max(peer.score - SCORE_FAILURE_PENALTY, MIN_PEER_SCORE)

    def get_all_peers(self) -> list[SyncPeer]:
        """Get all tracked peers."""
        return list(self._peers.values())
