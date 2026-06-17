"""Tracks peer chain status and selects peers for block download requests."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Final

from lean_spec.node.networking.peer import PeerInfo
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.node.networking.transport.peer_id import PeerId
from lean_spec.node.sync.config import MAX_CONCURRENT_REQUESTS
from lean_spec.spec.forks import Slot

INITIAL_PEER_SCORE: Final = 100
"""Starting score, mid-range so a new peer competes without dominating."""

MIN_PEER_SCORE: Final = 0
"""Score floor."""

MAX_PEER_SCORE: Final = 200
"""Score ceiling."""

SCORE_SUCCESS_BONUS: Final = 10
"""Reward per successful request."""

SCORE_FAILURE_PENALTY: Final = 20
"""
Penalty per failed request.

Double the success reward, so a failing peer loses weight faster than it earns it.
"""


@dataclass(slots=True)
class SyncPeer:
    """Sync-specific state for one peer: chain status and request tracking."""

    info: PeerInfo
    """Underlying record from the networking layer."""

    status: Status | None = None
    """Chain status from the last status exchange, or None if never exchanged."""

    requests_in_flight: int = 0
    """Count of requests sent but not yet completed."""

    score: int = INITIAL_PEER_SCORE
    """Reputation score; higher means more reliable."""

    @property
    def peer_id(self) -> PeerId:
        """The peer's identifier."""
        return self.info.peer_id

    def is_connected(self) -> bool:
        """Whether the peer is currently connected."""
        return self.info.is_connected()

    def is_available(self) -> bool:
        """Whether the peer is connected and below its in-flight request limit."""
        return self.is_connected() and self.requests_in_flight < MAX_CONCURRENT_REQUESTS

    def has_slot(self, slot: Slot) -> bool:
        """Whether the peer's last-reported head reaches the given slot."""
        return self.status is not None and self.status.head.slot >= slot

    def on_request_start(self) -> None:
        """Record that a request was sent."""
        self.requests_in_flight += 1

    def record_success(self) -> None:
        """Release the in-flight slot and reward the peer for a completed request."""
        self.requests_in_flight = max(0, self.requests_in_flight - 1)
        self.score = min(self.score + SCORE_SUCCESS_BONUS, MAX_PEER_SCORE)

    def record_failure(self) -> None:
        """Release the in-flight slot and penalize the peer for a failed request."""
        self.requests_in_flight = max(0, self.requests_in_flight - 1)
        self.score = max(self.score - SCORE_FAILURE_PENALTY, MIN_PEER_SCORE)


@dataclass(slots=True)
class PeerManager:
    """Tracks sync peers and selects among them for block requests."""

    peers: dict[PeerId, SyncPeer] = field(default_factory=dict)
    """Tracked peers, keyed by identifier."""

    def __len__(self) -> int:
        """Number of tracked peers."""
        return len(self.peers)

    def __contains__(self, peer_id: PeerId) -> bool:
        """Whether the peer is tracked."""
        return peer_id in self.peers

    def add_peer(self, peer_info: PeerInfo) -> SyncPeer:
        """Register a new peer, or refresh the networking record of an existing one."""
        existing_peer = self.peers.get(peer_info.peer_id)
        if existing_peer is not None:
            existing_peer.info = peer_info
            return existing_peer

        sync_peer = SyncPeer(info=peer_info)
        self.peers[peer_info.peer_id] = sync_peer
        return sync_peer

    def remove_peer(self, peer_id: PeerId) -> SyncPeer | None:
        """Stop tracking a peer, returning its state if it was present."""
        return self.peers.pop(peer_id, None)

    def update_status(self, peer_id: PeerId, status: Status) -> None:
        """Store a peer's latest chain status, unvalidated and used only for routing."""
        peer = self.peers.get(peer_id)
        if peer is not None:
            peer.status = status

    def select_peer_for_request(self, min_slot: Slot | None = None) -> SyncPeer | None:
        """
        Pick an available peer at random, weighted by score to favor reliable peers.

        Args:
            min_slot: If set, only peers whose head reaches this slot are considered.

        Returns:
            A selected peer, or None if none are available.
        """
        candidates = [
            peer
            for peer in self.peers.values()
            if peer.is_available() and (min_slot is None or peer.has_slot(min_slot))
        ]
        if not candidates:
            return None

        # Floor every weight at 1 so a zero-score peer still has a chance.
        # Without this floor a single failure could exclude a peer forever.
        weights = [max(peer.score, 1) for peer in candidates]
        return random.choices(candidates, weights=weights, k=1)[0]

    def get_network_finalized_slot(self) -> Slot | None:
        """Estimated sync target: the finalized slot most peers claim, not verified finality."""
        reported_finalized_slots = Counter(
            peer.status.finalized.slot
            for peer in self.peers.values()
            if peer.status is not None and peer.is_connected()
        )
        if not reported_finalized_slots:
            return None
        # Rank by report count first, then by the slot value.
        # The higher slot wins an equal-count tie, keeping the result insertion-order independent.
        return max(
            reported_finalized_slots,
            key=lambda finalized_slot: (reported_finalized_slots[finalized_slot], finalized_slot),
        )

    def on_request_success(self, peer_id: PeerId) -> None:
        """Close out a request as successful and raise the peer's score."""
        peer = self.peers.get(peer_id)
        if peer is not None:
            peer.record_success()

    def on_request_failure(self, peer_id: PeerId) -> None:
        """Close out a request as failed and lower the peer's score."""
        peer = self.peers.get(peer_id)
        if peer is not None:
            peer.record_failure()
