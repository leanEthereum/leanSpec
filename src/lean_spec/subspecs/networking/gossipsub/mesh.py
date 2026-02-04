"""
Gossipsub Mesh State
====================

Manages the mesh topology for gossipsub topics.

Overview
--------

Each subscribed topic maintains a **mesh**: a set of peers for full
message exchange. The mesh is the core data structure enabling
gossipsub's eager push protocol.

- **Mesh peers**: Exchange full messages immediately (eager push)
- **Non-mesh peers**: Receive IHAVE advertisements, request via IWANT (lazy pull)

Mesh vs Fanout
--------------

+----------+----------------------------------------------------------+
| Type     | Description                                              |
+==========+==========================================================+
| Mesh     | Peers for topics we subscribe to                         |
+----------+----------------------------------------------------------+
| Fanout   | Temporary peers for topics we publish to but don't       |
|          | subscribe to. Expires after fanout_ttl.                  |
+----------+----------------------------------------------------------+

Heartbeat Maintenance
---------------------

The mesh is maintained through periodic heartbeat:

1. **Graft** if |mesh| < D_low: add peers up to D
2. **Prune** if |mesh| > D_high: remove peers down to D
3. **Gossip**: send IHAVE to D_lazy non-mesh peers

References:
----------
- Gossipsub v1.0: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from ..transport import PeerId
from .parameters import GossipsubParameters
from .types import TopicId


@dataclass(slots=True)
class FanoutEntry:
    """Fanout state for a publish-only topic.

    Tracks peers used when publishing to topics we don't subscribe to.
    Fanout entries expire after a period of inactivity (fanout_ttl).

    Unlike mesh peers, fanout peers only receive our published messages.
    We don't receive their messages since we're not subscribed.
    """

    peers: set[PeerId] = field(default_factory=set)
    """Peers in the fanout for this topic.

    Selected randomly from available topic peers, up to D peers.
    """

    last_published: float = 0.0
    """Unix timestamp of the last publish to this topic.

    Used to determine if the entry has expired.
    """

    def is_stale(self, current_time: float, ttl: float) -> bool:
        """Check if this fanout entry has expired.

        Args:
            current_time: Current Unix timestamp.
            ttl: Time-to-live in seconds.

        Returns:
            True if the entry hasn't been used within ttl seconds.
        """
        return current_time - self.last_published > ttl


@dataclass(slots=True)
class TopicMesh:
    """Mesh state for a single topic.

    Represents the set of peers we exchange full messages with
    for a specific topic. Mesh membership is managed via
    GRAFT and PRUNE control messages.
    """

    peers: set[PeerId] = field(default_factory=set)
    """Peers in the mesh for this topic.

    These peers receive all published messages immediately
    and forward all received messages to us.
    """

    def add_peer(self, peer_id: PeerId) -> bool:
        """Add a peer to this topic's mesh.

        Args:
            peer_id: Peer to add.

        Returns:
            True if the peer was added, False if already present.
        """
        if peer_id in self.peers:
            return False
        self.peers.add(peer_id)
        return True

    def remove_peer(self, peer_id: PeerId) -> bool:
        """Remove a peer from this topic's mesh.

        Args:
            peer_id: Peer to remove.

        Returns:
            True if the peer was removed, False if not present.
        """
        if peer_id not in self.peers:
            return False
        self.peers.discard(peer_id)
        return True


@dataclass(slots=True)
class MeshState:
    """Complete mesh state for all subscribed topics.

    Central data structure managing mesh topology across all topics.
    Provides operations for subscription management, peer tracking,
    and gossip peer selection.
    """

    params: GossipsubParameters
    """Gossipsub parameters controlling mesh behavior."""

    _meshes: dict[TopicId, TopicMesh] = field(default_factory=dict, repr=False)
    """Mesh state for each subscribed topic. Keyed by topic ID."""

    _fanouts: dict[TopicId, FanoutEntry] = field(default_factory=dict, repr=False)
    """Fanout state for publish-only topics. Keyed by topic ID."""

    _subscriptions: set[TopicId] = field(default_factory=set, repr=False)
    """Set of topics we are subscribed to."""

    @property
    def d(self) -> int:
        """Target mesh size per topic."""
        return self.params.d

    @property
    def d_low(self) -> int:
        """Low watermark - graft when mesh is smaller."""
        return self.params.d_low

    @property
    def d_high(self) -> int:
        """High watermark - prune when mesh is larger."""
        return self.params.d_high

    @property
    def d_lazy(self) -> int:
        """Number of peers for IHAVE gossip."""
        return self.params.d_lazy

    def subscribe(self, topic: TopicId) -> None:
        """Subscribe to a topic, initializing its mesh.

        If we have fanout peers for this topic, they are
        promoted to the mesh automatically.

        Args:
            topic: Topic identifier to subscribe to.
        """
        if topic in self._subscriptions:
            return

        self._subscriptions.add(topic)

        # Promote fanout peers to mesh if any
        mesh = TopicMesh()
        if topic in self._fanouts:
            mesh.peers = self._fanouts[topic].peers.copy()
            del self._fanouts[topic]
        self._meshes[topic] = mesh

    def unsubscribe(self, topic: TopicId) -> set[PeerId]:
        """Unsubscribe from a topic.

        Args:
            topic: Topic identifier to unsubscribe from.

        Returns:
            Set of peers that were in the mesh (need PRUNE).
        """
        self._subscriptions.discard(topic)
        mesh = self._meshes.pop(topic, None)
        return mesh.peers if mesh else set()

    def is_subscribed(self, topic: TopicId) -> bool:
        """Check if subscribed to a topic.

        Args:
            topic: Topic identifier to check.

        Returns:
            True if subscribed.
        """
        return topic in self._subscriptions

    def get_mesh_peers(self, topic: TopicId) -> set[PeerId]:
        """Get mesh peers for a topic.

        Args:
            topic: Topic identifier.

        Returns:
            Copy of the mesh peer set, or empty set if not subscribed.
        """
        mesh = self._meshes.get(topic)
        return mesh.peers.copy() if mesh else set()

    def add_to_mesh(self, topic: TopicId, peer_id: PeerId) -> bool:
        """Add a peer to a topic's mesh.

        Args:
            topic: Topic identifier.
            peer_id: Peer to add.

        Returns:
            - True if added,
            - False if already present or not subscribed.
        """
        mesh = self._meshes.get(topic)
        if mesh is None:
            return False
        return mesh.add_peer(peer_id)

    def remove_from_mesh(self, topic: TopicId, peer_id: PeerId) -> bool:
        """Remove a peer from a topic's mesh.

        Args:
            topic: Topic identifier.
            peer_id: Peer to remove.

        Returns:
            - True if removed,
            - False if not present or not subscribed.
        """
        mesh = self._meshes.get(topic)
        if mesh is None:
            return False
        return mesh.remove_peer(peer_id)

    def get_fanout_peers(self, topic: TopicId) -> set[PeerId]:
        """Get fanout peers for a topic.

        Args:
            topic: Topic identifier.

        Returns:
            Copy of the fanout peer set, or empty set if none.
        """
        fanout = self._fanouts.get(topic)
        return fanout.peers.copy() if fanout else set()

    def update_fanout(self, topic: TopicId, available_peers: set[PeerId]) -> set[PeerId]:
        """Update fanout for publishing to a non-subscribed topic.

        For subscribed topics, returns mesh peers instead.

        Args:
            topic: Topic identifier.
            available_peers: All known peers for this topic.

        Returns:
            Peers to publish to (mesh or fanout).
        """
        if topic in self._subscriptions:
            return self.get_mesh_peers(topic)

        fanout = self._fanouts.get(topic)
        if fanout is None:
            fanout = FanoutEntry()
            self._fanouts[topic] = fanout

        fanout.last_published = time.time()

        # Fill fanout up to D peers
        if len(fanout.peers) < self.d:
            candidates = available_peers - fanout.peers
            needed = self.d - len(fanout.peers)
            new_peers = random.sample(list(candidates), min(needed, len(candidates)))
            fanout.peers.update(new_peers)

        return fanout.peers.copy()

    def cleanup_fanouts(self, ttl: float) -> int:
        """Remove expired fanout entries.

        Args:
            ttl: Time-to-live in seconds.

        Returns:
            Number of entries removed.
        """
        current_time = time.time()
        stale = [t for t, f in self._fanouts.items() if f.is_stale(current_time, ttl)]
        for topic in stale:
            del self._fanouts[topic]
        return len(stale)

    def select_peers_for_gossip(self, topic: TopicId, all_topic_peers: set[PeerId]) -> list[PeerId]:
        """Select non-mesh peers for IHAVE gossip.

        Randomly selects up to D_lazy peers from those not in the mesh.
        These peers receive IHAVE messages during heartbeat.

        Args:
            topic: Topic identifier.
            all_topic_peers: All known peers subscribed to this topic.

        Returns:
            List of peers to send IHAVE gossip to.
        """
        mesh_peers = self.get_mesh_peers(topic)
        candidates = list(all_topic_peers - mesh_peers)

        if len(candidates) <= self.d_lazy:
            return candidates

        return random.sample(candidates, self.d_lazy)
