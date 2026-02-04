"""
Gossipsub Control Messages
==========================

Control messages orchestrate the gossip mesh topology and message propagation.

Overview
--------

Gossipsub uses control messages piggybacked on regular RPC messages to:

- Manage mesh membership (GRAFT/PRUNE)
- Enable lazy message propagation (IHAVE/IWANT)
- Reduce bandwidth for large messages (IDONTWANT)

Control Message Types
---------------------

+-------------+----------------------------------------------------------+
| Message     | Purpose                                                  |
+=============+==========================================================+
| GRAFT       | Request to join a peer's mesh for a topic                |
+-------------+----------------------------------------------------------+
| PRUNE       | Notify peer of removal from mesh                         |
+-------------+----------------------------------------------------------+
| IHAVE       | Advertise message IDs available for a topic              |
+-------------+----------------------------------------------------------+
| IWANT       | Request full messages by their IDs                       |
+-------------+----------------------------------------------------------+
| IDONTWANT   | Signal that specific messages are not needed (v1.2)      |
+-------------+----------------------------------------------------------+

Protocol Flow
-------------

**Mesh Management:**

1. Peer A sends GRAFT to peer B for topic T
2. Peer B adds A to its mesh for T (or sends PRUNE if refusing)
3. Both peers now exchange full messages for topic T

**Lazy Pull:**

1. Peer A receives message M, adds to cache
2. Peer A sends IHAVE with M's ID to non-mesh peers
3. Peer B responds with IWANT if it needs M
4. Peer A sends full message M

References:
----------
- Gossipsub v1.0: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md
- Gossipsub v1.2: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.2.md
"""

from __future__ import annotations

from lean_spec.subspecs.networking.gossipsub.types import MessageId
from lean_spec.types import StrictBaseModel


class Graft(StrictBaseModel):
    """Request to join a peer's mesh for a topic.

    Sent when a peer wants to upgrade from gossip-only to full message exchange.

    The receiving peer should add the sender to its mesh unless:

    - The peer is already in the mesh
    - The mesh is at capacity (|mesh| >= D_high)
    - The peer is in a backoff period from a recent PRUNE
    """

    topic_id: str
    """Topic identifier to join the mesh for."""


class Prune(StrictBaseModel):
    """Notification of removal from a peer's mesh.

    Sent when:

    - A peer unsubscribes from a topic
    - Mesh size exceeds D_high during heartbeat
    - A GRAFT is rejected

    The pruned peer should not send GRAFT for this topic
    until the backoff period expires.
    """

    topic_id: str
    """Topic identifier being pruned from."""


class IHave(StrictBaseModel):
    """Advertisement of cached message IDs for a topic.

    Sent to non-mesh peers during heartbeat to enable lazy pull.
    Recipients can request any missing messages via IWANT.

    Only includes messages from recent cache windows (mcache_gossip).
    """

    topic_id: str
    """Topic the advertised messages belong to."""

    message_ids: list[MessageId]
    """IDs of messages available in the sender's cache."""


class IWant(StrictBaseModel):
    """Request for full messages by their IDs.

    Sent in response to IHAVE when the peer needs specific messages.
    The peer should respond with the requested messages if still cached.
    """

    message_ids: list[MessageId]
    """IDs of messages being requested."""


class IDontWant(StrictBaseModel):
    """Signal that specific messages are not needed.

    Introduced in gossipsub v1.2 for bandwidth optimization.

    Sent immediately after receiving a large message to tell mesh peers
    not to forward their copy. Only used for messages exceeding the
    IDONTWANT size threshold (typically 1KB).
    """

    message_ids: list[MessageId]
    """IDs of messages the sender does not want to receive."""


class ControlMessage(StrictBaseModel):
    """Container for aggregated control messages.

    Multiple control messages are batched into a single RPC
    for efficiency. An RPC can contain any combination of
    control message types.
    """

    grafts: list[Graft] = []
    """GRAFT messages requesting mesh membership."""

    prunes: list[Prune] = []
    """PRUNE messages notifying mesh removal."""

    ihaves: list[IHave] = []
    """IHAVE messages advertising cached message IDs."""

    iwants: list[IWant] = []
    """IWANT messages requesting full messages."""

    idontwants: list[IDontWant] = []
    """IDONTWANT messages declining specific messages (v1.2)."""

    def is_empty(self) -> bool:
        """Check if this control message contains no data."""
        return not (self.grafts or self.prunes or self.ihaves or self.iwants or self.idontwants)
