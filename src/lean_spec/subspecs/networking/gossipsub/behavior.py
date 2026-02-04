"""
Gossipsub Behavior Implementation
=================================

This module implements the gossipsub protocol behavior for interoperability
with rust-libp2p and go-libp2p implementations.

Architecture
------------

The GossipsubBehavior manages the gossipsub mesh and handles protocol
interactions::

    GossipsubBehavior
        |
        +-- MeshState (mesh topology per topic)
        |
        +-- MessageCache (recent messages for IHAVE/IWANT)
        |
        +-- SeenCache (deduplication)
        |
        +-- PeerStreams (RPC streams per peer)

Protocol Flow
-------------

**On Connection:**

1. Peer connects via QUIC/TCP
2. Open gossipsub stream (negotiate /meshsub/1.1.0)
3. Send subscription RPC for our topics
4. Receive peer's subscriptions
5. Exchange GRAFT to join mesh

**Heartbeat (every 700ms):**

1. Check mesh sizes (GRAFT if too few, PRUNE if too many)
2. Send IHAVE to non-mesh peers (lazy gossip)
3. Process pending IWANT responses
4. Age message cache

**On Message Received:**

1. Validate message ID (dedupe via SeenCache)
2. Validate message content (topic, signature if required)
3. Forward to mesh peers
4. Emit event to application layer
5. Send IDONTWANT to mesh peers (if large message)

References:
-----------
- Gossipsub v1.1: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
- rust-libp2p gossipsub: https://github.com/libp2p/rust-libp2p/tree/master/protocols/gossipsub
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from lean_spec.subspecs.networking.config import (
    MESSAGE_DOMAIN_VALID_SNAPPY,
    MESSAGE_ID_SIZE,
)
from lean_spec.subspecs.networking.gossipsub.mcache import MessageCache, SeenCache
from lean_spec.subspecs.networking.gossipsub.mesh import MeshState
from lean_spec.subspecs.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    Message,
    create_subscription_rpc,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.types import Bytes20

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class GossipsubMessageEvent:
    """Event emitted when a valid message is received."""

    peer_id: PeerId
    """Peer that sent the message."""

    topic: str
    """Topic the message belongs to."""

    data: bytes
    """Message payload (may be compressed)."""

    message_id: bytes
    """Computed message ID."""


@dataclass(slots=True)
class GossipsubPeerEvent:
    """Event emitted on peer subscription changes."""

    peer_id: PeerId
    """Peer whose subscription changed."""

    topic: str
    """Topic affected."""

    subscribed: bool
    """True if peer subscribed, False if unsubscribed."""


@dataclass(slots=True)
class PeerState:
    """State tracked for each connected peer."""

    peer_id: PeerId
    """Peer identifier."""

    subscriptions: set[str] = field(default_factory=set)
    """Topics this peer is subscribed to."""

    outbound_stream: Any | None = None
    """Outbound RPC stream (we opened this to send)."""

    inbound_stream: Any | None = None
    """Inbound RPC stream (they opened this to receive)."""

    receive_task: asyncio.Task[None] | None = None
    """Task running the receive loop for this peer."""

    last_rpc_time: float = 0.0
    """Timestamp of last RPC exchange."""

    backoff: dict[str, float] = field(default_factory=dict)
    """Per-topic backoff expiry times (from PRUNE)."""


@dataclass
class GossipsubBehavior:
    """
    Gossipsub protocol behavior implementation.

    This class manages the gossipsub mesh and handles protocol interactions
    with connected peers. It provides:

    - Subscription management
    - Mesh topology (GRAFT/PRUNE)
    - Message propagation
    - Lazy gossip (IHAVE/IWANT)
    - Heartbeat-based maintenance
    """

    params: GossipsubParameters = field(default_factory=GossipsubParameters)
    """Protocol parameters."""

    _instance_id: int = field(default_factory=lambda: id(object()))
    """Unique instance ID for debugging."""

    mesh: MeshState = field(init=False)
    """Mesh topology state."""

    message_cache: MessageCache = field(default_factory=MessageCache)
    """Cache of recent messages for IHAVE/IWANT."""

    seen_cache: SeenCache = field(default_factory=SeenCache)
    """Cache of seen message IDs for deduplication."""

    _peers: dict[PeerId, PeerState] = field(default_factory=dict)
    """Connected peer states."""

    _subscriptions: set[str] = field(default_factory=set)
    """Our subscribed topics."""

    _event_queue: asyncio.Queue[GossipsubMessageEvent | GossipsubPeerEvent] = field(
        default_factory=asyncio.Queue
    )
    """Queue of events for the application."""

    _running: bool = False
    """Whether the behavior is running."""

    _heartbeat_task: asyncio.Task[None] | None = None
    """Background heartbeat task."""

    _message_handler: Callable[[GossipsubMessageEvent], None] | None = None
    """Optional callback for received messages."""

    _stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    """Event to signal stop to the events generator."""

    def __post_init__(self) -> None:
        """Initialize fields that depend on other fields."""
        self.mesh = MeshState(params=self.params)

    def subscribe(self, topic: str) -> None:
        """
        Subscribe to a topic.

        Joining a topic means:

        1. Track the topic as subscribed
        2. Create mesh for the topic
        3. Notify all connected peers
        4. Send GRAFT to establish mesh connections

        Args:
            topic: Topic string to subscribe to.
        """
        from lean_spec.subspecs.networking.gossipsub.stream import broadcast_subscription

        if topic in self._subscriptions:
            return

        self._subscriptions.add(topic)
        self.mesh.subscribe(topic)

        logger.debug("Subscribed to topic %s", topic)

        # Notify all connected peers
        if self._running:
            asyncio.create_task(broadcast_subscription(self, topic, subscribe=True))

    def unsubscribe(self, topic: str) -> None:
        """
        Unsubscribe from a topic.

        Leaving a topic means:

        1. Remove from subscriptions
        2. Send PRUNE to mesh peers
        3. Clean up mesh state

        Args:
            topic: Topic string to unsubscribe from.
        """
        from lean_spec.subspecs.networking.gossipsub.stream import broadcast_subscription

        if topic not in self._subscriptions:
            return

        self._subscriptions.discard(topic)
        self.mesh.unsubscribe(topic)

        logger.debug("Unsubscribed from topic %s", topic)

        # Notify all connected peers
        if self._running:
            asyncio.create_task(broadcast_subscription(self, topic, subscribe=False))

    async def start(self) -> None:
        """Start the gossipsub behavior (heartbeat loop)."""
        from lean_spec.subspecs.networking.gossipsub.heartbeat import heartbeat_loop

        if self._running:
            return

        self._running = True
        self._heartbeat_task = asyncio.create_task(heartbeat_loop(self))
        logger.info("[GS %x] GossipsubBehavior started", self._instance_id % 0xFFFF)

    async def stop(self) -> None:
        """Stop the gossipsub behavior."""
        self._running = False

        # Signal events() generator to stop.
        self._stop_event.set()

        # Cancel heartbeat task.
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        # Cancel all receive loop tasks.
        receive_tasks = []
        for state in self._peers.values():
            if state.receive_task is not None and not state.receive_task.done():
                state.receive_task.cancel()
                receive_tasks.append(state.receive_task)

        # Wait for all receive tasks to complete.
        for task in receive_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass

        logger.info("GossipsubBehavior stopped")

    async def add_peer(self, peer_id: PeerId, stream: Any, *, inbound: bool = False) -> None:
        """
        Add a connected peer and establish gossipsub session.

        Libp2p uses separate streams for each direction:
        - Outbound stream: we opened this to send RPCs
        - Inbound stream: they opened this to send us RPCs

        Args:
            peer_id: Peer identifier.
            stream: Stream for RPC exchange.
            inbound: True if this is an inbound stream (peer opened to us).
        """
        from lean_spec.subspecs.networking.gossipsub.stream import receive_loop

        existing = self._peers.get(peer_id)

        if inbound:
            # Peer opened an inbound stream to us - use for receiving.
            if existing is None:
                # Peer not yet known, create state with inbound stream.
                state = PeerState(peer_id=peer_id, inbound_stream=stream)
                self._peers[peer_id] = state
                gs_id = self._instance_id % 0xFFFF
                logger.info("[GS %x] Added gossipsub peer %s (inbound first)", gs_id, peer_id)
            else:
                # Peer already exists, set the inbound stream.
                if existing.inbound_stream is not None:
                    logger.debug("Peer %s already has inbound stream, ignoring", peer_id)
                    return
                existing.inbound_stream = stream
                state = existing
                logger.debug("Added inbound stream for peer %s", peer_id)

            # Start receiving RPCs on the inbound stream.
            # Track the task so we can cancel it on stop().
            receive_task = asyncio.create_task(receive_loop(self, peer_id, stream))
            state.receive_task = receive_task

            # Yield to allow the receive loop task to start before we return.
            # This ensures the listener is ready to receive subscription RPCs
            # that the dialer sends immediately after connecting.
            await asyncio.sleep(0)

        else:
            # We opened an outbound stream - use for sending.
            if existing is None:
                # Peer not yet known, create state with outbound stream.
                state = PeerState(peer_id=peer_id, outbound_stream=stream)
                self._peers[peer_id] = state
                gs_id = self._instance_id % 0xFFFF
                logger.info("[GS %x] Added gossipsub peer %s (outbound first)", gs_id, peer_id)
            else:
                # Peer already exists, set the outbound stream.
                if existing.outbound_stream is not None:
                    logger.debug("Peer %s already has outbound stream, ignoring", peer_id)
                    return
                existing.outbound_stream = stream
                logger.debug("Added outbound stream for peer %s", peer_id)

            # Send our subscriptions on the outbound stream.
            if self._subscriptions:
                rpc = create_subscription_rpc(list(self._subscriptions), subscribe=True)
                await self._send_rpc(peer_id, rpc)

    def has_outbound_stream(self, peer_id: PeerId) -> bool:
        """
        Check if a peer already has an outbound stream.

        Args:
            peer_id: Peer identifier.

        Returns:
            True if the peer has an outbound stream, False otherwise.
        """
        state = self._peers.get(peer_id)
        return state is not None and state.outbound_stream is not None

    async def remove_peer(self, peer_id: PeerId) -> None:
        """
        Remove a disconnected peer.

        Args:
            peer_id: Peer identifier.
        """
        state = self._peers.pop(peer_id, None)
        if state is None:
            return

        # Remove from all meshes
        for topic in self._subscriptions:
            self.mesh.remove_from_mesh(topic, peer_id)

        logger.info("Removed gossipsub peer %s", peer_id)

    async def publish(self, topic: str, data: bytes) -> None:
        """
        Publish a message to a topic.

        Publishing sends the message to:

        1. All mesh peers for the topic
        2. Fanout peers if not subscribed to topic

        Args:
            topic: Topic to publish to.
            data: Message payload.
        """
        from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage

        # Create message
        msg = Message(topic=topic, data=data)

        # Compute message ID
        msg_id = self._compute_message_id(topic.encode("utf-8"), data)

        # Check if already seen
        if self.seen_cache.has(msg_id):
            logger.debug("Skipping duplicate message %s", msg_id.hex()[:8])
            return

        # Mark as seen
        self.seen_cache.add(msg_id, time.time())

        # Add to message cache
        cache_msg = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=data)
        self.message_cache.put(topic, cache_msg)

        # Get peers to send to
        if topic in self._subscriptions:
            peers = self.mesh.get_mesh_peers(topic)
        else:
            peers = self.mesh.get_fanout_peers(topic)

        # Log mesh state when empty (helps debug mesh formation issues).
        if not peers:
            subscribed_peers = [p for p, s in self._peers.items() if topic in s.subscriptions]
            outbound_peers = [p for p, s in self._peers.items() if s.outbound_stream]
            logger.warning(
                "[GS %x] Empty mesh for %s: total_peers=%d subscribed=%d outbound=%d",
                self._instance_id % 0xFFFF,  # Short hex ID
                topic.split("/")[-2],  # Just "block" or "attestation"
                len(self._peers),
                len(subscribed_peers),
                len(outbound_peers),
            )

        # Create RPC with message
        rpc = RPC(publish=[msg])

        # Send to all peers
        for peer_id in peers:
            await self._send_rpc(peer_id, rpc)

        logger.debug("Published message to %d peers on topic %s", len(peers), topic)

    async def get_next_event(
        self,
    ) -> GossipsubMessageEvent | GossipsubPeerEvent | None:
        """
        Get the next event from the queue.

        Returns None when stopped or no event available.

        Returns:
            The next event, or None if stopped.
        """
        if not self._running:
            return None

        # Create tasks for both queue get and stop event.
        queue_task = asyncio.create_task(self._event_queue.get())
        stop_task = asyncio.create_task(self._stop_event.wait())

        try:
            done, pending = await asyncio.wait(
                [queue_task, stop_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Cancel pending tasks.
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            # Check if stop was signaled.
            if stop_task in done:
                return None

            # Return the event from the queue.
            if queue_task in done:
                return queue_task.result()

            return None

        except asyncio.CancelledError:
            # Cancel pending tasks on external cancellation.
            queue_task.cancel()
            stop_task.cancel()
            try:
                await queue_task
            except asyncio.CancelledError:
                pass
            try:
                await stop_task
            except asyncio.CancelledError:
                pass
            return None

    # =========================================================================
    # Internal Methods
    # =========================================================================

    async def _send_rpc(self, peer_id: PeerId, rpc: RPC) -> None:
        """Send an RPC to a peer on the outbound stream."""
        from lean_spec.subspecs.networking.gossipsub.stream import send_rpc

        await send_rpc(self, peer_id, rpc)

    def _compute_message_id(self, topic: bytes, data: bytes) -> Bytes20:
        """
        Compute message ID using Ethereum consensus spec algorithm.

        message_id = SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]
        """
        # Domain byte for message-id isolation (0x01 for valid snappy)
        domain = bytes(MESSAGE_DOMAIN_VALID_SNAPPY)

        # Build message for hashing
        msg = domain + struct.pack("<Q", len(topic)) + topic + data

        # SHA256 truncated to MESSAGE_ID_SIZE bytes
        return Bytes20(hashlib.sha256(msg).digest()[:MESSAGE_ID_SIZE])

    def set_message_handler(self, handler: Callable[[GossipsubMessageEvent], None]) -> None:
        """Set a callback for received messages."""
        self._message_handler = handler
