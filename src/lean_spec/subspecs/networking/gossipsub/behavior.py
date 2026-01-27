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
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from lean_spec.subspecs.networking.config import (
    MESSAGE_DOMAIN_VALID_SNAPPY,
    MESSAGE_ID_SIZE,
    PRUNE_BACKOFF,
)
from lean_spec.subspecs.networking.gossipsub.mcache import MessageCache, SeenCache
from lean_spec.subspecs.networking.gossipsub.mesh import MeshState
from lean_spec.subspecs.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
    SubOpts,
    create_graft_rpc,
    create_subscription_rpc,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint
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

    Usage::

        behavior = GossipsubBehavior(params=GossipsubParameters())
        await behavior.start()

        # Subscribe to topics
        behavior.subscribe("/leanconsensus/0x12345678/block/ssz_snappy")

        # Add peer connection
        await behavior.add_peer(peer_id, stream)

        # Publish message
        await behavior.publish(topic, data)

        # Process events
        async for event in behavior.events():
            if isinstance(event, GossipsubMessageEvent):
                # Handle received message
                pass
    """

    params: GossipsubParameters = field(default_factory=GossipsubParameters)
    """Protocol parameters."""

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
        if topic in self._subscriptions:
            return

        self._subscriptions.add(topic)
        self.mesh.subscribe(topic)

        logger.debug("Subscribed to topic %s", topic)

        # Notify all connected peers
        if self._running:
            asyncio.create_task(self._broadcast_subscription(topic, subscribe=True))

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
        if topic not in self._subscriptions:
            return

        self._subscriptions.discard(topic)
        self.mesh.unsubscribe(topic)

        logger.debug("Unsubscribed from topic %s", topic)

        # Notify all connected peers
        if self._running:
            asyncio.create_task(self._broadcast_subscription(topic, subscribe=False))

    async def start(self) -> None:
        """Start the gossipsub behavior (heartbeat loop)."""
        if self._running:
            return

        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("GossipsubBehavior started")

    async def stop(self) -> None:
        """Stop the gossipsub behavior."""
        self._running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

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
        existing = self._peers.get(peer_id)

        if inbound:
            # Peer opened an inbound stream to us - use for receiving.
            if existing is None:
                # Peer not yet known, create state with inbound stream.
                state = PeerState(peer_id=peer_id, inbound_stream=stream)
                self._peers[peer_id] = state
                logger.info("Added gossipsub peer %s (inbound first)", peer_id)
            else:
                # Peer already exists, set the inbound stream.
                if existing.inbound_stream is not None:
                    logger.debug("Peer %s already has inbound stream, ignoring", peer_id)
                    return
                existing.inbound_stream = stream
                logger.debug("Added inbound stream for peer %s", peer_id)

            # Start receiving RPCs on the inbound stream.
            asyncio.create_task(self._receive_loop(peer_id, stream))

        else:
            # We opened an outbound stream - use for sending.
            if existing is None:
                # Peer not yet known, create state with outbound stream.
                state = PeerState(peer_id=peer_id, outbound_stream=stream)
                self._peers[peer_id] = state
                logger.info("Added gossipsub peer %s (outbound first)", peer_id)
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
        from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage

        cache_msg = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=data)
        self.message_cache.put(topic, cache_msg)

        # Get peers to send to
        if topic in self._subscriptions:
            peers = self.mesh.get_mesh_peers(topic)
        else:
            peers = self.mesh.get_fanout_peers(topic)

        # Create RPC with message
        rpc = RPC(publish=[msg])

        # Send to all peers
        for peer_id in peers:
            await self._send_rpc(peer_id, rpc)

        logger.debug("Published message to %d peers on topic %s", len(peers), topic)

    async def events(self):
        """
        Async generator yielding gossipsub events.

        Yields GossipsubMessageEvent for received messages
        and GossipsubPeerEvent for subscription changes.
        """
        while self._running:
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                yield event
            except asyncio.TimeoutError:
                continue

    # =========================================================================
    # Internal Methods
    # =========================================================================

    async def _heartbeat_loop(self) -> None:
        """Background heartbeat for mesh maintenance."""
        interval = self.params.heartbeat_interval_secs

        while self._running:
            try:
                await asyncio.sleep(interval)
                await self._heartbeat()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Heartbeat error: %s", e)

    async def _heartbeat(self) -> None:
        """
        Perform heartbeat maintenance.

        The heartbeat:

        1. Maintains mesh sizes (GRAFT if < D_low, PRUNE if > D_high)
        2. Sends IHAVE gossip to non-mesh peers
        3. Ages the message cache
        """
        now = time.time()

        for topic in self._subscriptions:
            await self._maintain_mesh(topic, now)
            await self._emit_gossip(topic)

        # Age message cache
        self.message_cache.shift()

        # Clean up seen cache
        self.seen_cache.cleanup(now)

    async def _maintain_mesh(self, topic: str, now: float) -> None:
        """Maintain mesh size for a topic."""
        mesh_peers = self.mesh.get_mesh_peers(topic)
        mesh_size = len(mesh_peers)

        # Find eligible peers (subscribed to topic, not in mesh, and can send to).
        #
        # IMPORTANT: Only consider peers we can actually send to.
        # If we don't have an outbound stream yet (peer just connected, stream
        # setup still in progress), skip them. They'll become eligible once
        # their outbound stream is established.
        eligible = []
        for peer_id, state in self._peers.items():
            # Must have outbound stream to send GRAFT
            if state.outbound_stream is None:
                continue
            if topic in state.subscriptions and peer_id not in mesh_peers:
                # Check backoff
                backoff_until = state.backoff.get(topic, 0)
                if now >= backoff_until:
                    eligible.append(peer_id)

        # GRAFT if too few peers
        if mesh_size < self.params.d_low and eligible:
            needed = self.params.d - mesh_size
            to_graft = eligible[: min(needed, len(eligible))]

            for peer_id in to_graft:
                self.mesh.add_to_mesh(topic, peer_id)

            # Send GRAFT
            rpc = create_graft_rpc([topic])
            for peer_id in to_graft:
                await self._send_rpc(peer_id, rpc)

            logger.debug("GRAFT %d peers for topic %s", len(to_graft), topic)

        # PRUNE if too many peers
        elif mesh_size > self.params.d_high:
            # Keep peers with best scores (for now, just take first D)
            to_prune = list(mesh_peers)[self.params.d :]

            for peer_id in to_prune:
                self.mesh.remove_from_mesh(topic, peer_id)

            # Send PRUNE
            prune_rpc = RPC(
                control=ControlMessage(prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)])
            )
            for peer_id in to_prune:
                await self._send_rpc(peer_id, prune_rpc)

            logger.debug("PRUNE %d peers for topic %s", len(to_prune), topic)

    async def _emit_gossip(self, topic: str) -> None:
        """Send IHAVE gossip to non-mesh peers."""
        # Get message IDs from cache
        msg_ids = self.message_cache.get_gossip_ids(topic)
        if not msg_ids:
            return

        # Get all connected peers subscribed to this topic (with outbound streams).
        #
        # Only include peers we can actually send to. Peers without outbound
        # streams yet (still setting up) are skipped.
        all_topic_peers = {
            p
            for p, state in self._peers.items()
            if topic in state.subscriptions and state.outbound_stream is not None
        }

        # Select D_lazy non-mesh peers
        gossip_peers = self.mesh.select_peers_for_gossip(topic, all_topic_peers)
        if not gossip_peers:
            return

        # Send IHAVE
        msg_id_bytes = [
            msg_id if isinstance(msg_id, bytes) else bytes(msg_id) for msg_id in msg_ids
        ]
        ihave = ControlIHave(topic_id=topic, message_ids=msg_id_bytes)
        rpc = RPC(control=ControlMessage(ihave=[ihave]))

        for peer_id in gossip_peers:
            await self._send_rpc(peer_id, rpc)

        logger.debug(
            "IHAVE %d messages to %d peers for topic %s", len(msg_ids), len(gossip_peers), topic
        )

    async def _broadcast_subscription(self, topic: str, subscribe: bool) -> None:
        """Broadcast subscription change to all peers."""
        rpc = create_subscription_rpc([topic], subscribe)

        # Only send to peers we have outbound streams for
        for peer_id, state in self._peers.items():
            if state.outbound_stream is not None:
                await self._send_rpc(peer_id, rpc)

        # If subscribing, send GRAFT to eligible peers (must have outbound stream)
        if subscribe:
            eligible = [
                p
                for p, s in self._peers.items()
                if topic in s.subscriptions and s.outbound_stream is not None
            ][: self.params.d]

            if eligible:
                graft_rpc = create_graft_rpc([topic])
                for peer_id in eligible:
                    self.mesh.add_to_mesh(topic, peer_id)
                    await self._send_rpc(peer_id, graft_rpc)

    async def _send_rpc(self, peer_id: PeerId, rpc: RPC) -> None:
        """Send an RPC to a peer on the outbound stream."""
        state = self._peers.get(peer_id)
        if state is None or state.outbound_stream is None:
            # Expected during stream setup - peer might only have inbound stream yet.
            # The outbound stream will be established shortly.
            logger.debug("Cannot send RPC to %s: no outbound stream yet", peer_id)
            return

        try:
            data = rpc.encode()
            # Length-prefix the RPC (varint + data)
            frame = encode_varint(len(data)) + data
            logger.debug(
                "Sending RPC to %s: %d bytes (subs=%d, msgs=%d)",
                peer_id,
                len(frame),
                len(rpc.subscriptions),
                len(rpc.publish),
            )
            state.outbound_stream.write(frame)
            await state.outbound_stream.drain()
            logger.debug("RPC sent and drained to %s", peer_id)
            state.last_rpc_time = time.time()
        except Exception as e:
            logger.warning("Failed to send RPC to %s: %s", peer_id, e)

    async def _receive_loop(self, peer_id: PeerId, stream: Any) -> None:
        """Receive and process RPCs from a peer."""
        buffer = bytearray()
        logger.debug("Starting receive loop for peer %s", peer_id)

        try:
            while self._running and peer_id in self._peers:
                try:
                    chunk = await stream.read()
                    if not chunk:
                        logger.debug("Receive loop got empty chunk from %s, exiting", peer_id)
                        break
                    logger.debug("Received %d bytes from %s", len(chunk), peer_id)
                    buffer.extend(chunk)

                    # Try to parse complete RPCs
                    while buffer:
                        try:
                            # Read length prefix
                            if len(buffer) < 1:
                                break
                            length, varint_size = decode_varint(bytes(buffer), 0)
                            if len(buffer) < varint_size + length:
                                break

                            # Extract and parse RPC
                            rpc_data = bytes(buffer[varint_size : varint_size + length])
                            buffer = buffer[varint_size + length :]

                            rpc = RPC.decode(rpc_data)
                            logger.debug(
                                "Received RPC from %s: subs=%d, msgs=%d, ctrl=%s",
                                peer_id,
                                len(rpc.subscriptions),
                                len(rpc.publish),
                                bool(rpc.control),
                            )
                            await self._handle_rpc(peer_id, rpc)
                        except Exception as e:
                            logger.warning("Error parsing RPC from %s: %s", peer_id, e)
                            break

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.warning("Error receiving from %s: %s", peer_id, e)
                    break

        finally:
            # Clean up peer on disconnect
            await self.remove_peer(peer_id)

    async def _handle_rpc(self, peer_id: PeerId, rpc: RPC) -> None:
        """Handle an incoming RPC."""
        state = self._peers.get(peer_id)
        if state is None:
            return

        # Process subscriptions
        for sub in rpc.subscriptions:
            await self._handle_subscription(peer_id, sub)

        # Process published messages
        for msg in rpc.publish:
            await self._handle_message(peer_id, msg)

        # Process control messages
        if rpc.control:
            await self._handle_control(peer_id, rpc.control)

    async def _handle_subscription(self, peer_id: PeerId, sub: SubOpts) -> None:
        """Handle a subscription change from a peer."""
        state = self._peers.get(peer_id)
        if state is None:
            return

        if sub.subscribe:
            state.subscriptions.add(sub.topic_id)
            logger.debug("Peer %s subscribed to %s", peer_id, sub.topic_id)
        else:
            state.subscriptions.discard(sub.topic_id)
            # Remove from mesh if they unsubscribed
            self.mesh.remove_from_mesh(sub.topic_id, peer_id)
            logger.debug("Peer %s unsubscribed from %s", peer_id, sub.topic_id)

        # Emit event
        await self._event_queue.put(
            GossipsubPeerEvent(peer_id=peer_id, topic=sub.topic_id, subscribed=sub.subscribe)
        )

    async def _handle_message(self, peer_id: PeerId, msg: Message) -> None:
        """Handle a published message from a peer."""
        if not msg.topic:
            return

        # Compute message ID
        msg_id = self._compute_message_id(msg.topic.encode("utf-8"), msg.data)

        # Check if already seen
        if self.seen_cache.has(msg_id):
            return

        # Mark as seen
        self.seen_cache.add(msg_id, time.time())

        # Add to cache
        from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage

        cache_msg = GossipsubMessage(topic=msg.topic.encode("utf-8"), raw_data=msg.data)
        self.message_cache.put(msg.topic, cache_msg)

        # Forward to mesh peers (excluding sender)
        if msg.topic in self._subscriptions:
            mesh_peers = self.mesh.get_mesh_peers(msg.topic)
            forward_rpc = RPC(publish=[msg])

            for mesh_peer in mesh_peers:
                if mesh_peer != peer_id:
                    await self._send_rpc(mesh_peer, forward_rpc)

        # Emit event to application
        event = GossipsubMessageEvent(
            peer_id=peer_id, topic=msg.topic, data=msg.data, message_id=msg_id
        )
        await self._event_queue.put(event)

        # Call handler if set
        if self._message_handler:
            self._message_handler(event)

        logger.debug(
            "Received message %s from %s on topic %s", msg_id.hex()[:8], peer_id, msg.topic
        )

    async def _handle_control(self, peer_id: PeerId, control: ControlMessage) -> None:
        """Handle control messages from a peer."""
        state = self._peers.get(peer_id)
        if state is None:
            return

        # Handle GRAFT
        for graft in control.graft:
            await self._handle_graft(peer_id, graft)

        # Handle PRUNE
        for prune in control.prune:
            await self._handle_prune(peer_id, prune)

        # Handle IHAVE
        for ihave in control.ihave:
            await self._handle_ihave(peer_id, ihave)

        # Handle IWANT
        for iwant in control.iwant:
            await self._handle_iwant(peer_id, iwant)

    async def _handle_graft(self, peer_id: PeerId, graft: ControlGraft) -> None:
        """Handle a GRAFT request from a peer."""
        topic = graft.topic_id

        # Check if we're subscribed to the topic
        if topic not in self._subscriptions:
            # Send PRUNE - we're not subscribed
            prune = ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)
            prune_rpc = RPC(control=ControlMessage(prune=[prune]))
            await self._send_rpc(peer_id, prune_rpc)
            return

        # Check mesh size
        mesh_peers = self.mesh.get_mesh_peers(topic)
        if len(mesh_peers) >= self.params.d_high:
            # Mesh is full, send PRUNE
            prune = ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)
            prune_rpc = RPC(control=ControlMessage(prune=[prune]))
            await self._send_rpc(peer_id, prune_rpc)
            return

        # Accept GRAFT
        self.mesh.add_to_mesh(topic, peer_id)
        logger.debug("Accepted GRAFT from %s for topic %s", peer_id, topic)

    async def _handle_prune(self, peer_id: PeerId, prune: ControlPrune) -> None:
        """Handle a PRUNE notification from a peer."""
        topic = prune.topic_id
        state = self._peers.get(peer_id)

        # Remove from mesh
        self.mesh.remove_from_mesh(topic, peer_id)

        # Set backoff
        if state and prune.backoff > 0:
            state.backoff[topic] = time.time() + prune.backoff

        logger.debug(
            "Received PRUNE from %s for topic %s (backoff=%ds)", peer_id, topic, prune.backoff
        )

    async def _handle_ihave(self, peer_id: PeerId, ihave: ControlIHave) -> None:
        """Handle an IHAVE advertisement from a peer."""
        # Find messages we don't have
        wanted = []
        for msg_id in ihave.message_ids:
            # Convert bytes to Bytes20 for cache lookup
            if len(msg_id) != 20:
                continue
            msg_id_typed = Bytes20(msg_id)
            if not self.seen_cache.has(msg_id_typed) and not self.message_cache.has(msg_id_typed):
                wanted.append(msg_id)

        if not wanted:
            return

        # Send IWANT
        iwant_rpc = RPC(control=ControlMessage(iwant=[ControlIWant(message_ids=wanted)]))
        await self._send_rpc(peer_id, iwant_rpc)

        logger.debug("Sent IWANT for %d messages from %s", len(wanted), peer_id)

    async def _handle_iwant(self, peer_id: PeerId, iwant: ControlIWant) -> None:
        """Handle an IWANT request from a peer."""
        messages = []

        for msg_id in iwant.message_ids:
            # Convert bytes to Bytes20 for cache lookup
            if len(msg_id) != 20:
                continue
            msg_id_typed = Bytes20(msg_id)
            cached = self.message_cache.get(msg_id_typed)
            if cached:
                messages.append(Message(topic=cached.topic.decode("utf-8"), data=cached.raw_data))

        if messages:
            rpc = RPC(publish=messages)
            await self._send_rpc(peer_id, rpc)

            logger.debug("Sent %d messages in response to IWANT from %s", len(messages), peer_id)

    def _compute_message_id(self, topic: bytes, data: bytes) -> Bytes20:
        """
        Compute message ID using Ethereum consensus spec algorithm.

        message_id = SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]
        """
        import hashlib
        import struct

        # Domain byte for message-id isolation (0x01 for valid snappy)
        domain = bytes(MESSAGE_DOMAIN_VALID_SNAPPY)

        # Build message for hashing
        msg = domain + struct.pack("<Q", len(topic)) + topic + data

        # SHA256 truncated to MESSAGE_ID_SIZE bytes
        return Bytes20(hashlib.sha256(msg).digest()[:MESSAGE_ID_SIZE])

    def set_message_handler(self, handler: Callable[[GossipsubMessageEvent], None]) -> None:
        """Set a callback for received messages."""
        self._message_handler = handler
