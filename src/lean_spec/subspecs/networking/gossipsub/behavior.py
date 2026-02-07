"""
Gossipsub Behavior Implementation
=================================

This module implements the gossipsub protocol behavior for interoperability
with rust-libp2p and go-libp2p implementations.

Architecture
------------

The behavior manages the gossipsub mesh, peer streams, and
protocol interactions::

    GossipsubBehavior
        |
        +-- MeshState (mesh topology per topic)
        |
        +-- MessageCache (recent messages for IHAVE/IWANT)
        |
        +-- SeenCache (deduplication)
        |
        +-- PeerState (per-peer streams and metadata)

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
import random
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from itertools import count
from typing import ClassVar, cast

from lean_spec.subspecs.networking.config import PRUNE_BACKOFF
from lean_spec.subspecs.networking.gossipsub.mcache import MessageCache, SeenCache
from lean_spec.subspecs.networking.gossipsub.mesh import MeshState
from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage
from lean_spec.subspecs.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.subspecs.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
    SubOpts,
    create_graft_rpc,
    create_subscription_rpc,
)
from lean_spec.subspecs.networking.gossipsub.types import MessageId
from lean_spec.subspecs.networking.transport import (
    PeerId,
    StreamReaderProtocol,
    StreamWriterProtocol,
)
from lean_spec.subspecs.networking.varint import decode_varint, encode_varint
from lean_spec.types import Bytes20, Uint16

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


IDONTWANT_SIZE_THRESHOLD: int = 1024
"""Minimum message size (bytes) to trigger IDONTWANT.

Messages smaller than this are cheap to transmit and don't
warrant the overhead of IDONTWANT control messages.
"""


@dataclass(slots=True)
class PeerState:
    """State tracked for each connected peer."""

    peer_id: PeerId
    """Peer identifier."""

    subscriptions: set[str] = field(default_factory=set)
    """Topics this peer is subscribed to."""

    outbound_stream: StreamWriterProtocol | None = None
    """Outbound RPC stream (we opened this to send)."""

    inbound_stream: StreamReaderProtocol | None = None
    """Inbound RPC stream (they opened this to receive)."""

    receive_task: asyncio.Task[None] | None = None
    """Task running the receive loop for this peer."""

    last_rpc_time: float = 0.0
    """Timestamp of last RPC exchange."""

    backoff: dict[str, float] = field(default_factory=dict)
    """Per-topic backoff expiry times (from PRUNE)."""

    dont_want_ids: set[MessageId] = field(default_factory=set)
    """Message IDs this peer does not want.

    Populated from incoming IDONTWANT control messages.
    Cleared each heartbeat.
    """


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

    _instance_id: int = field(init=False)
    """Unique instance ID for debugging."""

    _short_id: Uint16 = field(init=False, repr=False)
    """Truncated instance ID for log messages (lower 16 bits)."""

    mesh: MeshState = field(init=False)
    """Mesh topology state."""

    message_cache: MessageCache = field(init=False)
    """Cache of recent messages for IHAVE/IWANT."""

    seen_cache: SeenCache = field(init=False)
    """Cache of seen message IDs for deduplication."""

    _peers: dict[PeerId, PeerState] = field(default_factory=dict)
    """Connected peer states."""

    _event_queue: asyncio.Queue[GossipsubMessageEvent | GossipsubPeerEvent] = field(
        default_factory=lambda: asyncio.Queue(maxsize=4096)
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

    _background_tasks: set[asyncio.Task[None]] = field(default_factory=set)
    """Tracked background tasks for subscribe/unsubscribe broadcasts.

    Tasks are stored here to:
        - prevent garbage collection,
        - ensure exceptions are logged.
    """

    _id_counter: ClassVar[count] = count()

    def __post_init__(self) -> None:
        """Initialize derived fields, mesh state, and caches from params."""
        self._instance_id = next(GossipsubBehavior._id_counter)
        self._short_id = Uint16(self._instance_id % 0x10000)
        self.mesh = MeshState(params=self.params)
        self.message_cache = MessageCache(
            mcache_len=self.params.mcache_len,
            mcache_gossip=self.params.mcache_gossip,
        )
        self.seen_cache = SeenCache(ttl_seconds=self.params.seen_ttl_secs)

    def subscribe(self, topic: str) -> None:
        """Subscribe to a topic.

        Joining a topic means:

        1. Track the topic as subscribed
        2. Create mesh for the topic
        3. Notify all connected peers
        4. Send GRAFT to establish mesh connections

        Args:
            topic: Topic string to subscribe to.
        """
        if topic in self.mesh.subscriptions:
            return

        self.mesh.subscribe(topic)

        logger.debug("Subscribed to topic %s", topic)

        if self._running:
            self._spawn_background_task(self._broadcast_subscription(topic, subscribe=True))

    def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from a topic.

        Leaving a topic means:

        1. Remove from subscriptions
        2. Send PRUNE to mesh peers
        3. Clean up mesh state

        Args:
            topic: Topic string to unsubscribe from.
        """
        if topic not in self.mesh.subscriptions:
            return

        # Capture mesh peers before clearing mesh state.
        # These peers need PRUNE to learn we left the mesh.
        mesh_peers = self.mesh.unsubscribe(topic)

        logger.debug("Unsubscribed from topic %s", topic)

        if self._running:
            self._spawn_background_task(
                self._broadcast_subscription(topic, subscribe=False, prune_peers=mesh_peers)
            )

    async def start(self) -> None:
        """Start the gossipsub behavior (heartbeat loop)."""
        if self._running:
            return

        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("[GS %x] GossipsubBehavior started", self._short_id)

    async def stop(self) -> None:
        """Stop the gossipsub behavior."""
        self._running = False

        self._stop_event.set()

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        receive_tasks = []
        for state in self._peers.values():
            if state.receive_task is not None and not state.receive_task.done():
                state.receive_task.cancel()
                receive_tasks.append(state.receive_task)

        for task in receive_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass

        logger.info("GossipsubBehavior stopped")

    async def add_peer(
        self,
        peer_id: PeerId,
        stream: StreamReaderProtocol | StreamWriterProtocol,
        *,
        inbound: bool = False,
    ) -> None:
        """Add a connected peer and establish gossipsub session.

        Libp2p uses separate streams for each direction:

        - Outbound: we opened this to send RPCs
        - Inbound: they opened this to send us RPCs

        Args:
            peer_id: Peer identifier.
            stream: Stream for RPC exchange.
            inbound: True if this is an inbound stream (peer opened to us).
        """
        existing = self._peers.get(peer_id)

        if inbound:
            reader = cast(StreamReaderProtocol, stream)

            # Peer opened an inbound stream to us — use for receiving.
            if existing is None:
                state = PeerState(peer_id=peer_id, inbound_stream=reader)
                self._peers[peer_id] = state
                logger.info(
                    "[GS %x] Added gossipsub peer %s (inbound first)", self._short_id, peer_id
                )
            else:
                if existing.inbound_stream is not None:
                    logger.debug("Peer %s already has inbound stream, ignoring", peer_id)
                    return
                existing.inbound_stream = reader
                state = existing
                logger.debug("Added inbound stream for peer %s", peer_id)

            state.receive_task = asyncio.create_task(self._receive_loop(peer_id, reader))

            # Yield so the receive loop task starts before we return.
            # Ensures the listener is ready for subscription RPCs
            # that the dialer sends immediately after connecting.
            await asyncio.sleep(0)

        else:
            writer = cast(StreamWriterProtocol, stream)

            # We opened an outbound stream — use for sending.
            if existing is None:
                state = PeerState(peer_id=peer_id, outbound_stream=writer)
                self._peers[peer_id] = state
                logger.info(
                    "[GS %x] Added gossipsub peer %s (outbound first)", self._short_id, peer_id
                )
            else:
                if existing.outbound_stream is not None:
                    logger.debug("Peer %s already has outbound stream, ignoring", peer_id)
                    return
                existing.outbound_stream = writer
                logger.debug("Added outbound stream for peer %s", peer_id)

            if self.mesh.subscriptions:
                rpc = create_subscription_rpc(list(self.mesh.subscriptions), subscribe=True)
                await self._send_rpc(peer_id, rpc)

    def has_outbound_stream(self, peer_id: PeerId) -> bool:
        """Check if a peer already has an outbound stream."""
        state = self._peers.get(peer_id)
        return state is not None and state.outbound_stream is not None

    async def remove_peer(self, peer_id: PeerId) -> None:
        """Remove a disconnected peer."""
        state = self._peers.pop(peer_id, None)
        if state is None:
            return

        if state.receive_task is not None and not state.receive_task.done():
            state.receive_task.cancel()
            try:
                await state.receive_task
            except asyncio.CancelledError:
                pass

        for topic in self.mesh.subscriptions:
            self.mesh.remove_from_mesh(topic, peer_id)

        logger.info("Removed gossipsub peer %s", peer_id)

    async def publish(self, topic: str, data: bytes) -> None:
        """Publish a message to a topic.

        Sends the message to mesh peers, or fanout peers if not subscribed.

        Args:
            topic: Topic to publish to.
            data: Message payload.
        """
        msg = Message(topic=topic, data=data)
        msg_id = GossipsubMessage.compute_id(topic.encode("utf-8"), data)

        if self.seen_cache.has(msg_id):
            logger.debug("Skipping duplicate message %s", msg_id.hex()[:8])
            return

        self.seen_cache.add(msg_id, time.time())

        cache_msg = GossipsubMessage(topic=topic.encode("utf-8"), raw_data=data)
        self.message_cache.put(topic, cache_msg)

        if topic in self.mesh.subscriptions:
            peers = self.mesh.get_mesh_peers(topic)
        else:
            available = {
                p
                for p, s in self._peers.items()
                if topic in s.subscriptions and s.outbound_stream is not None
            }
            peers = self.mesh.update_fanout(topic, available)

        # Log mesh state when empty (helps debug mesh formation issues).
        if not peers:
            subscribed_peers = [p for p, s in self._peers.items() if topic in s.subscriptions]
            outbound_peers = [p for p, s in self._peers.items() if s.outbound_stream]
            logger.warning(
                "[GS %x] Empty mesh for %s: total_peers=%d subscribed=%d outbound=%d",
                self._short_id,
                topic,
                len(self._peers),
                len(subscribed_peers),
                len(outbound_peers),
            )

        rpc = RPC(publish=[msg])
        for peer_id in peers:
            await self._send_rpc(peer_id, rpc)

        logger.debug("Published message to %d peers on topic %s", len(peers), topic)

    async def get_next_event(
        self,
    ) -> GossipsubMessageEvent | GossipsubPeerEvent | None:
        """Get the next event from the queue.

        Returns None when stopped or no event available.
        """
        if not self._running:
            return None

        queue_task = asyncio.create_task(self._event_queue.get())
        stop_task = asyncio.create_task(self._stop_event.wait())

        try:
            done, pending = await asyncio.wait(
                [queue_task, stop_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            if stop_task in done:
                return None

            if queue_task in done:
                return queue_task.result()

            return None

        except asyncio.CancelledError:
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

    def set_message_handler(self, handler: Callable[[GossipsubMessageEvent], None]) -> None:
        """Set a callback for received messages."""
        self._message_handler = handler

    async def _handle_rpc(self, peer_id: PeerId, rpc: RPC) -> None:
        """Dispatch an incoming RPC to the appropriate handlers."""
        state = self._peers.get(peer_id)
        if state is None:
            return

        for sub in rpc.subscriptions:
            await self._handle_subscription(peer_id, sub)

        for msg in rpc.publish:
            await self._handle_message(peer_id, msg)

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
            # A peer that leaves a topic can't be a mesh member for it.
            self.mesh.remove_from_mesh(sub.topic_id, peer_id)
            logger.debug("Peer %s unsubscribed from %s", peer_id, sub.topic_id)

        await self._event_queue.put(
            GossipsubPeerEvent(peer_id=peer_id, topic=sub.topic_id, subscribed=sub.subscribe)
        )

    async def _handle_message(self, peer_id: PeerId, msg: Message) -> None:
        """Handle a published message from a peer."""
        if not msg.topic:
            return

        msg_id = GossipsubMessage.compute_id(msg.topic.encode("utf-8"), msg.data)

        # Deduplicate: each message is processed at most once.
        if self.seen_cache.has(msg_id):
            return
        self.seen_cache.add(msg_id, time.time())

        # Cache for IWANT responses to peers who receive our IHAVE gossip.
        cache_msg = GossipsubMessage(topic=msg.topic.encode("utf-8"), raw_data=msg.data)
        self.message_cache.put(msg.topic, cache_msg)

        # Only forward on topics we participate in (have a mesh for).
        if msg.topic in self.mesh.subscriptions:
            mesh_peers = self.mesh.get_mesh_peers(msg.topic)
            forward_rpc = RPC(publish=[msg])

            for mesh_peer in mesh_peers:
                if mesh_peer == peer_id:
                    continue
                # Skip peers that told us they already have this message.
                peer_state = self._peers.get(mesh_peer)
                if peer_state is not None and msg_id in peer_state.dont_want_ids:
                    continue
                await self._send_rpc(mesh_peer, forward_rpc)

            # Large messages warrant IDONTWANT to prevent redundant
            # forwards from other mesh peers who also received this.
            if len(msg.data) >= IDONTWANT_SIZE_THRESHOLD:
                idontwant_rpc = RPC(
                    control=ControlMessage(
                        idontwant=[ControlIDontWant(message_ids=[bytes(msg_id)])]
                    )
                )
                for mesh_peer in mesh_peers:
                    if mesh_peer != peer_id:
                        await self._send_rpc(mesh_peer, idontwant_rpc)

        event = GossipsubMessageEvent(
            peer_id=peer_id, topic=msg.topic, data=msg.data, message_id=msg_id
        )
        await self._event_queue.put(event)

        if self._message_handler:
            self._message_handler(event)

        logger.debug(
            "Received message %s from %s on topic %s", msg_id.hex()[:8], peer_id, msg.topic
        )

    async def _handle_control(self, peer_id: PeerId, control: ControlMessage) -> None:
        """Dispatch control messages to their handlers."""
        state = self._peers.get(peer_id)
        if state is None:
            return

        for graft in control.graft:
            await self._handle_graft(peer_id, graft)

        for prune in control.prune:
            await self._handle_prune(peer_id, prune)

        for ihave in control.ihave:
            await self._handle_ihave(peer_id, ihave)

        for iwant in control.iwant:
            await self._handle_iwant(peer_id, iwant)

        for idontwant in control.idontwant:
            self._handle_idontwant(peer_id, idontwant)

    async def _reject_graft(self, peer_id: PeerId, topic: str) -> None:
        """Send a PRUNE rejection in response to an unacceptable GRAFT."""
        prune_rpc = RPC(
            control=ControlMessage(prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)])
        )
        await self._send_rpc(peer_id, prune_rpc)

    async def _handle_graft(self, peer_id: PeerId, graft: ControlGraft) -> None:
        """Handle a GRAFT request from a peer."""
        topic = graft.topic_id

        # Silently ignore GRAFTs for unknown topics (v1.1).
        # Responding with PRUNE would enable bandwidth amplification
        # attacks (GRAFT/PRUNE storms on fake topics).
        if topic not in self.mesh.subscriptions:
            return

        # Reject peers that re-GRAFT too soon after PRUNE.
        state = self._peers.get(peer_id)
        if state is not None:
            backoff_until = state.backoff.get(topic, 0)
            if time.time() < backoff_until:
                await self._reject_graft(peer_id, topic)
                logger.debug("Rejected GRAFT from %s for %s: still in backoff", peer_id, topic)
                return

        # Reject if mesh is already at capacity.
        mesh_peers = self.mesh.get_mesh_peers(topic)
        if len(mesh_peers) >= self.params.d_high:
            await self._reject_graft(peer_id, topic)
            return

        self.mesh.add_to_mesh(topic, peer_id)
        logger.debug("Accepted GRAFT from %s for topic %s", peer_id, topic)

    async def _handle_prune(self, peer_id: PeerId, prune: ControlPrune) -> None:
        """Handle a PRUNE notification from a peer."""
        topic = prune.topic_id
        state = self._peers.get(peer_id)

        self.mesh.remove_from_mesh(topic, peer_id)

        # Honor the requested backoff to avoid re-grafting too soon.
        if state and prune.backoff > 0:
            state.backoff[topic] = time.time() + prune.backoff

        logger.debug(
            "Received PRUNE from %s for topic %s (backoff=%ds)", peer_id, topic, prune.backoff
        )

    async def _handle_ihave(self, peer_id: PeerId, ihave: ControlIHave) -> None:
        """Handle an IHAVE advertisement from a peer."""
        wanted = []
        for msg_id in ihave.message_ids:
            # Message IDs must be exactly 20 bytes (SHA256 truncated to 160 bits).
            if len(msg_id) != 20:
                continue
            msg_id_typed = Bytes20(msg_id)
            if not self.seen_cache.has(msg_id_typed) and not self.message_cache.has(msg_id_typed):
                wanted.append(msg_id)

        if not wanted:
            return

        iwant_rpc = RPC(control=ControlMessage(iwant=[ControlIWant(message_ids=wanted)]))
        await self._send_rpc(peer_id, iwant_rpc)

        logger.debug("Sent IWANT for %d messages from %s", len(wanted), peer_id)

    async def _handle_iwant(self, peer_id: PeerId, iwant: ControlIWant) -> None:
        """Handle an IWANT request from a peer."""
        messages = []

        for msg_id in iwant.message_ids:
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

    def _handle_idontwant(self, peer_id: PeerId, idontwant: ControlIDontWant) -> None:
        """Handle an IDONTWANT message from a peer (v1.2).

        Records message IDs the peer does not want so we skip
        forwarding those messages to them.
        """
        state = self._peers.get(peer_id)
        if state is None:
            return

        for msg_id in idontwant.message_ids:
            if len(msg_id) != 20:
                continue
            state.dont_want_ids.add(Bytes20(msg_id))

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
        """Perform heartbeat maintenance.

        1. Maintain mesh sizes (GRAFT/PRUNE)
        2. Send IHAVE gossip to non-mesh peers
        3. Age caches and clean up stale state
        """
        now = time.time()

        for topic in self.mesh.subscriptions:
            await self._maintain_mesh(topic, now)

        # Maintain fanout: fill entries that dropped below D.
        for topic in list(self.mesh.fanout_topics):
            fanout_peers = self.mesh.get_fanout_peers(topic)
            if len(fanout_peers) < self.params.d:
                available = {
                    p
                    for p, s in self._peers.items()
                    if topic in s.subscriptions and s.outbound_stream is not None
                }
                self.mesh.fill_fanout(topic, available)

        # Gossip covers both subscribed and fanout topics so that
        # IHAVE reaches peers even for topics we only publish to.
        gossip_topics = self.mesh.subscriptions | self.mesh.fanout_topics
        for topic in gossip_topics:
            await self._emit_gossip(topic)

        self.mesh.cleanup_fanouts(self.params.fanout_ttl_secs, now)
        self.message_cache.shift()
        self.seen_cache.cleanup(now)

        # IDONTWANT is only valid within a single heartbeat window;
        # stale entries would suppress legitimate new forwards.
        for state in self._peers.values():
            state.dont_want_ids.clear()

    async def _maintain_mesh(self, topic: str, now: float) -> None:
        """Maintain mesh size for a topic."""
        mesh_peers = self.mesh.get_mesh_peers(topic)
        mesh_size = len(mesh_peers)

        # Only consider peers with outbound streams.
        # Peers still in connection setup (no stream yet) become
        # eligible once their outbound stream is established.
        eligible = []
        for peer_id, state in self._peers.items():
            if state.outbound_stream is None:
                continue
            if topic in state.subscriptions and peer_id not in mesh_peers:
                backoff_until = state.backoff.get(topic, 0)
                if now >= backoff_until:
                    eligible.append(peer_id)

        if mesh_size < self.params.d_low and eligible:
            needed = self.params.d - mesh_size
            to_graft = random.sample(eligible, min(needed, len(eligible)))

            for peer_id in to_graft:
                self.mesh.add_to_mesh(topic, peer_id)

            rpc = create_graft_rpc([topic])
            for peer_id in to_graft:
                await self._send_rpc(peer_id, rpc)

            logger.debug("GRAFT %d peers for topic %s", len(to_graft), topic)

        elif mesh_size > self.params.d_high:
            excess = mesh_size - self.params.d
            to_prune = random.sample(list(mesh_peers), excess)

            for peer_id in to_prune:
                self.mesh.remove_from_mesh(topic, peer_id)

            # Set our own backoff to avoid premature re-GRAFT.
            prune_rpc = RPC(
                control=ControlMessage(prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)])
            )
            for peer_id in to_prune:
                await self._send_rpc(peer_id, prune_rpc)
                state = self._peers.get(peer_id)
                if state is not None:
                    state.backoff[topic] = now + PRUNE_BACKOFF

            logger.debug("PRUNE %d peers for topic %s", len(to_prune), topic)

    async def _emit_gossip(self, topic: str) -> None:
        """Send IHAVE gossip to non-mesh peers."""
        msg_ids = self.message_cache.get_gossip_ids(topic)
        if not msg_ids:
            return

        # Only peers with outbound streams can receive gossip.
        all_topic_peers = {
            p
            for p, state in self._peers.items()
            if topic in state.subscriptions and state.outbound_stream is not None
        }

        gossip_peers = self.mesh.select_peers_for_gossip(topic, all_topic_peers)
        if not gossip_peers:
            return

        ihave = ControlIHave(topic_id=topic, message_ids=cast(list[bytes], msg_ids))
        rpc = RPC(control=ControlMessage(ihave=[ihave]))

        for peer_id in gossip_peers:
            await self._send_rpc(peer_id, rpc)

        logger.debug(
            "IHAVE %d messages to %d peers for topic %s", len(msg_ids), len(gossip_peers), topic
        )

    async def _send_rpc(self, peer_id: PeerId, rpc: RPC) -> None:
        """Deliver an RPC to a peer using length-prefixed framing.

        Silently skips if the peer has no outbound stream yet.
        This is normal during connection setup -- the outbound
        stream arrives shortly after the inbound one.
        """
        state = self._peers.get(peer_id)
        if state is None or state.outbound_stream is None:
            logger.debug("Cannot send RPC to %s: no outbound stream yet", peer_id)
            return

        try:
            data = rpc.encode()

            # Libp2p frames each RPC with a varint length prefix.
            # The receiver uses this to know where one message ends
            # and the next begins on the multiplexed stream.
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

            state.last_rpc_time = time.time()
        except Exception as e:
            logger.warning("Failed to send RPC to %s: %s", peer_id, e)

    async def _receive_loop(self, peer_id: PeerId, stream: StreamReaderProtocol) -> None:
        """Process incoming RPCs from a peer for the lifetime of the connection.

        Each RPC is length-prefixed with a varint, matching the libp2p
        framing convention: ``[varint length][RPC payload] ...``

        On disconnect or stream error, the peer is cleaned up automatically.
        Corrupted data clears the buffer to prevent cascading parse failures.
        """
        buffer = bytearray()
        logger.debug("Starting receive loop for peer %s", peer_id)

        try:
            while self._running and peer_id in self._peers:
                try:
                    chunk = await stream.read(65536)
                    if not chunk:
                        logger.debug("Peer %s disconnected (empty read)", peer_id)
                        break

                    buffer.extend(chunk)

                    # A single network read may contain multiple RPCs,
                    # or a partial one. Drain all complete messages.
                    while buffer:
                        try:
                            length, varint_size = decode_varint(bytes(buffer), 0)
                        except Exception:
                            # Incomplete varint -- wait for more data.
                            break

                        # Not enough bytes yet -- wait for the next read.
                        if len(buffer) < varint_size + length:
                            break

                        rpc_data = bytes(buffer[varint_size : varint_size + length])
                        buffer = buffer[varint_size + length :]

                        try:
                            rpc = RPC.decode(rpc_data)
                            await self._handle_rpc(peer_id, rpc)
                        except Exception as e:
                            # Frame was already extracted; skip this RPC
                            # but continue parsing subsequent frames.
                            logger.warning("Error decoding RPC from %s: %s", peer_id, e)
                            continue

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.warning("Error receiving from %s: %s", peer_id, e)
                    break
        finally:
            await self.remove_peer(peer_id)

    async def _broadcast_subscription(
        self,
        topic: str,
        subscribe: bool,
        prune_peers: set[PeerId] | None = None,
    ) -> None:
        """Announce a subscription change and adjust the mesh accordingly.

        Every peer learns about the change so they can update their
        peer-subscription tables. Beyond that:

        - On subscribe: GRAFT eligible peers to seed the mesh.
        - On unsubscribe: PRUNE former mesh peers so they drop us.

        Args:
            topic: Topic being subscribed or unsubscribed.
            subscribe: True for subscribe, False for unsubscribe.
            prune_peers: Former mesh peers to PRUNE (unsubscribe only).
        """
        rpc = create_subscription_rpc([topic], subscribe)
        for peer_id, state in self._peers.items():
            if state.outbound_stream is not None:
                await self._send_rpc(peer_id, rpc)

        if subscribe:
            # Seed the mesh with up to D peers that already know the topic.
            # Fanout peers were already promoted to mesh by subscribe(),
            # so only GRAFT enough additional peers to reach D.
            current_mesh = self.mesh.get_mesh_peers(topic)
            needed = self.params.d - len(current_mesh)

            if needed > 0:
                eligible = [
                    p
                    for p, s in self._peers.items()
                    if topic in s.subscriptions
                    and s.outbound_stream is not None
                    and p not in current_mesh
                ][:needed]

                if eligible:
                    graft_rpc = create_graft_rpc([topic])
                    for peer_id in eligible:
                        self.mesh.add_to_mesh(topic, peer_id)
                        await self._send_rpc(peer_id, graft_rpc)
        else:
            # Former mesh peers must learn we left so they stop
            # forwarding messages and free our slot for another peer.
            if prune_peers:
                prune_rpc = RPC(
                    control=ControlMessage(
                        prune=[ControlPrune(topic_id=topic, backoff=PRUNE_BACKOFF)]
                    )
                )
                for peer_id in prune_peers:
                    if self._peers.get(peer_id) is not None:
                        await self._send_rpc(peer_id, prune_rpc)

    def _spawn_background_task(self, coro: Coroutine[None, None, None]) -> None:
        """Create a tracked background task with exception logging."""
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._on_background_task_done)

    def _on_background_task_done(self, task: asyncio.Task[None]) -> None:
        """Remove completed task and log any exception."""
        self._background_tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logger.warning("Background task failed: %s", task.exception())
