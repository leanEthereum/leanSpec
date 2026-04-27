"""
Network event source bridging transport to sync service.

This module produces events from real network connections. It bridges the
gap between the low-level transport layer (QUIC ConnectionManager) and the
high-level sync service.


WHY THIS MODULE EXISTS
----------------------
The sync service operates at a high level of abstraction. It thinks in
terms of "block arrived" or "peer connected" events. The transport layer
operates at the byte level: QUIC streams, encrypted frames, multiplexed
channels. This module translates between these worlds.


EVENT FLOW
----------
Messages flow through the system in stages:

1. ConnectionManager establishes QUIC connections.
2. LiveNetworkEventSource monitors connections for activity.
3. Incoming messages are parsed and converted to NetworkEvent objects.
4. NetworkService consumes events via async iteration.


WHY SSZ AND SNAPPY?
-------------------
SSZ (Simple Serialize) is Ethereum's canonical serialization format:

- Deterministic: Same object always produces same bytes.
- Merkleizable: Supports efficient proofs of inclusion.
- Fixed overhead: Known sizes enable buffer pre-allocation.

Snappy compression reduces bandwidth by 50-70% for typical blocks.
Gossip uses raw Snappy block format. Req-resp uses Snappy framing with CRC32C.


GOSSIPSUB v1.1 REQUIREMENTS
---------------------------
The Ethereum consensus spec requires gossipsub v1.1 (protocol "/meshsub/1.1.0").
Key v1.1 features used:

- Peer scoring: Misbehaving peers get lower scores.
- Extended validators: Message validation before forwarding.
- Flood publishing: High-priority messages bypass mesh constraints.


References:
    - Ethereum P2P spec: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
    - Gossipsub v1.1: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
    - SSZ spec: https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md
    - Snappy format: https://github.com/google/snappy/blob/main/format_description.txt
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from lean_spec.forks.lstar.containers import SignedBlock
from lean_spec.forks.lstar.containers.attestation import (
    SignedAggregatedAttestation,
    SignedAttestation,
)
from lean_spec.subspecs.networking.config import (
    GOSSIPSUB_DEFAULT_PROTOCOL_ID,
    GOSSIPSUB_PROTOCOL_ID_V12,
    RESP_TIMEOUT,
)
from lean_spec.subspecs.networking.gossipsub.behavior import (
    GossipsubBehavior,
    GossipsubMessageEvent,
)
from lean_spec.subspecs.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic, TopicKind
from lean_spec.subspecs.networking.gossipsub.types import TopicId
from lean_spec.subspecs.networking.reqresp.handler import (
    REQRESP_PROTOCOL_IDS,
    AsyncBlockLookup,
    ReqRespServer,
    RequestHandler,
)
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.service.events import (
    GossipAggregatedAttestationEvent,
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    PeerConnectedEvent,
    PeerDisconnectedEvent,
    PeerStatusEvent,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.subspecs.networking.transport.identity import IdentityKeypair
from lean_spec.subspecs.networking.transport.quic.connection import (
    QuicConnection,
    QuicConnectionManager,
    is_quic_multiaddr,
)
from lean_spec.subspecs.networking.transport.quic.stream import QuicStream
from lean_spec.subspecs.networking.transport.quic.stream_adapter import (
    NegotiationError,
    QuicStreamAdapter,
)
from lean_spec.subspecs.networking.types import ProtocolId
from lean_spec.types.exceptions import SSZSerializationError

from ..reqresp_client import ReqRespClient
from .gossip import GossipHandler
from .protocol import SUPPORTED_PROTOCOLS, GossipMessageError

logger = logging.getLogger(__name__)


@dataclass
class LiveNetworkEventSource:
    """
    Produces NetworkEvent objects from real network connections.

    Bridges the transport layer (ConnectionManager) to the event-driven
    sync layer.


    ARCHITECTURE
    ------------
    This class sits between two layers::

        Transport Layer (low-level)
              |
        LiveNetworkEventSource  <-- This class
              |
        NetworkService (high-level)

    The transport layer deals with bytes, streams, and connections.
    The sync layer deals with blocks, attestations, and peer status.
    This class translates between them.


    RESPONSIBILITIES
    ----------------
    - Accept incoming connections and emit PeerConnectedEvent.
    - Dial outbound connections and emit PeerConnectedEvent.
    - Exchange Status messages and emit PeerStatusEvent.
    - Receive gossip messages and emit GossipBlockEvent/GossipAttestationEvent.
    - Publish locally-produced blocks and attestations.


    CONCURRENCY MODEL
    -----------------
    Each connection spawns a background task that accepts incoming streams.
    Each gossip stream spawns its own task to read the message.

    This allows concurrent handling of multiple peers and messages.
    The event queue serializes delivery to the consumer.


    BACKPRESSURE
    ------------
    The event queue provides natural backpressure. If the consumer is
    slow, the queue grows. Eventually, async iteration semantics cause
    producers to wait.
    """

    connection_manager: QuicConnectionManager
    """Underlying transport manager for QUIC connections.

    Handles the full connection stack: QUIC transport with TLS 1.3 encryption.
    """

    reqresp_client: ReqRespClient
    """Client for req/resp protocol operations.

    Used for Status exchange and block/attestation requests.
    """

    quic_manager: QuicConnectionManager | None = None
    """Underlying transport manager for QUIC connections.

    Handles QUIC connections with libp2p-tls authentication.
    Initialized lazily on first QUIC connection.
    """

    _events: asyncio.Queue[NetworkEvent] = field(default_factory=asyncio.Queue)
    """Queue of pending events to yield.

    Events are produced by background tasks and consumed via async iteration.
    """

    _connections: dict[PeerId, QuicConnection] = field(default_factory=dict)
    """Active connections by peer ID.

    Used to route outbound messages and track peer state.
    """

    _our_status: Status | None = None
    """Our current chain status for handshakes.

    Contains our finalized checkpoint and head. Exchanged with peers on connect.
    """

    _network_name: str = "0x00000000"
    """Network name for gossip topics.

    4-byte identifier derived from genesis validators root and fork version.
    Used to validate incoming messages belong to the same fork.
    """

    _running: bool = False
    """Whether the event source is running.

    Controls the main loop and background tasks.
    """

    _gossip_handler: GossipHandler = field(init=False)
    """Handler for decoding incoming gossip messages.

    Initialized with the current network name.
    """

    _gossip_tasks: set[asyncio.Task[None]] = field(default_factory=set)
    """Background tasks processing incoming gossip streams.

    Tracked for cleanup on shutdown. Tasks remove themselves on completion.
    """

    _reqresp_handler: RequestHandler = field(init=False)
    """Handler for inbound ReqResp requests.

    Provides chain data to peers requesting Status or BlocksByRoot.
    """

    _reqresp_server: ReqRespServer = field(init=False)
    """Server for processing inbound ReqResp streams.

    Routes requests to the appropriate handler method.
    """

    _gossipsub_behavior: GossipsubBehavior = field(init=False)
    """GossipSub behavior for full protocol support.

    Manages mesh topology, control messages (GRAFT/PRUNE/IHAVE/IWANT),
    and message propagation for interoperability with rust-libp2p and go-libp2p.
    """

    _gossipsub_event_task: asyncio.Task | None = None
    """Background task forwarding gossipsub events to our event queue."""

    def __post_init__(self) -> None:
        """Wire up internal handlers from configuration."""
        self._gossip_handler = GossipHandler(network_name=self._network_name)
        self._reqresp_handler = RequestHandler()
        self._reqresp_server = ReqRespServer(handler=self._reqresp_handler)
        self._gossipsub_behavior = GossipsubBehavior(params=GossipsubParameters())

    @classmethod
    async def create(
        cls,
        connection_manager: QuicConnectionManager | None = None,
    ) -> LiveNetworkEventSource:
        """
        Create a new LiveNetworkEventSource.

        Args:
            connection_manager: Transport manager. Creates new if None.

        Returns:
            Initialized event source.
        """
        if connection_manager is None:
            identity_key = IdentityKeypair.generate()
            connection_manager = await QuicConnectionManager.create(identity_key)

        reqresp_client = ReqRespClient(connection_manager=connection_manager)

        return cls(
            connection_manager=connection_manager,
            reqresp_client=reqresp_client,
        )

    def set_status(self, status: Status) -> None:
        """
        Set our chain status for handshakes and inbound Status requests.

        Updates both the outbound status exchange and the inbound request handler.

        Args:
            status: Our current finalized and head checkpoints.
        """
        self._our_status = status
        self._reqresp_handler.our_status = status

    def set_network_name(self, network_name: str) -> None:
        """
        Set network name for gossip topics.

        Args:
            network_name: 4-byte fork identifier as hex string.
        """
        self._network_name = network_name
        self._gossip_handler = GossipHandler(network_name=network_name)

    def set_block_lookup(self, lookup: AsyncBlockLookup) -> None:
        """
        Set the callback for looking up blocks by root.

        Used by the inbound ReqResp handler to serve BlocksByRoot requests.

        Args:
            lookup: Async function that takes a Bytes32 root and returns
                the SignedBlock if available, None otherwise.
        """
        self._reqresp_handler.block_lookup = lookup

    def subscribe_gossip_topic(self, topic: TopicId) -> None:
        """
        Subscribe to a gossip topic.

        This enables receiving messages for the topic and participating
        in mesh management via GRAFT/PRUNE.

        Args:
            topic: Full topic string (e.g., "/leanconsensus/0x.../block/ssz_snappy").
        """
        self._gossipsub_behavior.subscribe(topic)
        logger.debug("Subscribed to gossip topic %s", topic)

    async def start_gossipsub(self) -> None:
        """
        Start the gossipsub behavior.

        This begins the heartbeat loop for mesh maintenance and starts
        forwarding gossipsub events to our event queue.
        """
        await self._gossipsub_behavior.start()

        # Start task to forward gossipsub events to our queue.
        self._gossipsub_event_task = asyncio.create_task(self._forward_gossipsub_events())
        self._gossip_tasks.add(self._gossipsub_event_task)
        self._gossipsub_event_task.add_done_callback(self._gossip_tasks.discard)

        logger.info("GossipSub behavior started")

    async def _forward_gossipsub_events(self) -> None:
        """Forward events from GossipsubBehavior to our event queue."""
        try:
            while self._running:
                event = await self._gossipsub_behavior.get_next_event()
                if event is None:
                    # Stopped or no event.
                    break
                if isinstance(event, GossipsubMessageEvent):
                    # Decode the message and emit appropriate event.
                    #
                    # Catch per-message exceptions to prevent one bad message
                    # from killing the entire forwarding loop.
                    try:
                        await self._handle_gossipsub_message(event)
                    except Exception as e:
                        logger.warning("Error handling gossipsub message: %s", e)
        except asyncio.CancelledError:
            pass

    async def _handle_gossipsub_message(self, event: GossipsubMessageEvent) -> None:
        """
        Handle a message received via GossipSub.

        Event data is already decompressed by the gossipsub behavior.
        Decodes SSZ bytes directly based on topic kind.

        Args:
            event: GossipSub message event from the behavior.
        """
        try:
            # Parse the topic to determine message type.
            topic = self._gossip_handler.get_topic(event.topic)

            # Decode SSZ bytes directly.
            #
            # The gossipsub behavior already decompressed the Snappy payload
            # during message ID computation. The event carries decompressed data.
            try:
                match topic.kind:
                    case TopicKind.BLOCK:
                        block = SignedBlock.decode_bytes(event.data)
                        await self._emit_gossip_block(block, event.peer_id)
                    case TopicKind.ATTESTATION_SUBNET:
                        att = SignedAttestation.decode_bytes(event.data)
                        await self._emit_gossip_attestation(att, event.peer_id)
                    case TopicKind.AGGREGATED_ATTESTATION:
                        agg = SignedAggregatedAttestation.decode_bytes(event.data)
                        await self._emit_gossip_aggregated_attestation(agg, event.peer_id)
            except SSZSerializationError as e:
                raise GossipMessageError(f"SSZ decode failed: {e}") from e

            logger.debug("Processed gossipsub message %s from %s", topic.kind.value, event.peer_id)

        except GossipMessageError as e:
            logger.warning("Failed to process gossipsub message: %s", e)

    def __aiter__(self) -> LiveNetworkEventSource:
        """Return self as async iterator."""
        return self

    async def __anext__(self) -> NetworkEvent:
        """
        Yield the next network event.

        Blocks until an event is available or stopped.

        Returns:
            Next event from the network.

        Raises:
            StopAsyncIteration: When no more events will arrive.
        """
        while self._running:
            try:
                return await asyncio.wait_for(self._events.get(), timeout=0.5)
            except asyncio.TimeoutError:
                # Check running flag and loop.
                continue

        raise StopAsyncIteration

    async def dial(self, multiaddr: str) -> PeerId | None:
        """
        Connect to a peer at the given multiaddr.

        Establishes a connection, exchanges Status, and emits events.

        Args:
            multiaddr: Address like "/ip4/127.0.0.1/udp/9000/quic-v1" or
                      "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/16Uiu2HAm..."

        Returns:
            Peer ID on success, None on failure.
        """
        # Ensure _running is set so background tasks (like _accept_streams)
        # can operate. Without this, _accept_streams exits immediately if
        # dial() is called before listen().
        self._running = True

        try:
            # Detect transport type and connect accordingly.
            if is_quic_multiaddr(multiaddr):
                conn = await self._dial_quic(multiaddr)
            else:
                conn = await self.connection_manager.connect(multiaddr)

            peer_id = conn.peer_id

            # Register connection.
            self._connections[peer_id] = conn
            self.reqresp_client.register_connection(peer_id, conn)

            # Emit connected event.
            await self._events.put(PeerConnectedEvent(peer_id=peer_id))

            # IMPORTANT: Start accepting streams FIRST, before any other operations.
            #
            # The peer (listener) will try to open an outbound gossipsub stream to us.
            # If we don't start accepting streams before our own operations, there's
            # a deadlock: we wait for them to accept our stream, they wait for us.
            task = asyncio.create_task(self._accept_streams(peer_id, conn))
            self._gossip_tasks.add(task)
            task.add_done_callback(self._gossip_tasks.discard)

            # Exchange status.
            await self._exchange_status(peer_id, conn)

            # Set up gossipsub stream for full protocol support.
            await self._setup_gossipsub_stream(peer_id, conn)

            logger.info("Connected to peer %s at %s", peer_id, multiaddr)
            return peer_id

        except Exception as e:
            logger.warning("Failed to connect to %s: %s", multiaddr, e)
            return None

    async def _ensure_quic_manager(self) -> None:
        """Initialize QUIC manager lazily on first use.

        Reuses the identity key from the connection manager for consistency.
        This ensures the same peer ID is used across all connections.
        Called automatically before any QUIC operation.
        """
        if self.quic_manager is None:
            # Reuse the same identity key for consistent peer ID.
            # Accesses internal field; no public API exists for this.
            identity_key = self.connection_manager._identity_key
            self.quic_manager = await QuicConnectionManager.create(identity_key)

    async def _dial_quic(self, multiaddr: str) -> QuicConnection:
        """Connect to a peer using QUIC transport.

        Ensures the QUIC manager is initialized before connecting.

        Args:
            multiaddr: QUIC address like "/ip4/127.0.0.1/udp/9000/quic-v1".

        Returns:
            Established QUIC connection.

        Raises:
            QuicTransportError: If connection fails.
        """
        await self._ensure_quic_manager()
        assert self.quic_manager is not None
        return await self.quic_manager.connect(multiaddr)

    async def listen(self, multiaddr: str) -> None:
        """Start listening for incoming connections.

        Automatically detects transport type from multiaddr:

        - QUIC: Routes to the QUIC listener
        - Other: Delegates to the connection manager

        Args:
            multiaddr: Address to listen on (e.g., "/ip4/0.0.0.0/udp/9000/quic-v1").
        """
        self._running = True

        if is_quic_multiaddr(multiaddr):
            await self._listen_quic(multiaddr)
        else:
            await self.connection_manager.listen(
                multiaddr,
                on_connection=self._handle_inbound_connection,
            )

    async def _listen_quic(self, multiaddr: str) -> None:
        """Listen for incoming QUIC connections.

        Ensures the QUIC manager is initialized.
        Registers the connection callback for accepted connections.

        Args:
            multiaddr: QUIC address to listen on.
        """
        await self._ensure_quic_manager()
        assert self.quic_manager is not None
        await self.quic_manager.listen(
            multiaddr,
            on_connection=self._handle_inbound_connection,
        )

    async def _handle_inbound_connection(self, conn: QuicConnection) -> None:
        """
        Handle a new inbound connection.

        Registers the connection, emits a connected event, and starts
        background stream acceptance. Status exchange and outbound
        gossipsub setup are deferred to avoid race conditions.

        Args:
            conn: Established connection.
        """
        peer_id = conn.peer_id

        # Register connection.
        self._connections[peer_id] = conn
        self.reqresp_client.register_connection(peer_id, conn)

        # Emit connected event.
        await self._events.put(PeerConnectedEvent(peer_id=peer_id))

        # Start accepting streams to handle peer's requests.
        task = asyncio.create_task(self._accept_streams(peer_id, conn))
        self._gossip_tasks.add(task)
        task.add_done_callback(self._gossip_tasks.discard)

        # NOTE: Do NOT initiate status exchange on inbound connections.
        # Only the dialer sends a status request. The listener only responds.
        # This matches ream's behavior and avoids simultaneous status streams.

        # NOTE: Do NOT set up outbound gossipsub stream immediately.
        # Opening a stream while the dialer is doing status exchange causes
        # aioquic to enter a bad state. The outbound stream is set up later,
        # when we receive the peer's inbound gossipsub stream.

        logger.info("Accepted connection from peer %s", peer_id)

    async def _exchange_status(
        self,
        peer_id: PeerId,
        conn: QuicConnection,
    ) -> None:
        """
        Exchange Status messages with a peer.

        Args:
            peer_id: Peer identifier.
            conn: QuicConnection to use.
        """
        if self._our_status is None:
            logger.debug("No status set, skipping status exchange")
            return

        try:
            peer_status = await self.reqresp_client.send_status(peer_id, self._our_status)

            if peer_status is not None:
                await self._events.put(PeerStatusEvent(peer_id=peer_id, status=peer_status))
                logger.debug(
                    "Received status from %s: head=%s",
                    peer_id,
                    peer_status.head.root.hex()[:8],
                )

        except Exception as e:
            logger.warning("Status exchange failed with %s: %s", peer_id, e)

    async def _setup_gossipsub_stream(
        self,
        peer_id: PeerId,
        conn: QuicConnection,
    ) -> None:
        """
        Set up the GossipSub stream for a peer.

        Opens a persistent stream for gossipsub protocol and registers
        the peer with the GossipsubBehavior.

        Args:
            peer_id: Peer identifier.
            conn: QuicConnection to use.
        """
        try:
            # Open the gossipsub stream.
            stream = await conn.open_stream(GOSSIPSUB_DEFAULT_PROTOCOL_ID)
            logger.info(
                "Opened outbound gossipsub stream_id=%d to %s (expect odd=server-initiated)",
                stream.stream_id,
                peer_id,
            )

            # Wrap in reader/writer for buffered I/O.
            wrapped_stream = QuicStreamAdapter(stream)

            # Add peer to the gossipsub behavior (outbound stream).
            await self._gossipsub_behavior.add_peer(peer_id, wrapped_stream, inbound=False)

            logger.info(
                "GossipSub outbound stream established with %s (stream_id=%d)",
                peer_id,
                stream.stream_id,
            )

        except Exception as e:
            logger.warning("Failed to setup gossipsub stream with %s: %s", peer_id, e)

    async def disconnect(self, peer_id: PeerId) -> None:
        """
        Disconnect from a peer.

        Args:
            peer_id: Peer to disconnect.
        """
        conn = self._connections.pop(peer_id, None)
        if conn is not None:
            self.reqresp_client.unregister_connection(peer_id)
            await conn.close()
            await self._events.put(PeerDisconnectedEvent(peer_id=peer_id))
            logger.info("Disconnected from peer %s", peer_id)

    async def stop(self) -> None:
        """Stop the event source and cancel background tasks."""
        self._running = False

        # Cancel gossip tasks first (including event forwarding task).
        # This must happen BEFORE stopping gossipsub behavior to avoid
        # async generator cleanup race conditions.
        #
        # Copy the set because done callbacks may modify it during iteration.
        tasks_to_cancel = list(self._gossip_tasks)
        for task in tasks_to_cancel:
            task.cancel()

        # Wait for gossip tasks to complete.
        for task in tasks_to_cancel:
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._gossip_tasks.clear()

        # Now stop the gossipsub behavior.
        await self._gossipsub_behavior.stop()

    async def _emit_gossip_block(
        self,
        block: SignedBlock,
        peer_id: PeerId,
    ) -> None:
        """
        Emit a gossip block event.

        Args:
            block: Block received from gossip.
            peer_id: Peer that sent it.
        """
        topic = GossipTopic(kind=TopicKind.BLOCK, network_name=self._network_name)
        await self._events.put(GossipBlockEvent(block=block, peer_id=peer_id, topic=topic))

    async def _emit_gossip_attestation(
        self,
        attestation: SignedAttestation,
        peer_id: PeerId,
    ) -> None:
        """
        Emit a gossip attestation event.

        Args:
            attestation: Attestation received from gossip.
            peer_id: Peer that sent it.
        """
        topic = GossipTopic(kind=TopicKind.ATTESTATION_SUBNET, network_name=self._network_name)
        await self._events.put(
            GossipAttestationEvent(attestation=attestation, peer_id=peer_id, topic=topic)
        )

    async def _emit_gossip_aggregated_attestation(
        self,
        signed_attestation: SignedAggregatedAttestation,
        peer_id: PeerId,
    ) -> None:
        """
        Emit a gossip aggregated attestation event.

        Args:
            signed_attestation: Aggregated attestation received from gossip.
            peer_id: Peer that sent it.
        """
        topic = GossipTopic(kind=TopicKind.AGGREGATED_ATTESTATION, network_name=self._network_name)
        await self._events.put(
            GossipAggregatedAttestationEvent(
                signed_attestation=signed_attestation, peer_id=peer_id, topic=topic
            )
        )

    async def _accept_streams(self, peer_id: PeerId, conn: QuicConnection) -> None:
        """
        Accept incoming streams from a connection.

        Runs in the background, accepting streams and dispatching them to
        the appropriate handler based on protocol ID.

        Args:
            peer_id: Peer that owns the connection.
            conn: QUIC connection to accept streams from.


        WHY BACKGROUND STREAM ACCEPTANCE?
        ---------------------------------
        QUIC multiplexing allows peers to open many streams concurrently.
        Each stream is an independent request/response conversation.

        Running stream acceptance in the background allows:

        - Concurrent handling of multiple incoming streams.
        - Non-blocking connection management.
        - Graceful handling of peer disconnection.

        Without background acceptance, the main event loop would block
        waiting for streams from one peer while ignoring others.


        PROTOCOL ID ROUTING
        -------------------
        The protocol ID (from multistream-select negotiation) determines
        how to handle the stream:

        - "/meshsub/1.1.0": Gossipsub message (block or attestation).
        - Other protocols: Req/resp handled elsewhere; close unknown.

        This routing happens at the stream level, not the message level.
        Each protocol has its own message format and semantics.
        """
        try:
            logger.info("Stream acceptor started for peer %s", peer_id)
            # Main loop: accept streams until shutdown or disconnection.
            #
            # The loop continues as long as:
            #   - We haven't been told to stop (_running is True).
            #   - The peer is still connected (peer_id in _connections).
            while self._running and peer_id in self._connections:
                try:
                    # Accept the next incoming stream.
                    #
                    # This blocks until a peer opens a stream or the connection closes.
                    # QUIC handles the low-level multiplexing.
                    stream = await conn.accept_stream()
                except Exception as e:
                    # Connection closed or other transport error.
                    #
                    # This is expected when the peer disconnects.
                    # Exit the loop cleanly rather than propagating.
                    logger.debug("Stream accept failed for %s: %s", peer_id, e)
                    break

                negotiated = await self._negotiate_inbound_stream(peer_id, stream)
                if negotiated is None:
                    # Negotiation failed; the stream has already been closed.
                    continue
                protocol_id, wrapper = negotiated

                if protocol_id in (GOSSIPSUB_DEFAULT_PROTOCOL_ID, GOSSIPSUB_PROTOCOL_ID_V12):
                    await self._handle_gossipsub_inbound_stream(peer_id, conn, protocol_id, wrapper)
                elif protocol_id in REQRESP_PROTOCOL_IDS:
                    self._handle_reqresp_inbound_stream(peer_id, protocol_id, wrapper)
                else:
                    # Unknown protocol.
                    #
                    # Close the stream gracefully. The peer may be running
                    # a newer client with protocols we don't support.
                    logger.debug(
                        "Unknown protocol %s from %s, closing stream", protocol_id, peer_id
                    )
                    await stream.close()

        except asyncio.CancelledError:
            # Task was cancelled during shutdown.
            #
            # This is normal cleanup behavior. Log and exit.
            logger.debug("Stream acceptor cancelled for %s", peer_id)

        except Exception as e:
            # Unexpected error.
            #
            # Log as warning since this may indicate a bug.
            # The connection will be cleaned up elsewhere.
            logger.warning("Stream acceptor error for %s: %s", peer_id, e)

    async def _negotiate_inbound_stream(
        self,
        peer_id: PeerId,
        stream: QuicStream,
    ) -> tuple[ProtocolId, QuicStreamAdapter] | None:
        """
        Run multistream-select on a freshly accepted inbound stream.

        Returns the negotiated protocol id and the wrapper that owns any
        bytes the peer sent during negotiation. The wrapper must be reused
        by the protocol handler so that buffered data is not lost.

        On any negotiation error the stream is closed and None is returned;
        the caller skips this stream and accepts the next one.

        Args:
            peer_id: Peer that owns the connection (for log context).
            stream: Raw stream returned by ``conn.accept_stream``.

        Returns:
            Tuple of (protocol_id, wrapper) on success, None on failure.
        """
        # QUIC streams need protocol negotiation.
        #
        # Multistream-select runs on top to agree on what protocol to use.
        # We create a wrapper for buffered I/O during negotiation, and
        # preserve it for later use (to avoid losing buffered data).
        try:
            wrapper = QuicStreamAdapter(stream)
            gs_id = self._gossipsub_behavior._instance_id % 0xFFFF
            logger.debug(
                "[GS %x] Accepting inbound stream %d from %s, negotiating protocol...",
                gs_id,
                stream.stream_id,
                peer_id,
            )
            protocol_id = await asyncio.wait_for(
                wrapper.negotiate_server(set(SUPPORTED_PROTOCOLS)),
                timeout=RESP_TIMEOUT,
            )
            stream._protocol_id = protocol_id
            logger.debug(
                "Negotiated protocol %s on stream %d with %s",
                protocol_id,
                stream.stream_id,
                peer_id,
            )
        except asyncio.TimeoutError:
            logger.debug(
                "Protocol negotiation timeout for %s stream %d",
                peer_id,
                stream.stream_id,
            )
            await stream.close()
            return None
        except NegotiationError as e:
            logger.debug(
                "Protocol negotiation failed for %s stream %d: %s",
                peer_id,
                stream.stream_id,
                e,
            )
            await stream.close()
            return None
        except EOFError:
            logger.debug(
                "Stream %d closed by peer %s during negotiation",
                stream.stream_id,
                peer_id,
            )
            await stream.close()
            return None
        except Exception as e:
            logger.warning(
                "Unexpected negotiation error for %s stream %d: %s",
                peer_id,
                stream.stream_id,
                e,
            )
            await stream.close()
            return None

        return protocol_id, wrapper

    async def _handle_gossipsub_inbound_stream(
        self,
        peer_id: PeerId,
        conn: QuicConnection,
        protocol_id: ProtocolId,
        wrapper: QuicStreamAdapter,
    ) -> None:
        """
        Register an inbound gossipsub stream and arm outbound setup.

        Args:
            peer_id: Peer that opened the stream.
            conn: Connection the stream belongs to (used to open our
                outbound stream when needed).
            protocol_id: Negotiated gossipsub protocol id (v1.1 or v1.2).
            wrapper: Adapter holding any bytes already buffered during
                multistream-select. Reusing this wrapper preserves those
                bytes for the gossipsub behavior.
        """
        # GossipSub stream: persistent RPC channel for protocol messages.
        #
        # If we receive an inbound gossipsub stream, add the peer to
        # the behavior. The behavior will handle all RPC exchange
        # (subscriptions, messages, control messages) on this stream.
        #
        # Libp2p uses separate streams for each direction:
        # - Outbound: we opened this to send our RPCs
        # - Inbound: they opened this to send us RPCs
        #
        # We support both v1.1 and v1.2 - the difference is IDONTWANT
        # messages which we can handle gracefully.
        gs_id = self._gossipsub_behavior._instance_id % 0xFFFF
        logger.debug(
            "[GS %x] Received inbound gossipsub stream (%s) from %s",
            gs_id,
            protocol_id,
            peer_id,
        )
        # Use the wrapper from negotiation to preserve any buffered data.
        #
        # During multistream negotiation, the peer may send additional
        # data (like subscription RPCs) that gets buffered in the wrapper.
        # Using the raw stream would lose this data.
        # Await directly to ensure peer is registered before setting up outbound.
        await self._gossipsub_behavior.add_peer(peer_id, wrapper, inbound=True)

        # Now that we've received the peer's inbound stream, set up our
        # outbound stream if we don't have one yet.
        #
        # For dialers: The outbound stream was already set up during
        # the dialing path, so this check prevents a duplicate.
        #
        # For listeners: The outbound stream is NOT set up immediately
        # (to avoid interfering with the dialer's status exchange).
        # This is where the listener's outbound stream gets created.
        #
        # IMPORTANT: We add a small delay before setting up the outbound
        # stream to allow the dialer to complete their operations first.
        # This prevents deadlock while still ensuring the outbound stream
        # is set up quickly enough for mesh formation.
        if self._gossipsub_behavior.has_outbound_stream(peer_id):
            logger.info(
                "Peer %s already has outbound gossipsub stream, skipping setup",
                peer_id,
            )
            return

        gossip_task = asyncio.create_task(self._setup_outbound_gossipsub_after_delay(peer_id, conn))
        self._gossip_tasks.add(gossip_task)
        gossip_task.add_done_callback(self._gossip_tasks.discard)

    async def _setup_outbound_gossipsub_after_delay(
        self,
        peer_id: PeerId,
        conn: QuicConnection,
    ) -> None:
        """
        Open our outbound gossipsub stream after a small delay.

        The delay lets the dialer complete its status exchange first.
        Re-checks the outbound-stream flag right before opening: the
        dialer path may have set up the stream while we were sleeping.

        Args:
            peer_id: Peer to open the outbound stream to.
            conn: Connection to use.
        """
        try:
            await asyncio.sleep(0.1)  # Small delay to avoid contention
            # Re-check BEFORE opening a stream. The dialing path
            # may have set up the outbound stream while we were
            # sleeping. Opening a duplicate gossipsub stream would
            # cause the handler to replace its reader with an orphan.
            if self._gossipsub_behavior.has_outbound_stream(peer_id):
                logger.info(
                    "Peer %s already has outbound stream (set by dialer), skipping duplicate setup",
                    peer_id,
                )
                return
            logger.info("Setting up outbound gossipsub stream for %s", peer_id)
            await self._setup_gossipsub_stream(peer_id, conn)
        except Exception as e:
            logger.warning("setup_outbound_with_delay failed for %s: %s", peer_id, e)

    def _handle_reqresp_inbound_stream(
        self,
        peer_id: PeerId,
        protocol_id: ProtocolId,
        wrapper: QuicStreamAdapter,
    ) -> None:
        """
        Hand off an inbound ReqResp stream to a background server task.

        Args:
            peer_id: Peer that opened the stream (for log context).
            protocol_id: Negotiated request/response protocol id.
            wrapper: Adapter holding any bytes already buffered during
                multistream-select. The raw stream would lose those bytes.
        """
        # ReqResp stream: Status or BlocksByRoot request.
        #
        # Handle in a separate task to allow concurrent request processing.
        # The ReqRespServer handles decoding, dispatching, and responding.
        #
        # IMPORTANT: Use the wrapper from negotiation (not raw stream).
        # The wrapper may have buffered data read during protocol negotiation.
        # Passing the raw stream would lose that buffered data.
        task = asyncio.create_task(
            self._reqresp_server.handle_stream(
                wrapper,
                protocol_id,
            )
        )
        self._gossip_tasks.add(task)
        task.add_done_callback(self._gossip_tasks.discard)
        logger.debug("Handling ReqResp %s from %s", protocol_id, peer_id)

    async def publish(self, topic: TopicId, data: bytes) -> None:
        """
        Broadcast a message to all connected peers on a topic.

        Uses the GossipSub behavior for proper mesh-based propagation.
        The behavior handles:

        - Sending to mesh peers
        - Respecting PRUNE backoffs
        - Deduplication via message cache

        Args:
            topic: Gossip topic string.
            data: Compressed message bytes (SSZ + Snappy).
        """
        if not self._connections:
            logger.debug("No peers connected, cannot publish to %s", topic)
            return

        try:
            await self._gossipsub_behavior.publish(topic, data)
            logger.debug("Published message to gossipsub topic %s", topic)
        except Exception as e:
            logger.warning("Failed to publish to gossipsub: %s", e)
