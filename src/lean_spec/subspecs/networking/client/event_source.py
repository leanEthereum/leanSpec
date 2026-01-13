"""
Network event source bridging transport to sync service.

This module implements NetworkEventSource, producing events from real
network connections. It bridges the gap between the low-level transport
layer (ConnectionManager + yamux) and the high-level sync service.

Event Flow
----------
1. ConnectionManager establishes connections (Noise + yamux)
2. LiveNetworkEventSource monitors connections for activity
3. Incoming messages are parsed and converted to NetworkEvent objects
4. NetworkService consumes events via async iteration
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic, TopicKind
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.service.events import (
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    PeerConnectedEvent,
    PeerDisconnectedEvent,
    PeerStatusEvent,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.subspecs.networking.transport.connection.manager import (
    ConnectionManager,
    YamuxConnection,
)

from .reqresp_client import ReqRespClient

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class LiveNetworkEventSource:
    """
    Produces NetworkEvent objects from real network connections.

    Implements the NetworkEventSource protocol for use with NetworkService.
    Bridges the transport layer (ConnectionManager) to the event-driven
    sync layer.

    Responsibilities
    ----------------
    - Accept incoming connections and emit PeerConnectedEvent
    - Dial outbound connections and emit PeerConnectedEvent
    - Exchange Status messages and emit PeerStatusEvent
    - (Future) Handle gossip messages and emit GossipBlockEvent/GossipAttestationEvent

    Usage
    -----
    ::

        event_source = LiveNetworkEventSource.create(connection_manager)

        # Dial bootnodes
        await event_source.dial("/ip4/127.0.0.1/tcp/9000")

        # Consume events
        async for event in event_source:
            await handle_event(event)
    """

    connection_manager: ConnectionManager
    """Underlying transport manager."""

    reqresp_client: ReqRespClient
    """Client for req/resp protocol operations."""

    _events: asyncio.Queue[NetworkEvent] = field(default_factory=asyncio.Queue)
    """Queue of pending events to yield."""

    _connections: dict[PeerId, YamuxConnection] = field(default_factory=dict)
    """Active connections by peer ID."""

    _our_status: Status | None = None
    """Our current chain status for handshakes."""

    _fork_digest: str = "0x00000000"
    """Fork digest for gossip topics."""

    _running: bool = False
    """Whether the event source is running."""

    @classmethod
    def create(
        cls,
        connection_manager: ConnectionManager | None = None,
    ) -> LiveNetworkEventSource:
        """
        Create a new LiveNetworkEventSource.

        Args:
            connection_manager: Transport manager. Creates new if None.

        Returns:
            Initialized event source.
        """
        if connection_manager is None:
            connection_manager = ConnectionManager.create()

        reqresp_client = ReqRespClient(connection_manager=connection_manager)

        return cls(
            connection_manager=connection_manager,
            reqresp_client=reqresp_client,
        )

    def set_status(self, status: Status) -> None:
        """
        Set our chain status for handshakes.

        Args:
            status: Our current finalized and head checkpoints.
        """
        self._our_status = status

    def set_fork_digest(self, fork_digest: str) -> None:
        """
        Set fork digest for gossip topics.

        Args:
            fork_digest: 4-byte fork identifier as hex string.
        """
        self._fork_digest = fork_digest

    def __aiter__(self) -> LiveNetworkEventSource:
        """Return self as async iterator."""
        return self

    async def __anext__(self) -> NetworkEvent:
        """
        Yield the next network event.

        Blocks until an event is available.

        Returns:
            Next event from the network.

        Raises:
            StopAsyncIteration: When no more events will arrive.
        """
        if not self._running:
            raise StopAsyncIteration

        return await self._events.get()

    async def dial(self, multiaddr: str) -> PeerId | None:
        """
        Connect to a peer at the given multiaddr.

        Establishes connection, exchanges Status, and emits events.

        Args:
            multiaddr: Address like "/ip4/127.0.0.1/tcp/9000"

        Returns:
            Peer ID on success, None on failure.
        """
        try:
            conn = await self.connection_manager.connect(multiaddr)
            peer_id = conn.peer_id

            # Register connection.
            self._connections[peer_id] = conn
            self.reqresp_client.register_connection(peer_id, conn)

            # Emit connected event.
            await self._events.put(PeerConnectedEvent(peer_id=peer_id))

            # Exchange status.
            await self._exchange_status(peer_id, conn)

            logger.info("Connected to peer %s at %s", peer_id, multiaddr)
            return peer_id

        except Exception as e:
            logger.warning("Failed to connect to %s: %s", multiaddr, e)
            return None

    async def listen(self, multiaddr: str) -> None:
        """
        Start listening for incoming connections.

        This runs in the background, accepting connections and emitting
        events for each.

        Args:
            multiaddr: Address to listen on (e.g., "/ip4/0.0.0.0/tcp/9000")
        """
        self._running = True
        await self.connection_manager.listen(
            multiaddr,
            on_connection=self._handle_inbound_connection,
        )

    async def _handle_inbound_connection(self, conn: YamuxConnection) -> None:
        """
        Handle a new inbound connection.

        Args:
            conn: Established connection.
        """
        peer_id = conn.peer_id

        # Register connection.
        self._connections[peer_id] = conn
        self.reqresp_client.register_connection(peer_id, conn)

        # Emit connected event.
        await self._events.put(PeerConnectedEvent(peer_id=peer_id))

        # Exchange status.
        await self._exchange_status(peer_id, conn)

        logger.info("Accepted connection from peer %s", peer_id)

    async def _exchange_status(
        self,
        peer_id: PeerId,
        conn: YamuxConnection,
    ) -> None:
        """
        Exchange Status messages with a peer.

        Args:
            peer_id: Peer identifier.
            conn: Connection to use.
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

    def stop(self) -> None:
        """Stop the event source."""
        self._running = False

    # =========================================================================
    # Gossip Message Handling (placeholder for future implementation)
    # =========================================================================

    async def _emit_gossip_block(
        self,
        block: SignedBlockWithAttestation,
        peer_id: PeerId,
    ) -> None:
        """
        Emit a gossip block event.

        Args:
            block: Block received from gossip.
            peer_id: Peer that sent it.
        """
        topic = GossipTopic(kind=TopicKind.BLOCK, fork_digest=self._fork_digest)
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
        topic = GossipTopic(kind=TopicKind.ATTESTATION, fork_digest=self._fork_digest)
        await self._events.put(
            GossipAttestationEvent(attestation=attestation, peer_id=peer_id, topic=topic)
        )
