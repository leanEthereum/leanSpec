"""
Network event source bridging transport to sync service.

This module implements NetworkEventSource, producing events from real
network connections. It bridges the gap between the low-level transport
layer (QUIC ConnectionManager) and the high-level sync service.


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


GOSSIP MESSAGE FLOW
-------------------
When a peer publishes a block or attestation, it arrives as follows:

1. Peer opens a QUIC stream with protocol ID "/meshsub/1.1.0".
2. Peer sends: [topic_length][topic][data_length][compressed_data].
3. We parse the topic to determine message type (block vs attestation).
4. We decompress the raw Snappy payload.
5. We decode the SSZ bytes into a typed object.
6. We emit a GossipBlockEvent or GossipAttestationEvent.


GOSSIP MESSAGE FORMAT
---------------------
Incoming gossip messages arrive on QUIC streams with the gossipsub protocol ID.
The message format is:

+------------------+---------------------------------------------+
| Field            | Description                                 |
+==================+=============================================+
| topic_length     | Varint: byte length of the topic string     |
+------------------+---------------------------------------------+
| topic            | UTF-8 string identifying message type       |
+------------------+---------------------------------------------+
| data_length      | Varint: byte length of compressed data      |
+------------------+---------------------------------------------+
| data             | Snappy-framed SSZ-encoded message           |
+------------------+---------------------------------------------+

Varints use LEB128 encoding (1-10 bytes depending on value).
Most lengths fit in 1-2 bytes since messages are typically under 16KB.


MESSAGE DEDUPLICATION
---------------------
Gossipsub uses message IDs to prevent duplicate delivery. The Ethereum
consensus spec defines message ID as:

    message_id = SHA256(MESSAGE_DOMAIN + topic_length + topic + data)[:20]

MESSAGE_DOMAIN is 0x00 for invalid Snappy, 0x01 for valid Snappy. This
domain separation ensures a message cannot be "replayed" by flipping
between compressed and raw forms.


WHY SSZ AND SNAPPY?
-------------------
SSZ (Simple Serialize) is Ethereum's canonical serialization format:

- Deterministic: Same object always produces same bytes.
- Merkleizable: Supports efficient proofs of inclusion.
- Fixed overhead: Known sizes enable buffer pre-allocation.

Snappy compression reduces bandwidth by 50-70% for typical blocks.
The framing format adds CRC32C checksums for corruption detection.


GOSSIPSUB v1.1 REQUIREMENTS
---------------------------
The Ethereum consensus spec requires gossipsub v1.1 (protocol "/meshsub/1.1.0").
Key v1.1 features used:

- Peer scoring: Misbehaving peers get lower scores.
- Extended validators: Message validation before forwarding.
- Flood publishing: High-priority messages bypass mesh constraints.


References:
    - Ethereum P2P spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md
    - Gossipsub v1.1: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md
    - SSZ spec: https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md
    - Snappy format: https://github.com/google/snappy/blob/main/format_description.txt
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from lean_spec.snappy import SnappyDecompressionError, frame_decompress
from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.containers.attestation import SignedAttestation
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
from lean_spec.subspecs.networking.gossipsub.topic import (
    ForkMismatchError,
    GossipTopic,
    TopicKind,
)
from lean_spec.subspecs.networking.reqresp.handler import (
    REQRESP_PROTOCOL_IDS,
    BlockLookup,
    DefaultRequestHandler,
    ReqRespServer,
)
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
from lean_spec.subspecs.networking.transport.connection import ConnectionManager, Stream
from lean_spec.subspecs.networking.transport.multistream import (
    NegotiationError,
    negotiate_server,
)
from lean_spec.subspecs.networking.transport.quic.connection import (
    QuicConnection,
    QuicConnectionManager,
    QuicStream,
    is_quic_multiaddr,
)
from lean_spec.subspecs.networking.varint import (
    VarintError,
    decode_varint,
    encode_varint,
)
from lean_spec.types.exceptions import SSZSerializationError

from .reqresp_client import ReqRespClient

logger = logging.getLogger(__name__)


class GossipMessageError(Exception):
    """Raised when a gossip message cannot be processed."""


SUPPORTED_PROTOCOLS: frozenset[str] = (
    frozenset({GOSSIPSUB_DEFAULT_PROTOCOL_ID, GOSSIPSUB_PROTOCOL_ID_V12}) | REQRESP_PROTOCOL_IDS
)
"""Protocols supported for incoming stream negotiation.

Includes:

- GossipSub v1.1 and v1.2
- Request/response protocols (Status, BlocksByRoot)
"""


class _QuicStreamReaderWriter:
    """Adapts QuicStream for multistream-select negotiation.

    Provides buffered read/write interface matching asyncio StreamReader/Writer.
    Used during protocol negotiation on QUIC streams.
    """

    def __init__(self, stream: QuicStream | Stream) -> None:
        self._stream = stream
        self._buffer = b""
        self._write_buffer = b""

    async def read(self, n: int | None = None) -> bytes:
        """Read bytes from the stream.

        - If n is provided, returns at most n bytes.
        - If n is None, returns all available data (no limit).

        If buffer has data, returns from buffer.
        Otherwise reads from stream and buffers excess.
        """
        # If no limit, return all buffered data plus new read
        if n is None:
            if self._buffer:
                result = self._buffer
                self._buffer = b""
                return result
            return await self._stream.read()

        # If we have buffered data, return from that first (up to n bytes)
        if self._buffer:
            result = self._buffer[:n]
            self._buffer = self._buffer[n:]
            return result

        # Read from stream
        data = await self._stream.read()
        if not data:
            return b""

        # Return up to n bytes, buffer the rest
        if len(data) > n:
            self._buffer = data[n:]
            return data[:n]
        return data

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes from the stream."""
        while len(self._buffer) < n:
            chunk = await self._stream.read()
            if not chunk:
                raise EOFError("Stream closed before enough data received")
            self._buffer += chunk

        result = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return result

    def write(self, data: bytes) -> None:
        """Buffer data for writing (synchronous for StreamWriter compatibility)."""
        self._write_buffer += data

    async def drain(self) -> None:
        """Flush buffered data to the stream."""
        if self._write_buffer:
            await self._stream.write(self._write_buffer)
            self._write_buffer = b""

    async def close(self) -> None:
        """Close the underlying stream."""
        await self._stream.close()

    async def finish_write(self) -> None:
        """Half-close the stream (signal end of writing)."""
        # Flush any buffered data first
        if self._write_buffer:
            await self._stream.write(self._write_buffer)
            self._write_buffer = b""
        # Call finish_write if available (QUIC streams have this)
        finish_write = getattr(self._stream, "finish_write", None)
        if finish_write is not None:
            await finish_write()

    async def wait_closed(self) -> None:
        """Wait for the stream to close."""
        # No-op for QUIC streams
        pass


@dataclass(slots=True)
class GossipHandler:
    """
    Handles incoming gossip messages from peers.

    Parses gossip message format, decompresses Snappy, decodes SSZ, and
    returns the appropriate decoded object.

    Supported topic kinds:

    - Block: Decodes to SignedBlockWithAttestation
    - Attestation: Decodes to SignedAttestation


    WHY TOPIC VALIDATION?
    ---------------------
    Topics contain:

    - Fork digest: 4-byte identifier derived from genesis + fork version.
    - Message type: "block" or "attestation".
    - Encoding: Always "ssz_snappy" for Ethereum.

    Validating the topic prevents:

    - Routing attacks: Reject messages for different forks.
    - Type confusion: Ensure we decode with the correct schema.
    - Protocol violations: Reject malformed topic strings.


    WHY SNAPPY?
    -----------
    Snappy reduces bandwidth by 50-70% for typical consensus messages.
    Beacon blocks contain many signatures and hashes which compress well.
    The framing format adds CRC32C checksums for corruption detection.


    WHY SSZ?
    --------
    SSZ (Simple Serialize) is Ethereum's canonical format because:

    - Deterministic: Same object always produces same bytes.
    - Merkleizable: Efficient proofs of inclusion.
    - Schema-driven: Type information comes from context, not wire format.

    The topic tells us the schema. The SSZ bytes are just raw data.
    """

    fork_digest: str
    """Expected fork digest for topic validation.

    Messages with mismatched fork digests are rejected. This prevents
    cross-fork message injection attacks.
    """

    def decode_message(
        self,
        topic_str: str,
        compressed_data: bytes,
    ) -> SignedBlockWithAttestation | SignedAttestation | None:
        """
        Decode a gossip message from topic and compressed data.

        Processing proceeds in order:

        1. Parse topic to determine message type.
        2. Validate fork digest.
        3. Decompress Snappy-framed data.
        4. Decode SSZ bytes using the appropriate schema.

        Each step can fail independently. Failures are wrapped in
        GossipMessageError for uniform handling. Fork mismatches raise
        ForkMismatchError.

        Args:
            topic_str: Full topic string (e.g., "/leanconsensus/0x.../block/ssz_snappy").
            compressed_data: Snappy-compressed SSZ data.

        Returns:
            Decoded block or attestation.

        Raises:
            ForkMismatchError: If fork_digest does not match.
            GossipMessageError: If the message cannot be decoded.
        """
        # Step 1: Parse topic to determine message type and validate fork.
        #
        # The topic string contains the fork digest and message kind.
        # Invalid topics are rejected before any decompression work.
        # Fork mismatch is checked early to prevent cross-fork attacks.
        # This prevents wasting CPU on malformed or cross-fork messages.
        try:
            topic = GossipTopic.from_string_validated(topic_str, self.fork_digest)
        except (ValueError, ForkMismatchError) as e:
            if isinstance(e, ForkMismatchError):
                raise
            raise GossipMessageError(f"Invalid topic: {e}") from e

        # Step 2: Decompress Snappy-framed data.
        #
        # Ethereum uses Snappy framing format for gossip (same as req/resp).
        # Framed Snappy includes stream identifier and CRC32C checksums.
        #
        # Decompression fails if:
        #   - Stream identifier is missing or invalid.
        #   - CRC checksum mismatch (data corruption).
        #   - Compressed data is truncated.
        #
        # Failed decompression indicates network corruption or a malicious peer.
        try:
            ssz_bytes = frame_decompress(compressed_data)
        except SnappyDecompressionError as e:
            raise GossipMessageError(f"Snappy decompression failed: {e}") from e

        # Step 3: Decode SSZ based on topic kind.
        #
        # SSZ decoding fails if the bytes don't match the expected schema.
        # For example: wrong length, invalid field values, or truncation.
        #
        # The topic determines which schema to use. This is why topic
        # validation must happen first.
        try:
            match topic.kind:
                case TopicKind.BLOCK:
                    return SignedBlockWithAttestation.decode_bytes(ssz_bytes)
                case TopicKind.ATTESTATION_SUBNET:
                    return SignedAttestation.decode_bytes(ssz_bytes)
        except SSZSerializationError as e:
            raise GossipMessageError(f"SSZ decode failed: {e}") from e

    def get_topic(self, topic_str: str) -> GossipTopic:
        """
        Parse and validate a topic string.

        Args:
            topic_str: Full topic string.

        Returns:
            Parsed GossipTopic.

        Raises:
            ForkMismatchError: If fork_digest does not match.
            GossipMessageError: If the topic is invalid.
        """
        try:
            return GossipTopic.from_string_validated(topic_str, self.fork_digest)
        except (ValueError, ForkMismatchError) as e:
            if isinstance(e, ForkMismatchError):
                raise
            raise GossipMessageError(f"Invalid topic: {e}") from e


async def read_gossip_message(stream: Stream) -> tuple[str, bytes]:
    """
    Read a gossip message from a QUIC stream.

    Gossip message wire format::

        [topic_len: varint][topic: UTF-8][data_len: varint][data: bytes]

    Args:
        stream: QUIC stream to read from.

    Returns:
        Tuple of (topic_string, compressed_data).

    Raises:
        GossipMessageError: If the message format is invalid.


    WHY VARINTS?
    ------------
    Varints (LEB128 encoding) use 1 byte for values 0-127, 2 bytes for
    128-16383, etc. Since topic lengths are typically ~50 bytes and data
    lengths under 1MB, varints save bandwidth compared to fixed-width integers.

    The libp2p gossipsub wire format uses varints throughout.


    WHY INCREMENTAL PARSING?
    ------------------------
    Varints have variable length. We cannot know how many bytes to read
    for the topic length until we try to decode it. The incremental
    approach:

    1. Read available data into buffer.
    2. Try to parse varint. If not enough bytes, read more.
    3. Once varint is complete, read the indicated payload.
    4. Repeat for data length and data payload.

    This handles network fragmentation gracefully. Data may arrive in
    arbitrary chunks due to QUIC framing.


    EDGE CASES HANDLED
    ------------------
    - Truncated varint: VarintError raised, we keep reading.
    - Truncated topic/data: Loop continues until complete.
    - Empty message: Caught before any parsing.
    - Invalid UTF-8 topic: GossipMessageError raised.
    - Stream closes early: GossipMessageError with "Truncated" message.
    """
    # Accumulate data in a buffer.
    #
    # Network data arrives in arbitrary chunks. We need to buffer until
    # we have complete fields. A bytearray is efficient for appending.
    buffer = bytearray()

    # Read and parse incrementally.
    #
    # The outer loop reads chunks from the network.
    # The inner parsing attempts to extract fields from the buffer.
    # We only return once we have a complete message.
    while True:
        chunk = await stream.read()
        if not chunk:
            # Stream closed. If buffer is empty, peer sent nothing.
            # If buffer has data, the message is incomplete.
            if not buffer:
                raise GossipMessageError("Empty gossip message")
            break
        buffer.extend(chunk)

        # Attempt to parse the accumulated data.
        #
        # Parsing can fail partway through if we don't have enough bytes.
        # In that case, we continue the outer loop to read more data.
        try:
            # Parse topic length varint.
            #
            # The varint tells us how many bytes the topic string occupies.
            # Most topics are ~50 bytes, so this is typically a 1-byte varint.
            topic_len, topic_len_bytes = decode_varint(bytes(buffer), 0)
            topic_end = topic_len_bytes + topic_len

            if len(buffer) >= topic_end:
                # We have the complete topic string.
                #
                # Topics are UTF-8 encoded. Invalid encoding indicates
                # a protocol violation or corrupted data.
                topic_str = buffer[topic_len_bytes:topic_end].decode("utf-8")

                if len(buffer) > topic_end:
                    # Parse data length varint.
                    #
                    # This tells us how many bytes of compressed data follow.
                    # Block messages can be several hundred KB compressed.
                    data_len, data_len_bytes = decode_varint(bytes(buffer), topic_end)
                    data_start = topic_end + data_len_bytes
                    data_end = data_start + data_len

                    if len(buffer) >= data_end:
                        # We have the complete message.
                        #
                        # Extract the compressed data and return.
                        # The caller will decompress and decode.
                        compressed_data = bytes(buffer[data_start:data_end])
                        return topic_str, compressed_data

        except VarintError:
            # Varint is incomplete (truncated in the middle).
            #
            # This is normal - we may have read only part of a varint.
            # Continue reading more data from the stream.
            continue

        except UnicodeDecodeError as e:
            # Topic bytes are not valid UTF-8.
            #
            # This indicates a protocol violation or corruption.
            # Fail immediately rather than trying to recover.
            raise GossipMessageError(f"Invalid topic encoding: {e}") from e

    # Loop exited without returning a complete message.
    #
    # The stream closed before we received all expected data.
    # This could be a network failure or peer misbehavior.
    raise GossipMessageError("Truncated gossip message")


@dataclass(slots=True)
class LiveNetworkEventSource:
    """
    Produces NetworkEvent objects from real network connections.

    Implements the NetworkEventSource protocol for use with NetworkService.
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

    connection_manager: ConnectionManager
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

    _fork_digest: str = "0x00000000"
    """Fork digest for gossip topics.

    4-byte identifier derived from genesis validators root and fork version.
    Used to validate incoming messages belong to the same fork.
    """

    _running: bool = False
    """Whether the event source is running.

    Controls the main loop and background tasks.
    """

    _gossip_handler: GossipHandler = field(init=False)
    """Handler for decoding incoming gossip messages.

    Initialized with the current fork digest.
    """

    _gossip_tasks: set[asyncio.Task[None]] = field(default_factory=set)
    """Background tasks processing incoming gossip streams.

    Tracked for cleanup on shutdown. Tasks remove themselves on completion.
    """

    _reqresp_handler: DefaultRequestHandler = field(init=False)
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
        """Initialize handlers with current configuration."""
        object.__setattr__(self, "_gossip_handler", GossipHandler(fork_digest=self._fork_digest))
        object.__setattr__(self, "_reqresp_handler", DefaultRequestHandler())
        object.__setattr__(self, "_reqresp_server", ReqRespServer(handler=self._reqresp_handler))
        object.__setattr__(
            self, "_gossipsub_behavior", GossipsubBehavior(params=GossipsubParameters())
        )

    @classmethod
    async def create(
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
            from lean_spec.subspecs.networking.transport.identity import IdentityKeypair

            identity_key = IdentityKeypair.generate()
            connection_manager = await ConnectionManager.create(identity_key)

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

    def set_fork_digest(self, fork_digest: str) -> None:
        """
        Set fork digest for gossip topics.

        Args:
            fork_digest: 4-byte fork identifier as hex string.
        """
        self._fork_digest = fork_digest
        object.__setattr__(self, "_gossip_handler", GossipHandler(fork_digest=fork_digest))

    def set_block_lookup(self, lookup: BlockLookup) -> None:
        """
        Set the callback for looking up blocks by root.

        Used by the inbound ReqResp handler to serve BlocksByRoot requests.

        Args:
            lookup: Async function that takes a Bytes32 root and returns
                the SignedBlockWithAttestation if available, None otherwise.
        """
        self._reqresp_handler.block_lookup = lookup

    def subscribe_gossip_topic(self, topic: str) -> None:
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
                    await self._handle_gossipsub_message(event)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("Error forwarding gossipsub events: %s", e)

    async def _handle_gossipsub_message(self, event: GossipsubMessageEvent) -> None:
        """
        Handle a message received via GossipSub.

        Decodes the message and emits the appropriate event type.

        Args:
            event: GossipSub message event from the behavior.
        """
        try:
            # Parse the topic to determine message type.
            topic = self._gossip_handler.get_topic(event.topic)

            # Decompress and decode the message.
            message = self._gossip_handler.decode_message(event.topic, event.data)

            # Emit the appropriate event.
            match topic.kind:
                case TopicKind.BLOCK:
                    if isinstance(message, SignedBlockWithAttestation):
                        await self._emit_gossip_block(message, event.peer_id)
                case TopicKind.ATTESTATION_SUBNET:
                    if isinstance(message, SignedAttestation):
                        await self._emit_gossip_attestation(message, event.peer_id)

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

        Establishes connection, exchanges Status, and emits events.
        Automatically detects transport type (TCP or QUIC) from multiaddr.

        Args:
            multiaddr: Address like "/ip4/127.0.0.1/tcp/9000" or
                      "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/16Uiu2HAm..."

        Returns:
            Peer ID on success, None on failure.
        """
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
            # Reuse the same identity key from the connection manager.
            # This ensures our peer ID is consistent across all connections.
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
        return await self.quic_manager.connect(multiaddr)  # type: ignore[union-attr]

    async def listen(self, multiaddr: str) -> None:
        """Start listening for incoming connections.

        Automatically detects transport type from multiaddr:

        - QUIC: Routes to QUIC listener
        - TCP: Routes to TCP listener

        Args:
            multiaddr: TCP or QUIC address to listen on.
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
        await self.quic_manager.listen(  # type: ignore[union-attr]
            multiaddr,
            on_connection=self._handle_inbound_quic_connection,
        )

    async def _handle_inbound_quic_connection(self, conn: QuicConnection) -> None:
        """Handle a new inbound QUIC connection.

        Performs the following steps:

        1. Register the connection for ReqResp operations
        2. Emit PeerConnectedEvent
        3. Start background stream acceptor

        The outbound gossipsub stream is set up LATER, after we receive the
        peer's inbound gossipsub stream. This avoids interfering with the
        dialer's status exchange.

        Args:
            conn: Established QUIC connection.
        """
        peer_id = conn.peer_id

        self._connections[peer_id] = conn
        self.reqresp_client.register_connection(peer_id, conn)

        await self._events.put(PeerConnectedEvent(peer_id=peer_id))

        # Start accepting streams to handle peer's requests.
        task = asyncio.create_task(self._accept_streams(peer_id, conn))
        self._gossip_tasks.add(task)
        task.add_done_callback(self._gossip_tasks.discard)

        # NOTE: Do NOT initiate status exchange on inbound connections.
        #
        # Only the dialer (outbound connection) sends a status request.
        # The listener (inbound connection) only responds to status requests.
        # This matches ream's behavior and avoids race conditions where both
        # sides try to open status streams simultaneously.

        # NOTE: Do NOT set up outbound gossipsub stream immediately.
        #
        # Opening a stream to the dialer while they're doing status exchange
        # causes aioquic to enter a bad state ("cannot call write() after FIN").
        # Instead, we set up our outbound stream AFTER receiving their inbound
        # gossipsub stream - see _accept_streams where this is triggered.

        gs_id = self._gossipsub_behavior._instance_id % 0xFFFF
        logger.info("[GS %x] Accepted QUIC connection from peer %s", gs_id, peer_id)

    async def _handle_inbound_connection(self, conn: QuicConnection) -> None:
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

        # Start accepting streams to handle peer's requests.
        task = asyncio.create_task(self._accept_streams(peer_id, conn))
        self._gossip_tasks.add(task)
        task.add_done_callback(self._gossip_tasks.discard)

        # NOTE: Do NOT initiate status exchange on inbound connections.
        # See _handle_inbound_quic_connection for explanation.

        # NOTE: Do NOT set up outbound gossipsub stream immediately.
        # See _handle_inbound_quic_connection for explanation.
        # The outbound stream is set up when we receive the peer's inbound stream.

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

            # Wrap in reader/writer for buffered I/O.
            wrapped_stream = _QuicStreamReaderWriter(stream)

            # Add peer to the gossipsub behavior (outbound stream).
            await self._gossipsub_behavior.add_peer(peer_id, wrapped_stream, inbound=False)

            logger.info("GossipSub stream established with %s", peer_id)

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
        topic = GossipTopic(kind=TopicKind.ATTESTATION_SUBNET, fork_digest=self._fork_digest)
        await self._events.put(
            GossipAttestationEvent(attestation=attestation, peer_id=peer_id, topic=topic)
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

                # QUIC streams need protocol negotiation.
                #
                # Multistream-select runs on top to agree on what protocol to use.
                # We create a wrapper for buffered I/O during negotiation, and
                # preserve it for later use (to avoid losing buffered data).
                wrapper: _QuicStreamReaderWriter | None = None

                try:
                    wrapper = _QuicStreamReaderWriter(stream)
                    gs_id = self._gossipsub_behavior._instance_id % 0xFFFF
                    logger.debug(
                        "[GS %x] Accepting stream %d from %s, attempting protocol negotiation",
                        gs_id,
                        stream.stream_id,
                        peer_id,
                    )
                    protocol_id = await asyncio.wait_for(
                        negotiate_server(
                            wrapper,
                            wrapper,  # type: ignore[arg-type]
                            set(SUPPORTED_PROTOCOLS),
                        ),
                        timeout=RESP_TIMEOUT,
                    )
                    stream._protocol_id = protocol_id
                    logger.debug("Negotiated protocol %s with %s", protocol_id, peer_id)
                except asyncio.TimeoutError:
                    logger.debug(
                        "Protocol negotiation timeout for %s stream %d",
                        peer_id,
                        stream.stream_id,
                    )
                    await stream.close()
                    continue
                except NegotiationError as e:
                    logger.debug(
                        "Protocol negotiation failed for %s stream %d: %s",
                        peer_id,
                        stream.stream_id,
                        e,
                    )
                    await stream.close()
                    continue
                except EOFError:
                    logger.debug(
                        "Stream %d closed by peer %s during negotiation",
                        stream.stream_id,
                        peer_id,
                    )
                    await stream.close()
                    continue
                except Exception as e:
                    logger.warning(
                        "Unexpected negotiation error for %s stream %d: %s",
                        peer_id,
                        stream.stream_id,
                        e,
                    )
                    await stream.close()
                    continue

                if protocol_id in (GOSSIPSUB_DEFAULT_PROTOCOL_ID, GOSSIPSUB_PROTOCOL_ID_V12):
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
                    #
                    # Wrapper is always set after negotiation (see above branches).
                    assert wrapper is not None
                    # Await directly to ensure peer is registered before setting up outbound.
                    await self._gossipsub_behavior.add_peer(peer_id, wrapper, inbound=True)

                    # Now that we've received the peer's inbound stream, set up our
                    # outbound stream if we don't have one yet.
                    #
                    # For dialers: They already set up their outbound stream in dial(),
                    # so this check prevents opening a duplicate stream.
                    #
                    # For listeners: They don't set up an outbound stream immediately
                    # (to avoid interfering with the dialer's status exchange), so this
                    # is where their outbound stream gets set up.
                    #
                    # IMPORTANT: We add a small delay before setting up the outbound
                    # stream to allow the dialer to complete their operations first.
                    # This prevents deadlock while still ensuring the outbound stream
                    # is set up quickly enough for mesh formation.
                    if not self._gossipsub_behavior.has_outbound_stream(peer_id):

                        async def setup_outbound_with_delay() -> None:
                            await asyncio.sleep(0.1)  # Small delay to avoid contention
                            await self._setup_gossipsub_stream(peer_id, conn)

                        gossip_task = asyncio.create_task(setup_outbound_with_delay())
                        self._gossip_tasks.add(gossip_task)
                        gossip_task.add_done_callback(self._gossip_tasks.discard)

                elif protocol_id in REQRESP_PROTOCOL_IDS:
                    # ReqResp stream: Status or BlocksByRoot request.
                    #
                    # Handle in a separate task to allow concurrent request processing.
                    # The ReqRespServer handles decoding, dispatching, and responding.
                    #
                    # IMPORTANT: Use the wrapper from negotiation (not raw stream).
                    # The wrapper may have buffered data read during protocol negotiation.
                    # Passing the raw stream would lose that buffered data.
                    #
                    # Wrapper is always set after negotiation (see above branches).
                    assert wrapper is not None
                    task = asyncio.create_task(
                        self._reqresp_server.handle_stream(
                            wrapper,  # type: ignore[arg-type]
                            protocol_id,
                        )
                    )
                    self._gossip_tasks.add(task)
                    task.add_done_callback(self._gossip_tasks.discard)
                    logger.debug("Handling ReqResp %s from %s", protocol_id, peer_id)

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

    async def _handle_gossip_stream(self, peer_id: PeerId, stream: Stream) -> None:
        """
        Handle an incoming gossip stream.

        Reads the gossip message, decodes it, and emits the appropriate event.

        Args:
            peer_id: Peer that sent the message.
            stream: QUIC stream containing the gossip message.


        COMPLETE FLOW
        -------------
        A gossip message goes through these stages:

        1. Read raw bytes from QUIC stream.
        2. Parse topic string and data length (varints).
        3. Decompress Snappy-framed data.
        4. Decode SSZ bytes into typed object.
        5. Emit event to the sync layer.

        Any stage can fail. Failures are logged but don't crash the handler.


        ERROR HANDLING STRATEGY
        -----------------------
        Gossip is best-effort. A single bad message should not:

        - Crash the node.
        - Disconnect the peer.
        - Block other messages.

        We log errors and continue. Peer scoring (not implemented here)
        would track repeated failures for reputation management.


        RESOURCE CLEANUP
        ----------------
        The stream MUST be closed in finally, even if errors occur.
        Unclosed streams leak QUIC resources and can cause deadlocks.
        """
        try:
            # Step 1: Read the gossip message from the stream.
            #
            # This parses the varint-prefixed topic and data fields.
            # May fail if the message is truncated or malformed.
            topic_str, compressed_data = await read_gossip_message(stream)

            # Step 2: Decode the message.
            #
            # This performs:
            #   - Topic validation (correct prefix, encoding, fork).
            #   - Snappy decompression with CRC verification.
            #   - SSZ decoding into the appropriate type.
            message = self._gossip_handler.decode_message(topic_str, compressed_data)
            topic = self._gossip_handler.get_topic(topic_str)

            # Step 3: Emit the appropriate event based on message type.
            #
            # The topic determines the expected message type.
            # We verify the decoded type matches to catch bugs.
            match topic.kind:
                case TopicKind.BLOCK:
                    if isinstance(message, SignedBlockWithAttestation):
                        await self._emit_gossip_block(message, peer_id)
                    else:
                        # Type mismatch indicates a bug in decode_message.
                        logger.warning("Block topic but got %s", type(message).__name__)

                case TopicKind.ATTESTATION_SUBNET:
                    if isinstance(message, SignedAttestation):
                        await self._emit_gossip_attestation(message, peer_id)
                    else:
                        # Type mismatch indicates a bug in decode_message.
                        logger.warning("Attestation topic but got %s", type(message).__name__)

            logger.debug("Received gossip %s from %s", topic.kind.value, peer_id)

        except GossipMessageError as e:
            # Expected error: malformed message, decompression failure, etc.
            #
            # This is not necessarily a bug. The peer may be misbehaving
            # or there may be network corruption. Log and continue.
            logger.warning("Gossip message error from %s: %s", peer_id, e)

        except Exception as e:
            # Unexpected error: likely a bug in our code.
            #
            # Log as warning to aid debugging. Don't crash.
            logger.warning("Unexpected error handling gossip from %s: %s", peer_id, e)

        finally:
            # Always close the stream to release QUIC resources.
            #
            # Unclosed streams cause resource leaks and can deadlock
            # the connection if too many accumulate.
            #
            # The try/except suppresses close errors. The stream may
            # already be closed if the connection dropped.
            try:
                await stream.close()
            except Exception:
                pass

    async def publish(self, topic: str, data: bytes) -> None:
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

    async def _send_gossip_message(
        self,
        conn: QuicConnection,
        topic: str,
        data: bytes,
    ) -> None:
        """
        Send a gossip message to a peer.

        Opens a new stream for the gossip message and sends the data.

        Args:
            conn: QuicConnection to the peer.
            topic: Topic string for the message.
            data: Message bytes to send.
        """
        # Open a new outbound stream for gossip protocol.
        stream = await conn.open_stream(GOSSIPSUB_DEFAULT_PROTOCOL_ID)

        try:
            # Format: topic length (varint) + topic + data length (varint) + data
            topic_bytes = topic.encode("utf-8")

            # Write topic length and topic.
            await stream.write(encode_varint(len(topic_bytes)))
            await stream.write(topic_bytes)

            # Write data length and data.
            await stream.write(encode_varint(len(data)))
            await stream.write(data)

        finally:
            await stream.close()
