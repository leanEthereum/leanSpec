"""Tests for the network event source."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lean_spec.forks.lstar.containers import SignedBlock
from lean_spec.forks.lstar.containers.attestation import SignedAttestation
from lean_spec.forks.lstar.containers.checkpoint import Checkpoint
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.snappy import compress
from lean_spec.subspecs.networking.client.event_source import (
    SUPPORTED_PROTOCOLS,
    GossipHandler,
    GossipMessageError,
    LiveNetworkEventSource,
    read_gossip_message,
)
from lean_spec.subspecs.networking.client.reqresp_client import ReqRespClient
from lean_spec.subspecs.networking.config import (
    GOSSIPSUB_DEFAULT_PROTOCOL_ID,
    GOSSIPSUB_PROTOCOL_ID_V12,
)
from lean_spec.subspecs.networking.gossipsub.topic import (
    ENCODING_POSTFIX,
    TOPIC_PREFIX,
    ForkMismatchError,
    GossipTopic,
    TopicKind,
)
from lean_spec.subspecs.networking.gossipsub.types import TopicId
from lean_spec.subspecs.networking.reqresp.handler import REQRESP_PROTOCOL_IDS
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.subspecs.networking.transport.quic.connection import (
    QuicConnection,
    QuicConnectionManager,
)
from lean_spec.subspecs.networking.varint import encode_varint
from lean_spec.types import Bytes32
from tests.lean_spec.helpers.builders import make_signed_attestation, make_signed_block

FORK_DIGEST = "0xaabbccdd"
WRONG_FORK_DIGEST = "0x11223344"


def _block_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"


def _attestation_topic(digest: str = FORK_DIGEST, subnet_id: int = 0) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/attestation_{subnet_id}/{ENCODING_POSTFIX}"


def _aggregation_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/aggregation/{ENCODING_POSTFIX}"


def _make_block() -> SignedBlock:
    return make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
    )


def _make_attestation() -> SignedAttestation:
    return make_signed_attestation(
        validator=ValidatorIndex(0),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
    )


def _build_gossip_wire(topic: str, ssz_data: bytes) -> bytes:
    """
    Build a complete gossip wire-format message.

    Produces the four-field frame that peers send over QUIC gossip streams:
    varint-encoded topic length, UTF-8 topic, varint-encoded data length,
    and Snappy-compressed SSZ payload.
    """
    topic_bytes = topic.encode("utf-8")
    compressed = compress(ssz_data)
    buf = bytearray()
    buf.extend(encode_varint(len(topic_bytes)))
    buf.extend(topic_bytes)
    buf.extend(encode_varint(len(compressed)))
    buf.extend(compressed)
    return bytes(buf)


class MockStream:
    """
    Simulates a QUIC stream that delivers data in configurable chunks.

    Each call to read returns the next chunk from the list.
    Returns empty bytes once all chunks are exhausted, signaling EOF.
    Used to test wire-format reassembly across arbitrary read boundaries.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)

    async def read(self) -> bytes:
        """Return next chunk or empty bytes when exhausted."""
        return next(self._chunks, b"")

    def write(self, data: bytes) -> None:
        """No-op write."""

    async def drain(self) -> None:
        """No-op drain."""

    async def close(self) -> None:
        """No-op close."""


class TestGossipHandlerForkMismatch:
    """
    Network name validation on incoming gossip messages.

    Every gossip topic embeds a network name identifying the consensus fork.
    Messages from peers on a different fork must be rejected immediately
    to avoid processing incompatible data.
    """

    def test_decode_message_raises_fork_mismatch(self) -> None:
        """Rejects messages whose topic carries a different network name."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        block = _make_block()
        compressed = compress(block.encode_bytes())

        with pytest.raises(ForkMismatchError, match=f"expected {FORK_DIGEST}"):
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)

    def test_get_topic_raises_fork_mismatch(self) -> None:
        """Rejects topic strings with mismatched network name."""
        handler = GossipHandler(network_name=FORK_DIGEST)

        with pytest.raises(ForkMismatchError, match=f"got {WRONG_FORK_DIGEST}"):
            handler.get_topic(_block_topic(WRONG_FORK_DIGEST))

    def test_fork_mismatch_error_attributes(self) -> None:
        """ForkMismatchError exposes expected and actual digests."""
        err = ForkMismatchError(expected=FORK_DIGEST, actual=WRONG_FORK_DIGEST)

        assert err.expected == FORK_DIGEST
        assert err.actual == WRONG_FORK_DIGEST

    def test_fork_mismatch_is_value_error(self) -> None:
        """ForkMismatchError inherits from ValueError."""
        assert issubclass(ForkMismatchError, ValueError)

    def test_decode_message_fork_mismatch_not_wrapped_as_gossip_error(self) -> None:
        """ForkMismatchError propagates directly, not wrapped in GossipMessageError."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        compressed = compress(b"\x00" * 32)

        with pytest.raises(ForkMismatchError):
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)

        # Verify it does NOT raise GossipMessageError
        try:
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)
        except ForkMismatchError:
            pass
        except GossipMessageError:
            pytest.fail("ForkMismatchError should not be wrapped in GossipMessageError")


class TestGossipHandlerAggregationTopic:
    """
    Aggregated attestation topic parsing and decoding.

    The aggregation topic carries attestations that have been aggregated
    by a committee member. The gossip handler must recognize this topic
    kind and decode its SSZ payload accordingly.
    """

    def test_get_topic_recognizes_aggregation(self) -> None:
        """Parses aggregation topic and returns AGGREGATED_ATTESTATION kind."""
        handler = GossipHandler(network_name=FORK_DIGEST)

        topic = handler.get_topic(_aggregation_topic())

        assert topic == GossipTopic(
            kind=TopicKind.AGGREGATED_ATTESTATION,
            network_name=FORK_DIGEST,
        )

    def test_decode_message_invalid_ssz_for_aggregation(self) -> None:
        """Raises GossipMessageError when SSZ bytes are invalid for aggregation."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        compressed = compress(b"\xff\xff\xff\xff")

        with pytest.raises(GossipMessageError, match="SSZ decode failed"):
            handler.decode_message(_aggregation_topic(), compressed)


class TestSupportedProtocols:
    """
    Verify the set of protocol IDs advertised during connection setup.

    An Ethereum consensus node must support gossipsub v1.1, gossipsub v1.2
    (for IDONTWANT bandwidth optimization), and all req/resp protocol IDs.
    The set must be immutable to prevent accidental mutation at runtime.
    """

    def test_contains_gossipsub_v11(self) -> None:
        """Includes gossipsub v1.1 as required by Ethereum consensus spec."""
        assert GOSSIPSUB_DEFAULT_PROTOCOL_ID in SUPPORTED_PROTOCOLS

    def test_contains_gossipsub_v12(self) -> None:
        """Includes gossipsub v1.2 for IDONTWANT bandwidth optimization."""
        assert GOSSIPSUB_PROTOCOL_ID_V12 in SUPPORTED_PROTOCOLS

    def test_contains_all_reqresp_protocols(self) -> None:
        """Includes all request/response protocol IDs."""
        assert REQRESP_PROTOCOL_IDS <= SUPPORTED_PROTOCOLS

    def test_is_frozenset(self) -> None:
        """Protocol set is immutable."""
        assert isinstance(SUPPORTED_PROTOCOLS, frozenset)

    def test_exact_composition(self) -> None:
        """Equals the union of gossipsub and reqresp protocol IDs."""
        expected = frozenset({GOSSIPSUB_DEFAULT_PROTOCOL_ID, GOSSIPSUB_PROTOCOL_ID_V12})
        expected |= REQRESP_PROTOCOL_IDS
        assert SUPPORTED_PROTOCOLS == expected


class TestReadGossipMessageChunked:
    """
    Gossip wire-format reassembly across arbitrary read boundaries.

    QUIC streams may deliver data in chunks of any size. The reader must
    correctly reassemble the four-field gossip frame regardless of where
    chunk boundaries fall: inside a varint, inside the topic string,
    between topic and data, or across three or more pieces.
    """

    async def test_message_split_at_varint_boundary(self) -> None:
        """Correctly reassembles when a read boundary falls inside a varint."""
        block = _make_block()
        wire = _build_gossip_wire(_block_topic(), block.encode_bytes())

        # Split so first chunk contains only 1 byte (partial varint for topic len)
        chunks = [wire[:1], wire[1:]]
        stream = MockStream(chunks)
        topic, compressed = await read_gossip_message(stream)

        assert topic == _block_topic()
        assert len(compressed) > 0

    async def test_message_split_inside_topic(self) -> None:
        """Correctly reassembles when a read boundary falls inside the topic string."""
        block = _make_block()
        wire = _build_gossip_wire(_block_topic(), block.encode_bytes())

        # Split inside the topic string (offset 5 is well within topic bytes)
        chunks = [wire[:5], wire[5:]]
        stream = MockStream(chunks)
        topic, compressed = await read_gossip_message(stream)

        assert topic == _block_topic()
        assert len(compressed) > 0

    async def test_message_split_between_topic_and_data(self) -> None:
        """Correctly reassembles when the split falls between topic and data sections."""
        block = _make_block()
        topic_str = _block_topic()
        wire = _build_gossip_wire(topic_str, block.encode_bytes())

        # Find the boundary: after topic_len varint + topic bytes
        topic_bytes = topic_str.encode("utf-8")
        varint_len = len(encode_varint(len(topic_bytes)))
        boundary = varint_len + len(topic_bytes)

        chunks = [wire[:boundary], wire[boundary:]]
        stream = MockStream(chunks)
        topic, compressed = await read_gossip_message(stream)

        assert topic == topic_str
        assert len(compressed) > 0

    async def test_three_chunk_delivery(self) -> None:
        """Handles message delivered in three arbitrary pieces."""
        att = _make_attestation()
        wire = _build_gossip_wire(_attestation_topic(), att.encode_bytes())

        third = len(wire) // 3
        chunks = [wire[:third], wire[third : 2 * third], wire[2 * third :]]
        stream = MockStream(chunks)
        topic, _ = await read_gossip_message(stream)

        assert topic == _attestation_topic()


def _make_mock_connection_manager() -> MagicMock:
    """Provide a mock QUIC connection manager with a stubbed identity key."""
    mgr = MagicMock(spec=QuicConnectionManager)
    mgr._identity_key = MagicMock()
    return mgr


def _make_mock_reqresp_client() -> MagicMock:
    """Provide a mock req/resp client with stubbed register/unregister hooks."""
    return MagicMock(spec=ReqRespClient)


def _make_event_source() -> LiveNetworkEventSource:
    """
    Build an event source wired to mock transport dependencies.

    Suitable for unit tests that exercise configuration, lifecycle, and
    event emission without real network connections.
    """
    return LiveNetworkEventSource(
        connection_manager=_make_mock_connection_manager(),
        reqresp_client=_make_mock_reqresp_client(),
    )


class TestLiveNetworkEventSourceSetStatus:
    """
    Chain status propagation to the event source and its req/resp handler.

    The sync service sets the local chain status (finalized checkpoint,
    head) so the event source can respond to incoming Status requests
    from peers during the handshake.
    """

    def test_set_status_stores_value(self) -> None:
        """Setting status makes it available for handshakes."""
        es = _make_event_source()
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
        )

        es.set_status(status)

        assert es._our_status == status

    def test_set_status_propagates_to_reqresp_handler(self) -> None:
        """Setting status also updates the inbound request handler."""
        es = _make_event_source()
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(10)),
        )

        es.set_status(status)

        assert es._reqresp_handler.our_status == status


class TestLiveNetworkEventSourceSetForkDigest:
    """
    Network name reconfiguration at runtime.

    When the chain crosses a fork boundary, the event source must update
    its network name and recreate the gossip handler so that subsequent
    topic validation uses the new digest.
    """

    def test_set_fork_digest_updates_field(self) -> None:
        """Updates the stored network name."""
        es = _make_event_source()

        es.set_network_name("0xdeadbeef")

        assert es._network_name == "0xdeadbeef"

    def test_set_fork_digest_recreates_gossip_handler(self) -> None:
        """Recreates the gossip handler with the new digest."""
        es = _make_event_source()

        es.set_network_name("0xdeadbeef")

        assert es._gossip_handler.network_name == "0xdeadbeef"

    def test_set_fork_digest_new_handler_validates_correctly(self) -> None:
        """The recreated handler rejects topics with the old digest."""
        es = _make_event_source()
        es.set_network_name("0xdeadbeef")

        # Old default digest should now be rejected
        with pytest.raises(ForkMismatchError, match="expected 0xdeadbeef"):
            es._gossip_handler.get_topic(_block_topic("0x00000000"))


class TestLiveNetworkEventSourceSetBlockLookup:
    """
    Block lookup callback registration.

    The req/resp handler needs a callback to retrieve blocks by root
    when peers send BeaconBlocksByRoot requests.
    """

    def test_set_block_lookup_propagates_to_handler(self) -> None:
        """Sets the block lookup callback on the reqresp handler."""
        es = _make_event_source()

        async def mock_lookup(root: Bytes32) -> SignedBlock | None:
            return None

        es.set_block_lookup(mock_lookup)

        assert es._reqresp_handler.block_lookup is mock_lookup


class TestLiveNetworkEventSourceSubscribeGossipTopic:
    """
    Gossip topic subscription delegation to the gossipsub behavior.

    Subscribing to a topic tells the gossipsub mesh layer to join
    that topic and begin accepting messages from mesh peers.
    """

    def test_subscribe_delegates_to_behavior(self) -> None:
        """Subscribes the topic in the gossipsub behavior."""
        es = _make_event_source()
        topic = GossipTopic.block(FORK_DIGEST).to_topic_id()

        es.subscribe_gossip_topic(topic)

        assert topic in es._gossipsub_behavior.mesh.subscriptions


class TestLiveNetworkEventSourceAsyncIteration:
    """
    Async iterator protocol conformance.

    The sync service consumes network events via `async for event in source`.
    The event source must implement the async iterator protocol correctly,
    including signaling exhaustion when stopped.
    """

    def test_aiter_returns_self(self) -> None:
        """Async iteration returns the event source itself."""
        es = _make_event_source()

        assert es.__aiter__() is es

    async def test_anext_raises_stop_when_not_running(self) -> None:
        """Raises StopAsyncIteration immediately when not running."""
        es = _make_event_source()

        with pytest.raises(StopAsyncIteration):
            await es.__anext__()


class TestLiveNetworkEventSourceDisconnect:
    """
    Peer disconnection cleanup.

    Disconnecting a peer must close its QUIC connection, unregister it
    from the req/resp client, and emit a disconnect event so the sync
    service can update its peer tracking state.
    """

    async def test_disconnect_known_peer_emits_event(self) -> None:
        """Disconnecting a tracked peer emits PeerDisconnectedEvent."""
        es = _make_event_source()
        peer_id = PeerId.from_base58("peerA")

        mock_conn = AsyncMock(spec=QuicConnection)
        es._connections[peer_id] = mock_conn

        await es.disconnect(peer_id)

        assert peer_id not in es._connections
        mock_conn.close.assert_awaited_once()

        from lean_spec.subspecs.networking.service.events import PeerDisconnectedEvent

        event = es._events.get_nowait()
        assert event == PeerDisconnectedEvent(peer_id=peer_id)

    async def test_disconnect_unknown_peer_is_noop(self) -> None:
        """Disconnecting an untracked peer does nothing."""
        es = _make_event_source()
        peer_id = PeerId.from_base58("peerB")

        await es.disconnect(peer_id)

        assert es._events.empty()

    async def test_disconnect_unregisters_reqresp(self) -> None:
        """Disconnecting also unregisters the peer from the reqresp client."""
        mock_client = _make_mock_reqresp_client()
        es = LiveNetworkEventSource(
            connection_manager=_make_mock_connection_manager(),
            reqresp_client=mock_client,
        )
        peer_id = PeerId.from_base58("peerC")
        es._connections[peer_id] = AsyncMock(spec=QuicConnection)

        await es.disconnect(peer_id)

        mock_client.unregister_connection.assert_called_once_with(peer_id)


class TestLiveNetworkEventSourceStop:
    """
    Graceful shutdown of the event source.

    Stopping must clear the running flag, cancel all background gossip
    tasks, and leave the task set empty so no work continues after shutdown.
    """

    async def test_stop_sets_running_false(self) -> None:
        """Stopping clears the running flag."""
        es = _make_event_source()
        es._running = True

        await es.stop()

        assert es._running is False

    async def test_stop_cancels_gossip_tasks(self) -> None:
        """Stopping cancels all tracked background tasks."""
        es = _make_event_source()
        es._running = True

        task = asyncio.create_task(asyncio.sleep(100))
        es._gossip_tasks.add(task)

        await es.stop()

        assert task.cancelled()

    async def test_stop_clears_task_set(self) -> None:
        """The gossip task set is empty after stopping."""
        es = _make_event_source()
        es._running = True

        task = asyncio.create_task(asyncio.sleep(100))
        es._gossip_tasks.add(task)

        await es.stop()

        assert len(es._gossip_tasks) == 0


class TestLiveNetworkEventSourcePublish:
    """
    Gossip message publishing through the event source.

    Publishing delegates to the gossipsub behavior layer. Errors during
    publish must be caught to prevent one failed send from disrupting
    the event loop.
    """

    async def test_publish_no_connections_is_noop(self) -> None:
        """Publishing with no connections returns without error."""
        es = _make_event_source()
        assert len(es._connections) == 0

        # Should not raise
        await es.publish(TopicId("/some/topic"), b"data")

    async def test_publish_delegates_to_behavior(self) -> None:
        """Publishing with active connections delegates to gossipsub behavior."""
        es = _make_event_source()
        peer_id = PeerId.from_base58("peerD")
        es._connections[peer_id] = MagicMock(spec=QuicConnection)

        with patch.object(
            es._gossipsub_behavior, "publish", new_callable=AsyncMock
        ) as mock_publish:
            await es.publish(TopicId("/test/topic"), b"payload")

            mock_publish.assert_awaited_once_with(TopicId("/test/topic"), b"payload")

    async def test_publish_exception_is_caught(self) -> None:
        """Exceptions during publish are caught, not propagated."""
        es = _make_event_source()
        peer_id = PeerId.from_base58("peerE")
        es._connections[peer_id] = MagicMock(spec=QuicConnection)

        with patch.object(
            es._gossipsub_behavior,
            "publish",
            new_callable=AsyncMock,
            side_effect=RuntimeError("network error"),
        ):
            # Should not raise
            await es.publish(TopicId("/test/topic"), b"payload")


class TestLiveNetworkEventSourceInit:
    """
    Default state after event source construction.

    A freshly created event source must start in a safe default state:
    zero network name, no connections, no chain status, stopped, and
    an empty event queue.
    """

    def test_default_fork_digest(self) -> None:
        """Initializes with zero network name."""
        es = _make_event_source()
        assert es._network_name == "0x00000000"

    def test_gossip_handler_matches_fork_digest(self) -> None:
        """Post-init creates gossip handler with the configured network name."""
        es = _make_event_source()
        assert es._gossip_handler.network_name == "0x00000000"

    def test_not_running_initially(self) -> None:
        """Event source starts in stopped state."""
        es = _make_event_source()
        assert es._running is False

    def test_no_connections_initially(self) -> None:
        """No peer connections on construction."""
        es = _make_event_source()
        assert es._connections == {}

    def test_no_status_initially(self) -> None:
        """No chain status configured on construction."""
        es = _make_event_source()
        assert es._our_status is None

    def test_event_queue_empty_initially(self) -> None:
        """Event queue is empty on construction."""
        es = _make_event_source()
        assert es._events.empty()


class TestGossipHandlerDecodeRoundtrip:
    """
    SSZ encode-compress-decode roundtrip fidelity.

    Gossip messages are SSZ-encoded, Snappy-compressed, and sent over
    the wire. Decoding must recover the original SSZ bytes exactly,
    ensuring no data loss through the compression layer.
    """

    def test_block_roundtrip_preserves_ssz(self) -> None:
        """Block SSZ bytes are identical after decode."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        block = _make_block()
        original_bytes = block.encode_bytes()

        result = handler.decode_message(
            _block_topic(),
            compress(original_bytes),
        )

        assert isinstance(result, SignedBlock)
        assert result.encode_bytes() == original_bytes

    def test_attestation_roundtrip_preserves_ssz(self) -> None:
        """Attestation SSZ bytes are identical after decode."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        att = _make_attestation()
        original_bytes = att.encode_bytes()

        result = handler.decode_message(
            _attestation_topic(),
            compress(original_bytes),
        )

        assert isinstance(result, SignedAttestation)
        assert result.encode_bytes() == original_bytes
