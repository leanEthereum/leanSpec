"""Tests for the live network event source."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lean_spec.node.networking.client.event_source import LiveNetworkEventSource
from lean_spec.node.networking.client.reqresp_client import ReqRespClient
from lean_spec.node.networking.gossipsub.topic import (
    ENCODING_POSTFIX,
    TOPIC_PREFIX,
    ForkMismatchError,
    GossipTopic,
)
from lean_spec.node.networking.gossipsub.types import TopicId
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.node.networking.transport import PeerId
from lean_spec.node.networking.transport.quic.connection import (
    QuicConnection,
    QuicConnectionManager,
)
from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.forks.lstar.containers import SignedBlock
from lean_spec.spec.ssz import Bytes32

FORK_DIGEST = "0xaabbccdd"


def _block_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"


def _make_mock_connection_manager() -> MagicMock:
    """Provide a mock QUIC connection manager."""
    return MagicMock(spec=QuicConnectionManager)


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
        with pytest.raises(ForkMismatchError) as exception_info:
            es._gossip_handler.get_topic(_block_topic("0x00000000"))
        assert str(exception_info.value) == "Fork mismatch: expected 0xdeadbeef, got 0x00000000"


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

        mock_connection = AsyncMock(spec=QuicConnection)
        es._connections[peer_id] = mock_connection

        await es.disconnect(peer_id)

        assert peer_id not in es._connections
        mock_connection.close.assert_awaited_once()

        from lean_spec.node.networking.service.events import PeerDisconnectedEvent

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
        """Stopping flips the stop event back to set."""
        es = _make_event_source()
        es._stop_event.clear()

        await es.stop()

        assert es._stop_event.is_set()

    async def test_stop_cancels_gossip_tasks(self) -> None:
        """Stopping cancels all tracked background tasks."""
        es = _make_event_source()
        es._stop_event.clear()

        task = asyncio.create_task(asyncio.sleep(100))
        es._gossip_tasks.add(task)

        await es.stop()

        assert task.cancelled()

    async def test_stop_clears_task_set(self) -> None:
        """The gossip task set is empty after stopping."""
        es = _make_event_source()
        es._stop_event.clear()

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
        assert es._stop_event.is_set()

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
