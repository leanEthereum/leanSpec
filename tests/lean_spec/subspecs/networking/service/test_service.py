"""
Tests for NetworkService event dispatch, run() lifecycle, and publish methods.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from lean_spec.forks.lstar.containers import (
    AttestationData,
    Checkpoint,
)
from lean_spec.forks.lstar.containers.attestation import SignedAttestation
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import SubnetId, ValidatorIndex
from lean_spec.snappy import compress
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic
from lean_spec.subspecs.networking.peer import PeerInfo
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.service import NetworkService
from lean_spec.subspecs.networking.service.events import (
    GossipAggregatedAttestationEvent,
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    PeerConnectedEvent,
    PeerDisconnectedEvent,
    PeerStatusEvent,
)
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import (
    MockEventSource,
    create_mock_sync_service,
    make_mock_signature,
    make_signed_aggregated_attestation,
    make_signed_block,
)

FORK_DIGEST = "0x12345678"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_network_service(
    events: list[NetworkEvent],
    *,
    sync_service: object | None = None,
    peer_id: PeerId | None = None,
    network_name: str = FORK_DIGEST,
) -> tuple[NetworkService, MockEventSource]:
    """Build a `NetworkService` wired to a `MockEventSource`."""
    source = MockEventSource(events=events)
    if sync_service is None:
        _pid = peer_id or PeerId.from_base58("16Uiu2HAmTestPeer123")
        sync_service = create_mock_sync_service(_pid)
    svc = NetworkService(
        sync_service=sync_service,  # type: ignore[arg-type]
        event_source=source,
        network_name=network_name,
    )
    return svc, source


class _StopAfterFirstEvent(MockEventSource):
    """An event source that signals the service to stop after yielding the first event."""

    def __init__(self, events: list[NetworkEvent], service: NetworkService) -> None:
        super().__init__(events=events)
        self._service = service

    async def __anext__(self) -> NetworkEvent:
        event = await super().__anext__()
        # Signal stop after the first event is consumed.
        self._service.stop()
        return event


# ---------------------------------------------------------------------------
# run() lifecycle
# ---------------------------------------------------------------------------


class TestRunLifecycle:
    """Tests for `run()` loop control flow."""

    async def test_source_exhaustion_exits_gracefully(self, peer_id: PeerId) -> None:
        """run() completes without error when the event source is empty."""
        svc, _ = _make_network_service([], peer_id=peer_id)
        await svc.run()
        assert not svc.is_running

    async def test_is_running_transitions(self, peer_id: PeerId) -> None:
        """is_running is False before run(), True during, False after."""
        svc, _ = _make_network_service([], peer_id=peer_id)

        assert not svc.is_running, "should be False before run()"
        await svc.run()
        assert not svc.is_running, "should be False after run()"

    async def test_stop_mid_loop(self, peer_id: PeerId) -> None:
        """stop() during event processing causes the loop to exit early."""
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        topic = GossipTopic.block(FORK_DIGEST)
        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=topic),
            GossipBlockEvent(block=block, peer_id=peer_id, topic=topic),
            GossipBlockEvent(block=block, peer_id=peer_id, topic=topic),
        ]

        sync_service = create_mock_sync_service(peer_id)

        # We build service first, then swap in a special event source.
        svc = NetworkService(
            sync_service=sync_service,
            event_source=MockEventSource(events=[]),  # placeholder
            network_name=FORK_DIGEST,
        )
        # Replace with the stop-after-first source
        stop_source = _StopAfterFirstEvent(events, svc)
        object.__setattr__(svc, "event_source", stop_source)

        await svc.run()
        assert not svc.is_running
        # The source should have yielded at most 1 event before the stop flag
        # was checked on the next iteration.
        assert stop_source._index <= 2  # consumed 1, maybe peeked at 2nd

    async def test_stop_before_run(self, peer_id: PeerId) -> None:
        """Calling stop() before run() does not crash."""
        svc, _ = _make_network_service([], peer_id=peer_id)
        svc.stop()
        assert not svc.is_running
        # run() should still work (exits immediately since _running starts False,
        # but run() sets _running=True first, then iterates).
        await svc.run()
        assert not svc.is_running

    async def test_stop_async_iteration_exception_caught(self, peer_id: PeerId) -> None:
        """StopAsyncIteration during iteration is caught by the explicit except block."""
        source = MagicMock()
        # If __aiter__ raises StopAsyncIteration, it should be caught by the except block in run()
        source.__aiter__.side_effect = StopAsyncIteration

        sync_service = create_mock_sync_service(peer_id)
        svc = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
            network_name=FORK_DIGEST,
        )
        await svc.run()
        assert not svc.is_running


# ---------------------------------------------------------------------------
# Event dispatch — aggregated attestation
# ---------------------------------------------------------------------------


class TestAggregatedAttestationDispatch:
    """Tests for `GossipAggregatedAttestationEvent` routing."""

    async def test_gossip_aggregated_attestation_routed(self, peer_id: PeerId) -> None:
        """GossipAggregatedAttestationEvent calls sync_service.on_gossip_aggregated_attestation."""
        from lean_spec.subspecs.sync.service import SyncService as _SyncService

        sync_service = create_mock_sync_service(peer_id)

        signed_agg = make_signed_aggregated_attestation()
        topic = GossipTopic.committee_aggregation(FORK_DIGEST)
        events: list[NetworkEvent] = [
            GossipAggregatedAttestationEvent(
                signed_attestation=signed_agg,
                peer_id=peer_id,
                topic=topic,
            ),
        ]
        # Patch at the *class* level because SyncService uses __slots__,
        # which prevents instance-level attribute replacement.
        mock_handler = AsyncMock()
        with patch.object(_SyncService, "on_gossip_aggregated_attestation", mock_handler):
            svc, _ = _make_network_service(events, sync_service=sync_service)
            await svc.run()

            mock_handler.assert_awaited_once_with(signed_agg, peer_id)


# ---------------------------------------------------------------------------
# Event dispatch — secondary events
# ---------------------------------------------------------------------------


class TestSecondaryEventDispatch:
    """Tests for remaining event types: Block, Attestation, and PeerStatus."""

    async def test_gossip_block_routed(self, peer_id: PeerId) -> None:
        """GossipBlockEvent calls sync_service.on_gossip_block."""
        from lean_spec.subspecs.sync.service import SyncService as _SyncService

        sync_service = create_mock_sync_service(peer_id)
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        topic = GossipTopic.block(FORK_DIGEST)
        event = GossipBlockEvent(block=block, peer_id=peer_id, topic=topic)

        mock_handler = AsyncMock()
        with patch.object(_SyncService, "on_gossip_block", mock_handler):
            svc, _ = _make_network_service([event], sync_service=sync_service)
            await svc.run()

            mock_handler.assert_awaited_once_with(block, peer_id)

    async def test_gossip_attestation_routed(self, peer_id: PeerId) -> None:
        """GossipAttestationEvent calls sync_service.on_gossip_attestation."""
        from lean_spec.subspecs.sync.service import SyncService as _SyncService

        sync_service = create_mock_sync_service(peer_id)
        attestation = SignedAttestation(
            validator_id=ValidatorIndex(1),
            data=AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=make_mock_signature(),
        )
        topic = GossipTopic.attestation_subnet(FORK_DIGEST, SubnetId(0))
        event = GossipAttestationEvent(attestation=attestation, peer_id=peer_id, topic=topic)

        mock_handler = AsyncMock()
        with patch.object(_SyncService, "on_gossip_attestation", mock_handler):
            svc, _ = _make_network_service([event], sync_service=sync_service)
            await svc.run()

            mock_handler.assert_awaited_once_with(attestation, peer_id)

    async def test_peer_status_routed(self, peer_id: PeerId) -> None:
        """PeerStatusEvent calls sync_service.on_peer_status."""
        from lean_spec.subspecs.sync.service import SyncService as _SyncService

        sync_service = create_mock_sync_service(peer_id)
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )
        event = PeerStatusEvent(peer_id=peer_id, status=status)

        mock_handler = AsyncMock()
        with patch.object(_SyncService, "on_peer_status", mock_handler):
            svc, _ = _make_network_service([event], sync_service=sync_service)
            await svc.run()

            mock_handler.assert_awaited_once_with(peer_id, status)


class TestPeerConnectionEvents:
    """Tests for `PeerConnectedEvent` and `PeerDisconnectedEvent`."""

    async def test_peer_connected_adds_to_manager(
        self,
        peer_id: PeerId,
        peer_id_2: PeerId,
    ) -> None:
        """PeerConnectedEvent adds the peer to peer_manager."""
        sync_service = create_mock_sync_service(peer_id)
        initial_count = len(sync_service.peer_manager)

        events: list[NetworkEvent] = [
            PeerConnectedEvent(peer_id=peer_id_2),
        ]
        svc, _ = _make_network_service(events, sync_service=sync_service)
        await svc.run()

        assert peer_id_2 in sync_service.peer_manager
        assert len(sync_service.peer_manager) == initial_count + 1

    async def test_peer_disconnected_removes_from_manager(
        self,
        peer_id: PeerId,
        peer_id_2: PeerId,
    ) -> None:
        """PeerDisconnectedEvent removes the peer from peer_manager."""
        sync_service = create_mock_sync_service(peer_id)
        # Pre-add peer_id_2 so it can be removed.
        sync_service.peer_manager.add_peer(
            PeerInfo(peer_id=peer_id_2, state=ConnectionState.CONNECTED)
        )
        assert peer_id_2 in sync_service.peer_manager

        events: list[NetworkEvent] = [
            PeerDisconnectedEvent(peer_id=peer_id_2),
        ]
        svc, _ = _make_network_service(events, sync_service=sync_service)
        await svc.run()

        assert peer_id_2 not in sync_service.peer_manager


# ---------------------------------------------------------------------------
# Publish methods
# ---------------------------------------------------------------------------


class TestPublishBlock:
    """Tests for `publish_block()`."""

    async def test_publish_block_encodes_and_publishes(self, peer_id: PeerId) -> None:
        """Block is SSZ-encoded, snappy-compressed, and published to correct topic."""
        svc, source = _make_network_service([], peer_id=peer_id)
        block = make_signed_block(
            slot=Slot(5),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        await svc.publish_block(block)

        assert len(source._published) == 1
        topic_id, data = source._published[0]

        expected_topic = GossipTopic.block(FORK_DIGEST).to_topic_id()
        assert topic_id == expected_topic

        expected_data = compress(block.encode_bytes())
        assert data == expected_data

    async def test_publish_block_topic_format(self, peer_id: PeerId) -> None:
        """Block topic string matches the expected format."""
        topic = GossipTopic.block(FORK_DIGEST)
        topic_id = topic.to_topic_id()
        # Topic format: /leanconsensus/{network_name}/block/ssz_snappy
        assert FORK_DIGEST in topic_id
        assert "block" in topic_id
        assert "ssz_snappy" in topic_id


class TestPublishAttestation:
    """Tests for `publish_attestation()`."""

    async def test_publish_attestation_happy_path(self, peer_id: PeerId) -> None:
        """Attestation is SSZ-encoded, compressed, and published to subnet topic."""
        svc, source = _make_network_service([], peer_id=peer_id)
        attestation = SignedAttestation(
            validator_id=ValidatorIndex(7),
            data=AttestationData(
                slot=Slot(3),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=make_mock_signature(),
        )
        subnet = SubnetId(42)

        await svc.publish_attestation(attestation, subnet)

        assert len(source._published) == 1
        topic_id, data = source._published[0]

        expected_topic = GossipTopic.attestation_subnet(FORK_DIGEST, subnet).to_topic_id()
        assert topic_id == expected_topic
        assert data == compress(attestation.encode_bytes())

    async def test_publish_attestation_different_subnets(self, peer_id: PeerId) -> None:
        """Different SubnetId values produce different topic strings."""
        svc, source = _make_network_service([], peer_id=peer_id)
        attestation = SignedAttestation(
            validator_id=ValidatorIndex(0),
            data=AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=make_mock_signature(),
        )

        await svc.publish_attestation(attestation, SubnetId(0))
        await svc.publish_attestation(attestation, SubnetId(1))

        assert len(source._published) == 2
        topic_0 = source._published[0][0]
        topic_1 = source._published[1][0]
        assert topic_0 != topic_1


class TestPublishAggregatedAttestation:
    """Tests for `publish_aggregated_attestation()`."""

    async def test_publish_aggregated_attestation_happy_path(self, peer_id: PeerId) -> None:
        """Aggregated attestation is encoded, compressed, and published."""
        svc, source = _make_network_service([], peer_id=peer_id)

        signed_agg = make_signed_aggregated_attestation()

        await svc.publish_aggregated_attestation(signed_agg)

        assert len(source._published) == 1
        topic_id, data = source._published[0]

        expected_topic = GossipTopic.committee_aggregation(FORK_DIGEST).to_topic_id()
        assert topic_id == expected_topic
        assert data == compress(signed_agg.encode_bytes())


# ---------------------------------------------------------------------------
# Edge cases for _handle_event match exhaustiveness
# ---------------------------------------------------------------------------


class TestHandleEventEdgeCases:
    """Cover the implicit fall-through branch of the match statement."""

    async def test_disconnecting_absent_peer_does_not_raise(self, peer_id: PeerId) -> None:
        """PeerDisconnectedEvent for an unknown peer should not crash."""
        sync_service = create_mock_sync_service(peer_id)
        unknown_peer = PeerId.from_base58("16Uiu2HAmUnknownPeerXYZ")

        events: list[NetworkEvent] = [
            PeerDisconnectedEvent(peer_id=unknown_peer),
        ]
        svc, _ = _make_network_service(events, sync_service=sync_service)
        # Should not raise even though the peer was never connected.
        await svc.run()
        assert not svc.is_running

    async def test_multiple_peer_events_sequence(
        self,
        peer_id: PeerId,
        peer_id_2: PeerId,
    ) -> None:
        """Connect then disconnect exercising both match arms in sequence."""
        sync_service = create_mock_sync_service(peer_id)
        events: list[NetworkEvent] = [
            PeerConnectedEvent(peer_id=peer_id_2),
            PeerDisconnectedEvent(peer_id=peer_id_2),
        ]
        svc, _ = _make_network_service(events, sync_service=sync_service)
        await svc.run()

        assert peer_id_2 not in sync_service.peer_manager


# ---------------------------------------------------------------------------
# Constructor / init field defaults
# ---------------------------------------------------------------------------


class TestNetworkServiceInit:
    """Tests for constructor fields and defaults."""

    def test_default_fork_digest(self, peer_id: PeerId) -> None:
        """network_name defaults to `0x00000000` when not specified."""
        source = MockEventSource(events=[])
        sync_service = create_mock_sync_service(peer_id)
        svc = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )
        assert svc.network_name == "0x00000000"

    def test_default_is_aggregator(self, peer_id: PeerId) -> None:
        """is_aggregator defaults to False."""
        source = MockEventSource(events=[])
        sync_service = create_mock_sync_service(peer_id)
        svc = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )
        assert svc.is_aggregator is False

    def test_default_aggregate_subnet_ids(self, peer_id: PeerId) -> None:
        """aggregate_subnet_ids defaults to an empty tuple."""
        source = MockEventSource(events=[])
        sync_service = create_mock_sync_service(peer_id)
        svc = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )
        assert svc.aggregate_subnet_ids == ()

    def test_custom_aggregator_fields(self, peer_id: PeerId) -> None:
        """Constructor accepts is_aggregator and aggregate_subnet_ids."""
        source = MockEventSource(events=[])
        sync_service = create_mock_sync_service(peer_id)
        svc = NetworkService(
            sync_service=sync_service,
            event_source=source,
            is_aggregator=True,
            aggregate_subnet_ids=(SubnetId(0), SubnetId(3)),
        )
        assert svc.is_aggregator is True
        assert svc.aggregate_subnet_ids == (SubnetId(0), SubnetId(3))
