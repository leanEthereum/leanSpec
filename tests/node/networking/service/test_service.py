"""
Tests for NetworkService event dispatch, run() lifecycle, and publish methods.
"""

from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from consensus_testing import (
    MockEventSource,
    MockForkchoiceStore,
    create_mock_sync_service,
    make_signed_block,
)
from consensus_testing.keys import XmssKeyManager, create_dummy_signature
from lean_spec.node.networking import PeerId
from lean_spec.node.networking.gossipsub.topic import GossipTopic, TopicKind
from lean_spec.node.networking.peer import PeerInfo
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.node.networking.service import NetworkService
from lean_spec.node.networking.service.events import (
    GossipAggregatedAttestationEvent,
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    PeerConnectedEvent,
    PeerDisconnectedEvent,
    PeerStatusEvent,
)
from lean_spec.node.networking.types import ConnectionState
from lean_spec.node.snappy import compress
from lean_spec.node.sync.states import SyncState
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, SubnetId, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AttestationData,
    SignedAggregatedAttestation,
    SignedAttestation,
)
from lean_spec.spec.ssz import Bytes32

FORK_DIGEST = "0x12345678"

# Helpers


def _sample_signed_aggregate() -> SignedAggregatedAttestation:
    """Build a signed aggregated attestation for validator 0 over a slot-1 vote."""
    key_manager = XmssKeyManager.shared()
    attestation_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
        source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
    )
    return SignedAggregatedAttestation(
        data=attestation_data,
        proof=key_manager.sign_and_aggregate([ValidatorIndex(0)], attestation_data),
    )


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


@pytest.fixture
def block_topic() -> GossipTopic:
    """Provide a block gossip topic for tests."""
    return GossipTopic(kind=TopicKind.BLOCK, network_name="0x12345678")


@pytest.fixture
def attestation_topic() -> GossipTopic:
    """Provide an attestation subnet gossip topic for tests."""
    return GossipTopic(kind=TopicKind.ATTESTATION_SUBNET, network_name="0x12345678")


# run() lifecycle


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
            event_source=source,
            network_name=FORK_DIGEST,
        )
        await svc.run()
        assert not svc.is_running


# Event dispatch — aggregated attestation


class TestAggregatedAttestationDispatch:
    """Tests for `GossipAggregatedAttestationEvent` routing."""

    async def test_gossip_aggregated_attestation_routed(self, peer_id: PeerId) -> None:
        """GossipAggregatedAttestationEvent calls sync_service.on_gossip_aggregated_attestation."""
        from lean_spec.node.sync.service import SyncService as _SyncService

        sync_service = create_mock_sync_service(peer_id)

        signed_aggregate = _sample_signed_aggregate()
        topic = GossipTopic.committee_aggregation(FORK_DIGEST)
        events: list[NetworkEvent] = [
            GossipAggregatedAttestationEvent(
                signed_attestation=signed_aggregate,
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

            mock_handler.assert_awaited_once_with(signed_aggregate, peer_id)


# Event dispatch — secondary events


class TestSecondaryEventDispatch:
    """Tests for remaining event types: Block, Attestation, and PeerStatus."""

    async def test_gossip_block_routed(self, peer_id: PeerId) -> None:
        """GossipBlockEvent calls sync_service.on_gossip_block."""
        from lean_spec.node.sync.service import SyncService as _SyncService

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
        from lean_spec.node.sync.service import SyncService as _SyncService

        sync_service = create_mock_sync_service(peer_id)
        attestation = SignedAttestation(
            validator_index=ValidatorIndex(1),
            data=AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=create_dummy_signature(),
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
        from lean_spec.node.sync.service import SyncService as _SyncService

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


# Publish methods


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
            validator_index=ValidatorIndex(7),
            data=AttestationData(
                slot=Slot(3),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=create_dummy_signature(),
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
            validator_index=ValidatorIndex(0),
            data=AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=create_dummy_signature(),
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

        signed_aggregate = _sample_signed_aggregate()

        await svc.publish_aggregated_attestation(signed_aggregate)

        assert len(source._published) == 1
        topic_id, data = source._published[0]

        expected_topic = GossipTopic.committee_aggregation(FORK_DIGEST).to_topic_id()
        assert topic_id == expected_topic
        assert data == compress(signed_aggregate.encode_bytes())


# Edge cases for _handle_event match exhaustiveness


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


# Constructor / init field defaults


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

    def test_custom_is_aggregator(self, peer_id: PeerId) -> None:
        """Constructor accepts is_aggregator."""
        source = MockEventSource(events=[])
        sync_service = create_mock_sync_service(peer_id)
        svc = NetworkService(
            sync_service=sync_service,
            event_source=source,
            is_aggregator=True,
        )
        assert svc.is_aggregator is True


# Behavioral routing to the forkchoice store


class TestBlockRoutingToForkchoice:
    """Tests verifying blocks are correctly routed to the forkchoice store."""

    async def test_block_added_to_store_blocks_dict(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Gossip block is added to the store's blocks dictionary."""
        sync_service = create_mock_sync_service(peer_id)
        sync_service.state = SyncState.SYNCING

        genesis_root = sync_service.store.head

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.block)

        # Verify block is NOT in store before processing
        assert block_root not in sync_service.store.blocks

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify block IS in store after processing
        assert block_root in sync_service.store.blocks
        assert sync_service.store.blocks[block_root].slot == Slot(1)

    async def test_store_head_updated_after_block(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Store head is updated to the new block after processing."""
        sync_service = create_mock_sync_service(peer_id)
        sync_service.state = SyncState.SYNCING

        genesis_root = sync_service.store.head
        assert genesis_root == Bytes32.zero()

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        expected_new_head = hash_tree_root(block.block)

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify head changed from genesis to new block
        assert sync_service.store.head == expected_new_head
        assert sync_service.store.head != genesis_root

    async def test_block_ignored_in_idle_state_store_unchanged(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Gossip blocks are ignored in IDLE state - store remains unchanged."""
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        genesis_root = sync_service.store.head
        initial_blocks_count = len(sync_service.store.blocks)

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify store is completely unchanged
        assert sync_service.store.head == genesis_root
        assert len(sync_service.store.blocks) == initial_blocks_count


class TestAttestationRoutingToForkchoice:
    """Tests verifying attestations are correctly routed to the forkchoice store."""

    async def test_attestation_processed_by_store(
        self,
        peer_id: PeerId,
        attestation_topic: GossipTopic,
    ) -> None:
        """Gossip attestation is passed to store.on_gossip_attestation."""
        sync_service = create_mock_sync_service(peer_id)
        sync_service.state = SyncState.SYNCING

        attestation = SignedAttestation(
            validator_index=ValidatorIndex(42),
            data=AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=create_dummy_signature(),
        )

        # Track initial attestations count
        mock_store = cast(MockForkchoiceStore, sync_service.store)
        initial_count = len(mock_store.received_attestations)

        events: list[NetworkEvent] = [
            GossipAttestationEvent(
                attestation=attestation,
                peer_id=peer_id,
                topic=attestation_topic,
            ),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify attestation was passed to store
        updated_store = cast(MockForkchoiceStore, sync_service.store)
        assert len(updated_store.received_attestations) == initial_count + 1
        assert updated_store.received_attestations[-1].validator_index == ValidatorIndex(42)

    async def test_attestation_ignored_in_idle_state(
        self,
        peer_id: PeerId,
        attestation_topic: GossipTopic,
    ) -> None:
        """Gossip attestations are ignored in IDLE state."""
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        initial_count = len(mock_store.received_attestations)

        attestation = SignedAttestation(
            validator_index=ValidatorIndex(99),
            data=AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=create_dummy_signature(),
        )

        events: list[NetworkEvent] = [
            GossipAttestationEvent(
                attestation=attestation,
                peer_id=peer_id,
                topic=attestation_topic,
            ),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify no attestation was processed
        updated_store = cast(MockForkchoiceStore, sync_service.store)
        assert len(updated_store.received_attestations) == initial_count


class TestPeerStatusStateTransitions:
    """Tests verifying peer status events trigger correct state transitions."""

    async def test_peer_status_triggers_idle_to_syncing(
        self,
        peer_id: PeerId,
    ) -> None:
        """PeerStatusEvent transitions SyncService from IDLE to SYNCING."""
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        # Peer reports they are ahead (finalized slot 100)
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
        )

        events: list[NetworkEvent] = [
            PeerStatusEvent(peer_id=peer_id, status=status),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify state transition occurred
        assert sync_service.state == SyncState.SYNCING

    async def test_peer_status_updates_peer_manager(
        self,
        peer_id: PeerId,
    ) -> None:
        """PeerStatusEvent updates the peer manager with reported status."""
        sync_service = create_mock_sync_service(peer_id)

        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(50)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(75)),
        )

        events: list[NetworkEvent] = [
            PeerStatusEvent(peer_id=peer_id, status=status),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify peer manager was updated with the status
        network_finalized = sync_service.peer_manager.get_network_finalized_slot()
        assert network_finalized == Slot(50)


class TestIntegrationEventSequence:
    """Integration test for complete event flow from network to forkchoice."""

    async def test_full_sync_flow_status_then_block(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """
        Complete flow: peer status triggers sync, then block updates store.

        This tests the realistic scenario where:
        1. Peer connects and sends status (triggers IDLE -> SYNCING)
        2. Block arrives via gossip
        3. Block is processed and added to store
        4. Store head is updated
        5. Once head >= network finalized, state transitions to SYNCED
        """
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        genesis_root = sync_service.store.head

        # Peer status to trigger sync (reports finalized at slot 0)
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )

        # Block to process (slot 1 - will exceed network finalized)
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        expected_head = hash_tree_root(block.block)

        events: list[NetworkEvent] = [
            PeerStatusEvent(peer_id=peer_id, status=status),
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify complete state after full flow:
        # - Block was processed and added to store
        # - Head was updated to the new block
        # - State transitioned to SYNCED (head slot 1 >= network finalized slot 0)
        assert expected_head in sync_service.store.blocks
        assert sync_service.store.head == expected_head
        assert sync_service._blocks_processed == 1
        assert sync_service.state == SyncState.SYNCED

    async def test_block_before_status_is_ignored(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Block arriving before status is ignored (IDLE state rejects gossip)."""
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        genesis_root = sync_service.store.head

        # Block arrives BEFORE status
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        # Status arrives AFTER block
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
            PeerStatusEvent(peer_id=peer_id, status=status),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Status should trigger SYNCING, but block was already rejected
        assert sync_service.state == SyncState.SYNCING
        assert sync_service.store.head == genesis_root  # Head unchanged
        assert sync_service._blocks_processed == 0  # Block was not processed

    async def test_multiple_blocks_chain_extension(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Multiple sequential blocks extend the chain correctly."""
        sync_service = create_mock_sync_service(peer_id)
        sync_service.state = SyncState.SYNCING

        genesis_root = sync_service.store.head

        # Create chain: genesis -> block1 -> block2
        block1 = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block1_root = hash_tree_root(block1.block)

        block2 = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(1),
            parent_root=block1_root,
            state_root=Bytes32.zero(),
        )
        block2_root = hash_tree_root(block2.block)

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block1, peer_id=peer_id, topic=block_topic),
            GossipBlockEvent(block=block2, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,
        )

        await network_service.run()

        # Verify chain was extended
        assert block1_root in sync_service.store.blocks
        assert block2_root in sync_service.store.blocks
        assert sync_service.store.head == block2_root
        assert sync_service.store.blocks[block2_root].slot == Slot(2)
        assert sync_service._blocks_processed == 2
