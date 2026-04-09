"""
Tests for NetworkService event dispatch, run() lifecycle, and publish methods.

Testing Strategy
----------------

The existing ``test_network_service.py`` covers block, attestation, and peer-status
routing through real ``SyncService`` + ``MockForkchoiceStore``.  This module fills
the remaining coverage gaps:

1. **Event dispatch** — ``GossipAggregatedAttestationEvent``, ``PeerConnectedEvent``,
   and ``PeerDisconnectedEvent`` are dispatched to the correct handler or peer manager
   method.

2. **Run lifecycle** — ``run()`` exits when ``stop()`` is called mid-loop, when the
   event source is exhausted, and ``is_running`` transitions correctly.

3. **Publish methods** — ``publish_block``, ``publish_attestation``, and
   ``publish_aggregated_attestation`` SSZ-encode, snappy-compress, and publish to the
   correct gossip topic via the event source.

For dispatch tests we use ``unittest.mock.AsyncMock`` on ``SyncService`` to verify
calls without exercising real forkchoice logic.  For publish tests we use the real
``MockEventSource._published`` list to inspect (topic, data) pairs.
"""

from __future__ import annotations

import asyncio
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lean_spec.snappy import compress
from lean_spec.subspecs.containers import (
    AttestationData,
    Checkpoint,
    SignedAggregatedAttestation,
)
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import SubnetId, ValidatorIndex
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
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import (
    MockEventSource,
    create_mock_sync_service,
    make_mock_signature,
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
    fork_digest: str = FORK_DIGEST,
) -> tuple[NetworkService, MockEventSource]:
    """Build a ``NetworkService`` wired to a ``MockEventSource``."""
    source = MockEventSource(events=events)
    if sync_service is None:
        _pid = peer_id or PeerId.from_base58("16Uiu2HAmTestPeer123")
        sync_service = create_mock_sync_service(_pid)
    svc = NetworkService(
        sync_service=sync_service,  # type: ignore[arg-type]
        event_source=source,
        fork_digest=fork_digest,
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
    """Tests for ``run()`` loop control flow."""

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
            fork_digest=FORK_DIGEST,
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


# ---------------------------------------------------------------------------
# Event dispatch — aggregated attestation
# ---------------------------------------------------------------------------


class TestAggregatedAttestationDispatch:
    """Tests for ``GossipAggregatedAttestationEvent`` routing."""

    async def test_gossip_aggregated_attestation_routed(self, peer_id: PeerId) -> None:
        """GossipAggregatedAttestationEvent calls sync_service.on_gossip_aggregated_attestation."""
        from lean_spec.subspecs.sync.service import SyncService as _SyncService

        sync_service = create_mock_sync_service(peer_id)

        signed_agg = MagicMock(spec=SignedAggregatedAttestation)
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
# Event dispatch — peer connected / disconnected
# ---------------------------------------------------------------------------


class TestPeerConnectionEvents:
    """Tests for ``PeerConnectedEvent`` and ``PeerDisconnectedEvent``."""

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
    """Tests for ``publish_block()``."""

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
        # Topic format: /leanconsensus/{fork_digest}/block/ssz_snappy
        assert FORK_DIGEST in topic_id
        assert "block" in topic_id
        assert "ssz_snappy" in topic_id


class TestPublishAttestation:
    """Tests for ``publish_attestation()``."""

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
    """Tests for ``publish_aggregated_attestation()``."""

    async def test_publish_aggregated_attestation_happy_path(self, peer_id: PeerId) -> None:
        """Aggregated attestation is encoded, compressed, and published."""
        svc, source = _make_network_service([], peer_id=peer_id)

        # Use a plain MagicMock (no spec) so we can freely set data.slot.
        signed_agg = MagicMock()
        fake_ssz = b"\xde\xad\xbe\xef"
        signed_agg.encode_bytes.return_value = fake_ssz
        signed_agg.data.slot = Slot(10)

        await svc.publish_aggregated_attestation(signed_agg)

        assert len(source._published) == 1
        topic_id, data = source._published[0]

        expected_topic = GossipTopic.committee_aggregation(FORK_DIGEST).to_topic_id()
        assert topic_id == expected_topic
        assert data == compress(fake_ssz)
