"""Tests for peer manager module."""

from __future__ import annotations

from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer.info import PeerInfo
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.subspecs.sync.config import MAX_CONCURRENT_REQUESTS
from lean_spec.subspecs.sync.peer_manager import PeerManager, SyncPeer
from lean_spec.types import Bytes32


def peer(name: str) -> PeerId:
    """Create a PeerId from a test name."""
    return PeerId.from_base58(name)


class TestSyncPeer:
    """Tests for SyncPeer."""

    def test_create_sync_peer(self, connected_peer_info: PeerInfo) -> None:
        """SyncPeer can be created from PeerInfo."""
        sync_peer = SyncPeer(info=connected_peer_info)

        assert sync_peer.info == connected_peer_info
        assert sync_peer.peer_id == connected_peer_info.peer_id
        assert sync_peer.status is None
        assert sync_peer.requests_in_flight == 0

    def test_is_connected(self, connected_peer_info: PeerInfo) -> None:
        """is_connected returns True when peer is connected."""
        sync_peer = SyncPeer(info=connected_peer_info)
        assert sync_peer.is_connected()

    def test_is_connected_when_disconnected(self, disconnected_peer_info: PeerInfo) -> None:
        """is_connected returns False when peer is disconnected."""
        sync_peer = SyncPeer(info=disconnected_peer_info)
        assert not sync_peer.is_connected()

    def test_is_available(self, connected_peer_info: PeerInfo) -> None:
        """is_available returns True when connected and below request limit."""
        sync_peer = SyncPeer(info=connected_peer_info)
        assert sync_peer.is_available()

    def test_is_available_false_when_disconnected(self, disconnected_peer_info: PeerInfo) -> None:
        """is_available returns False when peer is disconnected."""
        sync_peer = SyncPeer(info=disconnected_peer_info)
        assert not sync_peer.is_available()

    def test_is_available_false_at_request_limit(self, connected_peer_info: PeerInfo) -> None:
        """is_available returns False when at MAX_CONCURRENT_REQUESTS."""
        sync_peer = SyncPeer(info=connected_peer_info)
        sync_peer.requests_in_flight = MAX_CONCURRENT_REQUESTS
        assert not sync_peer.is_available()

    def test_has_slot_false_without_status(self, connected_peer_info: PeerInfo) -> None:
        """has_slot returns False when no status is set."""
        sync_peer = SyncPeer(info=connected_peer_info)
        assert not sync_peer.has_slot(Slot(100))

    def test_has_slot_true_when_head_at_or_past(
        self, connected_peer_info: PeerInfo, sample_status: Status
    ) -> None:
        """has_slot returns True when peer's head is at or past the slot."""
        sync_peer = SyncPeer(info=connected_peer_info, status=sample_status)
        # Status has head at slot 150
        assert sync_peer.has_slot(Slot(100))
        assert sync_peer.has_slot(Slot(150))
        assert not sync_peer.has_slot(Slot(151))

    def test_on_request_start(self, connected_peer_info: PeerInfo) -> None:
        """on_request_start increments requests_in_flight."""
        sync_peer = SyncPeer(info=connected_peer_info)
        sync_peer.on_request_start()
        assert sync_peer.requests_in_flight == 1

    def test_on_request_complete(self, connected_peer_info: PeerInfo) -> None:
        """on_request_complete decrements requests_in_flight."""
        sync_peer = SyncPeer(info=connected_peer_info)
        sync_peer.requests_in_flight = 2
        sync_peer.on_request_complete()
        assert sync_peer.requests_in_flight == 1

    def test_on_request_complete_does_not_go_negative(self, connected_peer_info: PeerInfo) -> None:
        """on_request_complete does not let in_flight go negative."""
        sync_peer = SyncPeer(info=connected_peer_info)
        sync_peer.on_request_complete()
        assert sync_peer.requests_in_flight == 0


class TestPeerManagerBasicOperations:
    """Tests for basic PeerManager operations."""

    def test_empty_manager(self) -> None:
        """New PeerManager has no peers."""
        manager = PeerManager()
        assert len(manager) == 0

    def test_add_peer(self, connected_peer_info: PeerInfo) -> None:
        """Adding a peer registers it in the manager."""
        manager = PeerManager()
        sync_peer = manager.add_peer(connected_peer_info)

        assert len(manager) == 1
        assert connected_peer_info.peer_id in manager
        assert sync_peer.info == connected_peer_info

    def test_add_peer_updates_existing(self, peer_id: PeerId) -> None:
        """Adding a peer with same ID updates the existing entry."""
        manager = PeerManager()
        info1 = PeerInfo(peer_id=peer_id, state=ConnectionState.DISCONNECTED)
        info2 = PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED)

        sync_peer1 = manager.add_peer(info1)
        sync_peer2 = manager.add_peer(info2)

        assert len(manager) == 1
        assert sync_peer1 is sync_peer2
        assert sync_peer2.info == info2

    def test_remove_peer(self, connected_peer_info: PeerInfo) -> None:
        """Removing a peer returns it and removes from manager."""
        manager = PeerManager()
        manager.add_peer(connected_peer_info)

        removed = manager.remove_peer(connected_peer_info.peer_id)

        assert removed is not None
        assert len(manager) == 0

    def test_remove_nonexistent_peer(self) -> None:
        """Removing a nonexistent peer returns None."""
        manager = PeerManager()
        assert manager.remove_peer(peer("16Uiu2HAmNonexistent")) is None

    def test_get_peer(self, connected_peer_info: PeerInfo) -> None:
        """Getting a peer by ID returns the SyncPeer."""
        manager = PeerManager()
        manager.add_peer(connected_peer_info)

        peer = manager.get_peer(connected_peer_info.peer_id)
        assert peer is not None
        assert peer.peer_id == connected_peer_info.peer_id

    def test_get_nonexistent_peer(self) -> None:
        """Getting a nonexistent peer returns None."""
        manager = PeerManager()
        assert manager.get_peer(peer("16Uiu2HAmNonexistent")) is None

    def test_clear(self, connected_peer_info: PeerInfo) -> None:
        """Clear removes all peers."""
        manager = PeerManager()
        manager.add_peer(connected_peer_info)
        manager.clear()
        assert len(manager) == 0


class TestPeerManagerStatusTracking:
    """Tests for PeerManager status tracking."""

    def test_update_status(self, connected_peer_info: PeerInfo, sample_status: Status) -> None:
        """update_status sets the peer's chain status."""
        manager = PeerManager()
        manager.add_peer(connected_peer_info)

        manager.update_status(connected_peer_info.peer_id, sample_status)

        peer = manager.get_peer(connected_peer_info.peer_id)
        assert peer is not None
        assert peer.status == sample_status

    def test_update_status_nonexistent_peer(self, sample_status: Status) -> None:
        """update_status does nothing for nonexistent peer."""
        manager = PeerManager()
        # Should not raise
        manager.update_status(peer("16Uiu2HAmNonexistent"), sample_status)


class TestPeerManagerPeerSelection:
    """Tests for PeerManager peer selection."""

    def test_select_peer_for_request(self, connected_peer_info: PeerInfo) -> None:
        """select_peer_for_request returns an available peer."""
        manager = PeerManager()
        manager.add_peer(connected_peer_info)

        peer = manager.select_peer_for_request()
        assert peer is not None

    def test_select_peer_for_request_none_when_empty(self) -> None:
        """select_peer_for_request returns None when no peers."""
        manager = PeerManager()
        assert manager.select_peer_for_request() is None

    def test_select_peer_for_request_none_when_unavailable(
        self, disconnected_peer_info: PeerInfo
    ) -> None:
        """select_peer_for_request returns None when no available peers."""
        manager = PeerManager()
        manager.add_peer(disconnected_peer_info)
        assert manager.select_peer_for_request() is None

    def test_select_peer_for_request_filters_by_min_slot(
        self, peer_id: PeerId, peer_id_2: PeerId
    ) -> None:
        """select_peer_for_request filters by min_slot when specified."""
        manager = PeerManager()

        info1 = PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED)
        info2 = PeerInfo(peer_id=peer_id_2, state=ConnectionState.CONNECTED)

        sync_peer1 = manager.add_peer(info1)
        sync_peer2 = manager.add_peer(info2)

        sync_peer1.status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(50)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
        )
        sync_peer2.status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(200)),
        )

        # Request slot 150 - only peer2 has it
        selected = manager.select_peer_for_request(min_slot=Slot(150))
        assert selected is not None
        assert selected.peer_id == peer_id_2


class TestPeerManagerNetworkConsensus:
    """Tests for PeerManager network consensus methods."""

    def test_get_network_finalized_slot_mode(
        self, peer_id: PeerId, peer_id_2: PeerId, peer_id_3: PeerId
    ) -> None:
        """get_network_finalized_slot returns the mode of finalized slots."""
        manager = PeerManager()

        for pid, fin_slot in [(peer_id, 100), (peer_id_2, 100), (peer_id_3, 150)]:
            info = PeerInfo(peer_id=pid, state=ConnectionState.CONNECTED)
            sync_peer = manager.add_peer(info)
            sync_peer.status = Status(
                finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(fin_slot)),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(fin_slot + 50)),
            )

        finalized = manager.get_network_finalized_slot()
        assert finalized == Slot(100)

    def test_get_network_finalized_slot_none_without_status(
        self, connected_peer_info: PeerInfo
    ) -> None:
        """get_network_finalized_slot returns None if no peers have status."""
        manager = PeerManager()
        manager.add_peer(connected_peer_info)
        assert manager.get_network_finalized_slot() is None

    def test_get_network_finalized_slot_ignores_disconnected(
        self, peer_id: PeerId, peer_id_2: PeerId
    ) -> None:
        """get_network_finalized_slot ignores disconnected peers."""
        manager = PeerManager()

        info1 = PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED)
        info2 = PeerInfo(peer_id=peer_id_2, state=ConnectionState.DISCONNECTED)

        sync_peer1 = manager.add_peer(info1)
        sync_peer2 = manager.add_peer(info2)

        sync_peer1.status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
        )
        sync_peer2.status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(200)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(250)),
        )

        finalized = manager.get_network_finalized_slot()
        assert finalized == Slot(100)


class TestPeerManagerRequestCallbacks:
    """Tests for PeerManager request callbacks."""

    def test_on_request_success(self, connected_peer_info: PeerInfo) -> None:
        """on_request_success decrements in-flight count."""
        manager = PeerManager()
        sync_peer = manager.add_peer(connected_peer_info)
        sync_peer.requests_in_flight = 1

        manager.on_request_success(connected_peer_info.peer_id)
        assert sync_peer.requests_in_flight == 0

    def test_on_request_success_nonexistent_peer(self) -> None:
        """on_request_success does nothing for nonexistent peer."""
        manager = PeerManager()
        # Should not raise
        manager.on_request_success(peer("16Uiu2HAmNonexistent"))

    def test_on_request_failure(self, connected_peer_info: PeerInfo) -> None:
        """on_request_failure decrements in-flight count."""
        manager = PeerManager()
        sync_peer = manager.add_peer(connected_peer_info)
        sync_peer.requests_in_flight = 1

        manager.on_request_failure(connected_peer_info.peer_id)
        assert sync_peer.requests_in_flight == 0

    def test_on_request_failure_nonexistent_peer(self) -> None:
        """on_request_failure does nothing for nonexistent peer."""
        manager = PeerManager()
        # Should not raise
        manager.on_request_failure(peer("16Uiu2HAmNonexistent"))


class TestPeerManagerGetAllPeers:
    """Tests for PeerManager get_all_peers method."""

    def test_get_all_peers_empty(self) -> None:
        """get_all_peers returns empty list when no peers."""
        manager = PeerManager()
        assert manager.get_all_peers() == []

    def test_get_all_peers_returns_all(self, peer_id: PeerId, peer_id_2: PeerId) -> None:
        """get_all_peers returns all tracked peers."""
        manager = PeerManager()

        for pid in [peer_id, peer_id_2]:
            info = PeerInfo(peer_id=pid, state=ConnectionState.CONNECTED)
            manager.add_peer(info)

        peers = manager.get_all_peers()
        assert len(peers) == 2
