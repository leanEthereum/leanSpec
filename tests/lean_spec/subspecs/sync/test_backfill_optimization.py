"""Tests for BackfillSync optimizations (Range sync and Store awareness)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer import PeerInfo
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.subspecs.sync.backfill_sync import BackfillSync
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers.builders import make_signed_block
from tests.lean_spec.helpers.mocks import MockNetworkRequester


@pytest.fixture
def peer_id() -> PeerId:
    """Provide a peer ID."""
    return PeerId(b"peer_1".ljust(32, b"\x00"))


@pytest.fixture
def network() -> MockNetworkRequester:
    """Provide mock network."""
    return MockNetworkRequester()


@pytest.fixture
def store() -> MagicMock:
    """Provide a mock store."""
    store = MagicMock()
    store.blocks = {}
    store.latest_finalized = MagicMock()
    store.latest_finalized.slot = Slot(0)
    store.latest_finalized.root = Bytes32.zero()
    return store


@pytest.fixture
def backfill_system(
    peer_id: PeerId, network: MockNetworkRequester, store: MagicMock
) -> BackfillSync:
    """Provide a complete BackfillSync with connected peer and store awareness."""
    manager = PeerManager()
    manager.add_peer(PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED))
    return BackfillSync(
        peer_manager=manager,
        block_cache=BlockCache(),
        network=network,
        get_store=lambda: store,
    )


class TestBackfillOptimizations:
    """Tests for range sync and store awareness in BackfillSync."""

    async def test_store_awareness_skips_known_parents(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        store: MagicMock,
        peer_id: PeerId,
    ) -> None:
        """Backfill does not request parents that are already in the Store."""
        # Parent is in the store.
        parent_root = Bytes32(b"\x01" * 32)
        store.blocks[parent_root] = MagicMock()

        # Child is received.
        child = make_signed_block(
            slot=Slot(10),
            parent_root=parent_root,
            proposer_index=ValidatorIndex(0),
            state_root=Bytes32.zero(),
        )
        child_root = network.add_block(child)

        await backfill_system.fill_missing([child_root])

        # Verify child was added to cache.
        assert child_root in backfill_system.block_cache

        # Verify NO request was made for parent (since it's in Store).
        # The request_log should only contain the initial request for the child.
        assert len(network.request_log) == 1
        assert network.request_log[0][1] == [child_root]

    async def test_range_sync_triggered_by_large_gap_during_backfill(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        store: MagicMock,
        peer_id: PeerId,
    ) -> None:
        """Backfill triggers range sync when a large gap is detected."""
        # Store is at slot 0.
        store.latest_finalized.slot = Slot(0)

        # Pre-fill the parent in the network at slot 50.
        block_50 = make_signed_block(
            slot=Slot(50),
            parent_root=Bytes32.zero(),
            proposer_index=ValidatorIndex(0),
            state_root=Bytes32.zero(),
        )
        parent_root = network.add_block(block_50)

        # Receive a block at slot 100 via fill_missing.
        block_100 = make_signed_block(
            slot=Slot(100),
            parent_root=parent_root,
            proposer_index=ValidatorIndex(0),
            state_root=Bytes32.zero(),
        )
        root_100 = network.add_block(block_100)

        # Parent of block_50 is in store.
        store.blocks[Bytes32.zero()] = MagicMock()

        await backfill_system.fill_missing([root_100])

        # Log should contain:
        # 1. BlocksByRoot(root_100)
        # 2. BlocksByRange(1, 99)
        assert len(network.request_log) == 2
        assert network.request_log[0][1] == [root_100]
        assert network.request_log[1][1] == (Slot(1), Uint64(99))

    async def test_range_deduplication(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
    ) -> None:
        """Multiple overlapping range requests are deduplicated."""
        # Request range 1-10.
        await backfill_system.fill_range(start_slot=Slot(1), count=Uint64(10))
        assert backfill_system._max_range_slot == Slot(10)
        assert len(network.request_log) == 1
        assert network.request_log[0][1] == (Slot(1), Uint64(10))

        # Request range 5-15.
        await backfill_system.fill_range(start_slot=Slot(5), count=Uint64(11))

        # Should only request 11-15 (count=5).
        assert len(network.request_log) == 2
        assert network.request_log[1][1] == (Slot(11), Uint64(5))
        assert backfill_system._max_range_slot == Slot(15)

    async def test_full_range_skip_if_already_covered(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
    ) -> None:
        """Range requests fully covered by previous ones are skipped entirely."""
        await backfill_system.fill_range(start_slot=Slot(1), count=Uint64(100))
        assert len(network.request_log) == 1

        # Request a sub-range.
        await backfill_system.fill_range(start_slot=Slot(10), count=Uint64(20))

        # No new request should be made.
        assert len(network.request_log) == 1
