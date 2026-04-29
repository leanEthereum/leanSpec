"""Tests for backfill synchronization module."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer import PeerInfo
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.subspecs.sync.backfill_sync import BackfillSync
from lean_spec.subspecs.sync.block_cache import BlockCache, PendingBlock
from lean_spec.subspecs.sync.config import MAX_BACKFILL_DEPTH, MAX_BLOCKS_PER_REQUEST
from lean_spec.subspecs.sync.peer_manager import (
    INITIAL_PEER_SCORE,
    SCORE_SUCCESS_BONUS,
    PeerManager,
    SyncPeer,
)
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import MockNetworkRequester, make_signed_block


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
    """Provide a complete BackfillSync with connected peer."""
    manager = PeerManager()
    manager.add_peer(PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED))
    return BackfillSync(
        peer_manager=manager,
        block_cache=BlockCache(),
        network=network,
        is_known_root=lambda root: root in store.blocks,
        get_finalized_slot=lambda: store.latest_finalized.slot,
    )


class TestBackfillChainResolution:
    """Tests for resolving chains of missing parents."""

    async def test_fetch_single_missing_block(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """Fetching a single missing block adds it to cache."""
        block = make_signed_block(
            slot=Slot(10),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        block_root = network.add_block(block)

        await backfill_system.fill_missing([block_root])

        cached = backfill_system.block_cache.get(block_root)
        assert cached is not None
        assert cached == PendingBlock(
            block=block,
            root=block_root,
            parent_root=Bytes32.zero(),
            slot=Slot(10),
            received_from=peer_id,
            received_at=cached.received_at,
            backfill_depth=1,
        )

    async def test_recursive_parent_chain_resolution(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """Backfill recursively fetches missing parents up the chain."""
        # Disable gap detection to test pure recursion.
        backfill_system.get_finalized_slot = None

        grandparent = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"\x01" * 32),
        )
        grandparent_root = network.add_block(grandparent)

        parent = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=grandparent_root,
            state_root=Bytes32(b"\x02" * 32),
        )
        parent_root = network.add_block(parent)

        child = make_signed_block(
            slot=Slot(3),
            proposer_index=ValidatorIndex(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x03" * 32),
        )
        child_root = network.add_block(child)

        await backfill_system.fill_missing([child_root])

        child_cached = backfill_system.block_cache.get(child_root)
        parent_cached = backfill_system.block_cache.get(parent_root)
        grandparent_cached = backfill_system.block_cache.get(grandparent_root)

        assert child_cached is not None
        assert child_cached == PendingBlock(
            block=child,
            root=child_root,
            parent_root=parent_root,
            slot=Slot(3),
            received_from=peer_id,
            received_at=child_cached.received_at,
            backfill_depth=1,
        )

        assert parent_cached is not None
        assert parent_cached == PendingBlock(
            block=parent,
            root=parent_root,
            parent_root=grandparent_root,
            slot=Slot(2),
            received_from=peer_id,
            received_at=parent_cached.received_at,
            backfill_depth=2,
        )

        assert grandparent_cached is not None
        assert grandparent_cached == PendingBlock(
            block=grandparent,
            root=grandparent_root,
            parent_root=Bytes32.zero(),
            slot=Slot(1),
            received_from=peer_id,
            received_at=grandparent_cached.received_at,
            backfill_depth=3,
        )

    async def test_depth_limit_stops_infinite_recursion(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
    ) -> None:
        """Backfill stops at MAX_BACKFILL_DEPTH to prevent infinite recursion."""
        root = Bytes32(b"\x01" * 32)

        await backfill_system.fill_missing([root], depth=MAX_BACKFILL_DEPTH)

        assert network.request_log == []
        assert root not in backfill_system.block_cache

    async def test_skips_already_cached_blocks(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """Blocks already in cache are not re-requested."""
        block = make_signed_block(
            slot=Slot(5),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        block_root = network.add_block(block)

        backfill_system.block_cache.add(block, peer_id)

        await backfill_system.fill_missing([block_root])

        assert network.request_log == []


class TestBatchingAndPeerManagement:
    """Tests for request batching and peer interaction."""

    async def test_large_request_split_into_batches(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
        peer_id: PeerId,
    ) -> None:
        """Requests larger than MAX_BLOCKS_PER_REQUEST are split."""
        num_roots = MAX_BLOCKS_PER_REQUEST + 5
        roots = [Bytes32(i.to_bytes(32, "big")) for i in range(num_roots)]

        await backfill_system.fill_missing(roots)

        assert network.request_log == [
            (peer_id, roots[:MAX_BLOCKS_PER_REQUEST]),
            (peer_id, roots[MAX_BLOCKS_PER_REQUEST:]),
        ]

    async def test_no_requests_without_available_peer(
        self,
        network: MockNetworkRequester,
    ) -> None:
        """No requests made when no peers are available."""
        manager = PeerManager()
        backfill = BackfillSync(
            peer_manager=manager,
            block_cache=BlockCache(),
            network=network,
        )

        await backfill.fill_missing([Bytes32(b"\x01" * 32)])

        assert network.request_log == []

    async def test_network_failure_handled_gracefully(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
    ) -> None:
        """Network failures don't crash and pending state is cleaned up."""
        network.should_fail = True
        root = Bytes32(b"\x01" * 32)

        await backfill_system.fill_missing([root])

        assert backfill_system._pending == set()


class TestRequestTracking:
    """Tests for request in-flight tracking."""

    async def test_empty_response_does_not_leak_requests_in_flight(
        self,
        peer_id: PeerId,
        network: MockNetworkRequester,
    ) -> None:
        """Empty response completes the request, keeping the peer available."""
        manager = PeerManager()
        info = PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED)
        manager.add_peer(info)
        backfill = BackfillSync(
            peer_manager=manager,
            block_cache=BlockCache(),
            network=network,
        )

        # Request a root the network doesn't have (returns empty).
        unknown_root = Bytes32(b"\xff" * 32)
        await backfill.fill_missing([unknown_root])

        peer = manager.get_peer(peer_id)
        assert peer == SyncPeer(
            info=info,
            requests_in_flight=0,
            score=INITIAL_PEER_SCORE + SCORE_SUCCESS_BONUS,
        )

    async def test_in_flight_deduplication(
        self,
        backfill_system: BackfillSync,
        network: MockNetworkRequester,
    ) -> None:
        """Duplicate fill_missing calls for the same root make only one request."""
        block = make_signed_block(
            slot=Slot(5),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        root = network.add_block(block)

        # First call fetches the block (may also try to fetch its parent).
        await backfill_system.fill_missing([root])
        requests_after_first = len(network.request_log)
        assert requests_after_first >= 1

        # Second call: root is now in cache, so no new request.
        await backfill_system.fill_missing([root])
        assert len(network.request_log) == requests_after_first

    async def test_retry_after_failure_clears_pending(
        self,
        peer_id: PeerId,
    ) -> None:
        """Failed request clears pending so a retry can succeed."""
        network = MockNetworkRequester()
        manager = PeerManager()
        manager.add_peer(PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED))
        backfill = BackfillSync(
            peer_manager=manager,
            block_cache=BlockCache(),
            network=network,
        )

        block = make_signed_block(
            slot=Slot(5),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        root = network.add_block(block)

        # First call fails.
        network.should_fail = True
        await backfill.fill_missing([root])
        assert backfill._pending == set()

        # Second call succeeds.
        network.should_fail = False
        await backfill.fill_missing([root])
        assert root in backfill.block_cache

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
