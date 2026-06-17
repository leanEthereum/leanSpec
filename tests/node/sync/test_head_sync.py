"""Tests for head synchronization module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

import pytest

from consensus_testing import MockForkchoiceStore, make_signed_block
from lean_spec.node.networking import PeerId
from lean_spec.node.sync.backfill_sync import BackfillSync
from lean_spec.node.sync.block_cache import BlockCache
from lean_spec.node.sync.head_sync import HeadSync
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import SignedBlock
from lean_spec.spec.ssz import Bytes32, Uint64


@dataclass
class NullBackfillSync:
    """Backfill stub that records fill_missing calls without doing real work."""

    fill_missing_calls: list[list[Bytes32]] = field(default_factory=list)

    async def fill_missing(self, roots: list[Bytes32]) -> None:
        """Record the call without performing any backfill."""
        self.fill_missing_calls.append(roots)

    async def fill_gap_above_head(self, target_slot: Slot, head_slot: Slot) -> bool:
        """Report no range fetch so routing falls back to root recursion."""
        return target_slot > head_slot + Slot(1)


def _null_backfill() -> BackfillSync:
    """Create a NullBackfillSync cast to BackfillSync for type safety."""
    return cast(BackfillSync, NullBackfillSync())


class TestGossipBlockProcessing:
    """Tests for processing gossip blocks with known parents."""

    @pytest.fixture
    def genesis_setup(self, genesis_block) -> tuple[Bytes32, Store]:
        """Provide genesis root and store with genesis block."""
        genesis_root = hash_tree_root(genesis_block)
        store = MockForkchoiceStore()
        store.blocks[genesis_root] = genesis_block
        return genesis_root, cast(Store, store)

    async def test_block_with_known_parent_processed_immediately(
        self,
        genesis_setup: tuple[Bytes32, Store],
        peer_id: PeerId,
    ) -> None:
        """Block whose parent is in store is processed immediately."""
        genesis_root, store = genesis_setup
        processed_blocks: list[Bytes32] = []

        def track_processing(s: Any, block: SignedBlock) -> Any:
            root = hash_tree_root(block.block)
            processed_blocks.append(root)
            new_store = MockForkchoiceStore()
            new_store.blocks = dict(s.blocks)
            new_store.blocks[root] = block.block
            return new_store

        head_sync = HeadSync(
            block_cache=BlockCache(),
            backfill=_null_backfill(),
            process_block=track_processing,
        )

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.block)

        new_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert new_store is not None
        assert block_root in processed_blocks

    async def test_block_with_unknown_parent_cached_and_triggers_backfill(
        self,
        peer_id: PeerId,
    ) -> None:
        """Block whose parent is unknown is cached and backfill is triggered."""
        store = cast(Store, MockForkchoiceStore())
        backfill = NullBackfillSync()

        head_sync = HeadSync(
            block_cache=BlockCache(),
            backfill=cast(BackfillSync, backfill),
            process_block=lambda s, b: s,
        )

        unknown_parent = Bytes32(b"\x01" * 32)
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=unknown_parent,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.block)

        result_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result_store is None
        assert block_root in head_sync.block_cache
        assert head_sync.block_cache.orphan_count == 1
        assert backfill.fill_missing_calls == [[unknown_parent]]

    async def test_duplicate_block_skipped(
        self,
        genesis_setup: tuple[Bytes32, Store],
        peer_id: PeerId,
    ) -> None:
        """Block already in store is skipped without processing."""
        genesis_root, store = genesis_setup

        # Add a block that's already in the store
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.block)
        store.blocks[block_root] = block.block

        call_count = 0

        def should_not_be_called(s: Any, b: SignedBlock) -> Any:
            nonlocal call_count
            call_count += 1
            return s

        head_sync = HeadSync(
            block_cache=BlockCache(),
            backfill=_null_backfill(),
            process_block=should_not_be_called,
        )

        result_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result_store is None
        assert call_count == 0


class TestDescendantProcessing:
    """Tests for processing cached descendants when parent arrives."""

    async def test_cached_children_processed_when_parent_arrives(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """When a parent block is processed, its cached children are processed too."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        # Create parent and child
        parent = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        parent_root = hash_tree_root(parent.block)

        child = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x02" * 32),
        )
        child_root = hash_tree_root(child.block)

        # Pre-cache the child (waiting for parent)
        block_cache.add(child, peer_id)

        processing_order: list[Bytes32] = []

        def track_processing(s: Any, block: SignedBlock) -> Any:
            root = hash_tree_root(block.block)
            processing_order.append(root)
            new_store = MockForkchoiceStore()
            new_store.blocks = dict(s.blocks)
            new_store.blocks[root] = block.block
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=track_processing,
        )

        # Process parent - should trigger child processing
        new_store = await head_sync.on_gossip_block(parent, peer_id, store)

        assert new_store is not None
        assert processing_order == [parent_root, child_root]
        assert child_root not in block_cache  # Removed after processing

    async def test_chain_of_descendants_processed_in_slot_order(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Deep chain of descendants is processed in correct slot order."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        # Create chain: slot1 -> slot2 -> slot3 -> slot4
        blocks = []
        parent_root = genesis_root
        for i in range(1, 5):
            block = make_signed_block(
                slot=Slot(i),
                proposer_index=ValidatorIndex(0),
                parent_root=parent_root,
                state_root=Bytes32(bytes([i]) * 32),
            )
            blocks.append(block)
            parent_root = hash_tree_root(block.block)

        # Cache all except the first (which will be gossiped)
        for block in blocks[1:]:
            block_cache.add(block, peer_id)

        processing_order: list[int] = []

        def track_processing(s: Any, block: SignedBlock) -> Any:
            processing_order.append(int(block.block.slot))
            root = hash_tree_root(block.block)
            new_store = MockForkchoiceStore()
            new_store.blocks = dict(s.blocks)
            new_store.blocks[root] = block.block
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=track_processing,
        )

        # Process first block - should cascade to all descendants
        new_store = await head_sync.on_gossip_block(blocks[0], peer_id, store)

        assert new_store is not None
        assert processing_order == [1, 2, 3, 4]


class TestErrorHandling:
    """Tests for error handling during block processing."""

    async def test_processing_error_reported_as_not_processed(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Processing errors are swallowed, reported as not processed, never raised."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block

        def fail_processing(s: Any, b: SignedBlock) -> Any:
            raise Exception("State transition failed")

        head_sync = HeadSync(
            block_cache=BlockCache(),
            backfill=_null_backfill(),
            process_block=fail_processing,
        )

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        returned_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert returned_store is None


class TestStorePropagation:
    """Tests for store propagation through descendant processing."""

    async def test_store_propagated_through_descendant_chain(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Returned store contains ALL processed blocks, not just the parent."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        # Build chain: parent -> child1 -> child2
        parent = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        parent_root = hash_tree_root(parent.block)

        child1 = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x02" * 32),
        )
        child1_root = hash_tree_root(child1.block)

        child2 = make_signed_block(
            slot=Slot(3),
            proposer_index=ValidatorIndex(0),
            parent_root=child1_root,
            state_root=Bytes32(b"\x03" * 32),
        )
        child2_root = hash_tree_root(child2.block)

        # Pre-cache descendants.
        block_cache.add(child1, peer_id)
        block_cache.add(child2, peer_id)

        def track_processing(s: Any, block: SignedBlock) -> Any:
            root = hash_tree_root(block.block)
            new_store = MockForkchoiceStore()
            new_store.blocks = dict(s.blocks)
            new_store.blocks[root] = block.block
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=track_processing,
        )

        new_store = await head_sync.on_gossip_block(parent, peer_id, store)

        assert new_store is not None
        assert {parent_root, child1_root, child2_root} <= set(new_store.blocks.keys())


# Backfill routing decisions on gossip blocks.
#
# These cover the gap-detection branch in cache-and-backfill:
#
# - Reject blocks at or below the finalized slot (no cache, no backfill).
# - Accept blocks above head with a single-slot gap and route to root recursion.
# - Accept blocks above head with a multi-slot gap and route to range fetch.
# - Accept alt-fork blocks at or below head and route to root recursion.


@dataclass
class _RecordingBackfill:
    """
    Backfill stub recording range and root-recursion requests.

    Used as the I/O boundary mock for head sync's backfill dependency.
    Each method appends its arguments verbatim and performs no real work.
    """

    range_calls: list[tuple[Slot, Uint64]] = field(default_factory=list)
    """Recorded range fetch requests as (start_slot, count)."""

    missing_calls: list[list[Bytes32]] = field(default_factory=list)
    """Recorded root recursion requests, each entry the full roots list."""

    async def fill_range(self, start_slot: Slot, count: Uint64) -> None:
        """Record a range fetch request."""
        self.range_calls.append((start_slot, count))

    async def fill_missing(self, roots: list[Bytes32]) -> None:
        """Record a root recursion request."""
        self.missing_calls.append(roots)

    async def fill_gap_above_head(self, target_slot: Slot, head_slot: Slot) -> bool:
        """Run the real gap arithmetic, recording the range fetch it would issue."""
        if target_slot <= head_slot:
            return False
        gap_floor = head_slot + Slot(1)
        gap_size = int(target_slot - gap_floor)
        if gap_size <= 0:
            return False
        await self.fill_range(start_slot=gap_floor, count=Uint64(gap_size))
        return True


def _backfill() -> tuple[_RecordingBackfill, BackfillSync]:
    """Build a recording backfill double and the BackfillSync-typed view."""
    recorder = _RecordingBackfill()
    return recorder, cast(BackfillSync, recorder)


def _store_with_head(
    *,
    finalized_slot: int,
    head_slot: int,
) -> tuple[Store, Bytes32]:
    """
    Build a mock forkchoice store with a finalized slot and a head block.

    Returns the typed store and the head root. The head block carries the
    requested head slot so subsequent gap math sees the configured value.
    """
    store = MockForkchoiceStore()
    store.latest_finalized = Checkpoint(root=Bytes32.zero(), slot=Slot(finalized_slot))

    head_root = Bytes32(b"\x77" * 32)
    head_block = make_signed_block(
        slot=Slot(head_slot),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32(b"\x88" * 32),
    )
    store.blocks[head_root] = head_block.block
    store.head = head_root
    store.head_slot = Slot(head_slot)
    return cast(Store, store), head_root


def _make_head_sync(backfill: BackfillSync) -> HeadSync:
    """Create a HeadSync wired to the supplied backfill double."""

    def never_called(_s: Any, _b: SignedBlock) -> Any:
        # The cache-and-backfill path must never invoke block processing.
        raise AssertionError("process_block must not be called for cached blocks")

    return HeadSync(
        block_cache=BlockCache(),
        backfill=backfill,
        process_block=never_called,
    )


def _gossip_block(slot: int, parent_root: Bytes32, state_seed: int) -> SignedBlock:
    """Construct a gossip block with the requested slot and parent_root."""
    return make_signed_block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        state_root=Bytes32(bytes([state_seed]) * 32),
    )


class TestRejectionBelowFinalized:
    """Tests for the finalized-slot floor on incoming gossip blocks."""

    async def test_block_at_finalized_slot_is_silently_rejected(self, peer_id: PeerId) -> None:
        """A gossip block at slot equal to finalized is dropped without effect."""
        store, _head_root = _store_with_head(finalized_slot=10, head_slot=10)
        recorder, backfill = _backfill()
        head_sync = _make_head_sync(backfill)

        unknown_parent = Bytes32(b"\x33" * 32)
        block = _gossip_block(slot=10, parent_root=unknown_parent, state_seed=1)
        block_root = hash_tree_root(block.block)

        returned_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert returned_store is None
        assert recorder.range_calls == []
        assert recorder.missing_calls == []
        assert block_root not in head_sync.block_cache

    async def test_block_below_finalized_slot_is_silently_rejected(self, peer_id: PeerId) -> None:
        """A gossip block at slot below finalized is dropped without effect."""
        store, _head_root = _store_with_head(finalized_slot=10, head_slot=20)
        recorder, backfill = _backfill()
        head_sync = _make_head_sync(backfill)

        unknown_parent = Bytes32(b"\x33" * 32)
        block = _gossip_block(slot=5, parent_root=unknown_parent, state_seed=1)
        block_root = hash_tree_root(block.block)

        returned_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert returned_store is None
        assert recorder.range_calls == []
        assert recorder.missing_calls == []
        assert block_root not in head_sync.block_cache


class TestBackfillRoutingAboveHead:
    """Tests for routing between range and root backfill above the head slot."""

    async def test_single_slot_gap_above_head_uses_root_recursion(self, peer_id: PeerId) -> None:
        """A gossip block at exactly head+1 with unknown parent recurses by root."""
        store, _head_root = _store_with_head(finalized_slot=5, head_slot=10)
        recorder, backfill = _backfill()
        head_sync = _make_head_sync(backfill)

        unknown_parent = Bytes32(b"\x44" * 32)
        block = _gossip_block(slot=11, parent_root=unknown_parent, state_seed=1)
        block_root = hash_tree_root(block.block)

        result_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result_store is None
        assert recorder.range_calls == []
        assert recorder.missing_calls == [[unknown_parent]]
        assert block_root in head_sync.block_cache

    async def test_multi_slot_gap_above_head_uses_range_fetch(self, peer_id: PeerId) -> None:
        """A gossip block far above head triggers a contiguous range fetch."""
        store, _head_root = _store_with_head(finalized_slot=10, head_slot=20)
        recorder, backfill = _backfill()
        head_sync = _make_head_sync(backfill)

        unknown_parent = Bytes32(b"\x55" * 32)
        block = _gossip_block(slot=100, parent_root=unknown_parent, state_seed=1)
        block_root = hash_tree_root(block.block)

        result_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result_store is None
        # gap_floor = head+1 = 21, gap_size = 100 - 21 = 79.
        assert recorder.range_calls == [(Slot(21), Uint64(79))]
        assert recorder.missing_calls == []
        assert block_root in head_sync.block_cache


class TestAltForkRoutingAtOrBelowHead:
    """Tests for alt-fork gossip handling when the slot is at or below head."""

    async def test_alt_fork_block_below_head_above_finalized_uses_root_recursion(
        self, peer_id: PeerId
    ) -> None:
        """An alt-fork block at slot below head and above finalized recurses by root."""
        store, _head_root = _store_with_head(finalized_slot=10, head_slot=20)
        recorder, backfill = _backfill()
        head_sync = _make_head_sync(backfill)

        unknown_parent = Bytes32(b"\x66" * 32)
        block = _gossip_block(slot=15, parent_root=unknown_parent, state_seed=1)
        block_root = hash_tree_root(block.block)

        result_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result_store is None
        assert recorder.range_calls == []
        assert recorder.missing_calls == [[unknown_parent]]
        assert block_root in head_sync.block_cache
