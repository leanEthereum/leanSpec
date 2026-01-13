"""Tests for block cache module."""

from __future__ import annotations

from time import time
from unittest.mock import MagicMock

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.block_cache import BlockCache, PendingBlock
from lean_spec.subspecs.sync.config import MAX_CACHED_BLOCKS
from lean_spec.types import Bytes32, Uint64

from .conftest import create_signed_block


class TestPendingBlock:
    """Tests for PendingBlock dataclass."""

    def test_create_pending_block(self, peer_id: PeerId) -> None:
        """PendingBlock can be created with required fields."""
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        root = hash_tree_root(block.message.block)

        pending = PendingBlock(
            block=block,
            root=root,
            parent_root=block.message.block.parent_root,
            slot=block.message.block.slot,
            received_from=peer_id,
        )

        assert pending.block == block
        assert pending.root == root
        assert pending.parent_root == Bytes32.zero()
        assert pending.slot == Slot(1)
        assert pending.received_from == peer_id
        assert pending.backfill_depth == 0

    def test_pending_block_default_received_at(self, peer_id: PeerId) -> None:
        """PendingBlock sets received_at to current time by default."""
        before = time()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        root = hash_tree_root(block.message.block)

        pending = PendingBlock(
            block=block,
            root=root,
            parent_root=Bytes32.zero(),
            slot=Slot(1),
            received_from=peer_id,
        )
        after = time()

        assert before <= pending.received_at <= after

    def test_pending_block_custom_backfill_depth(self, peer_id: PeerId) -> None:
        """PendingBlock can be created with custom backfill depth."""
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        root = hash_tree_root(block.message.block)

        pending = PendingBlock(
            block=block,
            root=root,
            parent_root=Bytes32.zero(),
            slot=Slot(1),
            received_from=peer_id,
            backfill_depth=5,
        )

        assert pending.backfill_depth == 5


class TestBlockCacheBasicOperations:
    """Tests for basic BlockCache operations."""

    def test_empty_cache(self) -> None:
        """New BlockCache is empty."""
        cache = BlockCache()

        assert len(cache) == 0
        assert cache.is_empty
        assert cache.orphan_count == 0

    def test_add_block(self, peer_id: PeerId) -> None:
        """Adding a block stores it in the cache."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)

        assert len(cache) == 1
        assert not cache.is_empty
        assert pending.block == block
        assert pending.received_from == peer_id

    def test_contains_block(self, peer_id: PeerId) -> None:
        """Contains check works for cached blocks."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)

        assert pending.root in cache
        assert Bytes32(b"\xff" * 32) not in cache

    def test_get_block(self, peer_id: PeerId) -> None:
        """Getting a block by root returns the PendingBlock."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)
        retrieved = cache.get(pending.root)

        assert retrieved is not None
        assert retrieved == pending

    def test_get_nonexistent_block(self) -> None:
        """Getting a nonexistent block returns None."""
        cache = BlockCache()

        result = cache.get(Bytes32.zero())

        assert result is None

    def test_remove_block(self, peer_id: PeerId) -> None:
        """Removing a block returns it and removes from cache."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)
        removed = cache.remove(pending.root)

        assert removed == pending
        assert len(cache) == 0
        assert pending.root not in cache

    def test_remove_nonexistent_block(self) -> None:
        """Removing a nonexistent block returns None."""
        cache = BlockCache()

        result = cache.remove(Bytes32.zero())

        assert result is None

    def test_clear_cache(self, peer_id: PeerId) -> None:
        """Clear removes all blocks from the cache."""
        cache = BlockCache()
        for i in range(5):
            block = create_signed_block(
                slot=Slot(i + 1),
                proposer_index=Uint64(0),
                parent_root=Bytes32(i.to_bytes(32, "big")),
                state_root=Bytes32.zero(),
            )
            cache.add(block, peer_id)

        assert len(cache) == 5

        cache.clear()

        assert len(cache) == 0
        assert cache.is_empty
        assert cache.orphan_count == 0


class TestBlockCacheDeduplication:
    """Tests for block deduplication in BlockCache."""

    def test_adding_same_block_twice_returns_existing(self, peer_id: PeerId) -> None:
        """Adding the same block twice returns the existing PendingBlock."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending1 = cache.add(block, peer_id)
        pending2 = cache.add(block, peer_id)

        assert pending1 is pending2
        assert len(cache) == 1

    def test_deduplication_preserves_original_peer(
        self, peer_id: PeerId, peer_id_2: PeerId
    ) -> None:
        """Deduplication keeps the original peer, not the second sender."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending1 = cache.add(block, peer_id)
        pending2 = cache.add(block, peer_id_2)

        assert pending2.received_from == peer_id  # Original peer preserved
        assert pending1.received_from == peer_id_2 or pending1.received_from == peer_id


class TestBlockCacheOrphanTracking:
    """Tests for orphan block tracking in BlockCache."""

    def test_mark_orphan(self, peer_id: PeerId) -> None:
        """Marking a block as orphan adds it to the orphan set."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)
        cache.mark_orphan(pending.root)

        assert cache.orphan_count == 1

    def test_mark_orphan_idempotent(self, peer_id: PeerId) -> None:
        """Marking the same block as orphan multiple times does not duplicate."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)
        cache.mark_orphan(pending.root)
        cache.mark_orphan(pending.root)

        assert cache.orphan_count == 1

    def test_mark_orphan_nonexistent_block_does_nothing(self) -> None:
        """Marking a nonexistent block as orphan does nothing."""
        cache = BlockCache()

        cache.mark_orphan(Bytes32.zero())

        assert cache.orphan_count == 0

    def test_unmark_orphan(self, peer_id: PeerId) -> None:
        """Unmarking an orphan removes it from the orphan set."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)
        cache.mark_orphan(pending.root)
        cache.unmark_orphan(pending.root)

        assert cache.orphan_count == 0

    def test_unmark_orphan_nonexistent_does_nothing(self) -> None:
        """Unmarking a nonexistent orphan does nothing."""
        cache = BlockCache()

        # Should not raise
        cache.unmark_orphan(Bytes32.zero())

        assert cache.orphan_count == 0

    def test_remove_clears_orphan_status(self, peer_id: PeerId) -> None:
        """Removing a block also removes its orphan status."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)
        cache.mark_orphan(pending.root)

        assert cache.orphan_count == 1

        cache.remove(pending.root)

        assert cache.orphan_count == 0

    def test_get_orphan_parents(self, peer_id: PeerId) -> None:
        """get_orphan_parents returns missing parent roots for orphans."""
        cache = BlockCache()
        parent_root = Bytes32(b"\x01" * 32)
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)
        cache.mark_orphan(pending.root)

        orphan_parents = cache.get_orphan_parents()

        assert len(orphan_parents) == 1
        assert parent_root in orphan_parents

    def test_get_orphan_parents_deduplicates(self, peer_id: PeerId) -> None:
        """get_orphan_parents deduplicates when multiple orphans share a parent."""
        cache = BlockCache()
        common_parent = Bytes32(b"\x01" * 32)

        # Two orphan blocks with the same missing parent
        block1 = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=common_parent,
            state_root=Bytes32.zero(),
        )
        block2 = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=common_parent,
            state_root=Bytes32(b"\x02" * 32),
        )

        pending1 = cache.add(block1, peer_id)
        pending2 = cache.add(block2, peer_id)
        cache.mark_orphan(pending1.root)
        cache.mark_orphan(pending2.root)

        orphan_parents = cache.get_orphan_parents()

        # Should return the common parent only once
        assert len(orphan_parents) == 1
        assert common_parent in orphan_parents

    def test_get_orphan_parents_excludes_cached_parents(self, peer_id: PeerId) -> None:
        """get_orphan_parents excludes parents that are already in the cache."""
        cache = BlockCache()

        # Add a parent block
        parent_block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        parent_pending = cache.add(parent_block, peer_id)

        # Add child block that references the cached parent
        child_block = create_signed_block(
            slot=Slot(2),
            proposer_index=Uint64(0),
            parent_root=parent_pending.root,
            state_root=Bytes32.zero(),
        )
        child_pending = cache.add(child_block, peer_id)
        cache.mark_orphan(child_pending.root)

        orphan_parents = cache.get_orphan_parents()

        # Parent is in cache, so should not be returned
        assert len(orphan_parents) == 0


class TestBlockCacheParentChildIndex:
    """Tests for parent-to-children index in BlockCache."""

    def test_get_children_empty(self) -> None:
        """get_children returns empty list for unknown parent."""
        cache = BlockCache()

        children = cache.get_children(Bytes32.zero())

        assert children == []

    def test_get_children_single_child(self, peer_id: PeerId) -> None:
        """get_children returns the single child of a parent."""
        cache = BlockCache()
        parent_root = Bytes32(b"\x01" * 32)
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)

        children = cache.get_children(parent_root)

        assert len(children) == 1
        assert children[0] == pending

    def test_get_children_multiple_children(self, peer_id: PeerId) -> None:
        """get_children returns all children of a parent."""
        cache = BlockCache()
        parent_root = Bytes32(b"\x01" * 32)

        # Two blocks with the same parent (competing blocks)
        block1 = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32.zero(),
        )
        block2 = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=parent_root,
            state_root=Bytes32(b"\x02" * 32),
        )

        pending1 = cache.add(block1, peer_id)
        pending2 = cache.add(block2, peer_id)

        children = cache.get_children(parent_root)

        assert len(children) == 2
        roots = {c.root for c in children}
        assert pending1.root in roots
        assert pending2.root in roots

    def test_get_children_sorted_by_slot(self, peer_id: PeerId) -> None:
        """get_children returns children sorted by slot."""
        cache = BlockCache()
        parent_root = Bytes32(b"\x01" * 32)

        # Add blocks out of order
        block_slot3 = create_signed_block(
            slot=Slot(3),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x03" * 32),
        )
        block_slot1 = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        block_slot2 = create_signed_block(
            slot=Slot(2),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x02" * 32),
        )

        cache.add(block_slot3, peer_id)
        cache.add(block_slot1, peer_id)
        cache.add(block_slot2, peer_id)

        children = cache.get_children(parent_root)

        assert len(children) == 3
        assert children[0].slot == Slot(1)
        assert children[1].slot == Slot(2)
        assert children[2].slot == Slot(3)

    def test_remove_clears_parent_index(self, peer_id: PeerId) -> None:
        """Removing a block clears it from the parent-to-children index."""
        cache = BlockCache()
        parent_root = Bytes32(b"\x01" * 32)
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)
        assert len(cache.get_children(parent_root)) == 1

        cache.remove(pending.root)

        assert len(cache.get_children(parent_root)) == 0


class TestBlockCacheCapacityManagement:
    """Tests for cache capacity management and FIFO eviction."""

    def test_cache_respects_max_capacity(self, peer_id: PeerId) -> None:
        """Cache does not exceed MAX_CACHED_BLOCKS."""
        cache = BlockCache()

        # Add more blocks than the limit
        for i in range(MAX_CACHED_BLOCKS + 10):
            block = create_signed_block(
                slot=Slot(i + 1),
                proposer_index=Uint64(0),
                parent_root=Bytes32(i.to_bytes(32, "big")),
                state_root=Bytes32((i + 1).to_bytes(32, "big")),
            )
            cache.add(block, peer_id)

        assert len(cache) == MAX_CACHED_BLOCKS

    def test_fifo_eviction_oldest_first(self, peer_id: PeerId) -> None:
        """FIFO eviction removes the oldest blocks first."""
        cache = BlockCache()

        # Track the first blocks added
        first_roots = []
        for i in range(MAX_CACHED_BLOCKS):
            block = create_signed_block(
                slot=Slot(i + 1),
                proposer_index=Uint64(0),
                parent_root=Bytes32(i.to_bytes(32, "big")),
                state_root=Bytes32((i + 1).to_bytes(32, "big")),
            )
            pending = cache.add(block, peer_id)
            if i < 10:  # Track first 10 blocks
                first_roots.append(pending.root)

        # All first blocks should still be present
        for root in first_roots:
            assert root in cache

        # Add 10 more blocks to trigger eviction
        for i in range(10):
            block = create_signed_block(
                slot=Slot(MAX_CACHED_BLOCKS + i + 1),
                proposer_index=Uint64(0),
                parent_root=Bytes32((MAX_CACHED_BLOCKS + i).to_bytes(32, "big")),
                state_root=Bytes32((MAX_CACHED_BLOCKS + i + 1).to_bytes(32, "big")),
            )
            cache.add(block, peer_id)

        # First 10 blocks should have been evicted
        for root in first_roots:
            assert root not in cache

        assert len(cache) == MAX_CACHED_BLOCKS

    def test_eviction_clears_orphan_status(self, peer_id: PeerId) -> None:
        """Evicted blocks have their orphan status cleared."""
        cache = BlockCache()

        # Add a block and mark it as orphan
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32.zero(),
        )
        pending = cache.add(block, peer_id)
        cache.mark_orphan(pending.root)

        assert cache.orphan_count == 1

        # Fill cache to trigger eviction of the first block
        for i in range(MAX_CACHED_BLOCKS):
            new_block = create_signed_block(
                slot=Slot(i + 2),
                proposer_index=Uint64(0),
                parent_root=Bytes32((i + 1).to_bytes(32, "big")),
                state_root=Bytes32((i + 2).to_bytes(32, "big")),
            )
            cache.add(new_block, peer_id)

        # The original orphan should be evicted
        assert pending.root not in cache


class TestBlockCacheProcessable:
    """Tests for get_processable with Store integration."""

    def test_get_processable_empty_cache(self) -> None:
        """get_processable returns empty list for empty cache."""
        cache = BlockCache()
        mock_store = MagicMock()
        mock_store.blocks = {}

        processable = cache.get_processable(mock_store)

        assert processable == []

    def test_get_processable_no_parents_in_store(self, peer_id: PeerId) -> None:
        """get_processable returns empty when no parents are in Store."""
        cache = BlockCache()
        mock_store = MagicMock()
        mock_store.blocks = {}

        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32.zero(),
        )
        cache.add(block, peer_id)

        processable = cache.get_processable(mock_store)

        assert processable == []

    def test_get_processable_finds_block_with_parent_in_store(self, peer_id: PeerId) -> None:
        """get_processable finds blocks whose parents are in Store."""
        cache = BlockCache()
        parent_root = Bytes32(b"\x01" * 32)

        mock_store = MagicMock()
        mock_store.blocks = {parent_root: MagicMock()}

        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32.zero(),
        )
        pending = cache.add(block, peer_id)

        processable = cache.get_processable(mock_store)

        assert len(processable) == 1
        assert processable[0] == pending

    def test_get_processable_sorted_by_slot(self, peer_id: PeerId) -> None:
        """get_processable returns blocks sorted by slot."""
        cache = BlockCache()
        parent_root = Bytes32(b"\x01" * 32)

        mock_store = MagicMock()
        mock_store.blocks = {parent_root: MagicMock()}

        # Add blocks out of order
        block3 = create_signed_block(
            slot=Slot(3),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x03" * 32),
        )
        block1 = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        block2 = create_signed_block(
            slot=Slot(2),
            proposer_index=Uint64(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x02" * 32),
        )

        cache.add(block3, peer_id)
        cache.add(block1, peer_id)
        cache.add(block2, peer_id)

        processable = cache.get_processable(mock_store)

        assert len(processable) == 3
        assert processable[0].slot == Slot(1)
        assert processable[1].slot == Slot(2)
        assert processable[2].slot == Slot(3)


class TestBlockCacheBackfillDepth:
    """Tests for backfill depth tracking."""

    def test_add_with_backfill_depth(self, peer_id: PeerId) -> None:
        """Adding a block with backfill depth tracks the depth."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id, backfill_depth=10)

        assert pending.backfill_depth == 10

    def test_add_default_backfill_depth_is_zero(self, peer_id: PeerId) -> None:
        """Adding a block without backfill depth defaults to 0."""
        cache = BlockCache()
        block = create_signed_block(
            slot=Slot(1),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        pending = cache.add(block, peer_id)

        assert pending.backfill_depth == 0
