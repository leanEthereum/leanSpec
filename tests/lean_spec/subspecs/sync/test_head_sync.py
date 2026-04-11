"""Tests for head synchronization module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

import pytest

from lean_spec.subspecs.containers import SignedBlock
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.backfill_sync import BackfillSync
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.head_sync import HeadSync, HeadSyncResult
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import MockForkchoiceStore, make_signed_block


@dataclass
class NullBackfillSync:
    """Backfill stub that records fill_missing calls without doing real work."""

    fill_missing_calls: list[list[Bytes32]] = field(default_factory=list)

    async def fill_missing(self, roots: list[Bytes32]) -> None:
        """Record the call without performing any backfill."""
        self.fill_missing_calls.append(roots)


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
            new_store.blocks[root] = object()
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

        result, new_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=True,
            cached=False,
            backfill_triggered=False,
            descendants_processed=0,
        )
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

        result, _ = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=True,
            backfill_triggered=True,
            descendants_processed=0,
        )
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

        result, _ = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=False,
            backfill_triggered=False,
            descendants_processed=0,
        )
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
            new_store.blocks[root] = object()
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=track_processing,
        )

        # Process parent - should trigger child processing
        result, _ = await head_sync.on_gossip_block(parent, peer_id, store)

        assert result == HeadSyncResult(
            processed=True,
            cached=False,
            backfill_triggered=False,
            descendants_processed=1,
        )
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
            new_store.blocks[root] = object()
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=track_processing,
        )

        # Process first block - should cascade to all descendants
        result, _ = await head_sync.on_gossip_block(blocks[0], peer_id, store)

        assert result == HeadSyncResult(
            processed=True,
            cached=False,
            backfill_triggered=False,
            descendants_processed=3,
        )
        assert processing_order == [1, 2, 3, 4]


class TestProcessAllProcessable:
    """Tests for batch processing of processable blocks."""

    async def test_processes_all_blocks_with_known_parents(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """All blocks whose parents are in store are processed."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        # Create two independent blocks with genesis as parent
        block1 = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        block2 = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(1),
            parent_root=genesis_root,
            state_root=Bytes32(b"\x02" * 32),
        )

        block_cache.add(block1, peer_id)
        block_cache.add(block2, peer_id)

        processed_count = 0

        def count_processing(s: Any, block: SignedBlock) -> Any:
            nonlocal processed_count
            processed_count += 1
            root = hash_tree_root(block.block)
            new_store = MockForkchoiceStore()
            new_store.blocks = dict(s.blocks)
            new_store.blocks[root] = object()
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=count_processing,
        )

        count, _ = await head_sync.process_all_processable(store)

        assert count == 2
        assert processed_count == 2
        assert len(block_cache) == 0  # Both removed

    async def test_processing_failure_removes_block_from_cache(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Failed blocks are removed to prevent infinite retry loops."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.block)
        block_cache.add(block, peer_id)

        def fail_processing(s: Any, b: SignedBlock) -> Any:
            raise Exception("Validation failed")

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=fail_processing,
        )

        count, _ = await head_sync.process_all_processable(store)

        assert count == 0
        assert block_root not in block_cache  # Removed despite failure


class TestErrorHandling:
    """Tests for error handling during block processing."""

    async def test_processing_error_captured_in_result(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Processing errors are captured in the result, not raised."""
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

        result, returned_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=False,
            backfill_triggered=False,
            descendants_processed=0,
            error="State transition failed",
        )
        assert returned_store is store  # Original store returned on error

    async def test_sibling_error_does_not_block_other_siblings(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Error processing one child doesn't prevent processing siblings."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        # Two siblings
        block1 = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32(b"\x01" * 32),
        )

        block2 = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(1),
            parent_root=genesis_root,
            state_root=Bytes32(b"\x02" * 32),
        )

        block_cache.add(block1, peer_id)
        block_cache.add(block2, peer_id)

        call_count = 0
        successful_roots: set[Bytes32] = set()

        def fail_first(s: Any, block: SignedBlock) -> Any:
            nonlocal call_count
            call_count += 1
            root = hash_tree_root(block.block)
            if call_count == 1:
                raise Exception("First fails")
            successful_roots.add(root)
            new_store = MockForkchoiceStore()
            new_store.blocks = dict(s.blocks)
            new_store.blocks[root] = object()
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=fail_first,
        )

        count, _ = await head_sync.process_all_processable(store)

        assert call_count == 2  # Both attempted
        assert count == 1  # One succeeded
        assert len(successful_roots) == 1


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
            new_store.blocks[root] = object()
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=track_processing,
        )

        result, new_store = await head_sync.on_gossip_block(parent, peer_id, store)

        assert result == HeadSyncResult(
            processed=True,
            cached=False,
            backfill_triggered=False,
            descendants_processed=2,
        )
        assert {parent_root, child1_root, child2_root} <= set(new_store.blocks.keys())


class TestReentrantGuard:
    """Tests for reentrant processing guard."""

    async def test_reentrant_call_returns_not_processed(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Block already in _processing returns processed=False, cached=False."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block

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

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.block)

        # Simulate reentrant call by pre-adding to _processing.
        head_sync._processing.add(block_root)

        result, returned_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=False,
            backfill_triggered=False,
            descendants_processed=0,
        )
        assert returned_store is store
        assert call_count == 0


class TestProcessAllProcessableConvergence:
    """Tests for process_all_processable convergence."""

    async def test_chain_processed_in_single_call(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Chain A -> B -> C all processed in one process_all_processable call."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockForkchoiceStore())
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        # Build chain: A -> B -> C, all with genesis as ultimate ancestor.
        block_a = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        root_a = hash_tree_root(block_a.block)

        block_b = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=root_a,
            state_root=Bytes32(b"\x02" * 32),
        )
        root_b = hash_tree_root(block_b.block)

        block_c = make_signed_block(
            slot=Slot(3),
            proposer_index=ValidatorIndex(0),
            parent_root=root_b,
            state_root=Bytes32(b"\x03" * 32),
        )

        block_cache.add(block_a, peer_id)
        block_cache.add(block_b, peer_id)
        block_cache.add(block_c, peer_id)

        processing_order: list[int] = []

        def track_processing(s: Any, block: SignedBlock) -> Any:
            processing_order.append(int(block.block.slot))
            root = hash_tree_root(block.block)
            new_store = MockForkchoiceStore()
            new_store.blocks = dict(s.blocks)
            new_store.blocks[root] = object()
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=_null_backfill(),
            process_block=track_processing,
        )

        count, _ = await head_sync.process_all_processable(store)

        assert count == 3
        assert processing_order == [1, 2, 3]
        assert len(block_cache) == 0
