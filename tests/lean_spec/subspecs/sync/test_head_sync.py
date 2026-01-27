"""Tests for head synchronization module."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.backfill_sync import BackfillSync
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.head_sync import HeadSync
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import make_signed_block


class MockStore:
    """Mock store that tracks which blocks exist."""

    def __init__(self, existing_roots: set[Bytes32] | None = None) -> None:
        """Initialize with optional existing block roots."""
        self.blocks: dict[Bytes32, object] = {}
        if existing_roots:
            for root in existing_roots:
                self.blocks[root] = MagicMock()


class TestGossipBlockProcessing:
    """Tests for processing gossip blocks with known parents."""

    @pytest.fixture
    def genesis_setup(self, genesis_block) -> tuple[Bytes32, Store]:
        """Provide genesis root and store with genesis block."""
        genesis_root = hash_tree_root(genesis_block)
        mock_store = MockStore({genesis_root})
        mock_store.blocks[genesis_root] = genesis_block
        return genesis_root, cast(Store, mock_store)

    def test_block_with_known_parent_processed_immediately(
        self,
        genesis_setup: tuple[Bytes32, Store],
        peer_id: PeerId,
    ) -> None:
        """Block whose parent is in store is processed immediately."""
        genesis_root, store = genesis_setup
        processed_blocks: list[Bytes32] = []

        def track_processing(s: Any, block: SignedBlockWithAttestation) -> Any:
            root = hash_tree_root(block.message.block)
            processed_blocks.append(root)
            new_store = MockStore(set(s.blocks.keys()) | {root})
            return new_store

        head_sync = HeadSync(
            block_cache=BlockCache(),
            backfill=MagicMock(spec=BackfillSync),
            process_block=track_processing,
        )

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.message.block)

        result, new_store = asyncio.run(head_sync.on_gossip_block(block, peer_id, store))

        assert result.processed is True
        assert result.cached is False
        assert result.backfill_triggered is False
        assert block_root in processed_blocks

    def test_block_with_unknown_parent_cached_and_triggers_backfill(
        self,
        peer_id: PeerId,
    ) -> None:
        """Block whose parent is unknown is cached and backfill is triggered."""
        store = cast(Store, MockStore())
        backfill = MagicMock(spec=BackfillSync)
        backfill.fill_missing = AsyncMock()

        head_sync = HeadSync(
            block_cache=BlockCache(),
            backfill=backfill,
            process_block=MagicMock(),
        )

        unknown_parent = Bytes32(b"\x01" * 32)
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=unknown_parent,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.message.block)

        result, _ = asyncio.run(head_sync.on_gossip_block(block, peer_id, store))

        assert result.processed is False
        assert result.cached is True
        assert result.backfill_triggered is True
        assert block_root in head_sync.block_cache
        assert head_sync.block_cache.orphan_count == 1
        backfill.fill_missing.assert_called_once_with([unknown_parent])

    def test_duplicate_block_skipped(
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
        block_root = hash_tree_root(block.message.block)
        store.blocks[block_root] = block.message.block

        process_block = MagicMock()
        head_sync = HeadSync(
            block_cache=BlockCache(),
            backfill=MagicMock(spec=BackfillSync),
            process_block=process_block,
        )

        result, _ = asyncio.run(head_sync.on_gossip_block(block, peer_id, store))

        assert result.processed is False
        assert result.cached is False
        process_block.assert_not_called()


class TestDescendantProcessing:
    """Tests for processing cached descendants when parent arrives."""

    def test_cached_children_processed_when_parent_arrives(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """When a parent block is processed, its cached children are processed too."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockStore({genesis_root}))
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        # Create parent and child
        parent = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32(b"\x01" * 32),
        )
        parent_root = hash_tree_root(parent.message.block)

        child = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=parent_root,
            state_root=Bytes32(b"\x02" * 32),
        )
        child_root = hash_tree_root(child.message.block)

        # Pre-cache the child (waiting for parent)
        block_cache.add(child, peer_id)

        processing_order: list[Bytes32] = []

        def track_processing(s: Any, block: SignedBlockWithAttestation) -> Any:
            root = hash_tree_root(block.message.block)
            processing_order.append(root)
            new_store = MockStore(set(s.blocks.keys()) | {root})
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=MagicMock(spec=BackfillSync),
            process_block=track_processing,
        )

        # Process parent - should trigger child processing
        result, _ = asyncio.run(head_sync.on_gossip_block(parent, peer_id, store))

        assert result.processed is True
        assert result.descendants_processed == 1
        assert processing_order == [parent_root, child_root]
        assert child_root not in block_cache  # Removed after processing

    def test_chain_of_descendants_processed_in_slot_order(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Deep chain of descendants is processed in correct slot order."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockStore({genesis_root}))
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
            parent_root = hash_tree_root(block.message.block)

        # Cache all except the first (which will be gossiped)
        for block in blocks[1:]:
            block_cache.add(block, peer_id)

        processing_order: list[int] = []

        def track_processing(s: Any, block: SignedBlockWithAttestation) -> Any:
            processing_order.append(int(block.message.block.slot))
            root = hash_tree_root(block.message.block)
            new_store = MockStore(set(s.blocks.keys()) | {root})
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=MagicMock(spec=BackfillSync),
            process_block=track_processing,
        )

        # Process first block - should cascade to all descendants
        result, _ = asyncio.run(head_sync.on_gossip_block(blocks[0], peer_id, store))

        assert result.processed is True
        assert result.descendants_processed == 3
        assert processing_order == [1, 2, 3, 4]


class TestProcessAllProcessable:
    """Tests for batch processing of processable blocks."""

    def test_processes_all_blocks_with_known_parents(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """All blocks whose parents are in store are processed."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockStore({genesis_root}))
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

        def count_processing(s: Any, block: SignedBlockWithAttestation) -> Any:
            nonlocal processed_count
            processed_count += 1
            root = hash_tree_root(block.message.block)
            new_store = MockStore(set(s.blocks.keys()) | {root})
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=MagicMock(spec=BackfillSync),
            process_block=count_processing,
        )

        count, _ = asyncio.run(head_sync.process_all_processable(store))

        assert count == 2
        assert processed_count == 2
        assert len(block_cache) == 0  # Both removed

    def test_processing_failure_removes_block_from_cache(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Failed blocks are removed to prevent infinite retry loops."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockStore({genesis_root}))
        store.blocks[genesis_root] = genesis_block
        block_cache = BlockCache()

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.message.block)
        block_cache.add(block, peer_id)

        def fail_processing(s: Any, b: SignedBlockWithAttestation) -> Any:
            raise Exception("Validation failed")

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=MagicMock(spec=BackfillSync),
            process_block=fail_processing,
        )

        count, _ = asyncio.run(head_sync.process_all_processable(store))

        assert count == 0
        assert block_root not in block_cache  # Removed despite failure


class TestErrorHandling:
    """Tests for error handling during block processing."""

    def test_processing_error_captured_in_result(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Processing errors are captured in the result, not raised."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockStore({genesis_root}))
        store.blocks[genesis_root] = genesis_block

        def fail_processing(s: Any, b: SignedBlockWithAttestation) -> Any:
            raise Exception("State transition failed")

        head_sync = HeadSync(
            block_cache=BlockCache(),
            backfill=MagicMock(spec=BackfillSync),
            process_block=fail_processing,
        )

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        result, returned_store = asyncio.run(head_sync.on_gossip_block(block, peer_id, store))

        assert result.processed is False
        assert result.error == "State transition failed"
        assert returned_store is store  # Original store returned on error

    def test_sibling_error_does_not_block_other_siblings(
        self,
        genesis_block,
        peer_id: PeerId,
    ) -> None:
        """Error processing one child doesn't prevent processing siblings."""
        genesis_root = hash_tree_root(genesis_block)
        store = cast(Store, MockStore({genesis_root}))
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

        def fail_first(s: Any, block: SignedBlockWithAttestation) -> Any:
            nonlocal call_count
            call_count += 1
            root = hash_tree_root(block.message.block)
            if call_count == 1:
                raise Exception("First fails")
            successful_roots.add(root)
            new_store = MockStore(set(s.blocks.keys()) | {root})
            return new_store

        head_sync = HeadSync(
            block_cache=block_cache,
            backfill=MagicMock(spec=BackfillSync),
            process_block=fail_first,
        )

        count, _ = asyncio.run(head_sync.process_all_processable(store))

        assert call_count == 2  # Both attempted
        assert count == 1  # One succeeded
        assert len(successful_roots) == 1
