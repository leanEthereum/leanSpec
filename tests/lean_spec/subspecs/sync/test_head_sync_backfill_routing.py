"""Tests for backfill routing decisions taken by head sync on gossip blocks.

These cover the gap-detection branch in cache-and-backfill:

- Reject blocks at or below the finalized slot (no cache, no backfill).
- Accept blocks above head with a single-slot gap and route to root recursion.
- Accept blocks above head with a multi-slot gap and route to range fetch.
- Accept alt-fork blocks at or below head and route to root recursion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

from lean_spec.forks.lstar import Store
from lean_spec.forks.lstar.containers import SignedBlock
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.backfill_sync import BackfillSync
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.head_sync import HeadSync, HeadSyncResult
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import MockForkchoiceStore, make_signed_block


@dataclass
class _RecordingBackfill:
    """Backfill stub recording range and root-recursion requests.

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


def _backfill() -> tuple[_RecordingBackfill, BackfillSync]:
    """Build a recording backfill double and the BackfillSync-typed view."""
    recorder = _RecordingBackfill()
    return recorder, cast(BackfillSync, recorder)


def _store_with_head(
    *,
    finalized_slot: int,
    head_slot: int,
) -> tuple[Store, Bytes32]:
    """Build a mock forkchoice store with a finalized slot and a head block.

    Returns the typed store and the head root. The head block carries the
    requested head slot so subsequent gap math sees the configured value.
    """
    store = MockForkchoiceStore()
    store.latest_finalized.slot = Slot(finalized_slot)

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

        result, returned_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=False,
            backfill_triggered=False,
            descendants_processed=0,
        )
        assert returned_store is store
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

        result, returned_store = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=False,
            backfill_triggered=False,
            descendants_processed=0,
        )
        assert returned_store is store
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

        result, _ = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=True,
            backfill_triggered=True,
            descendants_processed=0,
        )
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

        result, _ = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=True,
            backfill_triggered=True,
            descendants_processed=0,
        )
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

        result, _ = await head_sync.on_gossip_block(block, peer_id, store)

        assert result == HeadSyncResult(
            processed=False,
            cached=True,
            backfill_triggered=True,
            descendants_processed=0,
        )
        assert recorder.range_calls == []
        assert recorder.missing_calls == [[unknown_parent]]
        assert block_root in head_sync.block_cache
