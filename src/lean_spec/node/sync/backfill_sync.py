"""Backfill synchronization for resolving orphan blocks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from itertools import batched
from typing import Protocol

from lean_spec.node.networking.config import MAX_REQUEST_BLOCKS
from lean_spec.node.networking.transport.peer_id import PeerId
from lean_spec.node.sync.block_cache import BlockCache
from lean_spec.node.sync.config import MAX_BACKFILL_DEPTH
from lean_spec.node.sync.peer_manager import PeerManager
from lean_spec.spec.forks import SignedBlock, Slot
from lean_spec.spec.ssz import Bytes32, Uint64

logger = logging.getLogger(__name__)


class StoreView(Protocol):
    """Read-only view of forkchoice state used by backfill."""

    def has_root(self, root: Bytes32) -> bool:
        """Return True if the block root is present in the store."""
        ...

    def head_slot(self) -> Slot:
        """Return the slot of the current canonical head."""
        ...


class NetworkRequester(Protocol):
    """Network source of blocks for backfill."""

    async def request_blocks_by_root(
        self,
        peer_id: PeerId,
        roots: list[Bytes32],
    ) -> list[SignedBlock]:
        """
        Request blocks by root from one peer.

        Returns the blocks the peer held; fewer than requested if it lacked some, empty on error.
        """
        ...

    async def request_blocks_by_range(
        self,
        peer_id: PeerId,
        start_slot: Slot,
        count: Uint64,
    ) -> list[SignedBlock]:
        """
        Request blocks by slot range from one peer, starting inclusive.

        Returns the blocks the peer held; empty slots are skipped, empty on error.
        """
        ...


@dataclass(slots=True)
class BackfillSync:
    """
    Resolves orphan blocks by fetching their missing parent chains.

    This fetches parents into the cache only.
    Processing and integrating the fetched blocks is the caller's job.

    Single-threaded async; concurrent calls are not supported.
    """

    peer_manager: PeerManager
    """Peer manager for selecting request targets."""

    block_cache: BlockCache
    """Block cache holding orphan blocks."""

    network: NetworkRequester
    """Network interface for block requests."""

    store_view: StoreView
    """Read-only window into the store, for known-root and gap checks."""

    _pending: set[Bytes32] = field(default_factory=set)
    """Roots currently being fetched, to avoid duplicate requests."""

    _max_range_slot: Slot | None = field(default=None)
    """
    Highest slot covered by a range request, or None before any.

    Advances only on an authoritative answer, so a non-covering empty reply can be retried.
    """

    async def fill_missing(
        self,
        roots: list[Bytes32],
        depth: int = 0,
    ) -> None:
        """
        Fetch missing blocks by root, recursing into parents that are also missing.

        Entry point for backfill.
        The depth argument is internal recursion bookkeeping; callers leave it at zero.
        """
        if depth >= MAX_BACKFILL_DEPTH:
            # Stop without erroring: deep chains may be legitimate but exceed what backfill fetches.
            return

        # Filter out roots we are already fetching or have cached.
        roots_to_fetch = [
            root for root in roots if root not in self._pending and root not in self.block_cache
        ]
        if not roots_to_fetch:
            return

        # Mark roots as pending to avoid duplicate requests.
        self._pending.update(roots_to_fetch)
        try:
            # A by-root request carries at most the wire limit of roots.
            # A wider set becomes several round-trips.
            for batch in batched(roots_to_fetch, MAX_REQUEST_BLOCKS):
                # No slot floor: these roots map to unknown slots, so any peer might hold them.
                peer = self.peer_manager.select_peer_for_request()
                if peer is None:
                    # Not an error: peers may reconnect later.
                    continue

                peer.on_request_start()
                try:
                    blocks = await self.network.request_blocks_by_root(
                        peer_id=peer.peer_id, roots=list(batch)
                    )
                    # Empty or not, the request completed; release the in-flight slot.
                    self.peer_manager.on_request_success(peer.peer_id)
                    if blocks:
                        await self._process_received_blocks(blocks, peer.peer_id, depth)
                except Exception:
                    self.peer_manager.on_request_failure(peer.peer_id)
        finally:
            self._pending.difference_update(roots_to_fetch)

    async def fill_range(
        self,
        start_slot: Slot,
        count: Uint64,
        depth: int = 0,
    ) -> None:
        """Fetch a contiguous slot range in one sweep, cheaper than recursing parent-by-parent."""
        if depth >= MAX_BACKFILL_DEPTH:
            return
        if count == Uint64(0):
            return

        # Skip slots a previous authoritative fetch already covered.
        # A failed or non-covering fetch leaves the watermark, so a retry can re-cover them.
        watermark = self._max_range_slot
        if watermark is None or start_slot > watermark:
            actual_start = start_slot
        else:
            actual_start = watermark + Slot(1)
        end_slot = start_slot + Slot(int(count) - 1)

        if end_slot < actual_start:
            logger.debug(
                "Skipping range fetch [%s, %s]: already covered (watermark=%s)",
                start_slot,
                end_slot,
                watermark,
            )
            return

        # Each request is bounded by the wire limit, so a wider range becomes several round-trips.
        for batch in batched(range(int(actual_start), int(end_slot) + 1), MAX_REQUEST_BLOCKS):
            batch_start = Slot(batch[0])
            last_slot = Slot(batch[-1])

            # Prefer a peer that claims the whole batch; fall back to any peer.
            peer = self.peer_manager.select_peer_for_request(min_slot=last_slot)
            peer_claims_range = peer is not None
            if peer is None:
                peer = self.peer_manager.select_peer_for_request()
            if peer is None:
                continue

            peer.on_request_start()
            try:
                blocks = await self.network.request_blocks_by_range(
                    peer_id=peer.peer_id,
                    start_slot=batch_start,
                    count=Uint64(len(batch)),
                )
            except Exception as exception:
                # Leave the watermark untouched so a retry against another peer can re-cover it.
                logger.warning("Range fetch failed from %s: %s", peer.peer_id, exception)
                self.peer_manager.on_request_failure(peer.peer_id)
                continue

            self.peer_manager.on_request_success(peer.peer_id)

            # Mark the range covered only on an authoritative answer.
            # A peer that claimed it, or that returned blocks, has covered it.
            # An empty reply from a fallback peer has not: another peer may still hold it.
            if peer_claims_range or blocks:
                self._max_range_slot = (
                    last_slot
                    if self._max_range_slot is None
                    else max(self._max_range_slot, last_slot)
                )

            if blocks:
                await self._process_received_blocks(blocks, peer.peer_id, depth)

    async def fill_gap_above_head(
        self,
        target_slot: Slot,
        head_slot: Slot,
        depth: int = 0,
    ) -> bool:
        """
        Range-fetch the gap between the head and a target slot above it.

        The floor is the head slot, not finalized: slots at or below head are already in the store.
        Returns whether a fetch was issued.
        """
        if target_slot <= head_slot:
            return False

        gap_floor = head_slot + Slot(1)
        gap_size = int(target_slot - gap_floor)
        if gap_size <= 0:
            return False

        logger.debug(
            "Backfill gap (%d slots) above head %s; range-fetching from %s.",
            gap_size,
            head_slot,
            gap_floor,
        )
        await self.fill_range(start_slot=gap_floor, count=Uint64(gap_size), depth=depth)
        return True

    async def _process_received_blocks(
        self,
        blocks: list[SignedBlock],
        peer_id: PeerId,
        depth: int,
    ) -> None:
        """Cache received blocks and recurse into any that are themselves orphans."""
        new_orphan_parents: list[Bytes32] = []

        for block in blocks:
            pending = self.block_cache.add(block=block, peer=peer_id, backfill_depth=depth + 1)

            # A block is an orphan when its parent is in neither the cache nor the store.
            parent_root = pending.parent_root
            parent_known = parent_root in self.block_cache or self.store_view.has_root(parent_root)
            if not parent_known:
                self.block_cache.mark_orphan(pending.root)
                if parent_root not in self._pending:
                    new_orphan_parents.append(parent_root)

        if not new_orphan_parents:
            return

        # When the missing parent sits far above what we know, fetch the gap as a
        # contiguous range rather than recursing parent-by-parent.
        if blocks:
            earliest_block = min(blocks, key=lambda b: b.block.slot)
            await self.fill_gap_above_head(
                target_slot=earliest_block.block.slot,
                head_slot=self.store_view.head_slot(),
                depth=depth + 1,
            )

        await self.fill_missing(new_orphan_parents, depth=depth + 1)
