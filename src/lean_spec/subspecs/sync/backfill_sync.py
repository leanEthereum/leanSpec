"""
Backfill synchronization for resolving orphan blocks.

When a block arrives whose parent is unknown, we need to fetch that parent.
If the parent also has an unknown parent, we continue recursively. This process
is called "backfill" because we are filling in gaps going backward in time.

The Challenge

Blocks can arrive out of order for several reasons:

1. **Gossip timing**: A child block gossips faster than its parent
2. **Parallel downloads**: Responses arrive in different order than requests
3. **Network partitions**: Some blocks were missed during a brief disconnect

Without backfill, these orphan blocks would be useless. With backfill, we can
resolve them once their parents arrive or are explicitly fetched.

How It Works

1. Track orphan blocks in the BlockCache
2. When an orphan is detected, request its parent from peers
3. If the fetched parent is also an orphan, request its parent
4. Continue recursively up to MAX_BACKFILL_DEPTH (512)
5. Once a parent chain is complete, process all waiting blocks

This is more memory-efficient than downloading the entire chain upfront,
and handles dynamic gaps naturally.

Depth Limiting

Backfill depth is limited to prevent attacks and resource exhaustion:

- An attacker could send a block claiming to have a parent millions of slots ago
- Without limits, we would exhaust memory trying to fetch the entire chain
- MAX_BACKFILL_DEPTH (512) covers legitimate reorgs while bounding resources
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from lean_spec.forks.lstar.containers import SignedBlock, Slot
from lean_spec.subspecs.networking.config import MAX_REQUEST_BLOCKS
from lean_spec.subspecs.networking.transport.peer_id import PeerId
from lean_spec.types import Bytes32, Uint64

from .block_cache import BlockCache
from .config import MAX_BACKFILL_DEPTH, MAX_BLOCKS_PER_REQUEST
from .peer_manager import PeerManager

logger = logging.getLogger(__name__)


class StoreView(Protocol):
    """
    Read-only view of forkchoice state used by backfill.

    Used to skip blocks already in the Store and to find the highest known
    canonical slot for gap detection.

    Decouples backfill from the concrete Store class.
    Lets tests supply a tiny in-memory implementation.
    """

    def has_root(self, root: Bytes32) -> bool:
        """Return True if the block root is present in the Store."""
        ...

    def finalized_slot(self) -> Slot:
        """Return the slot of the latest finalized checkpoint."""
        ...

    def head_slot(self) -> Slot:
        """Return the slot of the current canonical head."""
        ...


class NetworkRequester(Protocol):
    """
    Protocol for network block requests.

    This abstraction allows the sync service to request blocks without
    depending on a specific network implementation. The actual implementation
    will use libp2p and the BlocksByRoot protocol.

    Implementers should:
    - Handle request timeouts internally
    - Return empty list on network errors (not raise exceptions)
    - Track request success/failure for peer scoring
    """

    async def request_blocks_by_root(
        self,
        peer_id: PeerId,
        roots: list[Bytes32],
    ) -> list[SignedBlock]:
        """
        Request blocks by root from a specific peer.

        Args:
            peer_id: The peer to request from.
            roots: Block roots to request (up to MAX_REQUEST_BLOCKS).

        Returns:
            List of blocks the peer returned. May be fewer than requested
            if the peer does not have all blocks. Empty on error.
        """
        ...

    async def request_blocks_by_range(
        self,
        peer_id: PeerId,
        start_slot: Slot,
        count: Uint64,
    ) -> list[SignedBlock]:
        """
        Request blocks by slot range from a specific peer.

        Args:
            peer_id: Peer to request from.
            start_slot: Start slot of the range (inclusive).
            count: Number of blocks to request (up to MAX_REQUEST_BLOCKS).

        Returns:
            List of blocks the peer returned. May be fewer than requested
            if the peer does not have all blocks (empty slots are skipped).
            Empty on error.
        """
        ...


@dataclass(slots=True)
class BackfillSync:
    """
    Resolves orphan blocks by fetching missing parent chains.

    BackfillSync is the reactive component of the sync service. When blocks
    arrive with unknown parents, this class orchestrates fetching those parents.

    How It Works

    1. **Detection**: BlockCache marks blocks as orphans when added
    2. **Request**: BackfillSync requests missing parents from peers
    3. **Recursion**: If fetched parents are also orphans, continue fetching
    4. **Resolution**: When parent chain is complete, blocks become processable

    Integration

    BackfillSync does not process blocks itself. It only ensures parents exist
    in the BlockCache. The SyncService is responsible for:

    - Triggering backfill when orphans are detected
    - Processing blocks when they become processable
    - Integrating blocks into the Store

    Thread Safety

    This class is designed for single-threaded async operation. The `_pending`
    set tracks in-flight requests to avoid duplicate fetches.
    """

    peer_manager: PeerManager
    """Peer manager for selecting request targets."""

    block_cache: BlockCache
    """Block cache holding orphan blocks."""

    network: NetworkRequester
    """Network interface for block requests."""

    store_view: StoreView | None = field(default=None)
    """Read-only window into the Store.

    Used for known-root and gap checks.

    When None, backfill recurses by root only.
    No short-circuiting for blocks already in the Store.
    No range fills on detected gaps.
    Production callers must supply a view.
    """

    _pending: set[Bytes32] = field(default_factory=set)
    """Roots currently being fetched (to avoid duplicate requests)."""

    _max_range_slot: Slot = field(default_factory=lambda: Slot(0))
    """Highest slot covered by a successfully completed range request.

    Advanced only when the peer answers without raising — success or empty result.

    On exception, the watermark is left untouched.
    A subsequent call can then retry the same range, possibly via a different peer.
    """

    async def fill_missing(
        self,
        roots: list[Bytes32],
        depth: int = 0,
    ) -> None:
        """
        Fetch missing blocks by root.

        This is the main entry point for backfill. It requests the specified
        roots from peers and recursively fetches any parents that are also
        missing.

        Args:
            roots: Block roots to fetch.
            depth: Current recursion depth (for internal tracking).
                   Callers should not set this; it defaults to 0.

        Note:
            This method is async and may take significant time if many
            blocks need to be fetched recursively.
        """
        if depth >= MAX_BACKFILL_DEPTH:
            # Depth limit reached. Stop fetching to prevent resource exhaustion.
            # This is a safety measure, not an error. Deep chains may be
            # legitimate but we cannot fetch them via backfill.
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
            # Fetch in batches to respect request limits.
            for batch_start in range(0, len(roots_to_fetch), MAX_BLOCKS_PER_REQUEST):
                batch = roots_to_fetch[batch_start : batch_start + MAX_BLOCKS_PER_REQUEST]
                await self._fetch_batch(batch, depth)
        finally:
            # Always clear pending status, even on error.
            self._pending.difference_update(roots_to_fetch)

    async def fill_range(
        self,
        start_slot: Slot,
        count: Uint64,
        depth: int = 0,
    ) -> None:
        """
        Fetch missing blocks by slot range.

        This is a more efficient alternative to fill_missing when a large
        contiguous gap is detected.

        Args:
            start_slot: Start slot of the range.
            count: Number of blocks to request.
            depth: Current backfill depth.
        """
        if depth >= MAX_BACKFILL_DEPTH:
            return

        if count == Uint64(0):
            return

        # Skip slots already covered by a previous successful range fetch.
        # The watermark tracks the highest answered slot; earlier slots need not
        # be re-requested. Failed fetches do not advance the watermark, so a
        # retry can still re-cover the range.
        watermark = self._max_range_slot
        actual_start = start_slot if start_slot > watermark else watermark + Slot(1)
        end_slot = start_slot + Slot(int(count) - 1)

        if end_slot < actual_start:
            logger.debug(
                "Skipping range fetch [%s, %s]: already covered (watermark=%s)",
                start_slot,
                end_slot,
                watermark,
            )
            return

        # Split into per-message batches.
        #
        # Each network request is bounded by MAX_REQUEST_BLOCKS, so a wider
        # range becomes several round-trips here.
        current_slot = actual_start
        remaining = int(end_slot) - int(current_slot) + 1

        while remaining > 0:
            batch_count = min(remaining, MAX_REQUEST_BLOCKS)
            await self._fetch_range(current_slot, Uint64(batch_count), depth)
            current_slot = current_slot + Slot(batch_count)
            remaining -= batch_count

    async def _fetch_range(
        self,
        start_slot: Slot,
        count: Uint64,
        depth: int,
    ) -> None:
        """Fetch a range of blocks from a peer."""
        last_slot = start_slot + Slot(int(count) - 1)
        peer = self.peer_manager.select_peer_for_request(min_slot=last_slot)
        if peer is None:
            # Fallback to any peer if no one reports having the whole range.
            peer = self.peer_manager.select_peer_for_request()

        if peer is None:
            return

        peer.on_request_start()
        try:
            blocks = await self.network.request_blocks_by_range(
                peer_id=peer.peer_id,
                start_slot=start_slot,
                count=count,
            )
        except Exception as e:
            # Peer-side failure.
            #
            # Do not advance the watermark.
            # A retry against another peer can still re-cover the range.
            logger.warning("Range fetch failed from %s: %s", peer.peer_id, e)
            self.peer_manager.on_request_failure(peer.peer_id)
            return

        # The peer answered: success or empty.
        # Mark the range as covered so future range fills can skip it.
        self._max_range_slot = max(self._max_range_slot, last_slot)
        self.peer_manager.on_request_success(peer.peer_id)

        if blocks:
            await self._process_received_blocks(blocks, peer.peer_id, depth)

    async def _fetch_batch(
        self,
        roots: list[Bytes32],
        depth: int,
    ) -> None:
        """
        Fetch a batch of blocks from a peer.

        Selects the best available peer and requests the blocks. If the peer
        returns blocks, they are added to the cache and checked for orphan
        parents.

        Args:
            roots: Block roots to fetch (already filtered and limited).
            depth: Current backfill depth.
        """
        # Select a peer to request from.
        #
        # We do not specify a min_slot because we do not know what slots
        # these roots correspond to. Any connected peer might have them.
        peer = self.peer_manager.select_peer_for_request()
        if peer is None:
            # No available peers. Cannot proceed.
            # This is not an error; peers may reconnect later.
            return

        # Mark request in-flight for load tracking.
        peer.on_request_start()

        try:
            blocks = await self.network.request_blocks_by_root(
                peer_id=peer.peer_id,
                roots=roots,
            )

            if blocks:
                # Request succeeded with data.
                self.peer_manager.on_request_success(peer.peer_id)

                # Add blocks to cache and check for further orphans.
                await self._process_received_blocks(blocks, peer.peer_id, depth)
            else:
                # Empty response. Peer may not have the blocks.
                # Still a completed request — release the in-flight slot.
                self.peer_manager.on_request_success(peer.peer_id)

        except Exception:
            # Network error.
            self.peer_manager.on_request_failure(peer.peer_id)

    async def _process_received_blocks(
        self,
        blocks: list[SignedBlock],
        peer_id: PeerId,
        depth: int,
    ) -> None:
        """
        Process blocks received from a peer.

        Adds blocks to the cache and identifies any that are themselves
        orphans. If orphan parents are found, recursively fetches them.

        Args:
            blocks: Blocks received from the peer.
            peer_id: The peer that sent the blocks.
            depth: Current backfill depth.
        """
        new_orphan_parents: list[Bytes32] = []

        for block in blocks:
            # Add to cache with backfill depth tracking.
            pending = self.block_cache.add(
                block=block,
                peer=peer_id,
                backfill_depth=depth + 1,
            )

            # A block is an orphan if its parent is not in the cache or in the Store.
            parent_root = pending.parent_root
            parent_known = parent_root in self.block_cache or (
                self.store_view.has_root(parent_root) if self.store_view is not None else False
            )

            if not parent_known:
                # Parent unknown. Mark as orphan and queue for fetch.
                self.block_cache.mark_orphan(pending.root)
                if parent_root not in self._pending:
                    new_orphan_parents.append(parent_root)

        if not new_orphan_parents:
            return

        # When the earliest received block still has a missing parent far above
        # the highest slot we already know, fetching the gap as a contiguous
        # range is cheaper than recursing parent-by-parent.
        #
        # Floor the range at the head slot (highest known canonical slot), not
        # at the finalized slot. Slots above finalized but at or below head are
        # already in the Store and should not be re-downloaded.
        if self.store_view is not None and blocks:
            earliest_block = min(blocks, key=lambda b: b.block.slot)
            head_slot = self.store_view.head_slot()
            if earliest_block.block.slot > head_slot:
                gap_floor = head_slot + Slot(1)
                gap_size = int(earliest_block.block.slot - gap_floor)
                if gap_size > 0:
                    logger.debug(
                        "Backfill gap (%d slots) at slot %s; range-fetching from %s.",
                        gap_size,
                        earliest_block.block.slot,
                        gap_floor,
                    )
                    await self.fill_range(
                        start_slot=gap_floor,
                        count=Uint64(gap_size),
                        depth=depth + 1,
                    )

        await self.fill_missing(new_orphan_parents, depth=depth + 1)

    def reset(self) -> None:
        """Clear all pending state."""
        self._pending.clear()
        self._max_range_slot = Slot(0)
