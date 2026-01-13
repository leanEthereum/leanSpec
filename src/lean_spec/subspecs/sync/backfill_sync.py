"""
Backfill synchronization for resolving orphan blocks.

When a block arrives whose parent is unknown, we need to fetch that parent.
If the parent also has an unknown parent, we continue recursively. This process
is called "backfill" because we are filling in gaps going backward in time.

The Challenge
-------------
Blocks can arrive out of order for several reasons:

1. **Gossip timing**: A child block gossips faster than its parent
2. **Parallel downloads**: Responses arrive in different order than requests
3. **Network partitions**: Some blocks were missed during a brief disconnect

Without backfill, these orphan blocks would be useless. With backfill, we can
resolve them once their parents arrive or are explicitly fetched.

How It Works
------------
1. Track orphan blocks in the BlockCache
2. When an orphan is detected, request its parent from peers
3. If the fetched parent is also an orphan, request its parent
4. Continue recursively up to MAX_BACKFILL_DEPTH (512)
5. Once a parent chain is complete, process all waiting blocks

This is more memory-efficient than downloading the entire chain upfront,
and handles dynamic gaps naturally.

Depth Limiting
--------------
Backfill depth is limited to prevent attacks and resource exhaustion:

- An attacker could send a block claiming to have a parent millions of slots ago
- Without limits, we would exhaust memory trying to fetch the entire chain
- MAX_BACKFILL_DEPTH (512) covers legitimate reorgs while bounding resources
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.networking import PeerId
from lean_spec.types import Bytes32

from .block_cache import BlockCache
from .config import MAX_BACKFILL_DEPTH, MAX_BLOCKS_PER_REQUEST
from .peer_manager import PeerManager


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
    ) -> list[SignedBlockWithAttestation]:
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


@dataclass(slots=True)
class BackfillSync:
    """
    Resolves orphan blocks by fetching missing parent chains.

    BackfillSync is the reactive component of the sync service. When blocks
    arrive with unknown parents, this class orchestrates fetching those parents.

    How It Works
    ------------
    1. **Detection**: BlockCache marks blocks as orphans when added
    2. **Request**: BackfillSync requests missing parents from peers
    3. **Recursion**: If fetched parents are also orphans, continue fetching
    4. **Resolution**: When parent chain is complete, blocks become processable

    Integration
    -----------
    BackfillSync does not process blocks itself. It only ensures parents exist
    in the BlockCache. The SyncService is responsible for:

    - Calling `fill_missing()` when orphans are detected
    - Processing blocks when they become processable
    - Integrating blocks into the Store

    Thread Safety
    -------------
    This class is designed for single-threaded async operation. The `_pending`
    set tracks in-flight requests to avoid duplicate fetches.
    """

    peer_manager: PeerManager
    """Peer manager for selecting request targets."""

    block_cache: BlockCache
    """Block cache holding orphan blocks."""

    network: NetworkRequester
    """Network interface for block requests."""

    _pending: set[Bytes32] = field(default_factory=set)
    """Roots currently being fetched (to avoid duplicate requests)."""

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
                # Request succeeded.
                self.peer_manager.on_request_success(peer.peer_id)

                # Add blocks to cache and check for further orphans.
                await self._process_received_blocks(blocks, peer.peer_id, depth)
            else:
                # Empty response. Peer may not have the blocks.
                # This is not necessarily a failure (blocks may not exist).
                pass

        except Exception:
            # Network error.
            self.peer_manager.on_request_failure(peer.peer_id)

    async def _process_received_blocks(
        self,
        blocks: list[SignedBlockWithAttestation],
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

            # Check if this block's parent is known.
            #
            # A block is orphan if its parent is not in the cache.
            # (We cannot check the Store here; that is the SyncService's job.)
            parent_root = pending.parent_root
            if parent_root not in self.block_cache:
                # Parent unknown. Mark as orphan and queue for fetch.
                self.block_cache.mark_orphan(pending.root)
                if parent_root not in self._pending:
                    new_orphan_parents.append(parent_root)

        # Recursively fetch orphan parents.
        if new_orphan_parents:
            await self.fill_missing(new_orphan_parents, depth=depth + 1)

    async def fill_all_orphans(self) -> None:
        """
        Fetch parents for all current orphan blocks.

        Convenience method that fetches the parent roots of all blocks
        currently marked as orphans in the cache.
        """
        orphan_parents = self.block_cache.get_orphan_parents()
        if orphan_parents:
            await self.fill_missing(orphan_parents)

    def reset(self) -> None:
        """Clear all pending state."""
        self._pending.clear()
