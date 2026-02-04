"""
Head synchronization via gossip.

Once a node is close to the chain head, it primarily receives new blocks via
gossip rather than explicit requests. HeadSync manages this event-driven mode
of operation.

How It Works
------------
1. **Gossip arrives**: A new block is received via gossip subscription
2. **Check parent**: Does the parent exist in our Store?
3. **If yes**: Process immediately and check for cached descendants
4. **If no**: Cache the block and trigger backfill for the parent

This is more efficient than polling because:
- Blocks arrive as soon as they are produced
- No wasted requests for non-existent blocks
- Natural handling of out-of-order arrivals

Descendant Processing
---------------------
When a parent block arrives (either via gossip or backfill), there may be
cached children waiting for it:

1. Process the newly arrived block
2. Check the cache for blocks whose parent is this block
3. Process those children (recursively)
4. Continue until no more descendants are found

This ensures that chains of blocks are processed efficiently once their
common ancestor arrives.

Error Handling
--------------
Block processing can fail for various reasons:

- Invalid signatures
- State transition failures
- Inconsistent state roots

HeadSync reports these failures to the PeerManager for scoring but does not
crash. A single invalid block should not halt synchronization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32

from .backfill_sync import BackfillSync
from .block_cache import BlockCache

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class HeadSyncResult:
    """
    Result of processing a gossip block.

    Provides detailed feedback about what happened when a block was received.
    This allows the SyncService to make informed decisions about state.
    """

    processed: bool
    """True if the block was immediately integrated into the Store."""

    cached: bool
    """True if the block was added to the cache (parent unknown)."""

    backfill_triggered: bool
    """True if backfill was initiated for missing parents."""

    descendants_processed: int
    """Number of cached descendants that were also processed."""

    error: str | None = None
    """Error message if processing failed."""


@dataclass(slots=True)
class HeadSync:
    """
    Event-driven head following via gossip.

    HeadSync is the reactive component of the sync service. It processes
    blocks as they arrive from gossip, integrating them into the Store when
    possible or caching them for later processing.

    How It Works
    ------------
    When a gossip block arrives:

    1. **Check Store**: Is the parent already in our Store?
       - Yes: Process immediately via `store.on_block()`
       - No: Cache the block and trigger backfill

    2. **If processed**: Check cache for descendants
       - Process any cached blocks whose parent is now known
       - Repeat recursively

    3. **Return result**: Report what happened for state machine decisions

    Integration
    -----------
    HeadSync receives blocks but does not own the Store. The SyncService must:

    - Call `on_gossip_block()` when gossip blocks arrive
    - Apply the returned Store updates
    - Use the result to update sync state

    This separation ensures the Store remains the single source of truth.
    """

    block_cache: BlockCache
    """Cache for blocks awaiting parent resolution."""

    backfill: BackfillSync
    """Backfill syncer for fetching missing parents."""

    process_block: Callable[[Store, SignedBlockWithAttestation], Store]
    """
    Function to process a block into the Store.

    This is injected to allow flexibility in block processing.

    The default implementation uses `store.on_block()`, but tests can inject mocks.

    Signature: (store, block) -> new_store
    Raises: Exception on validation failure
    """

    _processing: set[Bytes32] = field(default_factory=set)
    """Blocks currently being processed (to avoid reentrant processing)."""

    async def on_gossip_block(
        self,
        block: SignedBlockWithAttestation,
        peer_id: PeerId,
        store: Store,
    ) -> tuple[HeadSyncResult, Store]:
        """
        Handle a block received via gossip.

        This is the main entry point for gossip blocks. It determines whether
        the block can be processed immediately or must be cached.

        Args:
            block: The signed block received via gossip.
            peer_id: The peer that sent the block.
            store: Current forkchoice store.

        Returns:
            Tuple of (result describing what happened, updated store).
            The store is unchanged if the block was cached.
        """
        block_inner = block.message.block
        block_root = hash_tree_root(block_inner)
        parent_root = block_inner.parent_root
        slot = block_inner.slot

        logger.debug(
            "on_gossip_block: slot=%s root=%s parent=%s",
            slot,
            block_root.hex()[:8],
            parent_root.hex()[:8],
        )

        # Skip if already processing (reentrant call).
        if block_root in self._processing:
            logger.debug("on_gossip_block: skipping - already processing")
            return HeadSyncResult(
                processed=False,
                cached=False,
                backfill_triggered=False,
                descendants_processed=0,
            ), store

        # Skip if already in store (duplicate).
        if block_root in store.blocks:
            logger.debug("on_gossip_block: skipping - already in store")
            return HeadSyncResult(
                processed=False,
                cached=False,
                backfill_triggered=False,
                descendants_processed=0,
            ), store

        # Check if parent exists in store.
        if parent_root in store.blocks:
            # Parent known. Process immediately.
            logger.debug("on_gossip_block: parent found, processing")
            return await self._process_block_with_descendants(
                block=block,
                peer_id=peer_id,
                store=store,
            )
        else:
            # Parent unknown. Cache and trigger backfill.
            logger.debug(
                "on_gossip_block: parent NOT found, caching. store has %d blocks",
                len(store.blocks),
            )
            return await self._cache_and_backfill(
                block=block,
                peer_id=peer_id,
                store=store,
            )

    async def _process_block_with_descendants(
        self,
        block: SignedBlockWithAttestation,
        peer_id: PeerId,
        store: Store,
    ) -> tuple[HeadSyncResult, Store]:
        """
        Process a block and any cached descendants.

        When a block is processed, there may be cached blocks waiting for it.
        This method implements the recursive descendant processing pattern.

        Args:
            block: Block to process.
            peer_id: Peer that sent the block.
            store: Current store.

        Returns:
            Result and updated store.
        """
        block_root = hash_tree_root(block.message.block)
        slot = block.message.block.slot
        self._processing.add(block_root)

        try:
            # Process the main block.
            try:
                logger.debug("_process_block: calling process_block for slot %s", slot)
                store = self.process_block(store, block)
                logger.debug(
                    "_process_block_with_descendants: SUCCESS for slot %s, store now has %d blocks",
                    slot,
                    len(store.blocks),
                )
            except Exception as e:
                logger.debug(
                    "_process_block_with_descendants: FAILED for slot %s: %s",
                    slot,
                    e,
                )
                return HeadSyncResult(
                    processed=False,
                    cached=False,
                    backfill_triggered=False,
                    descendants_processed=0,
                    error=str(e),
                ), store

            # Process cached descendants.
            descendants_count = await self._process_cached_descendants(
                parent_root=block_root,
                store=store,
                peer_id=peer_id,
            )

            return HeadSyncResult(
                processed=True,
                cached=False,
                backfill_triggered=False,
                descendants_processed=descendants_count,
            ), store

        finally:
            self._processing.discard(block_root)

    async def _process_cached_descendants(
        self,
        parent_root: Bytes32,
        store: Store,
        peer_id: PeerId,
    ) -> int:
        """
        Process any cached blocks that descend from the given parent.

        Processing pattern:
        - Find children in cache whose parent is `parent_root`
        - Process each child
        - Recursively process their descendants
        - Remove processed blocks from cache

        Args:
            parent_root: Root of the parent block just processed.
            store: Current store (may be updated during processing).
            peer_id: Peer ID for error attribution.

        Returns:
            Number of descendants successfully processed.
        """
        processed_count = 0

        # Get children from cache.
        children = self.block_cache.get_children(parent_root)

        for child in children:
            child_root = child.root

            # Skip if already processing or in store.
            if child_root in self._processing:
                continue
            if child_root in store.blocks:
                self.block_cache.remove(child_root)
                continue

            self._processing.add(child_root)

            try:
                # Process the child block.
                try:
                    store = self.process_block(store, child.block)
                    processed_count += 1

                    # Remove from cache after successful processing.
                    self.block_cache.remove(child_root)

                    # Unmark orphan status.
                    self.block_cache.unmark_orphan(child_root)

                    # Recursively process this child's descendants.
                    processed_count += await self._process_cached_descendants(
                        parent_root=child_root,
                        store=store,
                        peer_id=peer_id,
                    )

                except Exception:
                    # Processing failed. Leave in cache for retry or discard.
                    # Do not cascade the error; continue with other children.
                    pass

            finally:
                self._processing.discard(child_root)

        return processed_count

    async def _cache_and_backfill(
        self,
        block: SignedBlockWithAttestation,
        peer_id: PeerId,
        store: Store,
    ) -> tuple[HeadSyncResult, Store]:
        """
        Cache a block and trigger backfill for its parent.

        Called when a block's parent is not in the store. The block is
        cached and backfill is initiated to fetch the missing parent.

        Args:
            block: Block to cache.
            peer_id: Peer that sent the block.
            store: Current store (unchanged).

        Returns:
            Result indicating the block was cached, and unchanged store.
        """
        block_inner = block.message.block
        parent_root = block_inner.parent_root

        # Add to cache.
        pending = self.block_cache.add(block=block, peer=peer_id)

        # Mark as orphan.
        self.block_cache.mark_orphan(pending.root)

        # Trigger backfill for the missing parent.
        await self.backfill.fill_missing([parent_root])

        return HeadSyncResult(
            processed=False,
            cached=True,
            backfill_triggered=True,
            descendants_processed=0,
        ), store

    async def process_all_processable(self, store: Store) -> tuple[int, Store]:
        """
        Process all blocks in the cache that now have parents in the store.

        Called after backfill completes or store updates to process any
        blocks that have become processable.

        Args:
            store: Current store.

        Returns:
            Tuple of (count of blocks processed, updated store).
        """
        processed_count = 0

        while True:
            # Get processable blocks (parents in store).
            processable = self.block_cache.get_processable(store)
            if not processable:
                break

            for pending in processable:
                if pending.root in self._processing:
                    continue
                if pending.root in store.blocks:
                    self.block_cache.remove(pending.root)
                    continue

                self._processing.add(pending.root)

                try:
                    try:
                        store = self.process_block(store, pending.block)
                        processed_count += 1
                        self.block_cache.remove(pending.root)
                        self.block_cache.unmark_orphan(pending.root)

                    except Exception:
                        # Processing failed. Remove from cache to avoid infinite loop.
                        self.block_cache.remove(pending.root)

                finally:
                    self._processing.discard(pending.root)

        return processed_count, store

    def reset(self) -> None:
        """Clear processing state."""
        self._processing.clear()
