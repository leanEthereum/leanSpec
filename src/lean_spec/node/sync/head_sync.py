"""Head synchronization via gossip: process blocks whose parent is known, cache the rest."""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from lean_spec.node.networking.transport.peer_id import PeerId
from lean_spec.node.sync.backfill_sync import BackfillSync
from lean_spec.node.sync.block_cache import BlockCache
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import SignedBlock, Store
from lean_spec.spec.ssz import Bytes32

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class HeadSync:
    """Event-driven head follower: integrates gossip blocks or caches them for later."""

    block_cache: BlockCache
    """Cache for blocks awaiting parent resolution."""

    backfill: BackfillSync
    """Backfill syncer for fetching missing parents."""

    process_block: Callable[[Store, SignedBlock], Store]
    """Integrates a block into the store and returns the new store."""

    async def on_gossip_block(
        self,
        block: SignedBlock,
        peer_id: PeerId | None,
        store: Store,
    ) -> Store | None:
        """
        Handle a block received via gossip.

        Args:
            block: The signed block received via gossip.
            peer_id: The peer that sent the block.
            store: Current fork-choice store.

        Returns:
            The updated store, or None if the block was cached instead of processed.
        """
        block_inner = block.block
        block_root = hash_tree_root(block_inner)

        # Skip a duplicate already in the store.
        if block_root in store.blocks:
            return None

        # Parent missing: cache the block, backfill the gap, and leave the store untouched.
        if block_inner.parent_root not in store.blocks:
            # Reject blocks at or below the finalized slot.
            #
            # Such a block cannot be canonical.
            # It is most likely stale or replayed gossip from a misbehaving peer.
            # Dropping it here also stops the gap math below from underflowing.
            finalized_slot = store.latest_finalized.slot
            if block_inner.slot <= finalized_slot:
                logger.debug(
                    "Ignoring gossip block at slot %s: at or below finalized (%s)",
                    block_inner.slot,
                    finalized_slot,
                )
                return None

            cached_block = self.block_cache.add(block=block, peer=peer_id)
            self.block_cache.mark_orphan(cached_block.root)

            # A multi-slot gap above head is fetched as one contiguous range.
            # A smaller gap, or alt-fork gossip at or below head, recurses by parent root instead.
            head_slot = store.blocks[store.head].slot
            range_fetched = await self.backfill.fill_gap_above_head(
                target_slot=block_inner.slot,
                head_slot=head_slot,
            )
            if not range_fetched:
                await self.backfill.fill_missing([block_inner.parent_root])
            return None

        # Parent known: process the block. A failure leaves the store untouched.
        try:
            store = self.process_block(store, block)
        except Exception as exception:
            logger.debug(
                "Gossip block processing failed at slot %s: %s", block_inner.slot, exception
            )
            return None
        self.block_cache.remove(block_root)

        # Drain the chain of cached descendants this block unlocks, oldest slot first.
        # A deque keeps this iterative, so a long chain cannot exhaust the stack.
        unlocked_parents: deque[Bytes32] = deque([block_root])
        while unlocked_parents:
            for child in self.block_cache.get_children(unlocked_parents.popleft()):
                # A child may already have landed via another path.
                if child.root in store.blocks:
                    self.block_cache.remove(child.root)
                    continue
                try:
                    store = self.process_block(store, child.block)
                except Exception as exception:
                    # One bad block must not abort its siblings; drop it and keep draining.
                    # The failure is deterministic, so it would not succeed on retry.
                    logger.debug(
                        "Gossip block processing failed at slot %s: %s", child.slot, exception
                    )
                    continue
                self.block_cache.remove(child.root)
                unlocked_parents.append(child.root)

        return store
