"""
Block cache for downloaded blocks awaiting parent resolution.

Why Cache Blocks?
-----------------
In an ideal world, blocks arrive in perfect order: parent before child, always.
Reality differs. Network latency, parallel downloads, and gossip propagation
mean blocks often arrive before their parents are known.

Without caching, we would have two bad choices:

1. **Drop the block**: Wasteful. We will need it later.
2. **Re-request later**: Slow. Network round-trips add latency.

The block cache provides a third option: hold the block until its parent
arrives, then process both.

How It Works
------------
The cache maintains three data structures:

1. **Block storage**: Maps block root to PendingBlock (the block + metadata)
2. **Orphan set**: Roots of blocks whose parents are completely unknown
3. **Parent index**: Maps parent_root to child roots for descendant lookup

When a parent arrives:

1. Look up children via the parent index
2. Check if those children can now be processed
3. Process children in slot order (ensuring parent-before-child)
4. Recursively check if processed children have their own waiting children

Memory Safety
-------------
The cache is bounded by MAX_CACHED_BLOCKS (1024). When full, FIFO eviction
removes the oldest blocks. This prevents memory exhaustion from attacks or
prolonged network partitions that could otherwise grow the cache unboundedly.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from time import time
from typing import TYPE_CHECKING

from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32

from .config import MAX_CACHED_BLOCKS

if TYPE_CHECKING:
    from lean_spec.subspecs.forkchoice import Store


@dataclass(slots=True)
class PendingBlock:
    """
    A block awaiting integration into the Store.

    PendingBlock wraps a SignedBlockWithAttestation with metadata needed for
    cache management. This metadata answers key questions:

    - **Who sent it?** For peer scoring when we determine validity
    - **When did it arrive?** For timeout and staleness decisions
    - **How deep is the backfill?** To enforce MAX_BACKFILL_DEPTH limit

    Blocks remain pending until:

    1. Their parent arrives and they can be processed (success)
    2. They are evicted due to cache capacity limits (dropped)
    3. They are determined to be invalid (rejected)
    """

    block: SignedBlockWithAttestation
    """The complete signed block with attestation payload."""

    root: Bytes32
    """
    The SSZ hash tree root of the block.

    Computed once at cache insertion for efficiency. All subsequent lookups
    and comparisons use this cached value rather than recomputing.
    """

    parent_root: Bytes32
    """
    Root of the parent block.

    Stored separately for quick parent relationship lookups without
    deserializing the full block. This is the key to efficient descendant
    processing.
    """

    slot: Slot
    """
    Slot of the block.

    Used for ordering during batch processing. We must process blocks in
    slot order to ensure parents are processed before children.
    """

    received_from: PeerId
    """
    Peer that sent this block.

    Essential for peer scoring.
        - If the block is valid, the peer gets credit.
        - If invalid, they get penalized.

    This creates incentives for good behavior.
    """

    received_at: float = field(default_factory=time)
    """
    Unix timestamp when the block was received.

    Enables staleness detection and debugging.

    Very old pending blocks may indicate a stuck backfill or network issues.
    """

    backfill_depth: int = 0
    """
    Depth of backfill chain from original request.

    When fetching missing parents recursively, this tracks how deep we are.
        - A block at depth 0 came directly from gossip or an explicit request.
        - A block at depth 5 is the 5th ancestor we fetched while backfilling.

    Blocks with depth >= MAX_BACKFILL_DEPTH trigger backfill termination
    to prevent unbounded recursion during attacks or deep forks.
    """


@dataclass(slots=True)
class BlockCache:
    """
    Cache for blocks awaiting parent resolution.

    Holds blocks that cannot be immediately processed because their parent
    blocks are not yet in the Store.
    """

    _blocks: OrderedDict[Bytes32, PendingBlock] = field(default_factory=OrderedDict)
    """Block storage ordered by insertion time for FIFO eviction."""

    _orphans: set[Bytes32] = field(default_factory=set)
    """Roots of blocks whose parents are completely unknown."""

    _by_parent: defaultdict[Bytes32, set[Bytes32]] = field(default_factory=lambda: defaultdict(set))
    """Parent-to-children index for descendant processing."""

    def __len__(self) -> int:
        """Return the number of cached blocks."""
        return len(self._blocks)

    def __contains__(self, root: Bytes32) -> bool:
        """Check if a block root is in the cache."""
        return root in self._blocks

    def add(
        self,
        block: SignedBlockWithAttestation,
        peer: PeerId,
        backfill_depth: int = 0,
    ) -> PendingBlock:
        """
        Add a block to the cache.

        This is the primary entry point for caching blocks. The method handles:

        1. Deduplication (same block added twice returns existing entry)
        2. Capacity management (evicts oldest if full)
        3. Index maintenance (updates parent->children mapping)

        Args:
            block: The signed block to cache.
            peer: The peer that sent this block (for later scoring).
            backfill_depth: How deep in the backfill chain (0 = direct request).

        Returns:
            The PendingBlock wrapper, either newly created or existing.
        """
        block_inner = block.message.block
        root = hash_tree_root(block_inner)

        # Deduplication: if we already have this block, return the existing entry.
        #
        # This can happen when multiple peers send the same block via gossip,
        # or when a block is requested while already pending.
        if root in self._blocks:
            return self._blocks[root]

        # Capacity management: evict before adding to ensure we stay within bounds.
        #
        # We check >= rather than > because we are about to add one more.
        if len(self._blocks) >= MAX_CACHED_BLOCKS:
            self._evict_oldest()

        parent_root = block_inner.parent_root

        pending = PendingBlock(
            block=block,
            root=root,
            parent_root=parent_root,
            slot=block_inner.slot,
            received_from=peer,
            backfill_depth=backfill_depth,
        )

        # Insert into primary storage.
        self._blocks[root] = pending

        # Update parent index so we can find this block when its parent arrives.
        self._by_parent[parent_root].add(root)

        return pending

    def get(self, root: Bytes32) -> PendingBlock | None:
        """
        Get a cached block by root.

        Args:
            root: The block root to look up.

        Returns:
            The PendingBlock if found, None otherwise.
        """
        return self._blocks.get(root)

    def remove(self, root: Bytes32) -> PendingBlock | None:
        """
        Remove a block from the cache.

        Called after a block has been successfully processed or determined
        invalid. Maintains all index consistency automatically.

        Args:
            root: The block root to remove.

        Returns:
            The removed PendingBlock if it existed, None otherwise.
        """
        pending = self._blocks.pop(root, None)
        if pending is None:
            return None

        # Clean up orphan tracking.
        self._orphans.discard(root)

        # Clean up parent index.
        #
        # We must remove this block from its parent's child set. If that
        # leaves the parent with no children, remove the parent entry entirely
        # to avoid memory leaks from empty sets accumulating.
        children = self._by_parent.get(pending.parent_root)
        if children:
            children.discard(root)
            if not children:
                del self._by_parent[pending.parent_root]

        return pending

    def mark_orphan(self, root: Bytes32) -> None:
        """
        Mark a block as an orphan (parent not in Store or cache).

        An orphan is a block whose parent is completely unknown. This differs
        from a block whose parent is simply pending: orphans need backfill,
        pending blocks just need to wait.

        Typical flow:
        1. Block arrives
        2. Check if parent in Store -> no
        3. Check if parent in cache -> no
        4. Mark as orphan, trigger backfill for parent

        Args:
            root: The block root to mark as orphan.
        """
        if root in self._blocks:
            self._orphans.add(root)

    def unmark_orphan(self, root: Bytes32) -> None:
        """
        Remove orphan status from a block.

        Called when a block's parent has been received. The block is no longer
        an orphan because its parent now exists (in cache or Store).

        Args:
            root: The block root to unmark.
        """
        self._orphans.discard(root)

    def get_orphan_parents(self) -> list[Bytes32]:
        """
        Get roots of missing parent blocks for all orphans.

        This is the entry point for backfill. It returns a deduplicated list
        of parent roots that need to be fetched to resolve current orphans.

        Deduplication matters because multiple orphan blocks might share the
        same missing parent (e.g., two competing blocks at the same slot).

        Returns:
            List of parent block roots to fetch via BlocksByRoot requests.
        """
        missing_parents: set[Bytes32] = set()

        for root in self._orphans:
            pending = self._blocks.get(root)
            if pending is not None:
                # Only add if parent is not already in the cache.
                #
                # If parent is in cache, the orphan is not truly orphaned;
                # it just has not been processed yet.
                if pending.parent_root not in self._blocks:
                    missing_parents.add(pending.parent_root)

        return list(missing_parents)

    def get_children(self, parent_root: Bytes32) -> list[PendingBlock]:
        """
        Get all cached children of a given parent root.

        This is the core of descendant processing. When a parent block is
        successfully processed, call this method to find children that were
        waiting for it. Those children can now be processed.

        Results are sorted by slot to ensure parent-before-child ordering when
        processing a chain of descendants.

        Args:
            parent_root: The root of the parent block that was just processed.

        Returns:
            List of pending child blocks, sorted by slot (earliest first).
        """
        child_roots = self._by_parent.get(parent_root, set())
        children = [self._blocks[r] for r in child_roots if r in self._blocks]

        # Sort by slot ensures correct processing order.
        #
        # If block A at slot 100 and block B at slot 101 both waited for
        # parent P, we must process A before B.
        return sorted(children, key=lambda p: p.slot)

    def get_processable(self, store: "Store") -> list[PendingBlock]:
        """
        Get blocks whose parents exist in the Store.

        This method scans the cache for blocks that can be immediately processed.
        A block is processable if its parent is already in the Store (not just
        in the cache - it must be fully validated and integrated).

        Use this after processing new blocks to find newly-unblocked descendants.

        Args:
            store: The Store to check for parent existence.

        Returns:
            List of processable pending blocks, sorted by slot (earliest first).
        """
        processable: list[PendingBlock] = []

        for pending in self._blocks.values():
            # A block is processable if its parent is in the Store.
            #
            # Note: we check store.blocks, not the cache. The parent must be
            # fully processed, not just received.
            if pending.parent_root in store.blocks:
                processable.append(pending)

        # Sort ensures parent-before-child processing order.
        return sorted(processable, key=lambda p: p.slot)

    def get_highest_slot(self) -> Slot | None:
        """
        Get the highest slot among cached blocks.

        This is useful for progress reporting without exposing internal storage.

        Returns:
            The highest slot in the cache, or None if the cache is empty.
        """
        if not self._blocks:
            return None
        return max(p.slot for p in self._blocks.values())

    @property
    def orphan_count(self) -> int:
        """Number of orphan blocks in the cache."""
        return len(self._orphans)

    @property
    def is_empty(self) -> bool:
        """Check if the cache is empty."""
        return len(self._blocks) == 0

    def clear(self) -> None:
        """Remove all blocks from the cache."""
        self._blocks.clear()
        self._orphans.clear()
        self._by_parent.clear()

    def _evict_oldest(self) -> None:
        """
        Evict the oldest block to make room for new entries.

        FIFO (First-In-First-Out) eviction is used because:

        1. **Simplicity**: No scoring or prioritization needed
        2. **Fairness**: Old blocks had their chance; new ones deserve theirs
        3. **Attack resistance**: Attackers cannot keep malicious blocks cached
           by refreshing them

        More sophisticated strategies (LRU, priority queues) add complexity
        without clear benefits for this use case.
        """
        if not self._blocks:
            return

        # popitem(last=False) removes the first (oldest) entry.
        #
        # This is O(1) due to OrderedDict's doubly-linked list implementation.
        oldest_root, oldest_block = self._blocks.popitem(last=False)

        # Clean up orphan tracking.
        self._orphans.discard(oldest_root)

        # Clean up parent index to prevent memory leaks.
        children = self._by_parent.get(oldest_block.parent_root)
        if children:
            children.discard(oldest_root)
            if not children:
                del self._by_parent[oldest_block.parent_root]
