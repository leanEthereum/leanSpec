"""Block cache for downloaded blocks awaiting parent resolution."""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field

from lean_spec.node.networking.transport.peer_id import PeerId
from lean_spec.node.sync.config import MAX_CACHED_BLOCKS
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import SignedBlock, Slot
from lean_spec.spec.ssz import Bytes32


@dataclass(frozen=True, slots=True)
class PendingBlock:
    """A cached block plus the metadata needed to resolve and score it later."""

    block: SignedBlock
    """The complete signed block."""

    root: Bytes32
    """Hash tree root of the block, computed once at insertion to avoid recomputing."""

    parent_root: Bytes32
    """Root of the parent, stored separately so lookups need not deserialize the block."""

    slot: Slot
    """Slot of the block, used to order batch processing so parents precede children."""

    received_from: PeerId | None
    """Peer that sent the block, for later scoring. None for self-produced blocks."""

    backfill_depth: int = 0
    """
    How many ancestors deep this block was fetched while chasing a missing parent.

    Bounds recursion so deep forks or attacks cannot backfill without limit.
    """


@dataclass(slots=True)
class BlockCache:
    """Cache for blocks that cannot be processed yet because their parent is unknown."""

    _blocks: OrderedDict[Bytes32, PendingBlock] = field(default_factory=OrderedDict)
    """Blocks ordered by insertion time, so the oldest can be evicted first."""

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
        block: SignedBlock,
        peer: PeerId | None,
        backfill_depth: int = 0,
    ) -> PendingBlock:
        """
        Cache a block, evicting the oldest entry first if at capacity.

        Returns the existing entry if the block is already cached.
        """
        block_inner = block.block
        root = hash_tree_root(block_inner)

        # The same block can arrive from several peers, or be re-requested while pending.
        #
        # Return the existing entry instead of caching a duplicate.
        if root in self._blocks:
            return self._blocks[root]

        # Use >= here, not >: we are about to add one entry, so evict at the limit.
        if len(self._blocks) >= MAX_CACHED_BLOCKS:
            # Evict the oldest block (FIFO).
            #
            # Oldest-first means an attacker cannot keep a block cached by re-sending it.
            evicted_root, evicted = self._blocks.popitem(last=False)
            self._orphans.discard(evicted_root)

            # Detach the evicted block from its parent's child set.
            siblings = self._by_parent.get(evicted.parent_root)
            if siblings:
                siblings.discard(evicted_root)
                if not siblings:
                    del self._by_parent[evicted.parent_root]

            # Its cached children just lost their parent, so they are orphans again.
            for child_root in self._by_parent.get(evicted_root, set()):
                self.mark_orphan(child_root)

        pending = PendingBlock(
            block=block,
            root=root,
            parent_root=block_inner.parent_root,
            slot=block_inner.slot,
            received_from=peer,
            backfill_depth=backfill_depth,
        )
        self._blocks[root] = pending

        # Index by parent so this block is found when its parent is processed.
        self._by_parent[block_inner.parent_root].add(root)
        return pending

    def remove(self, root: Bytes32) -> PendingBlock | None:
        """
        Remove a block and clean up its orphan and parent-index entries.

        Returns the removed block, or None if it was not cached.
        """
        pending = self._blocks.pop(root, None)
        if pending is None:
            return None

        self._orphans.discard(root)

        # Drop this child from its parent's set.
        # Delete the parent entry once empty, so empty sets do not accumulate.
        children = self._by_parent.get(pending.parent_root)
        if children:
            children.discard(root)
            if not children:
                del self._by_parent[pending.parent_root]

        return pending

    def mark_orphan(self, root: Bytes32) -> None:
        """
        Mark a block as an orphan: its parent is in neither the store nor the cache.

        Unlike a block waiting on a pending parent, an orphan needs its parent backfilled.
        """
        if root in self._blocks:
            self._orphans.add(root)

    def get_children(self, parent_root: Bytes32) -> list[PendingBlock]:
        """Return the cached children of a parent, sorted by slot so parents process first."""
        child_roots = self._by_parent.get(parent_root, set())
        children = [self._blocks[root] for root in child_roots if root in self._blocks]
        # If two blocks at slots 100 and 101 share a parent, 100 must process first.
        return sorted(children, key=lambda pending: pending.slot)

    @property
    def orphan_count(self) -> int:
        """Number of orphan blocks in the cache."""
        return len(self._orphans)
