"""
Sync service orchestrator.

This is the main entry point for synchronization.

The Core Problem
----------------
When an Ethereum node starts, it has no chain history. Before it can validate
new blocks or produce attestations, it must synchronize with the network. This
involves:

1. **Discovery**: Finding peers with chain data
2. **Assessment**: Determining how far behind we are
3. **Download**: Fetching missing blocks when they arrive out of order
4. **Validation**: Verifying and integrating blocks into our Store

How It Works
------------
- Blocks arrive via gossip subscription
- If parent is known, process immediately
- If parent is unknown, cache block and fetch parent (backfill)
- When parents arrive, process waiting children

State Machine
-------------
::

    IDLE --> SYNCING --> SYNCED
      ^         |           |
      +---------+-----------+

- **IDLE**: Not syncing. Waiting for peers.
- **SYNCING**: Actively processing gossip and backfilling missing parents.
- **SYNCED**: Caught up with the network. Passive gossip only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lean_spec.subspecs import metrics
from lean_spec.subspecs.chain.clock import SlotClock
from lean_spec.subspecs.containers import (
    Block,
    SignedAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.forkchoice.store import Store
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.transport.peer_id import PeerId
from lean_spec.subspecs.ssz.hash import hash_tree_root

from .backfill_sync import BackfillSync, NetworkRequester
from .block_cache import BlockCache
from .head_sync import HeadSync
from .peer_manager import PeerManager
from .states import SyncState

if TYPE_CHECKING:
    from lean_spec.subspecs.storage import Database

BlockProcessor = Callable[[Store, SignedBlockWithAttestation], Store]


def default_block_processor(
    store: Store,
    block: SignedBlockWithAttestation,
) -> Store:
    """Default block processor using store block processing."""
    return store.on_block(block)


@dataclass(slots=True)
class SyncProgress:
    """
    Current synchronization progress.

    Provides a snapshot of sync state for monitoring and logging.
    """

    state: SyncState
    """Current sync state machine state."""

    local_head_slot: int | None = None
    """Slot of our current chain head."""

    network_finalized_slot: int | None = None
    """Network consensus on finalized slot (mode of peer reports)."""

    blocks_processed: int = 0
    """Total blocks integrated into Store this session."""

    peers_connected: int = 0
    """Number of connected peers with status."""

    cache_size: int = 0
    """Number of blocks in pending cache."""

    orphan_count: int = 0
    """Number of orphan blocks awaiting parents."""


@dataclass(slots=True)
class SyncService:
    """
    Main synchronization orchestrator.

    SyncService is the central coordinator for all sync activities. It:

    - Manages the sync state machine (IDLE -> SYNCING -> SYNCED)
    - Coordinates HeadSync and BackfillSync
    - Handles gossip block arrivals
    - Tracks peer status updates
    - Maintains the forkchoice Store

    Design Philosophy
    -----------------
    The service is designed to be:

    **Reactive**: Responds to gossip blocks rather than proactively fetching.
    **Simple**: No complex batch coordination or range downloads.
    **Resilient**: Handles peer failures and invalid blocks gracefully.
    **Observable**: Exposes progress for monitoring and debugging.

    The service does not own the network layer. It receives events and uses
    injected interfaces to make requests.
    """

    store: Store
    """Current forkchoice store. Updated as blocks are processed."""

    peer_manager: PeerManager
    """Peer manager for selection."""

    block_cache: BlockCache
    """Block cache for pending blocks."""

    clock: SlotClock
    """Slot clock for time conversion."""

    network: NetworkRequester
    """Network interface for block requests."""

    database: Database | None = field(default=None)
    """Optional database for persisting blocks and states."""

    process_block: BlockProcessor = field(default=default_block_processor)
    """Block processor function. Defaults to Store.on_block()."""

    _state: SyncState = field(default=SyncState.IDLE)
    """Current sync state."""

    _backfill: BackfillSync | None = field(default=None)
    """Backfill syncer instance (created lazily)."""

    _head_sync: HeadSync | None = field(default=None)
    """Head syncer instance (created lazily)."""

    _blocks_processed: int = field(default=0)
    """Counter for processed blocks."""

    _sync_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    """Lock to prevent concurrent sync operations."""

    def __post_init__(self) -> None:
        """Initialize sync components."""
        self._init_components()

    def _init_components(self) -> None:
        """
        Initialize sync sub-components.

        Creates BackfillSync and HeadSync instances with shared dependencies.
        """
        # BackfillSync handles fetching missing parent blocks from peers.
        #
        # It needs network access to request blocks and the cache to store them.
        self._backfill = BackfillSync(
            peer_manager=self.peer_manager,
            block_cache=self.block_cache,
            network=self.network,
        )

        # HeadSync processes incoming gossip blocks and coordinates backfill.
        #
        # We inject our wrapper to track block processing metrics.
        self._head_sync = HeadSync(
            block_cache=self.block_cache,
            backfill=self._backfill,
            process_block=self._process_block_wrapper,
        )

    def _process_block_wrapper(
        self,
        store: Store,
        block: SignedBlockWithAttestation,
    ) -> Store:
        """
        Wrapper for block processing that updates counters and persists data.

        This wrapper is injected into HeadSync to track processed blocks
        and optionally persist them to the database.
        """
        # Delegate to the actual block processor (typically Store.on_block).
        #
        # The processor validates the block and updates forkchoice state.
        with metrics.block_processing_time.time():
            new_store = self.process_block(store, block)

        # Track metrics after successful processing.
        #
        # We only count blocks that pass validation and update the store.
        self._blocks_processed += 1
        metrics.blocks_processed.inc()

        # Update chain state metrics.
        metrics.head_slot.set(float(new_store.blocks[new_store.head].slot))
        metrics.justified_slot.set(float(new_store.latest_justified.slot))
        metrics.finalized_slot.set(float(new_store.latest_finalized.slot))

        # Update validator count from head state.
        head_state = new_store.states.get(new_store.head)
        if head_state is not None:
            metrics.validators_count.set(float(len(head_state.validators)))

        # Persist block and state to database if available.
        #
        # This is write-through: data is persisted synchronously after processing.
        # The database call is optional - nodes can run without persistence.
        if self.database is not None:
            self._persist_block(new_store, block.message.block)

        return new_store

    def _persist_block(self, store: Store, block: Block) -> None:
        """
        Persist block and its post-state to the database.

        Called after successful block processing to ensure data survives restarts.

        Args:
            store: The updated store containing the new block and state.
            block: The block that was just processed.
        """
        if self.database is None:
            return

        block_root = hash_tree_root(block)

        # Persist block
        self.database.put_block(block, block_root)

        # Persist post-state
        post_state = store.states.get(block_root)
        if post_state is not None:
            self.database.put_state(post_state, block_root)

        # Update slot index for historical queries
        self.database.put_block_root_by_slot(block.slot, block_root)

        # Update head root
        self.database.put_head_root(store.head)

        # Update checkpoints
        self.database.put_justified_checkpoint(store.latest_justified)
        self.database.put_finalized_checkpoint(store.latest_finalized)

    @property
    def state(self) -> SyncState:
        """Current sync state."""
        return self._state

    @property
    def is_syncing(self) -> bool:
        """Check if actively syncing."""
        return self._state.is_syncing

    @property
    def is_synced(self) -> bool:
        """Check if synced with network."""
        return self._state == SyncState.SYNCED

    def get_progress(self) -> SyncProgress:
        """
        Get current sync progress.

        Returns:
            Snapshot of sync state for monitoring.
        """
        # Our head slot tells us where we are in the chain.
        #
        # This is the slot of the block our forkchoice currently considers head.
        head_slot = self.store.blocks[self.store.head].slot

        # Network finalized slot represents consensus across peers.
        #
        # This is calculated as the mode of peer-reported finalized slots.
        # A None value means we have not received enough peer status messages.
        network_slot = self.peer_manager.get_network_finalized_slot()

        return SyncProgress(
            state=self._state,
            local_head_slot=int(head_slot),
            network_finalized_slot=int(network_slot) if network_slot else None,
            blocks_processed=self._blocks_processed,
            # Only count peers that have an active connection.
            peers_connected=sum(1 for p in self.peer_manager.get_all_peers() if p.is_connected()),
            cache_size=len(self.block_cache),
            # Orphans are blocks waiting for parents to be fetched via backfill.
            orphan_count=self.block_cache.orphan_count,
        )

    async def on_peer_status(self, peer_id: PeerId, status: Status) -> None:
        """
        Handle peer status message.

        Called when a peer sends their chain status.

        This updates our view of the network and may trigger sync if we are behind.

        Args:
            peer_id: The peer that sent the status.
            status: The peer's chain status.
        """
        # Record this peer's view of the chain.
        #
        # Status contains their head root, head slot, and finalized checkpoint.
        # We use this to build a picture of network consensus.
        self.peer_manager.update_status(peer_id, status)

        # Check if this new information means we should start syncing.
        #
        # For example: if the peer reports a finalized slot ahead of our head,
        # we need to sync to catch up with the network.
        await self._check_sync_trigger()

    async def on_gossip_block(
        self,
        block: SignedBlockWithAttestation,
        peer_id: PeerId,
    ) -> None:
        """
        Handle block received via gossip.

        Called when a block arrives from gossip subscription.

        The block may be processable immediately or may need to wait for parents.

        Args:
            block: The signed block received.
            peer_id: The peer that propagated the block.
        """
        # Guard: Only process gossip in states that accept it.
        #
        # - IDLE state does not accept gossip because we have no peer information.
        # - SYNCING and SYNCED states accept gossip for different reasons.
        if not self._state.accepts_gossip:
            return

        if self._head_sync is None:
            raise RuntimeError("HeadSync not initialized")

        # Delegate to HeadSync for processing logic.
        #
        # HeadSync determines if:
        # - the block can be processed immediately (parent known) or
        # - must be cached (parent unknown, triggers backfill).
        result, new_store = await self._head_sync.on_gossip_block(
            block=block,
            peer_id=peer_id,
            store=self.store,
        )

        # Only update our store if the block was actually processed.
        #
        # A block may be cached instead of processed if its parent is unknown.
        if result.processed:
            self.store = new_store

        # Each processed block might complete our sync.
        #
        # We check after every block because gossip can deliver the final
        # block needed to catch up with the network.
        await self._check_sync_complete()

    async def on_gossip_attestation(
        self,
        attestation: SignedAttestation,
        peer_id: PeerId,  # noqa: ARG002
    ) -> None:
        """
        Handle attestation received via gossip.

        Attestations are votes from validators about which chain head they see.
        They influence forkchoice by adding weight to branches of the block tree.
        A branch with more attestation weight is more likely to become canonical.

        Unlike blocks, attestations do not require parent lookups. They reference
        a target checkpoint that must already exist in our store.

        Args:
            attestation: The signed attestation received.
            peer_id: The peer that propagated the attestation (unused for now).
        """
        # Guard: Only process gossip in states that accept it.
        #
        # Without peer status information, we cannot assess the validity context
        # of incoming attestations. IDLE state waits for peer discovery.
        if not self._state.accepts_gossip:
            return

        from lean_spec.subspecs.node.helpers import is_aggregator

        # Check if we are an aggregator
        is_aggregator_role = is_aggregator(self.store.validator_id)

        # Integrate the attestation into forkchoice state.
        #
        # The store validates the signature and updates branch weights.
        # Invalid attestations (bad signature, unknown target) are rejected.
        # Validation failures are logged but don't crash the event loop.
        try:
            self.store = self.store.on_gossip_attestation(
                signed_attestation=attestation,
                is_aggregator=is_aggregator_role,
            )
        except (AssertionError, KeyError):
            # Attestation validation failed.
            #
            # Common causes:
            # - Unknown blocks (source/target/head not in store yet)
            # - Attestation for future slot (clock drift)
            # - Invalid signature
            #
            # These are expected during normal operation and don't indicate bugs.
            pass

    async def start_sync(self) -> None:
        """
        Start or resume synchronization.

        This is the main entry point for initiating sync. It assesses the
        current state and begins appropriate sync activities.
        """
        # Serialize sync operations to prevent race conditions.
        #
        # Without this lock, concurrent calls to start_sync could cause
        # duplicate state transitions or conflicting sync operations.
        async with self._sync_lock:
            await self._check_sync_trigger()

    async def process_pending_blocks(self) -> int:
        """
        Process all blocks in cache that now have parents.

        Called after backfill completes or when blocks may have become
        processable.

        Returns:
            Number of blocks processed.
        """
        if self._head_sync is None:
            raise RuntimeError("HeadSync not initialized")

        # Process blocks in topological order (parents before children).
        #
        # When backfill fetches missing parents, it may unlock a chain of
        # waiting blocks. HeadSync handles the ordering to ensure each block
        # is processed only after its parent is in the store.
        count, new_store = await self._head_sync.process_all_processable(self.store)
        self.store = new_store

        return count

    async def _check_sync_trigger(self) -> None:
        """
        Check if sync should be triggered based on current state.

        Transitions to SYNCING if we have peers and are behind the network.
        """
        # Guard: Only trigger sync from stable states.
        #
        # If already SYNCING, we should not re-trigger.
        # This prevents redundant state transitions.
        if self._state not in (SyncState.IDLE, SyncState.SYNCED):
            return

        # Guard: Require peer information before syncing.
        #
        # Without peer status messages, we cannot determine if we are behind.
        # A None value means no peers have reported their finalized slot yet.
        network_finalized = self.peer_manager.get_network_finalized_slot()
        if network_finalized is None:
            return

        head_slot = self.store.blocks[self.store.head].slot

        # Trigger sync if the network has finalized blocks we do not have.
        #
        # Finalized blocks are guaranteed to never be reverted, so if the
        # network has finalized past our head, we are definitely behind.
        if network_finalized > head_slot:
            await self._transition_to(SyncState.SYNCING)
        elif self._state == SyncState.IDLE:
            # Transition from IDLE even if caught up.
            #
            # IDLE -> SYNCING enables gossip processing. Even if our head matches
            # the network, we need to enter SYNCING to begin accepting blocks.
            await self._transition_to(SyncState.SYNCING)

    async def _check_sync_complete(self) -> None:
        """
        Check if sync is complete and transition to SYNCED if so.

        We consider sync complete when our head is at or past the network
        finalized slot and there are no orphan blocks.
        """
        # Guard: Only check completion while actively syncing.
        if self._state != SyncState.SYNCING:
            return

        # Invariant: All orphan blocks must be resolved before declaring synced.
        #
        # Orphans indicate pending backfill requests. If we have orphans, we are
        # still waiting for parent blocks to arrive from peers.
        if self.block_cache.orphan_count > 0:
            return

        network_finalized = self.peer_manager.get_network_finalized_slot()
        if network_finalized is None:
            return

        head_slot = self.store.blocks[self.store.head].slot

        # Sync is complete when our head reaches the network finalized slot.
        #
        # We use >= because our head might be ahead of finalized (we may have
        # received unfinalized blocks via gossip). The key threshold is reaching
        # finalized, which means we have the canonical chain history.
        if head_slot >= network_finalized:
            await self._transition_to(SyncState.SYNCED)

    async def _transition_to(self, new_state: SyncState) -> None:
        """
        Transition to a new sync state.

        Args:
            new_state: Target state.

        Raises:
            ValueError: If transition is not allowed.
        """
        # Validate the transition against the state machine rules.
        #
        # The state machine enforces valid transitions:
        # - IDLE -> SYNCING (start sync)
        # - SYNCING -> SYNCED (caught up)
        # - SYNCED -> SYNCING (fell behind)
        # - Any -> IDLE (reset)
        if not self._state.can_transition_to(new_state):
            raise ValueError(f"Invalid state transition: {self._state.name} -> {new_state.name}")

        self._state = new_state

    def reset(self) -> None:
        """
        Reset all sync state.

        Clears counters, caches, and returns to IDLE state.
        """
        # Return to initial state.
        #
        # IDLE is the starting state where we wait for peer connections.
        self._state = SyncState.IDLE
        self._blocks_processed = 0

        # Clear the block cache to free memory.
        #
        # Cached blocks may be invalid or stale after a reset.
        self.block_cache.clear()

        # Reset sub-components to clear their internal state.
        #
        # This ensures no stale backfill requests or pending operations remain.
        if self._backfill is not None:
            self._backfill.reset()
        if self._head_sync is not None:
            self._head_sync.reset()
