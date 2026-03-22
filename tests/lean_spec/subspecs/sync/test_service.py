"""Tests for sync service module."""

from __future__ import annotations

from typing import cast

import pytest

from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.service import SyncProgress, SyncService
from lean_spec.subspecs.sync.states import SyncState
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import (
    MockForkchoiceStore,
    create_mock_sync_service,
    make_signed_attestation,
    make_signed_block,
)


@pytest.fixture
def sync_service(peer_id: PeerId) -> SyncService:
    """Provide a complete SyncService for integration testing."""
    return create_mock_sync_service(peer_id)


class TestStateMachineTransitions:
    """Tests for sync state machine transitions."""

    def test_starts_in_idle_state(self, sync_service: SyncService) -> None:
        """Service starts in IDLE state."""
        assert sync_service.state == SyncState.IDLE

    async def test_transitions_to_syncing_on_peer_status(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Receiving peer status triggers IDLE -> SYNCING transition."""
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
        )

        await sync_service.on_peer_status(peer_id, status)

        assert sync_service.state == SyncState.SYNCING

    async def test_transitions_to_synced_when_caught_up(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Transitions to SYNCED when head reaches network finalized slot."""
        # Start syncing
        sync_service._state = SyncState.SYNCING

        # Peer reports finalized at slot 0 (same as our head)
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )
        sync_service.peer_manager.update_status(peer_id, status)

        await sync_service._check_sync_complete()

        assert sync_service.state == SyncState.SYNCED

    async def test_stays_syncing_with_orphans(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Does not transition to SYNCED while orphans exist."""
        sync_service._state = SyncState.SYNCING

        # Add an orphan to the cache
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32.zero(),
        )
        pending = sync_service.block_cache.add(block, peer_id)
        sync_service.block_cache.mark_orphan(pending.root)

        # Peer reports we're caught up
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )
        sync_service.peer_manager.update_status(peer_id, status)

        await sync_service._check_sync_complete()

        assert sync_service.state == SyncState.SYNCING

    async def test_resyncs_when_falls_behind(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Transitions SYNCED -> SYNCING when fallen behind network."""
        sync_service._state = SyncState.SYNCED

        # Peer reports being ahead
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
        )

        await sync_service.on_peer_status(peer_id, status)

        assert sync_service.state == SyncState.SYNCING

    async def test_full_sync_lifecycle(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Complete lifecycle: IDLE -> SYNCING -> SYNCED -> SYNCING -> SYNCED."""
        # Start IDLE
        assert sync_service.state == SyncState.IDLE

        # 1. Peer connects with chain ahead -> SYNCING
        ahead_status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
        )
        await sync_service.on_peer_status(peer_id, ahead_status)
        assert sync_service.state == SyncState.SYNCING

        # 2. We catch up (simulate by updating peer status to match our head)
        caught_up_status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )
        sync_service.peer_manager.update_status(peer_id, caught_up_status)
        await sync_service._check_sync_complete()
        assert sync_service.state == SyncState.SYNCED

        # 3. Network advances -> back to SYNCING
        await sync_service.on_peer_status(peer_id, ahead_status)
        assert sync_service.state == SyncState.SYNCING

        # 4. Catch up again -> SYNCED
        sync_service.peer_manager.update_status(peer_id, caught_up_status)
        await sync_service._check_sync_complete()
        assert sync_service.state == SyncState.SYNCED


class TestGossipBlockHandling:
    """Tests for gossip block acceptance based on state."""

    async def test_ignores_gossip_in_idle_state(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Gossip blocks are ignored when in IDLE state."""
        assert sync_service.state == SyncState.IDLE

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )

        await sync_service.on_gossip_block(block, peer_id)

        # Block should not be processed or cached.
        assert sync_service._blocks_processed == 0
        assert sync_service.block_cache.orphan_count == 0
        assert len(sync_service.block_cache) == 0

    async def test_processes_gossip_in_syncing_state(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Gossip blocks are processed when in SYNCING state."""
        sync_service._state = SyncState.SYNCING

        # Get genesis root from store
        genesis_root = sync_service.store.head

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        await sync_service.on_gossip_block(block, peer_id)

        # Block should be processed (parent exists)
        assert sync_service._blocks_processed == 1

    async def test_caches_orphan_in_syncing_state(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Orphan blocks are cached when in SYNCING state."""
        sync_service._state = SyncState.SYNCING

        # Block with unknown parent
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.block)

        await sync_service.on_gossip_block(block, peer_id)

        # Block should be cached as orphan
        assert sync_service._blocks_processed == 0
        assert block_root in sync_service.block_cache
        assert sync_service.block_cache.orphan_count == 1


class TestProgressReporting:
    """Tests for sync progress reporting."""

    def test_progress_reflects_current_state(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """get_progress accurately reflects service state."""
        # Initial progress
        progress = sync_service.get_progress()
        assert progress == SyncProgress(
            state=SyncState.IDLE,
            local_head_slot=Slot(0),
            network_finalized_slot=None,
            blocks_processed=0,
            peers_connected=1,
            cache_size=0,
            orphan_count=0,
        )

        # After processing some blocks
        sync_service._state = SyncState.SYNCING
        sync_service._blocks_processed = 42

        progress = sync_service.get_progress()
        assert progress == SyncProgress(
            state=SyncState.SYNCING,
            local_head_slot=Slot(0),
            network_finalized_slot=None,
            blocks_processed=42,
            peers_connected=1,
            cache_size=0,
            orphan_count=0,
        )

    def test_progress_includes_network_consensus(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Progress includes network finalized slot from peers."""
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
        )
        sync_service.peer_manager.update_status(peer_id, status)

        progress = sync_service.get_progress()
        assert progress == SyncProgress(
            state=SyncState.IDLE,
            local_head_slot=Slot(0),
            network_finalized_slot=Slot(100),
            blocks_processed=0,
            peers_connected=1,
            cache_size=0,
            orphan_count=0,
        )

    def test_progress_tracks_cache_state(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Progress includes cache size and orphan count."""
        # Add blocks to cache
        block1 = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32(b"\x01" * 32),
        )
        block2 = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32(b"\x02" * 32),
            state_root=Bytes32(b"\x02" * 32),
        )

        pending1 = sync_service.block_cache.add(block1, peer_id)
        sync_service.block_cache.add(block2, peer_id)
        sync_service.block_cache.mark_orphan(pending1.root)

        progress = sync_service.get_progress()
        assert progress == SyncProgress(
            state=SyncState.IDLE,
            local_head_slot=Slot(0),
            network_finalized_slot=None,
            blocks_processed=0,
            peers_connected=1,
            cache_size=2,
            orphan_count=1,
        )


class TestReset:
    """Tests for service reset functionality."""

    def test_reset_clears_all_state(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """reset() returns service to initial state."""
        # Put service in a dirty state
        sync_service._state = SyncState.SYNCED
        sync_service._blocks_processed = 100

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32.zero(),
        )
        sync_service.block_cache.add(block, peer_id)

        # Verify backfill component exists before adding pending
        assert sync_service._backfill is not None
        sync_service._backfill._pending.add(Bytes32(b"\x02" * 32))

        # Reset
        sync_service.reset()

        # Verify clean state
        assert sync_service.state == SyncState.IDLE
        assert sync_service._blocks_processed == 0
        assert len(sync_service.block_cache) == 0
        assert sync_service._backfill is not None
        assert sync_service._backfill._pending == set()


class TestAttestationGossipHandling:
    """Tests for attestation gossip handling."""

    async def test_attestation_accepted_when_synced(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Attestation is processed when in SYNCED state."""
        sync_service._state = SyncState.SYNCED

        target = Checkpoint(root=sync_service.store.head, slot=Slot(0))
        attestation = make_signed_attestation(
            validator=ValidatorIndex(0),
            target=target,
        )

        await sync_service.on_gossip_attestation(attestation)

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        assert mock_store._attestations_received == [attestation]

    async def test_attestation_rejected_when_idle(
        self,
        sync_service: SyncService,
    ) -> None:
        """Attestation is ignored when in IDLE state."""
        assert sync_service.state == SyncState.IDLE

        target = Checkpoint(root=sync_service.store.head, slot=Slot(0))
        attestation = make_signed_attestation(
            validator=ValidatorIndex(0),
            target=target,
        )

        await sync_service.on_gossip_attestation(attestation)

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        assert mock_store._attestations_received == []

    async def test_attestation_buffered_when_block_unknown(
        self,
        sync_service: SyncService,
    ) -> None:
        """Attestation referencing unknown block is buffered for replay."""
        sync_service._state = SyncState.SYNCING

        # Make the mock store reject this attestation.
        unknown_root = Bytes32(b"\xab" * 32)
        target = Checkpoint(root=unknown_root, slot=Slot(99))
        attestation = make_signed_attestation(
            validator=ValidatorIndex(0),
            target=target,
        )

        # Override on_gossip_attestation to raise for unknown blocks.
        original_fn = sync_service.store.on_gossip_attestation

        def reject_unknown(signed_attestation, *, is_aggregator=False):
            if signed_attestation.data.target.root == unknown_root:
                raise KeyError("Unknown block")
            return original_fn(signed_attestation, is_aggregator=is_aggregator)

        sync_service.store.on_gossip_attestation = reject_unknown  # type: ignore[assignment]

        await sync_service.on_gossip_attestation(attestation)

        assert sync_service._pending_attestations == [attestation]

    async def test_buffered_attestation_replayed_after_block(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Buffered attestation is replayed when a new block is processed."""
        sync_service._state = SyncState.SYNCING

        target = Checkpoint(root=sync_service.store.head, slot=Slot(0))
        attestation = make_signed_attestation(
            validator=ValidatorIndex(0),
            target=target,
        )

        # Manually buffer an attestation.
        sync_service._pending_attestations.append(attestation)

        # Process a gossip block to trigger replay.
        genesis_root = sync_service.store.head
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        await sync_service.on_gossip_block(block, peer_id)

        # Attestation was replayed (accepted by mock store).
        assert sync_service._pending_attestations == []
        mock_store = cast(MockForkchoiceStore, sync_service.store)
        assert attestation in mock_store._attestations_received


class TestSyncedGossipBlocks:
    """Tests for gossip block handling in SYNCED state."""

    async def test_processes_gossip_in_synced_state(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Gossip blocks are processed when in SYNCED state."""
        sync_service._state = SyncState.SYNCED

        genesis_root = sync_service.store.head
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        await sync_service.on_gossip_block(block, peer_id)

        assert sync_service._blocks_processed == 1


class TestInvalidStateTransition:
    """Tests for invalid state transitions."""

    async def test_idle_to_synced_raises_value_error(
        self,
        sync_service: SyncService,
    ) -> None:
        """Direct IDLE -> SYNCED transition raises ValueError."""
        assert sync_service.state == SyncState.IDLE

        with pytest.raises(ValueError, match="Invalid state transition"):
            await sync_service._transition_to(SyncState.SYNCED)


class TestIdleToCaughtUp:
    """Tests for IDLE-to-SYNCING when already caught up."""

    async def test_idle_transitions_to_syncing_when_caught_up(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """IDLE transitions to SYNCING even when peer reports same head."""
        assert sync_service.state == SyncState.IDLE

        # Peer reports finalized at slot 0 (same as our head).
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )
        await sync_service.on_peer_status(peer_id, status)

        assert sync_service.state == SyncState.SYNCING
