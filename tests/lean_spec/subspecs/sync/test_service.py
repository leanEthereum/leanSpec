"""Tests for sync service module."""

from __future__ import annotations

from types import MappingProxyType
from typing import cast

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.forks.lstar.containers import (
    SignedAggregatedAttestation,
)
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.storage.database import Database
from lean_spec.subspecs.sync.config import MAX_PENDING_ATTESTATIONS
from lean_spec.subspecs.sync.service import SyncService
from lean_spec.subspecs.sync.states import SyncState
from lean_spec.types import Bytes32, Checkpoint, Slot, ValidatorIndex
from tests.lean_spec.helpers import (
    MockForkchoiceStore,
    RecordedCall,
    RecordingSyncDatabase,
    create_mock_sync_service,
    make_aggregated_proof,
    make_genesis_state,
    make_signed_attestation,
    make_signed_block,
    make_store_with_attestation_data,
)


def _signed_aggregated_attestation(key_manager: XmssKeyManager) -> SignedAggregatedAttestation:
    _, attestation_data = make_store_with_attestation_data(
        key_manager,
        num_validators=4,
        validator_id=ValidatorIndex(0),
    )
    proof = make_aggregated_proof(key_manager, [ValidatorIndex(1)], attestation_data)
    return SignedAggregatedAttestation(data=attestation_data, proof=proof)


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
        sync_service.state = SyncState.SYNCING

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
        sync_service.state = SyncState.SYNCING

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
        sync_service.state = SyncState.SYNCED

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
        sync_service.state = SyncState.SYNCING

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
        sync_service.state = SyncState.SYNCING

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


class TestAttestationGossipHandling:
    """Tests for attestation gossip handling."""

    async def test_attestation_accepted_when_synced(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Attestation is processed when in SYNCED state."""
        sync_service.state = SyncState.SYNCED

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
        sync_service.state = SyncState.SYNCING

        # Make the mock store reject this attestation.
        unknown_root = Bytes32(b"\xab" * 32)
        target = Checkpoint(root=unknown_root, slot=Slot(99))
        attestation = make_signed_attestation(
            validator=ValidatorIndex(0),
            target=target,
        )

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        mock_store.reject_attestation = lambda att: att.data.target.root == unknown_root

        await sync_service.on_gossip_attestation(attestation)

        assert list(sync_service._pending_attestations) == [attestation]

    async def test_buffered_attestation_replayed_after_block(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Buffered attestation is replayed when a new block is processed."""
        sync_service.state = SyncState.SYNCING

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
        assert list(sync_service._pending_attestations) == []
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
        sync_service.state = SyncState.SYNCED

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

    async def test_self_transition_raises_value_error(
        self,
        sync_service: SyncService,
    ) -> None:
        """A transition to the current state is rejected as a no-op move."""
        assert sync_service.state == SyncState.IDLE

        with pytest.raises(ValueError, match="Invalid state transition"):
            await sync_service._transition_to(SyncState.IDLE)


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


class TestGenesisStart:
    """Tests for genesis_start bootstrap behavior."""

    def test_genesis_start_begins_in_syncing(self, peer_id: PeerId) -> None:
        """When genesis_start is set, gossip is accepted without peer status."""
        service = create_mock_sync_service(peer_id, genesis_start=True)
        assert service.state == SyncState.SYNCING


class TestBlockPersistence:
    """Tests for process_block and database persistence."""

    def test_process_block_increments_counter_without_database(
        self,
        peer_id: PeerId,
    ) -> None:
        """Processed blocks are counted even when no database is configured."""
        service = create_mock_sync_service(peer_id)
        service.state = SyncState.SYNCING
        genesis_root = service.store.head
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        service.store = service.process_block(service.store, block)
        assert service._blocks_processed == 1

    def test_persist_skips_state_when_post_state_missing(
        self,
        peer_id: PeerId,
    ) -> None:
        """No put_state when the store has no post-state for the block root."""
        db = RecordingSyncDatabase()
        service = create_mock_sync_service(
            peer_id,
            database=cast(Database, db),
        )
        mock_store = cast(MockForkchoiceStore, service.store)
        # Justified advances each block; finalized stays at genesis (no prune).
        mock_store.advance_justified_on_block = True
        service.state = SyncState.SYNCING
        genesis_root = service.store.head
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        service.store = service.process_block(service.store, block)

        block_root = hash_tree_root(block.block)
        assert db.calls[0].name == "batch_write_enter"
        assert db.calls[-1].name == "batch_write_exit"

        empty: MappingProxyType[str, object] = MappingProxyType({})
        assert db.calls_inside_batch() == [
            RecordedCall(name="put_block", args=(block.block, block_root), kwargs=empty),
            RecordedCall(name="put_block_root_by_slot", args=(Slot(1), block_root), kwargs=empty),
            RecordedCall(name="put_head_root", args=(block_root,), kwargs=empty),
            RecordedCall(
                name="put_justified_checkpoint",
                args=(Checkpoint(root=block_root, slot=Slot(1)),),
                kwargs=empty,
            ),
            RecordedCall(
                name="put_finalized_checkpoint",
                args=(Checkpoint(root=Bytes32.zero(), slot=Slot(0)),),
                kwargs=empty,
            ),
        ]

    def test_persist_writes_state_and_prunes_when_finalized_advanced(
        self,
        peer_id: PeerId,
    ) -> None:
        """Post-state indexing and pruning run when finalization is past genesis."""
        db = RecordingSyncDatabase()
        service = create_mock_sync_service(
            peer_id,
            database=cast(Database, db),
        )
        mock_store = cast(MockForkchoiceStore, service.store)
        # Post-state indexing requires both a state to index and an advanced finalized.
        mock_store.on_block_post_state = make_genesis_state(num_validators=1)
        mock_store.advance_justified_on_block = True
        mock_store.advance_finalized_on_block = True
        service.state = SyncState.SYNCING
        genesis_root = service.store.head
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        service.store = service.process_block(service.store, block)

        block_root = hash_tree_root(block.block)
        assert db.calls[0].name == "batch_write_enter"
        assert db.calls[-1].name == "batch_write_exit"

        inner = db.calls_inside_batch()
        state_obj = inner[1].args[0]
        state_root = hash_tree_root(state_obj)

        empty: MappingProxyType[str, object] = MappingProxyType({})
        assert inner == [
            RecordedCall(name="put_block", args=(block.block, block_root), kwargs=empty),
            RecordedCall(name="put_state", args=(state_obj, block_root), kwargs=empty),
            RecordedCall(
                name="put_block_root_by_state_root",
                args=(state_root, block_root),
                kwargs=empty,
            ),
            RecordedCall(name="put_block_root_by_slot", args=(Slot(1), block_root), kwargs=empty),
            RecordedCall(name="put_head_root", args=(block_root,), kwargs=empty),
            RecordedCall(
                name="put_justified_checkpoint",
                args=(Checkpoint(root=block_root, slot=Slot(1)),),
                kwargs=empty,
            ),
            RecordedCall(
                name="put_finalized_checkpoint",
                args=(Checkpoint(root=block_root, slot=Slot(1)),),
                kwargs=empty,
            ),
            RecordedCall(
                name="prune_before_slot",
                args=(Slot(1),),
                kwargs=MappingProxyType({"keep_roots": frozenset({block_root})}),
            ),
        ]


class TestPublishAggregatedAttestation:
    """Tests for aggregated attestation publish wiring."""

    async def test_publisher_field_is_invoked(
        self,
        peer_id: PeerId,
        key_manager: XmssKeyManager,
    ) -> None:
        """The publisher field awaits whatever callable is wired to it."""
        service = create_mock_sync_service(peer_id)
        published: list[SignedAggregatedAttestation] = []

        async def capture(agg: SignedAggregatedAttestation) -> None:
            published.append(agg)

        service.publish_aggregated_attestation = capture
        signed = _signed_aggregated_attestation(key_manager)
        await service.publish_aggregated_attestation(signed)
        assert published == [signed]


class TestSyncTriggerGuards:
    """Tests for the SYNCING trigger embedded in on_peer_status."""

    async def test_noop_when_already_syncing(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """No second transition while already in SYNCING (SYNCING -> SYNCING is invalid)."""
        sync_service.state = SyncState.SYNCING
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
        )

        await sync_service.on_peer_status(peer_id, status)

        assert sync_service.state == SyncState.SYNCING


class TestSyncCompleteGuards:
    """Tests for _check_sync_complete early exits."""

    async def test_check_sync_complete_ignored_when_not_syncing(
        self,
        sync_service: SyncService,
        peer_id: PeerId,
    ) -> None:
        """Completion logic only runs during SYNCING (IDLE -> SYNCED is invalid)."""
        sync_service.state = SyncState.IDLE
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )
        sync_service.peer_manager.update_status(peer_id, status)

        await sync_service._check_sync_complete()

        assert sync_service.state == SyncState.IDLE


class TestPendingAttestationLimits:
    """Tests for bounded pending attestation queues."""

    async def test_pending_attestations_trimmed_to_max(
        self,
        sync_service: SyncService,
    ) -> None:
        """Buffer keeps only the most recent MAX_PENDING_ATTESTATIONS entries."""
        sync_service.state = SyncState.SYNCING
        unknown = Bytes32(b"\xcd" * 32)

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        mock_store.reject_attestation = lambda _att: True

        for i in range(MAX_PENDING_ATTESTATIONS + 50):
            target = Checkpoint(root=unknown, slot=Slot(i))
            att = make_signed_attestation(ValidatorIndex(0), target=target)
            await sync_service.on_gossip_attestation(att)

        assert len(sync_service._pending_attestations) == MAX_PENDING_ATTESTATIONS
        last_slot = MAX_PENDING_ATTESTATIONS + 49
        assert sync_service._pending_attestations[-1].data.slot == Slot(last_slot)

    async def test_pending_aggregated_trimmed_to_max(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
    ) -> None:
        """Aggregated attestation buffer uses the same cap."""
        sync_service.state = SyncState.SYNCING

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        mock_store.reject_aggregated_attestation = lambda _att: True

        signed = _signed_aggregated_attestation(key_manager)
        for _ in range(MAX_PENDING_ATTESTATIONS + 10):
            await sync_service.on_gossip_aggregated_attestation(signed)

        assert len(sync_service._pending_aggregated_attestations) == MAX_PENDING_ATTESTATIONS


class TestAggregatedAttestationGossip:
    """Tests for aggregated attestation gossip paths."""

    async def test_aggregated_accepted_when_syncing(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
    ) -> None:
        sync_service.state = SyncState.SYNCING
        signed = _signed_aggregated_attestation(key_manager)
        await sync_service.on_gossip_aggregated_attestation(signed)
        mock_store = cast(MockForkchoiceStore, sync_service.store)
        assert mock_store._aggregated_attestations_received == [signed]

    async def test_aggregated_buffered_on_key_error(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
    ) -> None:
        sync_service.state = SyncState.SYNCING
        signed = _signed_aggregated_attestation(key_manager)

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        mock_store.reject_aggregated_attestation = lambda _att: True

        await sync_service.on_gossip_aggregated_attestation(signed)
        assert list(sync_service._pending_aggregated_attestations) == [signed]

    async def test_replay_pending_mixed_success_and_failure(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
    ) -> None:
        sync_service.state = SyncState.SYNCING
        head = sync_service.store.head
        ok_target = Checkpoint(root=head, slot=Slot(0))
        ok_att = make_signed_attestation(ValidatorIndex(0), target=ok_target)
        bad_signed = _signed_aggregated_attestation(key_manager)

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        mock_store.reject_aggregated_attestation = lambda att: att is bad_signed

        sync_service._pending_attestations.append(ok_att)
        sync_service._pending_aggregated_attestations.append(bad_signed)
        sync_service._replay_pending_attestations()

        assert ok_att in mock_store._attestations_received
        assert list(sync_service._pending_aggregated_attestations) == [bad_signed]


class TestReplayPendingAttestationsPlain:
    """Replay behavior for the plain attestation pending queue."""

    def test_replay_plain_mixed_success_and_failure(self, sync_service: SyncService) -> None:
        """Still-invalid plain attestations stay buffered after replay."""
        sync_service.state = SyncState.SYNCING
        mock_store = cast(MockForkchoiceStore, sync_service.store)
        head = mock_store.head
        unknown = Bytes32(b"\xee" * 32)

        ok_att = make_signed_attestation(
            ValidatorIndex(0),
            target=Checkpoint(root=head, slot=Slot(0)),
        )
        bad_att = make_signed_attestation(
            ValidatorIndex(1),
            target=Checkpoint(root=unknown, slot=Slot(5)),
        )

        mock_store.reject_attestation = lambda att: att.data.target.root == unknown

        sync_service._pending_attestations.append(ok_att)
        sync_service._pending_attestations.append(bad_att)
        sync_service._replay_pending_attestations()

        assert ok_att in mock_store._attestations_received
        assert list(sync_service._pending_attestations) == [bad_att]
