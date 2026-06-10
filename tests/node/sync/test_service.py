"""Tests for sync service module."""

from __future__ import annotations

from types import MappingProxyType
from typing import cast

import pytest

from consensus_testing import (
    MockForkchoiceStore,
    RecordedCall,
    RecordingSyncDatabase,
    create_mock_sync_service,
    make_genesis_state,
    make_genesis_store,
    make_signed_attestation,
    make_signed_block,
)
from consensus_testing.keys import XmssKeyManager
from lean_spec.node.networking import PeerId
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.node.storage.database import Database
from lean_spec.node.sync.config import MAX_PENDING_ATTESTATIONS
from lean_spec.node.sync.service import SyncService
from lean_spec.node.sync.states import SyncState
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks import Checkpoint, Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import (
    AttestationData,
    MultiMessageAggregate,
    SignedAggregatedAttestation,
    SignedBlock,
    SingleMessageAggregate,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32


def make_store_with_attestation_data(
    num_validators: int,
    validator_index: ValidatorIndex,
) -> tuple[Store, AttestationData]:
    """Build a keyed store advanced to slot 1, with attestation data for that slot."""
    attestation_slot = Slot(1)
    store = make_genesis_store(
        num_validators=num_validators,
        validator_index=validator_index,
        time=Interval.from_slot(attestation_slot),
    )
    return store, LstarSpec().produce_attestation_data(store, attestation_slot)


def make_signed_block_from_store(
    store: Store,
    key_manager: XmssKeyManager,
    slot: Slot,
    proposer_index: ValidatorIndex,
) -> tuple[Store, SignedBlock]:
    """
    Produce an honestly signed block and advance the consumer store to accept it.

    Returns the time-advanced store and the signed block.
    The merged proof is built honestly because the caller feeds it through block processing.
    Block processing decodes and verifies the proof.
    """
    spec = LstarSpec()
    new_store, block, attestation_proofs = spec.produce_block_with_signatures(
        store, slot, proposer_index
    )
    block_root = hash_tree_root(block)

    head_state = new_store.states[new_store.head]
    public_keys_per_aggregate: list[list] = [
        [
            PublicKey.decode_bytes(head_state.validators[validator_index].attestation_public_key)
            for validator_index in attestation_proof.participants.to_validator_indices()
        ]
        for attestation_proof in attestation_proofs
    ]
    proposer_public_key = PublicKey.decode_bytes(
        head_state.validators[proposer_index].proposal_public_key
    )
    public_keys_per_aggregate.append([proposer_public_key])

    proposer_signature = key_manager.sign_block_root(proposer_index, slot, block_root)
    proposer_single_message_aggregate = SingleMessageAggregate.aggregate(
        children=[],
        raw_xmss=[(proposer_index, proposer_public_key, proposer_signature)],
        message=block_root,
        slot=slot,
    )
    merged_proof = MultiMessageAggregate.aggregate(
        [*attestation_proofs, proposer_single_message_aggregate],
        public_keys_per_aggregate=public_keys_per_aggregate,
    )

    advanced_store, _ = spec.on_tick(store, Interval.from_slot(block.slot), has_proposal=True)
    return advanced_store, SignedBlock(block=block, proof=merged_proof)


def _signed_aggregated_attestation(key_manager: XmssKeyManager) -> SignedAggregatedAttestation:
    _, attestation_data = make_store_with_attestation_data(
        num_validators=4,
        validator_index=ValidatorIndex(0),
    )
    proof = key_manager.sign_and_aggregate([ValidatorIndex(1)], attestation_data)
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
        assert mock_store.received_attestations == [attestation]

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
        assert mock_store.received_attestations == []

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
        mock_store.reject_attestation = (
            lambda attestation: attestation.data.target.root == unknown_root
        )

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
        assert attestation in mock_store.received_attestations


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

        with pytest.raises(ValueError) as exception_info:
            await sync_service._transition_to(SyncState.SYNCED)
        assert str(exception_info.value) == "Invalid state transition: IDLE -> SYNCED"

    async def test_self_transition_raises_value_error(
        self,
        sync_service: SyncService,
    ) -> None:
        """A transition to the current state is rejected as a no-op move."""
        assert sync_service.state == SyncState.IDLE

        with pytest.raises(ValueError) as exception_info:
            await sync_service._transition_to(SyncState.IDLE)
        assert str(exception_info.value) == "Invalid state transition: IDLE -> IDLE"


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

        async def capture(aggregate: SignedAggregatedAttestation) -> None:
            published.append(aggregate)

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
        mock_store.reject_attestation = lambda _attestation: True

        for i in range(MAX_PENDING_ATTESTATIONS + 50):
            target = Checkpoint(root=unknown, slot=Slot(i))
            attestation = make_signed_attestation(ValidatorIndex(0), target=target)
            await sync_service.on_gossip_attestation(attestation)

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
        mock_store.reject_aggregated_attestation = lambda _attestation: True

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
        assert mock_store.received_aggregated_attestations == [signed]

    async def test_aggregated_buffered_on_key_error(
        self,
        sync_service: SyncService,
        key_manager: XmssKeyManager,
    ) -> None:
        sync_service.state = SyncState.SYNCING
        signed = _signed_aggregated_attestation(key_manager)

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        mock_store.reject_aggregated_attestation = lambda _attestation: True

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
        ok_attestation = make_signed_attestation(ValidatorIndex(0), target=ok_target)
        bad_signed = _signed_aggregated_attestation(key_manager)

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        mock_store.reject_aggregated_attestation = lambda attestation: attestation is bad_signed

        sync_service._pending_attestations.append(ok_attestation)
        sync_service._pending_aggregated_attestations.append(bad_signed)
        sync_service._replay_pending_attestations()

        assert ok_attestation in mock_store.received_attestations
        assert list(sync_service._pending_aggregated_attestations) == [bad_signed]


class TestReplayPendingAttestationsPlain:
    """Replay behavior for the plain attestation pending queue."""

    def test_replay_plain_mixed_success_and_failure(self, sync_service: SyncService) -> None:
        """Still-invalid plain attestations stay buffered after replay."""
        sync_service.state = SyncState.SYNCING
        mock_store = cast(MockForkchoiceStore, sync_service.store)
        head = mock_store.head
        unknown = Bytes32(b"\xee" * 32)

        ok_attestation = make_signed_attestation(
            ValidatorIndex(0),
            target=Checkpoint(root=head, slot=Slot(0)),
        )
        bad_attestation = make_signed_attestation(
            ValidatorIndex(1),
            target=Checkpoint(root=unknown, slot=Slot(5)),
        )

        mock_store.reject_attestation = lambda attestation: attestation.data.target.root == unknown

        sync_service._pending_attestations.append(ok_attestation)
        sync_service._pending_attestations.append(bad_attestation)
        sync_service._replay_pending_attestations()

        assert ok_attestation in mock_store.received_attestations
        assert list(sync_service._pending_attestations) == [bad_attestation]


# Post-block single-message aggregate deconstruction.
#
# Exercises the deconstruction core: for every processed block (gossip,
# head-sync, or backfilled), the merged multi-message aggregate proof is split
# into per-attestation single-message aggregate proofs, merged with locally held
# partials, and written into the pending pool, replacing the partials it subsumes.
#
# Deconstruction only runs for an attestation when:
#
# - its target is ahead of the store's justified checkpoint, so the proof
#   can still help move justification, and
# - it adds at least one participant the node does not already hold.
#
# Only the decision/gate paths are exercised here.
# These tests check when the split runs, not the cryptographic split itself.
# The split-extract-merge round-trip is covered by the aggregation container tests.

# Round-robin proposer is slot % num_validators with four validators.
NUM_VALIDATORS = 4
CHAIN_SLOT = Slot(1)
CHAIN_PROPOSER = ValidatorIndex(1)
BLOCK_SLOT = Slot(2)
BLOCK_PROPOSER = ValidatorIndex(2)


def _setup(
    key_manager: XmssKeyManager,
    *,
    block_participants: list[ValidatorIndex],
):
    """
    Build a two-block chain and a signed block carrying an attestation.

    The chain block sits at slot 1. The returned signed block sits at slot
    2 and carries one attestation whose target is the slot-1 block, ahead
    of the still-genesis justified checkpoint. The returned store holds the
    slot-1 block and its state (the parent state the multi-message aggregate public_key layout
    is resolved against) with the justified checkpoint still at genesis.
    """
    spec = LstarSpec()
    base_store = make_genesis_store(
        num_validators=NUM_VALIDATORS, validator_index=ValidatorIndex(0)
    )

    consumer_store, chain_block = make_signed_block_from_store(
        base_store, key_manager, CHAIN_SLOT, CHAIN_PROPOSER
    )
    chain_store = spec.on_block(consumer_store, chain_block)
    chain_root = hash_tree_root(chain_block.block)

    # Target the slot-1 block; source stays at the genesis justified
    # checkpoint so the builder accepts the attestation.
    attestation_data = AttestationData(
        slot=BLOCK_SLOT,
        head=Checkpoint(root=chain_root, slot=CHAIN_SLOT),
        target=Checkpoint(root=chain_root, slot=CHAIN_SLOT),
        source=chain_store.latest_justified,
    )

    block_proof = key_manager.sign_and_aggregate(block_participants, attestation_data)
    chain_store = chain_store.model_copy(
        update={"latest_known_aggregated_payloads": {attestation_data: {block_proof}}}
    )
    producer_store = chain_store
    _, signed_block = make_signed_block_from_store(
        producer_store, key_manager, BLOCK_SLOT, BLOCK_PROPOSER
    )
    return chain_store, signed_block, attestation_data


def _service(peer_id: PeerId):
    """A SyncService usable to invoke the deconstruction core directly."""
    return create_mock_sync_service(peer_id)


def test_skips_when_target_not_ahead_of_justified(
    peer_id: PeerId, key_manager: XmssKeyManager
) -> None:
    """
    Target at or behind the justified checkpoint -> no aggregates.

    The block's attestation cannot move justification, so the expensive
    split is never attempted and the store is returned unchanged.
    """
    chain_store, signed_block, attestation_data = _setup(
        key_manager, block_participants=[ValidatorIndex(1), ValidatorIndex(2)]
    )
    # Justified now sits at the attestation's target slot.
    store = chain_store.model_copy(update={"latest_justified": attestation_data.target})
    service = _service(peer_id)

    new_store, aggregates = service._deconstruct_block_into_store(store, signed_block)

    assert aggregates == []
    assert new_store is store


def test_skips_when_block_adds_no_new_validators(
    peer_id: PeerId, key_manager: XmssKeyManager
) -> None:
    """
    Block participants are a subset of the local union -> no aggregates.

    The target is ahead of justified, so the only thing stopping the split
    is that the block adds no new participant. The store is unchanged.
    """
    block_participants = [ValidatorIndex(1), ValidatorIndex(2)]
    chain_store, signed_block, attestation_data = _setup(
        key_manager, block_participants=block_participants
    )

    local_partial = key_manager.sign_and_aggregate(
        [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)],
        attestation_data,
    )
    store = chain_store.model_copy(
        update={"latest_new_aggregated_payloads": {attestation_data: {local_partial}}}
    )
    service = _service(peer_id)

    new_store, aggregates = service._deconstruct_block_into_store(store, signed_block)

    assert aggregates == []
    assert new_store is store


def test_noop_when_parent_state_missing(peer_id: PeerId, key_manager: XmssKeyManager) -> None:
    """Without the parent state the public_key layout cannot be resolved -> no-op."""
    chain_store, signed_block, _ = _setup(
        key_manager, block_participants=[ValidatorIndex(1), ValidatorIndex(2)]
    )
    store = chain_store.model_copy(update={"states": {}})
    service = _service(peer_id)

    new_store, aggregates = service._deconstruct_block_into_store(store, signed_block)

    assert aggregates == []
    assert new_store is store
