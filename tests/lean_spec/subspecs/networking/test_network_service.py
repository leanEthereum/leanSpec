"""Tests for NetworkService event routing with meaningful behavioral assertions."""

from __future__ import annotations

from typing import cast

import pytest

from lean_spec.subspecs.containers import (
    AttestationData,
    Checkpoint,
)
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic, TopicKind
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.service import (
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    NetworkService,
    PeerStatusEvent,
)
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.states import SyncState
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import (
    MockEventSource,
    MockForkchoiceStore,
    create_mock_sync_service,
    make_mock_signature,
    make_signed_block,
)


@pytest.fixture
def block_topic() -> GossipTopic:
    """Provide a block gossip topic for tests."""
    return GossipTopic(kind=TopicKind.BLOCK, fork_digest="0x12345678")


@pytest.fixture
def attestation_topic() -> GossipTopic:
    """Provide an attestation subnet gossip topic for tests."""
    return GossipTopic(kind=TopicKind.ATTESTATION_SUBNET, fork_digest="0x12345678")


class TestBlockRoutingToForkchoice:
    """Tests verifying blocks are correctly routed to the forkchoice store."""

    async def test_block_added_to_store_blocks_dict(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Gossip block is added to the store's blocks dictionary."""
        sync_service = create_mock_sync_service(peer_id)
        sync_service._state = SyncState.SYNCING

        genesis_root = sync_service.store.head

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block_root = hash_tree_root(block.message.block)

        # Verify block is NOT in store before processing
        assert block_root not in sync_service.store.blocks

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify block IS in store after processing
        assert block_root in sync_service.store.blocks
        assert sync_service.store.blocks[block_root].slot == Slot(1)

    async def test_store_head_updated_after_block(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Store head is updated to the new block after processing."""
        sync_service = create_mock_sync_service(peer_id)
        sync_service._state = SyncState.SYNCING

        genesis_root = sync_service.store.head
        assert genesis_root == Bytes32.zero()

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        expected_new_head = hash_tree_root(block.message.block)

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify head changed from genesis to new block
        assert sync_service.store.head == expected_new_head
        assert sync_service.store.head != genesis_root

    async def test_block_ignored_in_idle_state_store_unchanged(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Gossip blocks are ignored in IDLE state - store remains unchanged."""
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        genesis_root = sync_service.store.head
        initial_blocks_count = len(sync_service.store.blocks)

        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify store is completely unchanged
        assert sync_service.store.head == genesis_root
        assert len(sync_service.store.blocks) == initial_blocks_count


class TestAttestationRoutingToForkchoice:
    """Tests verifying attestations are correctly routed to the forkchoice store."""

    async def test_attestation_processed_by_store(
        self,
        peer_id: PeerId,
        attestation_topic: GossipTopic,
    ) -> None:
        """Gossip attestation is passed to store.on_gossip_attestation."""
        sync_service = create_mock_sync_service(peer_id)
        sync_service._state = SyncState.SYNCING

        attestation = SignedAttestation(
            validator_id=ValidatorIndex(42),
            message=AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=make_mock_signature(),
        )

        # Track initial attestations count
        mock_store = cast(MockForkchoiceStore, sync_service.store)
        initial_count = len(mock_store._attestations_received)

        events: list[NetworkEvent] = [
            GossipAttestationEvent(
                attestation=attestation,
                peer_id=peer_id,
                topic=attestation_topic,
            ),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify attestation was passed to store
        updated_store = cast(MockForkchoiceStore, sync_service.store)
        assert len(updated_store._attestations_received) == initial_count + 1
        assert updated_store._attestations_received[-1].validator_id == Uint64(42)

    async def test_attestation_ignored_in_idle_state(
        self,
        peer_id: PeerId,
        attestation_topic: GossipTopic,
    ) -> None:
        """Gossip attestations are ignored in IDLE state."""
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        mock_store = cast(MockForkchoiceStore, sync_service.store)
        initial_count = len(mock_store._attestations_received)

        attestation = SignedAttestation(
            validator_id=ValidatorIndex(99),
            message=AttestationData(
                slot=Slot(1),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
                source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
            signature=make_mock_signature(),
        )

        events: list[NetworkEvent] = [
            GossipAttestationEvent(
                attestation=attestation,
                peer_id=peer_id,
                topic=attestation_topic,
            ),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify no attestation was processed
        updated_store = cast(MockForkchoiceStore, sync_service.store)
        assert len(updated_store._attestations_received) == initial_count


class TestPeerStatusStateTransitions:
    """Tests verifying peer status events trigger correct state transitions."""

    async def test_peer_status_triggers_idle_to_syncing(
        self,
        peer_id: PeerId,
    ) -> None:
        """PeerStatusEvent transitions SyncService from IDLE to SYNCING."""
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        # Peer reports they are ahead (finalized slot 100)
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(100)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
        )

        events: list[NetworkEvent] = [
            PeerStatusEvent(peer_id=peer_id, status=status),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify state transition occurred
        assert sync_service.state == SyncState.SYNCING

    async def test_peer_status_updates_peer_manager(
        self,
        peer_id: PeerId,
    ) -> None:
        """PeerStatusEvent updates the peer manager with reported status."""
        sync_service = create_mock_sync_service(peer_id)

        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(50)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(75)),
        )

        events: list[NetworkEvent] = [
            PeerStatusEvent(peer_id=peer_id, status=status),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify peer manager was updated with the status
        network_finalized = sync_service.peer_manager.get_network_finalized_slot()
        assert network_finalized == Slot(50)


class TestIntegrationEventSequence:
    """Integration test for complete event flow from network to forkchoice."""

    async def test_full_sync_flow_status_then_block(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """
        Complete flow: peer status triggers sync, then block updates store.

        This tests the realistic scenario where:
        1. Peer connects and sends status (triggers IDLE -> SYNCING)
        2. Block arrives via gossip
        3. Block is processed and added to store
        4. Store head is updated
        5. Once head >= network finalized, state transitions to SYNCED
        """
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        genesis_root = sync_service.store.head

        # Peer status to trigger sync (reports finalized at slot 0)
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )

        # Block to process (slot 1 - will exceed network finalized)
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        expected_head = hash_tree_root(block.message.block)

        events: list[NetworkEvent] = [
            PeerStatusEvent(peer_id=peer_id, status=status),
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify complete state after full flow:
        # - Block was processed and added to store
        # - Head was updated to the new block
        # - State transitioned to SYNCED (head slot 1 >= network finalized slot 0)
        assert expected_head in sync_service.store.blocks
        assert sync_service.store.head == expected_head
        assert sync_service._blocks_processed == 1
        assert sync_service.state == SyncState.SYNCED

    async def test_block_before_status_is_ignored(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Block arriving before status is ignored (IDLE state rejects gossip)."""
        sync_service = create_mock_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        genesis_root = sync_service.store.head

        # Block arrives BEFORE status
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )

        # Status arrives AFTER block
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block, peer_id=peer_id, topic=block_topic),
            PeerStatusEvent(peer_id=peer_id, status=status),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Status should trigger SYNCING, but block was already rejected
        assert sync_service.state == SyncState.SYNCING
        assert sync_service.store.head == genesis_root  # Head unchanged
        assert sync_service._blocks_processed == 0  # Block was not processed

    async def test_multiple_blocks_chain_extension(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Multiple sequential blocks extend the chain correctly."""
        sync_service = create_mock_sync_service(peer_id)
        sync_service._state = SyncState.SYNCING

        genesis_root = sync_service.store.head

        # Create chain: genesis -> block1 -> block2
        block1 = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=genesis_root,
            state_root=Bytes32.zero(),
        )
        block1_root = hash_tree_root(block1.message.block)

        block2 = make_signed_block(
            slot=Slot(2),
            proposer_index=ValidatorIndex(1),
            parent_root=block1_root,
            state_root=Bytes32.zero(),
        )
        block2_root = hash_tree_root(block2.message.block)

        events: list[NetworkEvent] = [
            GossipBlockEvent(block=block1, peer_id=peer_id, topic=block_topic),
            GossipBlockEvent(block=block2, peer_id=peer_id, topic=block_topic),
        ]
        source = MockEventSource(events=events)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=source,  # type: ignore[arg-type]
        )

        await network_service.run()

        # Verify chain was extended
        assert block1_root in sync_service.store.blocks
        assert block2_root in sync_service.store.blocks
        assert sync_service.store.head == block2_root
        assert sync_service.store.blocks[block2_root].slot == Slot(2)
        assert sync_service._blocks_processed == 2
