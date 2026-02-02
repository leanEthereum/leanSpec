"""Tests for NetworkService event routing with meaningful behavioral assertions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, cast

import pytest

from lean_spec.subspecs.chain.clock import SlotClock
from lean_spec.subspecs.containers import (
    AttestationData,
    Checkpoint,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.gossipsub.topic import GossipTopic, TopicKind
from lean_spec.subspecs.networking.peer.info import PeerInfo
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.service import (
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    NetworkService,
    PeerStatusEvent,
)
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.subspecs.sync.service import SyncService
from lean_spec.subspecs.sync.states import SyncState
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import TEST_VALIDATOR_ID, make_mock_signature, make_signed_block


@dataclass
class MockEventSource:
    """Mock source that yields predefined events."""

    events: list[NetworkEvent] = field(default_factory=list)
    _index: int = field(default=0, init=False)
    _published: list[tuple[str, bytes]] = field(default_factory=list, init=False)

    def __aiter__(self) -> "MockEventSource":
        return self

    async def __anext__(self) -> NetworkEvent:
        if self._index >= len(self.events):
            raise StopAsyncIteration
        event = self.events[self._index]
        self._index += 1
        await asyncio.sleep(0)
        return event

    async def publish(self, topic: str, data: bytes) -> None:
        """Mock publish - records published messages for testing."""
        self._published.append((topic, data))


@dataclass
class MockNetworkRequester:
    """Mock network for testing."""

    blocks_by_root: dict[Bytes32, SignedBlockWithAttestation] = field(default_factory=dict)

    async def request_blocks_by_root(
        self,
        peer_id: PeerId,
        roots: list[Bytes32],
    ) -> list[SignedBlockWithAttestation]:
        """Return blocks for requested roots."""
        return [self.blocks_by_root[r] for r in roots if r in self.blocks_by_root]


class MockStore:
    """
    Mock store that tracks actual forkchoice state changes.

    Unlike a trivial mock, this tracks blocks and head updates to verify
    that the routing layer correctly integrates blocks into forkchoice.
    """

    def __init__(self, head_slot: int = 0) -> None:
        """Initialize mock store with genesis block."""
        self._head_slot = head_slot
        self.head = Bytes32.zero()
        self.validator_id: ValidatorIndex = TEST_VALIDATOR_ID
        self.blocks: dict[Bytes32, Any] = {}
        self.states: dict[Bytes32, Any] = {}
        self._attestations_received: list[SignedAttestation] = []
        self._setup_genesis()

        # Required by metrics in the sync service
        self.latest_justified = Checkpoint(root=Bytes32.zero(), slot=Slot(0))
        self.latest_finalized = Checkpoint(root=Bytes32.zero(), slot=Slot(0))

    def _setup_genesis(self) -> None:
        """Set up genesis block in the store."""
        from unittest.mock import MagicMock

        genesis = MagicMock()
        genesis.slot = Slot(self._head_slot)
        self.blocks[self.head] = genesis

    def on_block(self, block: SignedBlockWithAttestation) -> "MockStore":
        """Process a block: add to blocks dict and update head."""
        new_store = MockStore(int(block.message.block.slot))
        new_store.blocks = dict(self.blocks)
        new_store.states = dict(self.states)
        new_store._attestations_received = list(self._attestations_received)
        root = hash_tree_root(block.message.block)
        new_store.blocks[root] = block.message.block
        new_store.head = root
        return new_store

    def on_gossip_attestation(
        self,
        signed_attestation: SignedAttestation,
        is_aggregator: bool = False,
    ) -> "MockStore":
        """Process an attestation: track it for verification."""
        new_store = MockStore(self._head_slot)
        new_store.blocks = dict(self.blocks)
        new_store.states = dict(self.states)
        new_store.head = self.head
        new_store._attestations_received = list(self._attestations_received)
        new_store._attestations_received.append(signed_attestation)
        return new_store


def create_sync_service(peer_id: PeerId) -> SyncService:
    """Create a SyncService with MockStore for testing."""
    mock_store = MockStore(head_slot=0)
    peer_manager = PeerManager()
    peer_manager.add_peer(PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED))

    return SyncService(
        store=cast(Store, mock_store),
        peer_manager=peer_manager,
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0), time_fn=lambda: 1000.0),
        network=MockNetworkRequester(),
        process_block=lambda s, b: s.on_block(b),
    )


@pytest.fixture
def peer_id() -> PeerId:
    """Provide a sample peer ID for tests."""
    return PeerId.from_base58("16Uiu2HAmTestPeer123")


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

    def test_block_added_to_store_blocks_dict(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Gossip block is added to the store's blocks dictionary."""
        sync_service = create_sync_service(peer_id)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify block IS in store after processing
        assert block_root in sync_service.store.blocks
        assert sync_service.store.blocks[block_root].slot == Slot(1)

    def test_store_head_updated_after_block(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Store head is updated to the new block after processing."""
        sync_service = create_sync_service(peer_id)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify head changed from genesis to new block
        assert sync_service.store.head == expected_new_head
        assert sync_service.store.head != genesis_root

    def test_block_ignored_in_idle_state_store_unchanged(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Gossip blocks are ignored in IDLE state - store remains unchanged."""
        sync_service = create_sync_service(peer_id)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify store is completely unchanged
        assert sync_service.store.head == genesis_root
        assert len(sync_service.store.blocks) == initial_blocks_count


class TestAttestationRoutingToForkchoice:
    """Tests verifying attestations are correctly routed to the forkchoice store."""

    def test_attestation_processed_by_store(
        self,
        peer_id: PeerId,
        attestation_topic: GossipTopic,
    ) -> None:
        """Gossip attestation is passed to store.on_gossip_attestation."""
        sync_service = create_sync_service(peer_id)
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
        mock_store = cast(MockStore, sync_service.store)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify attestation was passed to store
        updated_store = cast(MockStore, sync_service.store)
        assert len(updated_store._attestations_received) == initial_count + 1
        assert updated_store._attestations_received[-1].validator_id == Uint64(42)

    def test_attestation_ignored_in_idle_state(
        self,
        peer_id: PeerId,
        attestation_topic: GossipTopic,
    ) -> None:
        """Gossip attestations are ignored in IDLE state."""
        sync_service = create_sync_service(peer_id)
        assert sync_service.state == SyncState.IDLE

        mock_store = cast(MockStore, sync_service.store)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify no attestation was processed
        updated_store = cast(MockStore, sync_service.store)
        assert len(updated_store._attestations_received) == initial_count


class TestPeerStatusStateTransitions:
    """Tests verifying peer status events trigger correct state transitions."""

    def test_peer_status_triggers_idle_to_syncing(
        self,
        peer_id: PeerId,
    ) -> None:
        """PeerStatusEvent transitions SyncService from IDLE to SYNCING."""
        sync_service = create_sync_service(peer_id)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify state transition occurred
        assert sync_service.state == SyncState.SYNCING

    def test_peer_status_updates_peer_manager(
        self,
        peer_id: PeerId,
    ) -> None:
        """PeerStatusEvent updates the peer manager with reported status."""
        sync_service = create_sync_service(peer_id)

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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify peer manager was updated with the status
        network_finalized = sync_service.peer_manager.get_network_finalized_slot()
        assert network_finalized == Slot(50)


class TestIntegrationEventSequence:
    """Integration test for complete event flow from network to forkchoice."""

    def test_full_sync_flow_status_then_block(
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
        sync_service = create_sync_service(peer_id)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify complete state after full flow:
        # - Block was processed and added to store
        # - Head was updated to the new block
        # - State transitioned to SYNCED (head slot 1 >= network finalized slot 0)
        assert expected_head in sync_service.store.blocks
        assert sync_service.store.head == expected_head
        assert sync_service._blocks_processed == 1
        assert sync_service.state == SyncState.SYNCED

    def test_block_before_status_is_ignored(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Block arriving before status is ignored (IDLE state rejects gossip)."""
        sync_service = create_sync_service(peer_id)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Status should trigger SYNCING, but block was already rejected
        assert sync_service.state == SyncState.SYNCING
        assert sync_service.store.head == genesis_root  # Head unchanged
        assert sync_service._blocks_processed == 0  # Block was not processed

    def test_multiple_blocks_chain_extension(
        self,
        peer_id: PeerId,
        block_topic: GossipTopic,
    ) -> None:
        """Multiple sequential blocks extend the chain correctly."""
        sync_service = create_sync_service(peer_id)
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
            event_source=source,
        )

        asyncio.run(network_service.run())

        # Verify chain was extended
        assert block1_root in sync_service.store.blocks
        assert block2_root in sync_service.store.blocks
        assert sync_service.store.head == block2_root
        assert sync_service.store.blocks[block2_root].slot == Slot(2)
        assert sync_service._blocks_processed == 2
