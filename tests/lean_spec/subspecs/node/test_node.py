"""Tests for the Node orchestrator."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from lean_spec.subspecs.chain.config import HISTORICAL_ROOTS_LIMIT
from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    SignedBlockWithAttestation,
    State,
    Validator,
)
from lean_spec.subspecs.containers.block import BlockHeader
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.config import Config
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking import NetworkEvent, PeerId
from lean_spec.subspecs.node import Node, NodeConfig
from lean_spec.types import Bytes32, Bytes52, Uint64


class MockEventSource:
    """Mock event source that yields controlled events for testing."""

    def __init__(self, events: list[NetworkEvent] | None = None) -> None:
        """Initialize with optional list of events."""
        self._events = events or []
        self._index = 0
        self._published: list[tuple[str, bytes]] = []

    def __aiter__(self) -> MockEventSource:
        """Return self as async iterator."""
        return self

    async def __anext__(self) -> NetworkEvent:
        """Yield next event or stop iteration."""
        if self._index >= len(self._events):
            raise StopAsyncIteration
        event = self._events[self._index]
        self._index += 1
        return event

    async def publish(self, topic: str, data: bytes) -> None:
        """Mock publish - records published messages for testing."""
        self._published.append((topic, data))


class MockNetworkRequester:
    """Mock network requester for testing."""

    async def request_blocks_by_root(
        self,
        peer_id: PeerId,  # noqa: ARG002
        roots: list[Bytes32],  # noqa: ARG002
    ) -> list[SignedBlockWithAttestation]:
        """Return empty list (no blocks available)."""
        return []


@pytest.fixture
def validators() -> Validators:
    """Provide a minimal validator set for tests."""
    return Validators(
        data=[Validator(pubkey=Bytes52(b"\x00" * 52), index=ValidatorIndex(i)) for i in range(3)]
    )


@pytest.fixture
def node_config(validators: Validators) -> NodeConfig:
    """Provide a basic node configuration for tests."""
    return NodeConfig(
        genesis_time=Uint64(1704067200),
        validators=validators,
        event_source=MockEventSource(),
        network=MockNetworkRequester(),
        time_fn=lambda: 1704067200.0,
    )


class TestNodeFromGenesis:
    """Tests for Node.from_genesis factory method."""

    def test_creates_store_with_genesis_block(self, node_config: NodeConfig) -> None:
        """Store contains genesis block at slot 0."""
        node = Node.from_genesis(node_config)

        # Store should have exactly one block (genesis)
        assert len(node.store.blocks) == 1

        # Head should point to a block at slot 0
        head_block = node.store.blocks[node.store.head]
        assert head_block.slot == Slot(0)

    def test_genesis_block_has_correct_parent(self, node_config: NodeConfig) -> None:
        """Genesis block parent is zero hash."""
        node = Node.from_genesis(node_config)

        head_block = node.store.blocks[node.store.head]
        assert head_block.parent_root == Bytes32.zero()

    def test_clock_initialized_with_genesis_time(self, node_config: NodeConfig) -> None:
        """Clock uses genesis time from config."""
        node = Node.from_genesis(node_config)

        assert node.clock.genesis_time == node_config.genesis_time

    def test_services_share_sync_service(self, node_config: NodeConfig) -> None:
        """ChainService and NetworkService reference same SyncService."""
        node = Node.from_genesis(node_config)

        # All services should be wired to the same SyncService instance
        assert node.chain_service.sync_service is node.sync_service
        assert node.network_service.sync_service is node.sync_service

    def test_store_time_from_database_uses_intervals_not_seconds(self) -> None:
        """This test verifies the invariant that store time represents intervals."""

        test_slot = Slot(10)
        head_root = Bytes32(b"\x01" * 32)

        block = Block(
            slot=test_slot,
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )

        checkpoint = Checkpoint(root=head_root, slot=test_slot)

        state = State(
            config=Config(genesis_time=Uint64(1704067200)),
            slot=test_slot,
            latest_block_header=BlockHeader(
                slot=test_slot,
                proposer_index=ValidatorIndex(0),
                parent_root=Bytes32.zero(),
                state_root=Bytes32.zero(),
                body_root=Bytes32.zero(),
            ),
            latest_justified=checkpoint,
            latest_finalized=checkpoint,
            historical_block_hashes=HistoricalBlockHashes(data=[Bytes32.zero()]),
            justified_slots=JustifiedSlots(data=[]),
            validators=Validators(data=[]),
            justifications_roots=JustificationRoots(
                data=[Bytes32.zero()] * int(HISTORICAL_ROOTS_LIMIT)
            ),
            justifications_validators=JustificationValidators(data=[]),
        )

        # Simulates loading from an existing database.
        # Exercises the code path where time is computed from slot.
        mock_db = MagicMock()
        mock_db.get_head_root.return_value = head_root
        mock_db.get_block.return_value = block
        mock_db.get_state.return_value = state
        mock_db.get_justified_checkpoint.return_value = checkpoint
        mock_db.get_finalized_checkpoint.return_value = checkpoint

        # Patching to 8 distinguishes from the seconds per slot.
        patched_intervals = Uint64(8)
        with patch("lean_spec.subspecs.node.node.INTERVALS_PER_SLOT", patched_intervals):
            store = Node._try_load_from_database(mock_db, validator_id=ValidatorIndex(0))

        assert store is not None
        expected_time = Uint64(test_slot * patched_intervals)
        assert store.time == expected_time, (
            f"Store.time should use INTERVALS_PER_SLOT, not SECONDS_PER_SLOT. "
            f"Expected time={expected_time} (slot={test_slot} * intervals={patched_intervals}), "
            f"got time={store.time}"
        )


class TestNodeShutdown:
    """Tests for Node shutdown behavior."""

    def test_stop_sets_shutdown_event(self, node_config: NodeConfig) -> None:
        """Calling stop() sets the shutdown event."""
        node = Node.from_genesis(node_config)

        assert not node._shutdown.is_set()
        node.stop()
        assert node._shutdown.is_set()

    def test_is_running_reflects_shutdown_state(self, node_config: NodeConfig) -> None:
        """is_running property reflects shutdown event state."""
        node = Node.from_genesis(node_config)

        assert node.is_running is True
        node.stop()
        assert node.is_running is False


class TestNodeIntegration:
    """Integration tests for Node orchestration."""

    def test_run_exits_on_stop(self, node_config: NodeConfig) -> None:
        """Node.run() exits cleanly when stop() is called."""
        node = Node.from_genesis(node_config)

        async def run_node() -> None:
            # Schedule stop after a short delay
            asyncio.get_running_loop().call_later(0.05, node.stop)
            await node.run(install_signal_handlers=False)

        # Should complete without hanging or raising
        asyncio.run(run_node())

    def test_sync_service_receives_store_from_genesis(self, node_config: NodeConfig) -> None:
        """Sync service has access to the genesis store."""
        node = Node.from_genesis(node_config)

        # SyncService should have the same store as the node
        assert node.sync_service.store is not None
        assert len(node.sync_service.store.blocks) == 1

        # The store's head should be the genesis block
        head_block = node.sync_service.store.blocks[node.sync_service.store.head]
        assert head_block.slot == Slot(0)
