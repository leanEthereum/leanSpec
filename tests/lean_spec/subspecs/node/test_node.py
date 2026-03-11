"""Tests for the Node orchestrator."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from lean_spec.subspecs.api import ApiServerConfig
from lean_spec.subspecs.chain.config import (
    HISTORICAL_ROOTS_LIMIT,
    INTERVALS_PER_SLOT,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    State,
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
from lean_spec.subspecs.node import Node, NodeConfig
from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import MockEventSource, MockNetworkRequester, make_validators

GENESIS_TIME = Uint64(1704067200)


_DEFAULT_TEST_SLOT = Slot(10)


def _make_mock_db_data(
    test_slot: Slot = _DEFAULT_TEST_SLOT,
) -> tuple[MagicMock, Block, State, Checkpoint]:
    """Build a mock database with consistent block/state/checkpoint data."""
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
        config=Config(genesis_time=GENESIS_TIME),
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

    mock_db = MagicMock()
    mock_db.get_head_root.return_value = head_root
    mock_db.get_block.return_value = block
    mock_db.get_state.return_value = state
    mock_db.get_justified_checkpoint.return_value = checkpoint
    mock_db.get_finalized_checkpoint.return_value = checkpoint
    return mock_db, block, state, checkpoint


@pytest.fixture
def node_config() -> NodeConfig:
    """Provide a basic node configuration for tests."""
    return NodeConfig(
        genesis_time=GENESIS_TIME,
        validators=make_validators(3),
        event_source=MockEventSource(),
        network=MockNetworkRequester(),
        time_fn=lambda: 1704067200.0,
    )


class TestNodeFromGenesis:
    """Tests for Node.from_genesis factory method."""

    def test_creates_store_with_genesis_block(self, node_config: NodeConfig) -> None:
        """Store contains genesis block at slot 0."""
        node = Node.from_genesis(node_config)

        assert len(node.store.blocks) == 1

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

        assert node.chain_service.sync_service is node.sync_service
        assert node.network_service.sync_service is node.sync_service


class TestDatabaseLoading:
    """Tests for _try_load_from_database."""

    def test_returns_none_when_no_database(self) -> None:
        """No database returns None."""
        assert Node._try_load_from_database(None, validator_id=None) is None

    def test_returns_none_when_no_head_root(self) -> None:
        """Empty database returns None."""
        mock_db = MagicMock()
        mock_db.get_head_root.return_value = None

        assert Node._try_load_from_database(mock_db, validator_id=None) is None

    def test_returns_none_when_block_missing(self) -> None:
        """Missing block returns None."""
        mock_db = MagicMock()
        mock_db.get_head_root.return_value = Bytes32(b"\x01" * 32)
        mock_db.get_block.return_value = None
        mock_db.get_state.return_value = MagicMock()

        assert Node._try_load_from_database(mock_db, validator_id=None) is None

    def test_returns_none_when_state_missing(self) -> None:
        """Missing state returns None."""
        mock_db = MagicMock()
        mock_db.get_head_root.return_value = Bytes32(b"\x01" * 32)
        mock_db.get_block.return_value = MagicMock()
        mock_db.get_state.return_value = None

        assert Node._try_load_from_database(mock_db, validator_id=None) is None

    def test_returns_none_when_justified_missing(self) -> None:
        """Missing justified checkpoint returns None."""
        mock_db, block, state, _ = _make_mock_db_data()
        mock_db.get_justified_checkpoint.return_value = None

        assert Node._try_load_from_database(mock_db, validator_id=None) is None

    def test_returns_none_when_finalized_missing(self) -> None:
        """Missing finalized checkpoint returns None."""
        mock_db, block, state, _ = _make_mock_db_data()
        mock_db.get_finalized_checkpoint.return_value = None
        mock_db.get_justified_checkpoint.return_value = MagicMock()

        assert Node._try_load_from_database(mock_db, validator_id=None) is None

    def test_successful_load_uses_wall_clock_time(self) -> None:
        """Store time uses wall clock when it exceeds block-based time."""
        test_slot = Slot(10)
        mock_db, _, _, _ = _make_mock_db_data(test_slot)

        # Simulate 100 seconds after genesis (well past slot 10 at 4s/slot = 40s).
        wall_time = float(GENESIS_TIME) + 100.0
        store = Node._try_load_from_database(
            mock_db,
            validator_id=ValidatorIndex(0),
            genesis_time=GENESIS_TIME,
            time_fn=lambda: wall_time,
        )

        assert store is not None

        # Wall clock: 100s * 5 intervals / 4 seconds = 125 intervals.
        expected_wall = Uint64(100) * INTERVALS_PER_SLOT // SECONDS_PER_SLOT
        # Block-based: slot 10 * 5 = 50 intervals.
        expected_block = test_slot * INTERVALS_PER_SLOT
        assert expected_wall > expected_block
        assert store.time == expected_wall

    def test_load_uses_block_time_when_wall_clock_behind(self) -> None:
        """Store time floors to block-based time if wall clock is behind."""
        test_slot = Slot(100)
        mock_db, _, _, _ = _make_mock_db_data(test_slot)

        # Simulate wall clock only 10 seconds after genesis (slot 100 is at 400s).
        wall_time = float(GENESIS_TIME) + 10.0
        store = Node._try_load_from_database(
            mock_db,
            validator_id=ValidatorIndex(0),
            genesis_time=GENESIS_TIME,
            time_fn=lambda: wall_time,
        )

        assert store is not None

        # Block-based: slot 100 * 5 = 500 intervals.
        expected_block = test_slot * INTERVALS_PER_SLOT
        assert store.time == expected_block


class TestOptionalServiceWiring:
    """Tests for optional services (API server, validator service)."""

    def test_api_server_created_when_config_provided(self) -> None:
        """API server is created when api_config is set."""
        config = NodeConfig(
            genesis_time=GENESIS_TIME,
            validators=make_validators(3),
            event_source=MockEventSource(),
            network=MockNetworkRequester(),
            time_fn=lambda: 1704067200.0,
            api_config=ApiServerConfig(host="127.0.0.1", port=5052),
        )
        node = Node.from_genesis(config)
        assert node.api_server is not None

    def test_api_server_none_when_no_config(self, node_config: NodeConfig) -> None:
        """API server is None when api_config is not set."""
        node = Node.from_genesis(node_config)
        assert node.api_server is None

    def test_validator_service_created_when_registry_provided(self) -> None:
        """Validator service is created when validator_registry is set."""
        registry = ValidatorRegistry()
        registry.add(
            ValidatorEntry(
                index=ValidatorIndex(0),
                attestation_secret_key=MagicMock(),
                proposal_secret_key=MagicMock(),
            )
        )

        config = NodeConfig(
            genesis_time=GENESIS_TIME,
            validators=make_validators(3),
            event_source=MockEventSource(),
            network=MockNetworkRequester(),
            time_fn=lambda: 1704067200.0,
            validator_registry=registry,
        )
        node = Node.from_genesis(config)
        assert node.validator_service is not None

    def test_validator_service_none_when_no_registry(self, node_config: NodeConfig) -> None:
        """Validator service is None when no registry is set."""
        node = Node.from_genesis(node_config)
        assert node.validator_service is None


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

    async def test_wait_shutdown_stops_chain_service(self, node_config: NodeConfig) -> None:
        """Shutdown stops the chain service."""
        node = Node.from_genesis(node_config)
        asyncio.get_running_loop().call_later(0.05, node.stop)
        await node.run(install_signal_handlers=False)

        assert node.chain_service._running is False

    async def test_wait_shutdown_stops_network_service(self, node_config: NodeConfig) -> None:
        """Shutdown stops the network service."""
        node = Node.from_genesis(node_config)
        asyncio.get_running_loop().call_later(0.05, node.stop)
        await node.run(install_signal_handlers=False)

        assert node.network_service._running is False

    async def test_database_closed_after_run(self) -> None:
        """Database is closed after run exits."""
        mock_db = MagicMock()
        config = NodeConfig(
            genesis_time=GENESIS_TIME,
            validators=make_validators(3),
            event_source=MockEventSource(),
            network=MockNetworkRequester(),
            time_fn=lambda: 1704067200.0,
        )
        node = Node.from_genesis(config)
        node.database = mock_db

        asyncio.get_running_loop().call_later(0.05, node.stop)
        await node.run(install_signal_handlers=False)

        mock_db.close.assert_called_once()


class TestGenesisPersistence:
    """Tests for genesis block/state persistence to database."""

    def test_from_genesis_persists_block_to_database(self) -> None:
        """Genesis block is persisted to the database."""
        config = NodeConfig(
            genesis_time=GENESIS_TIME,
            validators=make_validators(3),
            event_source=MockEventSource(),
            network=MockNetworkRequester(),
            time_fn=lambda: 1704067200.0,
            database_path=":memory:",
        )
        node = Node.from_genesis(config)

        # The database should have the genesis block.
        assert node.database is not None
        head_root = node.database.get_head_root()
        assert head_root is not None
        block = node.database.get_block(head_root)
        assert block is not None
        assert block.slot == Slot(0)

    def test_from_genesis_persists_state_to_database(self) -> None:
        """Genesis state is persisted to the database."""
        config = NodeConfig(
            genesis_time=GENESIS_TIME,
            validators=make_validators(3),
            event_source=MockEventSource(),
            network=MockNetworkRequester(),
            time_fn=lambda: 1704067200.0,
            database_path=":memory:",
        )
        node = Node.from_genesis(config)

        assert node.database is not None
        head_root = node.database.get_head_root()
        assert head_root is not None
        state = node.database.get_state(head_root)
        assert state is not None

    def test_from_genesis_persists_checkpoints(self) -> None:
        """Justified and finalized checkpoints are persisted."""
        config = NodeConfig(
            genesis_time=GENESIS_TIME,
            validators=make_validators(3),
            event_source=MockEventSource(),
            network=MockNetworkRequester(),
            time_fn=lambda: 1704067200.0,
            database_path=":memory:",
        )
        node = Node.from_genesis(config)

        assert node.database is not None
        assert node.database.get_justified_checkpoint() is not None
        assert node.database.get_finalized_checkpoint() is not None

    def test_from_genesis_without_database_skips_persistence(self, node_config: NodeConfig) -> None:
        """No database means no persistence calls."""
        node = Node.from_genesis(node_config)
        assert node.database is None


class TestNodeIntegration:
    """Integration tests for Node orchestration."""

    async def test_run_exits_on_stop(self, node_config: NodeConfig) -> None:
        """Node.run() exits cleanly when stop() is called."""
        node = Node.from_genesis(node_config)

        asyncio.get_running_loop().call_later(0.05, node.stop)
        await node.run(install_signal_handlers=False)

    def test_sync_service_receives_store_from_genesis(self, node_config: NodeConfig) -> None:
        """Sync service has access to the genesis store."""
        node = Node.from_genesis(node_config)

        assert node.sync_service.store is not None
        assert len(node.sync_service.store.blocks) == 1

        head_block = node.sync_service.store.blocks[node.sync_service.store.head]
        assert head_block.slot == Slot(0)
