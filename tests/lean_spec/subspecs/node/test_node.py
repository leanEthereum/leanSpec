"""Tests for the Node orchestrator."""

from __future__ import annotations

import asyncio
import dataclasses
import signal
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.forks.lstar import State
from lean_spec.forks.lstar.containers import (
    Block,
    BlockBody,
)
from lean_spec.forks.lstar.containers.block import BlockHeader
from lean_spec.forks.lstar.containers.block.types import AggregatedAttestations
from lean_spec.forks.lstar.containers.checkpoint import Checkpoint
from lean_spec.forks.lstar.containers.config import Config
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.state import Validators
from lean_spec.forks.lstar.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.forks.lstar.spec import LstarSpec
from lean_spec.subspecs.api import ApiServerConfig
from lean_spec.subspecs.chain.config import (
    ATTESTATION_COMMITTEE_COUNT,
    HISTORICAL_ROOTS_LIMIT,
    INTERVALS_PER_SLOT,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.node import Node, NodeConfig
from lean_spec.subspecs.storage.sqlite import SQLiteDatabase
from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.types import Bytes32, Uint64
from tests.lean_spec.helpers import MockEventSource, MockNetworkRequester, make_validators

GENESIS_TIME = Uint64(1704067200)


_DEFAULT_TEST_SLOT = Slot(10)


def _make_populated_db(
    test_slot: Slot = _DEFAULT_TEST_SLOT,
) -> tuple[SQLiteDatabase, Block, State, Checkpoint]:
    """Build a real in-memory database populated with block/state/checkpoint data."""
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

    db = SQLiteDatabase(":memory:", State)
    db.put_block(block, head_root)
    db.put_state(state, head_root)
    db.put_head_root(head_root)
    db.put_justified_checkpoint(checkpoint)
    db.put_finalized_checkpoint(checkpoint)
    return db, block, state, checkpoint


def _make_mock_db_with_partial_data() -> MagicMock:
    """Build a mock database pre-populated with valid data for negative-path tests.

    Returns a MagicMock so individual methods can be overridden to return None,
    simulating partial DB corruption.
    """
    db, block, state, checkpoint = _make_populated_db()
    mock_db = MagicMock()
    mock_db.get_head_root.return_value = Bytes32(b"\x01" * 32)
    mock_db.get_block.return_value = block
    mock_db.get_state.return_value = state
    mock_db.get_justified_checkpoint.return_value = checkpoint
    mock_db.get_finalized_checkpoint.return_value = checkpoint
    return mock_db


@pytest.fixture
def node_config() -> NodeConfig:
    """Provide a basic node configuration for tests."""
    return NodeConfig(
        genesis_time=GENESIS_TIME,
        validators=make_validators(3),
        event_source=MockEventSource(),
        network=MockNetworkRequester(),
        fork=LstarSpec(),
        time_fn=lambda: 1704067200.0,
    )


def _make_validator_registry() -> ValidatorRegistry:
    """Create a minimal validator registry with one entry using real XMSS keys."""
    key_manager = XmssKeyManager.shared()
    kp = key_manager[ValidatorIndex(0)]
    registry = ValidatorRegistry()
    registry.add(
        ValidatorEntry(
            index=ValidatorIndex(0),
            attestation_secret_key=kp.attestation_secret,
            proposal_secret_key=kp.proposal_secret,
        )
    )
    return registry


@pytest.fixture
def node_with_validator(node_config: NodeConfig) -> Node:
    """Create a node with a validator registry configured."""
    config = dataclasses.replace(node_config, validator_registry=_make_validator_registry())
    return Node.from_genesis(config)


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
    """Tests for _try_load_store_from_database."""

    def test_returns_none_when_no_database(self) -> None:
        """No database returns None."""
        assert Node._try_load_store_from_database(None, validator_id=None) is None

    def test_returns_none_when_no_head_root(self) -> None:
        """Empty database returns None."""
        mock_db = MagicMock()
        mock_db.get_head_root.return_value = None

        assert Node._try_load_store_from_database(mock_db, validator_id=None) is None

    def test_returns_none_when_block_missing(self) -> None:
        """Missing block returns None."""
        mock_db = MagicMock()
        mock_db.get_head_root.return_value = Bytes32(b"\x01" * 32)
        mock_db.get_block.return_value = None
        mock_db.get_state.return_value = MagicMock()

        assert Node._try_load_store_from_database(mock_db, validator_id=None) is None

    def test_returns_none_when_state_missing(self) -> None:
        """Missing state returns None."""
        mock_db = MagicMock()
        mock_db.get_head_root.return_value = Bytes32(b"\x01" * 32)
        mock_db.get_block.return_value = MagicMock()
        mock_db.get_state.return_value = None

        assert Node._try_load_store_from_database(mock_db, validator_id=None) is None

    def test_returns_none_when_justified_missing(self) -> None:
        """Missing justified checkpoint returns None."""
        mock_db = _make_mock_db_with_partial_data()
        mock_db.get_justified_checkpoint.return_value = None

        assert Node._try_load_store_from_database(mock_db, validator_id=None) is None

    def test_returns_none_when_finalized_missing(self) -> None:
        """Missing finalized checkpoint returns None."""
        mock_db = _make_mock_db_with_partial_data()
        mock_db.get_finalized_checkpoint.return_value = None

        assert Node._try_load_store_from_database(mock_db, validator_id=None) is None

    def test_successful_load_uses_wall_clock_time(self) -> None:
        """Store time uses wall clock when it exceeds block-based time."""
        test_slot = Slot(10)
        db, _, _, _ = _make_populated_db(test_slot)

        # Simulate 100 seconds after genesis (well past slot 10 at 4s/slot = 40s).
        wall_time = float(GENESIS_TIME) + 100.0
        store = Node._try_load_store_from_database(
            db,
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
        db, _, _, _ = _make_populated_db(test_slot)

        # Simulate wall clock only 10 seconds after genesis (slot 100 is at 400s).
        wall_time = float(GENESIS_TIME) + 10.0
        store = Node._try_load_store_from_database(
            db,
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

    def test_api_server_created_when_config_provided(self, node_config: NodeConfig) -> None:
        """API server is created when api_config is set."""
        config = dataclasses.replace(
            node_config, api_config=ApiServerConfig(host="127.0.0.1", port=5052)
        )
        node = Node.from_genesis(config)
        assert node.api_server is not None

    def test_api_server_none_when_no_config(self, node_config: NodeConfig) -> None:
        """API server is None when api_config is not set."""
        node = Node.from_genesis(node_config)
        assert node.api_server is None

    def test_validator_service_created_when_registry_provided(
        self, node_with_validator: Node
    ) -> None:
        """Validator service is created when validator_registry is set."""
        assert node_with_validator.validator_service is not None

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

    async def test_database_closed_after_run(self, node_config: NodeConfig) -> None:
        """Database is closed after run exits."""
        mock_db = MagicMock()
        node = Node.from_genesis(node_config)
        node.database = mock_db

        asyncio.get_running_loop().call_later(0.05, node.stop)
        await node.run(install_signal_handlers=False)

        mock_db.close.assert_called_once()


class TestGenesisPersistence:
    """Tests for genesis block/state persistence to database."""

    @pytest.fixture
    def db_node(self, node_config: NodeConfig) -> Node:
        """Create a node with an in-memory database for persistence tests."""
        config = dataclasses.replace(node_config, database_path=":memory:")
        return Node.from_genesis(config)

    def test_from_genesis_persists_block_to_database(self, db_node: Node) -> None:
        """Genesis block is persisted to the database."""
        assert db_node.database is not None
        head_root = db_node.database.get_head_root()
        assert head_root is not None
        block = db_node.database.get_block(head_root)
        assert block is not None
        assert block.slot == Slot(0)

    def test_from_genesis_persists_state_to_database(self, db_node: Node) -> None:
        """Genesis state is persisted to the database."""
        assert db_node.database is not None
        head_root = db_node.database.get_head_root()
        assert head_root is not None
        state = db_node.database.get_state(head_root)
        assert state is not None

    def test_from_genesis_persists_checkpoints(self, db_node: Node) -> None:
        """Justified and finalized checkpoints are persisted."""
        node = db_node

        assert node.database is not None
        assert node.database.get_justified_checkpoint() is not None
        assert node.database.get_finalized_checkpoint() is not None

    def test_from_genesis_without_database_skips_persistence(self, node_config: NodeConfig) -> None:
        """No database means no persistence calls."""
        node = Node.from_genesis(node_config)
        assert node.database is None


class TestDatabaseGenesisTimeFallback:
    """Tests for genesis_time fallback to database."""

    def test_falls_back_to_database_genesis_time(self) -> None:
        """When genesis_time is None, loads it from the database.

        The store time should be computed using the database-provided
        genesis time, identical to passing it explicitly.
        """
        test_slot = Slot(10)
        db, _, _, _ = _make_populated_db(test_slot)
        db.put_genesis_time(GENESIS_TIME)

        wall_time = float(GENESIS_TIME) + 100.0
        store = Node._try_load_store_from_database(
            db,
            validator_id=None,
            genesis_time=None,
            time_fn=lambda: wall_time,
        )

        assert store is not None

        # Same math as test_successful_load_uses_wall_clock_time:
        # wall clock 100s * 5 intervals / 4 seconds = 125 intervals.
        expected_wall = Uint64(100) * INTERVALS_PER_SLOT // SECONDS_PER_SLOT
        assert store.time == expected_wall

    def test_zero_genesis_time_when_database_returns_none(self) -> None:
        """When both genesis_time param and database return None, falls back to zero."""
        test_slot = Slot(5)
        db, _, _, _ = _make_populated_db(test_slot)

        wall_time = 200.0
        store = Node._try_load_store_from_database(
            db,
            validator_id=None,
            genesis_time=None,
            time_fn=lambda: wall_time,
        )

        assert store is not None
        # With genesis_time=0, wall clock = 200s * INTERVALS_PER_SLOT / SECONDS_PER_SLOT
        expected_wall = Uint64(200) * INTERVALS_PER_SLOT // SECONDS_PER_SLOT
        expected_block = test_slot * INTERVALS_PER_SLOT
        assert store.time == max(expected_wall, expected_block)


class TestDatabaseResumeFromGenesis:
    """Tests for from_genesis loading from an existing database."""

    def test_from_genesis_resumes_from_database(self, node_config: NodeConfig) -> None:
        """When database has valid state, from_genesis skips genesis creation."""
        config = dataclasses.replace(node_config, database_path=":memory:")
        original_node = Node.from_genesis(config)
        assert original_node.database is not None

        # Patch SQLiteDatabase to reuse the same in-memory DB.
        with patch(
            "lean_spec.subspecs.node.node.SQLiteDatabase",
            return_value=original_node.database,
        ):
            resumed = Node.from_genesis(config)

        # The resumed node should have loaded from the DB (slot 0 genesis).
        head_block = resumed.store.blocks[resumed.store.head]
        assert head_block.slot == Slot(0)


class TestValidatorPublishWrappers:
    """Tests for the publish wrappers created when a validator registry is provided.

    The wrappers fan out each locally-produced block/attestation to both the
    network layer (gossip) and the local sync service (so forkchoice sees the
    produced item immediately, without waiting for a gossip round-trip).
    """

    async def test_block_publish_wrapper_calls_both_services(
        self, node_with_validator: Node
    ) -> None:
        """Block wrapper publishes to network and processes locally."""
        assert node_with_validator.validator_service is not None

        mock_block = MagicMock()
        publish_block = AsyncMock()
        on_gossip_block = AsyncMock()

        with (
            patch.object(type(node_with_validator.network_service), "publish_block", publish_block),
            patch.object(
                type(node_with_validator.sync_service), "on_gossip_block", on_gossip_block
            ),
        ):
            await node_with_validator.validator_service.on_block(mock_block)

        publish_block.assert_awaited_once_with(mock_block)
        on_gossip_block.assert_awaited_once_with(mock_block, peer_id=None)

    async def test_attestation_publish_wrapper_calls_both_services(
        self, node_with_validator: Node
    ) -> None:
        """Attestation wrapper publishes to network with computed subnet_id.

        The subnet_id is derived from the attestation's validator index via
        `compute_subnet_id(ATTESTATION_COMMITTEE_COUNT)`. This test
        verifies the computed value is forwarded correctly to the network.
        """
        assert node_with_validator.validator_service is not None

        mock_attestation = MagicMock()
        # The wrapper calls validator_id.compute_subnet_id(ATTESTATION_COMMITTEE_COUNT).
        expected_subnet = 42
        mock_attestation.validator_id.compute_subnet_id.return_value = expected_subnet

        publish_attestation = AsyncMock()
        on_gossip_attestation = AsyncMock()

        with (
            patch.object(
                type(node_with_validator.network_service),
                "publish_attestation",
                publish_attestation,
            ),
            patch.object(
                type(node_with_validator.sync_service),
                "on_gossip_attestation",
                on_gossip_attestation,
            ),
        ):
            await node_with_validator.validator_service.on_attestation(mock_attestation)

        # Verify subnet_id computation used the correct committee count.
        mock_attestation.validator_id.compute_subnet_id.assert_called_once_with(
            ATTESTATION_COMMITTEE_COUNT
        )
        # Verify the computed subnet_id was forwarded to the network layer.
        publish_attestation.assert_awaited_once_with(mock_attestation, expected_subnet)
        on_gossip_attestation.assert_awaited_once_with(mock_attestation)


class TestSignalHandlers:
    """Tests for signal handler installation."""

    async def test_signal_handlers_silently_ignored_on_error(self, node_config: NodeConfig) -> None:
        """Signal handler installation errors are silently ignored."""
        node = Node.from_genesis(node_config)

        with patch("asyncio.get_running_loop", side_effect=RuntimeError("not main thread")):
            # Should not raise.
            node._install_signal_handlers()

    async def test_run_installs_signal_handlers_by_default(self, node_config: NodeConfig) -> None:
        """run() installs signal handlers when install_signal_handlers=True."""
        node = Node.from_genesis(node_config)

        with patch.object(Node, "_install_signal_handlers", autospec=True) as mock_install:
            asyncio.get_running_loop().call_later(0.05, node.stop)
            await node.run(install_signal_handlers=True)

        mock_install.assert_called_once_with(node)

    def test_install_signal_handlers_success(self, node_config: NodeConfig) -> None:
        """Signal handlers are added to the event loop successfully."""
        node = Node.from_genesis(node_config)
        mock_loop = MagicMock()

        with patch("asyncio.get_running_loop", return_value=mock_loop):
            node._install_signal_handlers()

        # Both SIGINT and SIGTERM should be registered
        assert mock_loop.add_signal_handler.call_count == 2
        calls = [
            (signal.SIGINT, node._shutdown.set),
            (signal.SIGTERM, node._shutdown.set),
        ]
        mock_loop.add_signal_handler.assert_has_calls([call(*c) for c in calls], any_order=True)


class TestPeriodicLogging:
    """Tests for the periodic logging task.

    These tests call `_log_justified_finalized_periodically` directly
    rather than through `run()`, isolating the logging loop from the
    full TaskGroup lifecycle.

    Instead of patching `asyncio.sleep` (which would mutate the global
    asyncio module), we set the log interval to 0 so `sleep(0)` just
    yields control. A background task sets the shutdown event after
    one iteration completes.
    """

    async def test_logging_exits_on_shutdown(self, node_config: NodeConfig) -> None:
        """Periodic logging loop exits when shutdown event is set."""
        node = Node.from_genesis(node_config)

        # Pre-set shutdown so the loop exits after the first sleep.
        node._shutdown.set()
        await node._log_justified_finalized_periodically()

    async def test_logging_reports_metrics(self, node_config: NodeConfig) -> None:
        """Periodic logging updates Prometheus gauges at least once.

        Initializes the metric registry with a test collector, runs one
        full iteration of the loop, then asserts each gauge was set with
        the expected value derived from the genesis store by checking the
        real metric registry values.
        """
        from prometheus_client import CollectorRegistry

        from lean_spec.subspecs.metrics import registry as metrics_registry

        test_reg = CollectorRegistry()
        metrics_registry.init(registry=test_reg)

        try:
            node = Node.from_genesis(node_config)

            original_set = metrics_registry.lean_validators_count.set

            def trigger_shutdown(value: float) -> None:
                original_set(value)
                node._shutdown.set()

            with (
                patch("lean_spec.subspecs.node.node._JUSTIFIED_FINALIZED_LOG_INTERVAL_SEC", 0),
                patch.object(
                    metrics_registry.lean_validators_count, "set", side_effect=trigger_shutdown
                ),
            ):
                await node._log_justified_finalized_periodically()

            assert test_reg.get_sample_value("lean_current_slot") == 0.0
            assert test_reg.get_sample_value("lean_connected_peers") == 0.0
            assert test_reg.get_sample_value("lean_head_slot") == 0.0
            assert test_reg.get_sample_value("lean_safe_target_slot") == 0.0
            assert test_reg.get_sample_value("lean_latest_justified_slot") == 0.0
            assert test_reg.get_sample_value("lean_latest_finalized_slot") == 0.0
            assert test_reg.get_sample_value("lean_validators_count") == 0.0
        finally:
            metrics_registry.reset()
            metrics_registry._initialized = False

    async def test_logging_reports_zero_validators_without_service(
        self, node_config: NodeConfig
    ) -> None:
        """Validator count gauge is set to 0 when no validator service exists.

        This verifies the `len(self.validator_service.registry)` fallback
        path that returns 0 when `validator_service is None`.
        """
        from prometheus_client import CollectorRegistry

        from lean_spec.subspecs.metrics import registry as metrics_registry

        test_reg = CollectorRegistry()
        metrics_registry.init(registry=test_reg)

        try:
            node = Node.from_genesis(node_config)
            assert node.validator_service is None

            original_set = metrics_registry.lean_validators_count.set

            def trigger_shutdown(value: float) -> None:
                original_set(value)
                node._shutdown.set()

            with (
                patch("lean_spec.subspecs.node.node._JUSTIFIED_FINALIZED_LOG_INTERVAL_SEC", 0),
                patch.object(
                    metrics_registry.lean_validators_count, "set", side_effect=trigger_shutdown
                ),
            ):
                await node._log_justified_finalized_periodically()

            assert test_reg.get_sample_value("lean_validators_count") == 0.0
        finally:
            metrics_registry.reset()
            metrics_registry._initialized = False


class TestWaitShutdown:
    """Tests for _wait_shutdown with optional services."""

    async def test_wait_shutdown_skips_none_services(self, node_config: NodeConfig) -> None:
        """Shutdown handles None api_server and validator_service gracefully."""
        node = Node.from_genesis(node_config)
        assert node.api_server is None
        assert node.validator_service is None

        node._shutdown.set()
        await node._wait_shutdown()


class TestRunWithOptionalServices:
    """Tests for run() with optional API and validator services."""

    async def test_run_with_api_server(self, node_config: NodeConfig) -> None:
        """run() starts and runs the API server task when configured."""
        config = dataclasses.replace(
            node_config, api_config=ApiServerConfig(host="127.0.0.1", port=0)
        )
        node = Node.from_genesis(config)
        assert node.api_server is not None

        mock_start = AsyncMock()
        mock_run = AsyncMock()

        asyncio.get_running_loop().call_later(0.05, node.stop)
        with (
            patch.object(type(node.api_server), "start", mock_start),
            patch.object(type(node.api_server), "run", mock_run),
        ):
            await node.run(install_signal_handlers=False)

        # Both start() (called before TaskGroup) and run() (added to TaskGroup)
        # must be awaited for the API server to function.
        mock_start.assert_awaited_once()
        mock_run.assert_awaited_once()

    async def test_run_with_validator_service(self, node_with_validator: Node) -> None:
        """run() starts the validator service task when configured."""
        assert node_with_validator.validator_service is not None

        mock_run = AsyncMock()

        asyncio.get_running_loop().call_later(0.05, node_with_validator.stop)
        with patch.object(type(node_with_validator.validator_service), "run", mock_run):
            await node_with_validator.run(install_signal_handlers=False)

        mock_run.assert_awaited_once()


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
