"""
Consensus node orchestrator.

Wires together all services and runs them with structured concurrency.

The Node is the top-level entry point for a minimal Ethereum consensus client.
It initializes all components from genesis configuration and coordinates their
concurrent execution.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from lean_spec.forks import ForkProtocol, Store
from lean_spec.forks.lstar.containers import Block, BlockBody, SignedBlock
from lean_spec.forks.lstar.containers.attestation import SignedAttestation
from lean_spec.forks.lstar.containers.block.types import AggregatedAttestations
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.state import Validators
from lean_spec.forks.lstar.containers.validator import SubnetId, ValidatorIndex
from lean_spec.subspecs.api import AggregatorController, ApiServer, ApiServerConfig
from lean_spec.subspecs.chain import SlotClock
from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.chain.config import ATTESTATION_COMMITTEE_COUNT
from lean_spec.subspecs.chain.service import ChainService
from lean_spec.subspecs.metrics import registry as metrics
from lean_spec.subspecs.networking import NetworkService
from lean_spec.subspecs.networking.client.event_source import EventSource
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.storage import Database, SQLiteDatabase
from lean_spec.subspecs.sync import BlockCache, NetworkRequester, PeerManager, SyncService
from lean_spec.subspecs.validator import ValidatorRegistry, ValidatorService
from lean_spec.types import Bytes32, Uint64

logger = logging.getLogger(__name__)

# Interval in seconds for periodic justified/finalized slot logging.
_JUSTIFIED_FINALIZED_LOG_INTERVAL_SEC: Final = 10.0

_ZERO_TIME: Final = Uint64(0)
"""Default genesis time for database loading when no genesis time is available."""


@dataclass(frozen=True, slots=True)
class NodeConfig:
    """
    Configuration for a consensus node.

    Provides all parameters needed to initialize a node from genesis.
    """

    genesis_time: Uint64
    """Unix timestamp when slot 0 begins."""

    validators: Validators
    """Initial validator set for genesis state."""

    event_source: EventSource
    """Source of network events."""

    network: NetworkRequester
    """Interface for requesting blocks from peers."""

    fork: ForkProtocol
    """Fork specification for state/store construction."""

    time_fn: Callable[[], float] = field(default=time.time)
    """Time source (injectable for deterministic testing)."""

    api_config: ApiServerConfig | None = field(default=None)
    """Optional API server configuration. If None, API server is disabled."""

    database_path: Path | str | None = field(default=None)
    """
    Optional path to SQLite database file for persistence.

    If provided, the node will persist blocks and states to disk.
    On restart, existing state is loaded from the database.

    Use \":memory:\" for in-memory database (testing only).
    """

    validator_registry: ValidatorRegistry | None = field(default=None)
    """
    Optional validator registry with secret keys.

    If provided, the node will participate in consensus by:
    - Proposing blocks when scheduled
    - Creating attestations every slot

    If None, the node runs in passive mode (sync only).
    """

    network_name: str = field(default="0x00000000")
    """
    Network name for gossip topics.

    For devnet testing with ream, use "devnet0".
    """

    is_aggregator: bool = field(default=False)
    """
    Whether this node functions as an aggregator.

    Aggregator selection is static (node-level flag), not VRF-based rotation.
    The spec assumes at least one aggregator node exists in the network.

    With ATTESTATION_COMMITTEE_COUNT = 1, all validators share subnet 0.

    When True:
    - The node performs attestation aggregation operations
    - The ENR advertises aggregator capability to peers

    When False (default):
    - The node runs in standard validator or passive mode

    Seeds the initial value of the live aggregator flag on SyncService and
    NetworkService. The flag can be toggled at runtime via the admin API
    (see AggregatorController). Runtime toggles do not persist across
    restarts and do not update the local ENR or subnet subscriptions.
    """

    aggregate_subnet_ids: tuple[SubnetId, ...] = field(default_factory=tuple)
    """
    Additional attestation subnets to subscribe to and aggregate from.

    When set, the node subscribes to these subnets at the p2p layer in
    addition to validator-derived subnets. Effective only when is_aggregator
    is True — only aggregators import gossip attestations into forkchoice.

    Additive to the validator-derived subnet.
    """


@dataclass(slots=True)
class Node:
    """
    Consensus node orchestrator.

    Initializes all services from genesis.
    Runs them concurrently with structured concurrency.
    """

    store: Store
    """Forkchoice store containing chain state."""

    clock: SlotClock
    """Slot clock for time conversion."""

    sync_service: SyncService
    """Sync service that coordinates state updates."""

    chain_service: ChainService
    """Chain service that drives the consensus clock."""

    network_service: NetworkService
    """Network service that routes events to sync."""

    api_server: ApiServer | None = field(default=None)
    """Optional API server for checkpoint sync and status endpoints."""

    validator_service: ValidatorService | None = field(default=None)
    """Optional validator service for block/attestation production."""

    database: Database | None = field(default=None)
    """Optional database reference for lifecycle management."""

    _shutdown: asyncio.Event = field(default_factory=asyncio.Event)
    """Event signaling shutdown request."""

    @classmethod
    def from_genesis(cls, config: NodeConfig) -> Node:
        """
        Create a fully-wired node from genesis configuration.

        If a database path is provided and contains existing state, the node
        resumes from the persisted state. Otherwise, it starts fresh from genesis.

        Args:
            config: Node configuration with genesis parameters.

        Returns:
            A Node ready to run.
        """
        # Initialize database if path provided.
        #
        # The database is optional - nodes can run without persistence.
        database: Database | None = None
        if config.database_path is not None:
            database = SQLiteDatabase(config.database_path, config.fork.state_class)

        #
        # If database contains valid state, resume from there.
        # Otherwise, fall through to genesis initialization.
        validator_id = (
            config.validator_registry.primary_index() if config.validator_registry else None
        )
        fork = config.fork
        store = cls._try_load_store_from_database(
            database, validator_id, config.genesis_time, config.time_fn, fork
        )

        if store is None:
            # Generate genesis state from validators.
            #
            # Includes initial checkpoints, validator registry, and config.
            state = fork.generate_genesis(config.genesis_time, config.validators)

            # Create genesis block.
            #
            # Slot 0, no parent, empty body.
            # State root is the hash of the genesis state.
            block = Block(
                slot=Slot(0),
                proposer_index=ValidatorIndex(0),
                parent_root=Bytes32.zero(),
                state_root=hash_tree_root(state),
                body=BlockBody(attestations=AggregatedAttestations(data=[])),
            )

            # Initialize forkchoice store.
            #
            # Genesis block is both justified and finalized.
            store = fork.create_store(state, block, validator_id)

            # Persist genesis to database if available.
            #
            # Atomic write ensures a crash during genesis persistence
            # does not leave the database in a partial state.
            if database is not None:
                block_root = hash_tree_root(block)
                with database.batch_write():
                    database.put_block(block, block_root)
                    database.put_state(state, block_root)
                    database.put_head_root(block_root)
                    database.put_justified_checkpoint(store.latest_justified)
                    database.put_finalized_checkpoint(store.latest_finalized)
                    database.put_block_root_by_slot(block.slot, block_root)
                    database.put_block_root_by_state_root(hash_tree_root(state), block_root)
                    database.put_genesis_time(config.genesis_time)

        # Create shared dependencies.
        clock = SlotClock(genesis_time=config.genesis_time, time_fn=config.time_fn)
        peer_manager = PeerManager()
        block_cache = BlockCache()

        # Wire services together.
        #
        # Sync service is the hub. It owns the store and coordinates updates.
        # Chain and network services communicate through it.
        sync_service = SyncService(
            store=store,
            peer_manager=peer_manager,
            block_cache=block_cache,
            clock=clock,
            network=config.network,
            database=database,
            is_aggregator=config.is_aggregator,
            aggregate_subnet_ids=config.aggregate_subnet_ids,
            genesis_start=True,
        )

        chain_service = ChainService(sync_service=sync_service, clock=clock)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=config.event_source,
            network_name=config.network_name,
            is_aggregator=config.is_aggregator,
            aggregate_subnet_ids=config.aggregate_subnet_ids,
        )

        # Wire up aggregated attestation publishing.
        #
        # SyncService delegates aggregate publishing to NetworkService
        # via a callback, avoiding a circular dependency.
        sync_service.set_publish_agg_fn(network_service.publish_aggregated_attestation)

        # Create API server if configured
        api_server: ApiServer | None = None
        if config.api_config is not None:
            # Controller lets the admin API rotate the aggregator role at
            # runtime when another aggregator becomes unhealthy.
            aggregator_controller = AggregatorController(
                sync_service=sync_service,
                network_service=network_service,
            )
            # Store getter captures sync_service to get the live store
            api_server = ApiServer(
                config=config.api_config,
                store_getter=lambda: sync_service.store,
                aggregator_controller=aggregator_controller,
            )

        # Create validator service if registry provided.
        #
        # Validators need keys to sign blocks and attestations.
        # Without a registry, the node runs in passive mode.
        #
        # Wire callbacks to publish produced blocks/attestations to the network.
        validator_service: ValidatorService | None = None
        if config.validator_registry is not None:
            # These wrappers serve a dual purpose:
            #
            # 1. Publish to the network so peers receive the block/attestation.
            # 2. Process locally so the node's own store reflects what it produced.
            #
            # Without local processing, the node would not see its own produced
            # blocks/attestations in forkchoice until they arrived back via gossip.
            async def publish_attestation_wrapper(attestation: SignedAttestation) -> None:
                subnet_id = attestation.validator_id.compute_subnet_id(ATTESTATION_COMMITTEE_COUNT)
                await network_service.publish_attestation(attestation, subnet_id)
                await sync_service.on_gossip_attestation(attestation)

            async def publish_block_wrapper(block: SignedBlock) -> None:
                await network_service.publish_block(block)
                await sync_service.on_gossip_block(block, peer_id=None)

            validator_service = ValidatorService(
                sync_service=sync_service,
                clock=clock,
                registry=config.validator_registry,
                on_block=publish_block_wrapper,
                on_attestation=publish_attestation_wrapper,
            )

        return cls(
            store=store,
            clock=clock,
            sync_service=sync_service,
            chain_service=chain_service,
            network_service=network_service,
            api_server=api_server,
            validator_service=validator_service,
            database=database,
        )

    @staticmethod
    def _try_load_store_from_database(
        database: Database | None,
        validator_id: ValidatorIndex | None,
        genesis_time: Uint64 | None = None,
        time_fn: Callable[[], float] = time.time,
        fork: ForkProtocol | None = None,
    ) -> Store | None:
        """
        Try to load forkchoice store from existing database state.

        Returns None if database is empty or unavailable.

        Uses wall-clock time to set the store's time field. This ensures that
        after a restart, the store reflects actual elapsed time rather than just
        the head block's proposal moment. Without this, the store would reject
        valid attestations as "too far in future" until the chain service ticks
        catch up.

        Args:
            database: Database to load from.
            validator_id: Validator index for the store instance.
            genesis_time: Unix timestamp of genesis (slot 0).
            time_fn: Wall-clock time source.
            fork: Fork specification for store construction.

        Returns:
            Loaded Store or None if no valid state exists.
        """
        if database is None:
            return None

        # Check if database has existing state.
        head_root = database.get_head_root()
        if head_root is None:
            return None

        # Load head block and state.
        head_block = database.get_block(head_root)
        head_state = database.get_state(head_root)

        if head_block is None or head_state is None:
            return None

        # Load checkpoints.
        justified = database.get_justified_checkpoint()
        finalized = database.get_finalized_checkpoint()

        if justified is None or finalized is None:
            return None

        # Fall back to genesis time stored in the database.
        #
        # This enables self-contained restarts without external config.
        if genesis_time is None:
            genesis_time = database.get_genesis_time()

        # Compute store time from wall clock to avoid post-restart drift.
        #
        # Using only the head block's slot would set the store time to the
        # block's proposal moment. After a restart, this makes the store
        # think it's in the past, rejecting valid attestations as "future".
        # Instead, derive time from wall clock, floored by the block's slot.
        clock = SlotClock(genesis_time=genesis_time or _ZERO_TIME, time_fn=time_fn)
        wall_clock_intervals = clock.total_intervals()
        block_intervals = Interval.from_slot(head_block.slot)
        store_time = max(wall_clock_intervals, block_intervals)

        # Reconstruct minimal store from persisted data.
        #
        # The store starts with just the head block and state.
        # Additional blocks can be loaded on demand or via sync.
        if fork is not None:
            store_cls = fork.store_class
        else:
            from lean_spec.forks.lstar.store import Store

            store_cls = Store
        return store_cls(
            time=Interval(store_time),
            config=head_state.config,
            head=head_root,
            safe_target=head_root,
            latest_justified=justified,
            latest_finalized=finalized,
            blocks={head_root: head_block},
            states={head_root: head_state},
            validator_id=validator_id,
        )

    async def run(self, *, install_signal_handlers: bool = True) -> None:
        """
        Run all services until shutdown.

        Returns when shutdown is requested or a service fails.

        Args:
            install_signal_handlers: Whether to handle SIGINT/SIGTERM.
                Disable for testing or non-main threads.
        """
        if install_signal_handlers:
            self._install_signal_handlers()

        # Start API server if configured
        if self.api_server is not None:
            await self.api_server.start()

        # Run services concurrently.
        #
        # A separate task monitors the shutdown signal.
        # When triggered, it stops all services.
        # Once services exit, execution completes.
        # The finally block ensures the database is closed on shutdown.
        try:
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self.chain_service.run())
                tg.create_task(self.network_service.run())
                if self.api_server is not None:
                    tg.create_task(self.api_server.run())
                if self.validator_service is not None:
                    tg.create_task(self.validator_service.run())
                tg.create_task(self._log_justified_finalized_periodically())
                tg.create_task(self._wait_shutdown())
        finally:
            if self.database is not None:
                self.database.close()

    def _install_signal_handlers(self) -> None:
        """
        Install signal handlers for graceful shutdown.

        Handles SIGINT (Ctrl+C) and SIGTERM (process termination).

        Silently ignores errors if handlers cannot be installed.
        This happens in non-main threads or embedded contexts.
        """
        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, self._shutdown.set)
        except (ValueError, RuntimeError):
            # Cannot add handlers outside main thread.
            pass

    async def _log_justified_finalized_periodically(self) -> None:
        """
        Log latest justified and finalized slot periodically.

        Runs every _JUSTIFIED_FINALIZED_LOG_INTERVAL_SEC seconds to aid
        monitoring and debugging of consensus progress.
        Also updates Prometheus gauges for current_slot, connected_peers,
        and validators_count (on scrape).
        """
        while not self._shutdown.is_set():
            await asyncio.sleep(_JUSTIFIED_FINALIZED_LOG_INTERVAL_SEC)
            if self._shutdown.is_set():
                break
            store = self.sync_service.store
            peers_connected = sum(
                1 for p in self.sync_service.peer_manager.get_all_peers() if p.is_connected()
            )
            metrics.lean_current_slot.set(self.clock.current_slot())
            metrics.lean_connected_peers.set(peers_connected)
            metrics.lean_head_slot.set(store.blocks[store.head].slot)
            metrics.lean_safe_target_slot.set(store.blocks[store.safe_target].slot)
            metrics.lean_latest_justified_slot.set(store.latest_justified.slot)
            metrics.lean_latest_finalized_slot.set(store.latest_finalized.slot)
            count = (
                len(self.validator_service.registry) if self.validator_service is not None else 0
            )
            metrics.lean_validators_count.set(count)
            j = store.latest_justified
            f = store.latest_finalized
            j_root = j.root.hex()
            f_root = f.root.hex()
            logger.info("=" * 64)
            logger.info(
                "Peers=%s | Justified slot=%s root=%s | Finalized slot=%s root=%s",
                peers_connected,
                j.slot,
                j_root,
                f.slot,
                f_root,
            )
            logger.info("=" * 64)

    async def _wait_shutdown(self) -> None:
        """
        Wait for shutdown signal then stop services.

        Runs alongside the services.
        When shutdown is signaled, stops all services gracefully.
        """
        await self._shutdown.wait()

        # Signal services to stop.
        #
        # Each service exits its run loop when stopped.
        self.chain_service.stop()
        self.network_service.stop()
        if self.api_server is not None:
            self.api_server.stop()
        if self.validator_service is not None:
            self.validator_service.stop()

    def stop(self) -> None:
        """
        Request graceful shutdown.

        Signals the node to stop all services and exit.
        """
        self._shutdown.set()

    @property
    def is_running(self) -> bool:
        """Check if node is currently running."""
        return not self._shutdown.is_set()
