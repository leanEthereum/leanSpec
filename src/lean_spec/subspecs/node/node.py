"""
Consensus node orchestrator.

Wires together all services and runs them with structured concurrency.

The Node is the top-level entry point for a minimal Ethereum consensus client.
It initializes all components from genesis configuration and coordinates their
concurrent execution.
"""

from __future__ import annotations

import asyncio
import signal
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from lean_spec.subspecs.api import ApiServer, ApiServerConfig
from lean_spec.subspecs.chain import SlotClock
from lean_spec.subspecs.chain.config import ATTESTATION_COMMITTEE_COUNT, INTERVALS_PER_SLOT
from lean_spec.subspecs.chain.service import ChainService
from lean_spec.subspecs.containers import Block, BlockBody, State
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.networking import NetworkEventSource, NetworkService
from lean_spec.subspecs.networking.subnet import compute_subnet_id
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync import BlockCache, NetworkRequester, PeerManager, SyncService
from lean_spec.subspecs.validator import ValidatorRegistry, ValidatorService
from lean_spec.types import Bytes32, Uint64

if TYPE_CHECKING:
    from lean_spec.subspecs.storage import Database


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

    event_source: NetworkEventSource
    """Source of network events."""

    network: NetworkRequester
    """Interface for requesting blocks from peers."""

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

    fork_digest: str = field(default="0x00000000")
    """
    Fork digest for gossip topics.

    For devnet testing with ream, use "devnet0".
    """

    is_aggregator: bool = field(default=False)
    """
    Whether this node functions as an aggregator.

    When True:
    - The node performs attestation aggregation operations
    - The ENR advertises aggregator capability to peers

    When False (default):
    - The node runs in standard validator or passive mode
    """


def get_local_validator_id(registry: ValidatorRegistry | None) -> ValidatorIndex | None:
    """
    Get the validator index for this node.

    For now, returns None as a default for passive nodes or simple setups.
    Future implementations will look up keys in the registry.
    """
    if registry is None or len(registry) == 0:
        return None

    # For simplicity, use the first validator in the registry.
    return registry.indices()[0]


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
            database = cls._create_database(config.database_path)

        #
        # If database contains valid state, resume from there.
        # Otherwise, fall through to genesis initialization.
        validator_id = get_local_validator_id(config.validator_registry)
        store = cls._try_load_from_database(database, validator_id)

        if store is None:
            # Generate genesis state from validators.
            #
            # Includes initial checkpoints, validator registry, and config.
            state = State.generate_genesis(config.genesis_time, config.validators)

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
            store = Store.get_forkchoice_store(state, block, validator_id)

            # Persist genesis to database if available.
            if database is not None:
                block_root = hash_tree_root(block)
                database.put_block(block, block_root)
                database.put_state(state, block_root)
                database.put_head_root(block_root)
                database.put_justified_checkpoint(store.latest_justified)
                database.put_finalized_checkpoint(store.latest_finalized)
                database.put_block_root_by_slot(block.slot, block_root)

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
        )

        chain_service = ChainService(sync_service=sync_service, clock=clock)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=config.event_source,
            fork_digest=config.fork_digest,
            is_aggregator=config.is_aggregator,
        )

        # Create API server if configured
        api_server: ApiServer | None = None
        if config.api_config is not None:
            # Store getter captures sync_service to get the live store
            api_server = ApiServer(
                config=config.api_config,
                store_getter=lambda: sync_service.store,
            )

        # Create validator service if registry provided.
        #
        # Validators need keys to sign blocks and attestations.
        # Without a registry, the node runs in passive mode.
        #
        # Wire callbacks to publish produced blocks/attestations to the network.
        validator_service: ValidatorService | None = None
        if config.validator_registry is not None:
            # Create a wrapper for publish_attestation that computes the subnet_id
            # from the validator_id in the attestation
            async def publish_attestation_wrapper(attestation: SignedAttestation) -> None:
                subnet_id = compute_subnet_id(attestation.validator_id, ATTESTATION_COMMITTEE_COUNT)
                await network_service.publish_attestation(attestation, subnet_id)

            validator_service = ValidatorService(
                sync_service=sync_service,
                clock=clock,
                registry=config.validator_registry,
                on_block=network_service.publish_block,
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
        )

    @staticmethod
    def _create_database(path: Path | str) -> Database:
        """
        Create database instance from path.

        Args:
            path: Path to SQLite database file.

        Returns:
            Database instance ready for use.
        """
        from lean_spec.subspecs.storage import SQLiteDatabase

        # SQLite handles its own caching at the filesystem level.
        return SQLiteDatabase(path)

    @staticmethod
    def _try_load_from_database(
        database: Database | None,
        validator_id: ValidatorIndex | None,
    ) -> Store | None:
        """
        Try to load forkchoice store from existing database state.

        Returns None if database is empty or unavailable.

        Args:
            database: Database to load from.
            validator_id: Validator index for the store instance.

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

        # Reconstruct minimal store from persisted data.
        #
        # The store starts with just the head block and state.
        # Additional blocks can be loaded on demand or via sync.
        return Store(
            time=Uint64(head_block.slot * INTERVALS_PER_SLOT),
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
        async with asyncio.TaskGroup() as tg:
            tg.create_task(self.chain_service.run())
            tg.create_task(self.network_service.run())
            if self.api_server is not None:
                tg.create_task(self.api_server.run())
            if self.validator_service is not None:
                tg.create_task(self.validator_service.run())
            tg.create_task(self._wait_shutdown())

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
