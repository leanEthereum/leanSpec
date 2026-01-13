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

from lean_spec.subspecs.api import ApiServer, ApiServerConfig
from lean_spec.subspecs.chain import ChainService, SlotClock
from lean_spec.subspecs.containers import Block, BlockBody, State
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.networking import NetworkEventSource, NetworkService
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync import BlockCache, NetworkRequester, PeerManager, SyncService
from lean_spec.types import Bytes32, Uint64


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

    _shutdown: asyncio.Event = field(default_factory=asyncio.Event)
    """Event signaling shutdown request."""

    @classmethod
    def from_genesis(cls, config: NodeConfig) -> Node:
        """
        Create a fully-wired node from genesis configuration.

        Args:
            config: Node configuration with genesis parameters.

        Returns:
            A Node ready to run.
        """
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
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=hash_tree_root(state),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )

        # Initialize forkchoice store.
        #
        # Genesis block is both justified and finalized.
        store = Store.get_forkchoice_store(state, block)

        # Create shared dependencies.
        clock = SlotClock(genesis_time=config.genesis_time, _time_fn=config.time_fn)
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
        )

        chain_service = ChainService(sync_service=sync_service, clock=clock)
        network_service = NetworkService(
            sync_service=sync_service,
            event_source=config.event_source,
        )

        # Create API server if configured
        api_server: ApiServer | None = None
        if config.api_config is not None:
            api_server = ApiServer(config=config.api_config)
            # Set up store getter so API server can access current state
            # We use a lambda that captures sync_service to get the live store
            api_server.set_store_getter(lambda: sync_service.store)

        return cls(
            store=store,
            clock=clock,
            sync_service=sync_service,
            chain_service=chain_service,
            network_service=network_service,
            api_server=api_server,
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
