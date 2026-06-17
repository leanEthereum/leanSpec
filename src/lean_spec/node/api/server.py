"""API server implementation using aiohttp."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from aiohttp import web

from lean_spec.node.api.context import AggregatorRoleControl, ApiContext
from lean_spec.node.api.handlers import ApiHandlers
from lean_spec.spec.forks import LstarSpec, SignedBlock, Store
from lean_spec.spec.ssz import Bytes32

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ApiServerConfig:
    """Configuration for the API server."""

    host: str = "0.0.0.0"
    """Host address to bind to."""

    port: int = 5052
    """Port to listen on."""


@dataclass(slots=True)
class ApiServer:
    """HTTP API server using aiohttp."""

    config: ApiServerConfig
    """Server configuration."""

    spec: LstarSpec = field(default_factory=LstarSpec)
    """Fork spec used by handlers needing consensus computations (e.g. fork-choice weights)."""

    store_getter: Callable[[], Store | None] | None = None
    """Callable that returns the current Store instance."""

    signed_block_getter: Callable[[Bytes32], SignedBlock | None] | None = None
    """Optional callable returning the signed block for a block root."""

    aggregator_role_control: AggregatorRoleControl | None = None
    """Optional runtime accessor for the node's aggregator role."""

    _runner: web.AppRunner | None = field(default=None, init=False)
    """aiohttp application runner."""

    _site: web.TCPSite | None = field(default=None, init=False)
    """TCP site for the server."""

    _stop_event: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    """Set when the server stops, so run() can return without polling."""

    @property
    def store(self) -> Store | None:
        """Get the current Store instance."""
        return self.store_getter() if self.store_getter else None

    @property
    def bound_port(self) -> int:
        """
        TCP port the running server actually listens on.

        Resolves the OS-assigned port when the configuration requested port 0.
        """
        if self._runner is None:
            raise RuntimeError("API server is not running")
        # The runner exposes one socket address per listening site.
        # The port is the second element of the first address.
        return int(self._runner.addresses[0][1])

    async def start(self) -> None:
        """Start the API server in the background."""
        app = web.Application()

        # Resolve the shared dependencies once and bind them to the handlers.
        # Every route then serves through a handler method that reads them.
        context = ApiContext(
            spec=self.spec,
            store_getter=self.store_getter,
            aggregator_role_control=self.aggregator_role_control,
            signed_block_getter=self.signed_block_getter,
        )
        handlers = ApiHandlers(context)

        # The admin routes under /lean/v0/admin are unauthenticated.
        # Deployments must restrict access to them at the network layer.
        app.add_routes(
            [
                web.get("/lean/v0/health", handlers.health),
                web.get("/lean/v0/states/finalized", handlers.finalized_state),
                web.get("/lean/v0/blocks/finalized", handlers.finalized_block),
                web.get("/lean/v0/checkpoints/justified", handlers.justified_checkpoint),
                web.get("/lean/v0/fork_choice", handlers.fork_choice),
                web.get("/metrics", handlers.metrics),
                web.get("/lean/v0/admin/aggregator", handlers.aggregator_status),
                web.post("/lean/v0/admin/aggregator", handlers.aggregator_toggle),
            ]
        )

        self._runner = web.AppRunner(app)
        await self._runner.setup()

        self._site = web.TCPSite(self._runner, self.config.host, self.config.port)
        await self._site.start()

        logger.info("API server listening on %s:%d", self.config.host, self.bound_port)

    async def run(self) -> None:
        """Run the API server until it is asked to stop."""
        await self.start()
        await self._stop_event.wait()

    def stop(self) -> None:
        """Request graceful shutdown (fire-and-forget). Prefer aclose() in async code."""
        if self._runner is not None:
            asyncio.create_task(self.aclose())

    async def aclose(self) -> None:
        """Gracefully stop the server. Await this in async code for clean shutdown."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            logger.info("API server stopped")
        self._stop_event.set()
