"""
API server for checkpoint sync and node status endpoints.

Provides HTTP endpoints for:
- /lean/states/finalized - Serve finalized checkpoint state as SSZ
- /health - Health check endpoint

This matches the checkpoint sync API implemented in zeam.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from lean_spec.subspecs.forkchoice import Store

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ApiServerConfig:
    """Configuration for the API server."""

    host: str = "0.0.0.0"
    """Host address to bind to."""

    port: int = 5052
    """Port to listen on."""

    enabled: bool = True
    """Whether the API server is enabled."""


class ApiServer:
    """
    HTTP API server for checkpoint sync and node status.

    Provides endpoints for:
    - Checkpoint sync: Download finalized state for fast sync
    - Health checks: Verify node is running

    Uses aiohttp to handle HTTP protocol details efficiently.
    """

    def __init__(
        self,
        config: ApiServerConfig,
        store_getter: Callable[[], Store | None] = lambda: None,
    ):
        """
        Initialize the API server.

        Args:
            config: Server configuration.
            store_getter: Callable that returns the current Store instance.
        """
        self.config = config
        self._store_getter = store_getter
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    def set_store_getter(self, getter: Callable[[], Store | None]) -> None:
        """
        Set the store getter function.

        Args:
            getter: Callable that returns the current Store instance.
        """
        self._store_getter = getter

    @property
    def store(self) -> Store | None:
        """Get the current Store instance."""
        return self._store_getter()

    async def start(self) -> None:
        """Start the API server in the background."""
        if not self.config.enabled:
            logger.info("API server is disabled")
            return

        app = web.Application()
        app.add_routes(
            [
                web.get("/health", self._handle_health),
                web.get("/lean/states/finalized", self._handle_finalized_state),
            ]
        )

        self._runner = web.AppRunner(app)
        await self._runner.setup()

        self._site = web.TCPSite(self._runner, self.config.host, self.config.port)
        await self._site.start()

        logger.info(f"API server listening on {self.config.host}:{self.config.port}")

    async def run(self) -> None:
        """
        Run the API server until shutdown.

        This method blocks until stop() is called.
        """
        await self.start()

        # Keep running until stopped
        while self._runner is not None:
            await asyncio.sleep(1)

    def stop(self) -> None:
        """Request graceful shutdown."""
        if self._runner is not None:
            asyncio.create_task(self._async_stop())

    async def _async_stop(self) -> None:
        """Gracefully stop the server."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            logger.info("API server stopped")

    async def _handle_health(self, request: web.Request) -> web.Response:
        """Handle health check endpoint."""
        return web.json_response({"status": "healthy", "service": "lean-spec-api"})

    async def _handle_finalized_state(self, request: web.Request) -> web.Response:
        """
        Handle finalized checkpoint state endpoint.

        Serves the finalized state as SSZ binary at /lean/states/finalized.
        This endpoint is used for checkpoint sync - clients can download
        the finalized state to bootstrap quickly instead of syncing from genesis.
        """
        store = self.store
        if store is None:
            raise web.HTTPServiceUnavailable(reason="Store not initialized")

        finalized = store.latest_finalized

        if finalized.root not in store.states:
            raise web.HTTPNotFound(reason="Finalized state not available")

        state = store.states[finalized.root]

        # Run CPU-intensive SSZ encoding in a separate thread
        try:
            ssz_bytes = await asyncio.to_thread(state.encode_bytes)
        except Exception as e:
            logger.error(f"Failed to encode state: {e}")
            raise web.HTTPInternalServerError(reason="Encoding failed") from e

        return web.Response(body=ssz_bytes, content_type="application/octet-stream")
