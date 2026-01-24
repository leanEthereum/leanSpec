"""
API server for checkpoint sync, node status, and metrics endpoints.

Provides HTTP endpoints for:
- /lean/v0/states/finalized - Serve finalized checkpoint state as SSZ
- /lean/v0/checkpoints/justified - Return latest justified checkpoint information
- /lean/v0/health - Health check endpoint
- /metrics - Prometheus metrics endpoint

This matches the checkpoint sync API implemented in zeam.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from aiohttp import web

from lean_spec.subspecs.metrics import generate_metrics

if TYPE_CHECKING:
    from lean_spec.subspecs.forkchoice import Store

logger = logging.getLogger(__name__)


def _no_store() -> Store | None:
    """Default store getter that returns None."""
    return None


async def _handle_health(_request: web.Request) -> web.Response:
    """Handle health check endpoint."""
    return web.json_response({"status": "healthy", "service": "lean-spec-api"})


async def _handle_metrics(_request: web.Request) -> web.Response:
    """Handle Prometheus metrics endpoint."""
    return web.Response(
        body=generate_metrics(),
        content_type="text/plain; version=0.0.4; charset=utf-8",
    )


@dataclass(frozen=True, slots=True)
class ApiServerConfig:
    """Configuration for the API server."""

    host: str = "0.0.0.0"
    """Host address to bind to."""

    port: int = 5052
    """Port to listen on."""

    enabled: bool = True
    """Whether the API server is enabled."""


@dataclass(slots=True)
class ApiServer:
    """
    HTTP API server for checkpoint sync and node status.

    Provides endpoints for:
    - Checkpoint sync: Download finalized state for fast sync
    - Health checks: Verify node is running

    Uses aiohttp to handle HTTP protocol details efficiently.
    """

    config: ApiServerConfig
    """Server configuration."""

    store_getter: Callable[[], Store | None] = _no_store
    """Callable that returns the current Store instance."""

    _runner: web.AppRunner | None = field(default=None, init=False)
    """The aiohttp application runner."""

    _site: web.TCPSite | None = field(default=None, init=False)
    """The TCP site for the server."""

    @property
    def store(self) -> Store | None:
        """Get the current Store instance."""
        return self.store_getter()

    async def start(self) -> None:
        """Start the API server in the background."""
        if not self.config.enabled:
            logger.info("API server is disabled")
            return

        app = web.Application()
        app.add_routes(
            [
                web.get("/lean/v0/health", _handle_health),
                web.get("/metrics", _handle_metrics),
                web.get("/lean/v0/states/finalized", self._handle_finalized_state),
                web.get("/lean/v0/checkpoints/justified", self._handle_justified_checkpoint),
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

    async def _handle_finalized_state(self, _request: web.Request) -> web.Response:
        """
        Handle finalized checkpoint state endpoint.

        Serves the finalized state as SSZ binary at /lean/v0/states/finalized.
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

    async def _handle_justified_checkpoint(self, _request: web.Request) -> web.Response:
        """
        Handle latest justified checkpoint endpoint.

        Returns checkpoint info as JSON at /lean/v0/checkpoints/justified.
        Useful for monitoring consensus progress and fork choice state.

        Response format:
        {
            "slot": <slot_number>,
            "root": "<hex_root_hash>"
        }
        """
        store = self.store
        if store is None:
            raise web.HTTPServiceUnavailable(reason="Store not initialized")

        justified = store.latest_justified

        return web.json_response(
            {
                "slot": justified.slot,
                "root": justified.root.hex(),
            }
        )
