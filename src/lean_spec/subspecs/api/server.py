"""
API server implementation using aiohttp.

Provides the HTTP server that serves routes defined in routes.py.
See endpoints/ for endpoint specifications and handlers.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from aiohttp import web

from .routes import ROUTES

if TYPE_CHECKING:
    from lean_spec.subspecs.forkchoice import Store

logger = logging.getLogger(__name__)


_routes = [web.get(path, handler) for path, handler in ROUTES.items()]
"""aiohttp route definitions generated from ROUTES."""


# =============================================================================
# IMPLEMENTATION-SPECIFIC
# =============================================================================
# The following classes are implementation details.
# Other implementations may structure their code differently.


@dataclass(frozen=True, slots=True)
class ApiServerConfig:
    """
    Configuration for the API server.

    Implementation-specific. Other implementations may use different
    configuration patterns (env vars, config files, CLI args, etc.).
    """

    host: str = "0.0.0.0"
    """Host address to bind to."""

    port: int = 5052
    """Port to listen on."""

    enabled: bool = True
    """Whether the API server is enabled."""


@dataclass(slots=True)
class ApiServer:
    """
    HTTP API server using aiohttp.

    Implementation-specific. This class handles:
    - Server lifecycle (start, stop, run)
    - Route registration
    - Store access via callable getter

    Other implementations may use different frameworks or patterns.
    """

    config: ApiServerConfig
    """Server configuration."""

    store_getter: Callable[[], Store | None] | None = None
    """Callable that returns the current Store instance."""

    _runner: web.AppRunner | None = field(default=None, init=False)
    """aiohttp application runner."""

    _site: web.TCPSite | None = field(default=None, init=False)
    """TCP site for the server."""

    @property
    def store(self) -> Store | None:
        """Get the current Store instance."""
        return self.store_getter() if self.store_getter else None

    async def start(self) -> None:
        """Start the API server in the background."""
        if not self.config.enabled:
            logger.info("API server is disabled")
            return

        app = web.Application()

        # Store the store_getter in app for handlers that need store access
        app["store_getter"] = self.store_getter

        # Add all routes
        app.add_routes(_routes)

        self._runner = web.AppRunner(app)
        await self._runner.setup()

        self._site = web.TCPSite(self._runner, self.config.host, self.config.port)
        await self._site.start()

        logger.info(f"API server listening on {self.config.host}:{self.config.port}")

    async def run(self) -> None:
        """
        Run the API server until shutdown.

        Blocks until stop() is called.
        """
        await self.start()

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
