"""API route definitions."""

from collections.abc import Awaitable, Callable

from aiohttp import web

from .endpoints import checkpoint_sync, health, metrics

ROUTES: dict[str, Callable[[web.Request], Awaitable[web.Response]]] = {
    "/lean/v0/health": health.handle,
    "/lean/v0/states/finalized": checkpoint_sync.handle_finalized_state,
    "/lean/v0/checkpoints/justified": checkpoint_sync.handle_justified_checkpoint,
    "/metrics": metrics.handle,
}
"""All API routes mapped to their handlers."""
