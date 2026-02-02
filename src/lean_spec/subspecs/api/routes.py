"""API route definitions."""

from collections.abc import Awaitable, Callable

from aiohttp import web

from .endpoints import checkpoints, health, metrics, states

ROUTES: dict[str, Callable[[web.Request], Awaitable[web.Response]]] = {
    "/lean/v0/health": health.handle,
    "/lean/v0/states/finalized": states.handle_finalized,
    "/lean/v0/checkpoints/justified": checkpoints.handle_justified,
    "/metrics": metrics.handle,
}
"""All API routes mapped to their handlers."""
