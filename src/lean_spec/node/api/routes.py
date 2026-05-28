"""API route definitions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from aiohttp import web

from .endpoints import aggregator, checkpoints, fork_choice, health, metrics, states

Handler = Callable[[web.Request], Awaitable[web.Response]]
"""Type alias for aiohttp request handlers."""

ROUTES: dict[str, Handler] = {
    "/lean/v0/health": health.handle,
    "/lean/v0/states/finalized": states.handle_finalized,
    "/lean/v0/checkpoints/justified": checkpoints.handle_justified,
    "/lean/v0/fork_choice": fork_choice.handle,
    "/metrics": metrics.handle,
}
"""Read-only API routes registered as GET."""

ADMIN_ROUTES: list[tuple[str, str, Handler]] = [
    ("GET", "/lean/v0/admin/aggregator", aggregator.handle_status),
    ("POST", "/lean/v0/admin/aggregator", aggregator.handle_toggle),
]
"""Admin routes as (method, path, handler) triples for non-GET verbs."""
