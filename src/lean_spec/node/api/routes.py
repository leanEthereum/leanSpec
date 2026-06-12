"""API route definitions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import NamedTuple

from aiohttp import web

from lean_spec.node.api.endpoints import (
    aggregator,
    checkpoints,
    fork_choice,
    health,
    metrics,
    states,
)

Handler = Callable[[web.Request], Awaitable[web.Response]]
"""Type alias for aiohttp request handlers."""


class Route(NamedTuple):
    """One API route: its verb, path, handler, and access tier."""

    method: str
    """HTTP verb the route responds to."""

    path: str
    """URL path the route is registered under."""

    handler: Handler
    """Coroutine that serves requests to this route."""

    is_admin: bool
    """True for privileged admin routes, False for public read-only routes."""


ROUTES: list[Route] = [
    Route("GET", "/lean/v0/health", health.handle, is_admin=False),
    Route("GET", "/lean/v0/states/finalized", states.handle_finalized, is_admin=False),
    Route("GET", "/lean/v0/checkpoints/justified", checkpoints.handle_justified, is_admin=False),
    Route("GET", "/lean/v0/fork_choice", fork_choice.handle, is_admin=False),
    Route("GET", "/metrics", metrics.handle, is_admin=False),
    Route("GET", "/lean/v0/admin/aggregator", aggregator.handle_status, is_admin=True),
    Route("POST", "/lean/v0/admin/aggregator", aggregator.handle_toggle, is_admin=True),
]
"""Every API route, public and admin alike, tagged by access tier."""
