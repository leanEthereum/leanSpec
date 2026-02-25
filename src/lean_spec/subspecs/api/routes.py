"""API route definitions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from aiohttp import web

from .endpoints import checkpoints, fork_choice, health, states

ROUTES: dict[str, Callable[[web.Request], Awaitable[web.Response]]] = {
    "/lean/v0/health": health.handle,
    "/lean/v0/states/finalized": states.handle_finalized,
    "/lean/v0/checkpoints/justified": checkpoints.handle_justified,
    "/lean/v0/fork_choice": fork_choice.handle,
}
"""All API routes mapped to their handlers."""
