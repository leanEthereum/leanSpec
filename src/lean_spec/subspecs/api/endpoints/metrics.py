"""Metrics endpoint implementation."""

from __future__ import annotations

from aiohttp import web
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST


async def handle(request: web.Request) -> web.Response:
    """
    Handle metrics request.

    Returns Prometheus metrics in text format.
    Uses the Metrics instance registry if available, otherwise falls back
    to the default global registry.
    """
    metrics_getter = request.app.get("metrics_getter")
    metrics = metrics_getter() if metrics_getter else None

    if metrics is not None:
        body = generate_latest(metrics.registry)
    else:
        body = generate_latest()

    return web.Response(
        body=body,
        content_type=CONTENT_TYPE_LATEST,
    )
