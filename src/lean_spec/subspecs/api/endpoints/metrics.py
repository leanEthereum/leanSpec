"""Metrics endpoint (Prometheus exposition)."""

from __future__ import annotations

from aiohttp import web

from lean_spec.subspecs.metrics.registry import get_metrics_output

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


async def handle(_request: web.Request) -> web.Response:
    """
    Handle Prometheus metrics scrape request.

    Returns metrics in Prometheus text exposition format.
    """
    body = get_metrics_output()
    return web.Response(body=body, content_type=CONTENT_TYPE)
