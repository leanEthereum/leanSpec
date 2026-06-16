"""Metrics endpoint (Prometheus exposition)."""

from __future__ import annotations

from aiohttp import web

from lean_spec.node.metrics.registry import get_metrics_output

CONTENT_TYPE = "text/plain; version=0.0.4"
"""Prometheus text exposition media type, without the charset parameter."""

CHARSET = "utf-8"
"""Body encoding, passed separately from the media type.

aiohttp rejects a charset inside the content_type argument.
It must travel through the dedicated charset parameter instead.
"""


async def handle(_request: web.Request) -> web.Response:
    """
    Handle Prometheus metrics scrape request.

    Returns metrics in Prometheus text exposition format.
    """
    body = get_metrics_output()
    return web.Response(body=body, content_type=CONTENT_TYPE, charset=CHARSET)
