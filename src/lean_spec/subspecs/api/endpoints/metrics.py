"""[OPTIONAL] Metrics endpoint specification and handler."""

from aiohttp import web

from lean_spec.subspecs.metrics import generate_metrics

# =============================================================================
# SPEC CONSTANTS
# =============================================================================

CHARSET = "utf-8"
"""Character encoding for Prometheus metrics."""


async def handle(_request: web.Request) -> web.Response:
    """
    Handle metrics request.

    Returns Prometheus-format metrics. Implementation-specific; not required
    for conformance.

    Response: Prometheus text format (text/plain; version=0.0.4)

    Status Codes:
        200 OK: Metrics returned.
    """
    return web.Response(
        body=generate_metrics(),
        content_type="text/plain; version=0.0.4",
        charset=CHARSET,
    )
