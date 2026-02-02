"""Health endpoint specification and handler."""

from __future__ import annotations

import json

from aiohttp import web

# =============================================================================
# SPEC CONSTANTS
# =============================================================================

STATUS_HEALTHY = "healthy"
"""Fixed healthy status returned by the health endpoint."""

SERVICE_NAME = "lean-rpc-api"
"""Fixed service identifier returned by the health endpoint."""


# =============================================================================
# HANDLER
# =============================================================================


async def handle(_request: web.Request) -> web.Response:
    """
    Handle health check request.

    Returns server health status to indicate the service is operational.

    Response: JSON object with fields:
        - status (string): Always healthy when the endpoint is reachable.
        - service (string): Fixed identifier "lean-rpc-api".

    Status Codes:
        200 OK: Server is running.
    """
    return web.Response(
        body=json.dumps({"status": STATUS_HEALTHY, "service": SERVICE_NAME}),
        content_type="application/json",
    )
