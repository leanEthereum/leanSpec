"""Admin endpoints for toggling the aggregator role at runtime."""

from __future__ import annotations

import json
import logging

from aiohttp import web

logger = logging.getLogger(__name__)


async def handle_status(request: web.Request) -> web.Response:
    """
    Handle aggregator status request.

    Returns whether the node is currently acting as an aggregator.

    Response: JSON object with fields:
        - is_aggregator (bool): Whether the node is currently acting as aggregator.

    Status Codes:
        200 OK: Status returned successfully.
        503 Service Unavailable: Aggregator controller not wired.
    """
    controller = request.app.get("aggregator_controller")
    if controller is None:
        raise web.HTTPServiceUnavailable(reason="Aggregator controller not available")

    return web.Response(
        body=json.dumps({"is_aggregator": controller.is_enabled()}),
        content_type="application/json",
    )


async def handle_toggle(request: web.Request) -> web.Response:
    """
    Handle aggregator toggle request.

    Activates or deactivates the aggregator role at runtime so operators can
    rotate aggregator duties across nodes without restarting.

    Request body: JSON object with fields:
        - enabled (bool): Desired aggregator state.

    Response: JSON object with fields:
        - is_aggregator (bool): Aggregator state after the update.
        - previous (bool): Aggregator state before the update.

    Status Codes:
        200 OK: Role updated successfully.
        400 Bad Request: Body missing, malformed, or with wrong field types.
        503 Service Unavailable: Aggregator controller not wired.
    """
    controller = request.app.get("aggregator_controller")
    if controller is None:
        raise web.HTTPServiceUnavailable(reason="Aggregator controller not available")

    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise web.HTTPBadRequest(reason="Invalid JSON body") from exc

    if not isinstance(payload, dict) or "enabled" not in payload:
        raise web.HTTPBadRequest(reason="Missing 'enabled' field in body")

    enabled = payload["enabled"]
    # Explicit bool check rejects ints like 0/1, which JSON does not distinguish
    # from booleans in loose parsers but Python does.
    if not isinstance(enabled, bool):
        raise web.HTTPBadRequest(reason="'enabled' must be a boolean")

    previous = await controller.set_enabled(enabled)

    return web.Response(
        body=json.dumps({"is_aggregator": enabled, "previous": previous}),
        content_type="application/json",
    )
