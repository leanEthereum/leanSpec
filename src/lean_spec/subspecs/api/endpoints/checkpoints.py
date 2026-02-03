"""Checkpoints endpoint handlers."""

from __future__ import annotations

import json

from aiohttp import web


async def handle_justified(request: web.Request) -> web.Response:
    """
    Handle justified checkpoint request.

    Returns the latest justified checkpoint for monitoring consensus progress.

    Response: JSON object with fields:
        - slot (integer): The slot number of the justified checkpoint.
        - root (string): The block root as 0x-prefixed hex string (66 chars total).

    Status Codes:
        200 OK: Checkpoint returned successfully.
        503 Service Unavailable: Store not initialized.
    """
    store_getter = request.app.get("store_getter")
    store = store_getter() if store_getter else None

    if store is None:
        raise web.HTTPServiceUnavailable(reason="Store not initialized")

    justified = store.latest_justified

    return web.Response(
        body=json.dumps(
            {
                "slot": justified.slot,
                "root": "0x" + justified.root.hex(),
            }
        ),
        content_type="application/json",
    )
