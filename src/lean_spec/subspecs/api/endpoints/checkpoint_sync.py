"""
Checkpoint sync endpoint specifications and handlers.

Used for checkpoint sync - clients download finalized state to bootstrap quickly
instead of syncing from genesis.
"""

from __future__ import annotations

import asyncio
import json
import logging

from aiohttp import web

logger = logging.getLogger(__name__)


async def handle_finalized_state(request: web.Request) -> web.Response:
    """
    Handle finalized state request.

    Returns the finalized beacon state as raw SSZ bytes (not snappy compressed).

    Response: SSZ-encoded State (binary, application/octet-stream)

    Status Codes:
        200 OK: State returned successfully.
        404 Not Found: Finalized state not available in store.
        503 Service Unavailable: Store not initialized.
    """
    store_getter = request.app.get("store_getter")
    store = store_getter() if store_getter else None

    if store is None:
        raise web.HTTPServiceUnavailable(reason="Store not initialized")

    finalized = store.latest_finalized

    if finalized.root not in store.states:
        raise web.HTTPNotFound(reason="Finalized state not available")

    state = store.states[finalized.root]

    # Implementation detail: offload CPU-intensive encoding to thread pool
    try:
        ssz_bytes = await asyncio.to_thread(state.encode_bytes)
    except Exception as e:
        logger.error(f"Failed to encode state: {e}")
        raise web.HTTPInternalServerError(reason="Encoding failed") from e

    return web.Response(body=ssz_bytes, content_type="application/octet-stream")


async def handle_justified_checkpoint(request: web.Request) -> web.Response:
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
