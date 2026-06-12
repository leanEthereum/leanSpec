"""Blocks endpoint handlers."""

from __future__ import annotations

import asyncio
import logging

from aiohttp import web

logger = logging.getLogger(__name__)


async def handle_finalized(request: web.Request) -> web.Response:
    """
    Handle finalized signed block request.

    Returns the signed block for the finalized checkpoint as raw SSZ bytes
    (not snappy compressed).

    Together with the finalized state endpoint, this gives a
    checkpoint-syncing peer the (state, signed block) anchor pair.
    External consumers (other client implementations and the hive
    simulator) bootstrap their fork-choice store from this pair.

    The fork-choice store holds only unsigned blocks.
    Serving a signed block therefore needs a separate signed-block source,
    injected into the server by the embedding node.
    Nodes without such a source answer with 503.

    Response: SSZ-encoded SignedBlock (binary, application/octet-stream)

    Status Codes:
        200 OK: Signed block returned successfully.
        404 Not Found: Finalized signed block not available on this node.
        503 Service Unavailable: Store or signed-block source not initialized.
    """
    store_getter = request.app.get("store_getter")
    store = store_getter() if store_getter else None

    if store is None:
        raise web.HTTPServiceUnavailable(reason="Store not initialized")

    signed_block_getter = request.app.get("signed_block_getter")

    if signed_block_getter is None:
        raise web.HTTPServiceUnavailable(reason="Signed block source not configured")

    signed_block = signed_block_getter(store.latest_finalized.root)

    if signed_block is None:
        raise web.HTTPNotFound(reason="Finalized signed block not available")

    # Implementation detail: offload CPU-intensive encoding to thread pool
    try:
        ssz_bytes = await asyncio.to_thread(signed_block.encode_bytes)
    except Exception as exception:
        logger.error("Failed to encode signed block: %s", exception)
        raise web.HTTPInternalServerError(reason="Encoding failed") from exception

    return web.Response(body=ssz_bytes, content_type="application/octet-stream")
