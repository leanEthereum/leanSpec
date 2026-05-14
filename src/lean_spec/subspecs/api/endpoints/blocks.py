"""Blocks endpoint handlers."""

from __future__ import annotations

import asyncio
import logging

from aiohttp import web

logger = logging.getLogger(__name__)


async def handle_finalized(request: web.Request) -> web.Response:
    """
    Handle finalized signed block request.

    Returns the SignedBlock matching ``store.latest_finalized.root`` as raw
    SSZ bytes (not snappy compressed).

    Together with ``/lean/v0/states/finalized`` this lets a checkpoint-syncing
    node obtain the ``(state, signed_block)`` pair required by
    ``Store.create_store`` (which asserts
    ``anchor_block.state_root == hash_tree_root(state)`` and seeds
    ``store.blocks[anchor_root] = anchor_block``).

    Response: SSZ-encoded SignedBlock (binary, application/octet-stream)

    Status Codes:
        200 OK: SignedBlock returned successfully.
        404 Not Found: Finalized signed block not available on this node
            (e.g. server retains only ``Block`` and not ``SignedBlock``).
        503 Service Unavailable: Store / signed-block source not initialized.
    """
    signed_block_getter = request.app.get("signed_block_getter")
    store_getter = request.app.get("store_getter")
    store = store_getter() if store_getter else None

    if store is None:
        raise web.HTTPServiceUnavailable(reason="Store not initialized")

    if signed_block_getter is None:
        raise web.HTTPServiceUnavailable(reason="Signed block source not configured")

    finalized_root = store.latest_finalized.root
    signed_block = signed_block_getter(finalized_root)

    if signed_block is None:
        raise web.HTTPNotFound(reason="Finalized signed block not available")

    try:
        ssz_bytes = await asyncio.to_thread(signed_block.encode_bytes)
    except Exception as e:
        logger.error("Failed to encode signed block: %s", e)
        raise web.HTTPInternalServerError(reason="Encoding failed") from e

    return web.Response(body=ssz_bytes, content_type="application/octet-stream")
