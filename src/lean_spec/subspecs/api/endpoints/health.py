"""Health endpoint specification and handler."""

from __future__ import annotations

from aiohttp import web


async def handle(request: web.Request) -> web.Response:
    """
    Handle health check request.

    Returns server health status to indicate the service is operational.

    Response: JSON object with fields:
        - status (string): "ok"
        - slot (int): Current head slot
        - synced (boolean): Whether the node is synced

    Status Codes:
        200 OK: Server is synced.
        503 Service Unavailable: Server is not synced.
    """
    store_getter = request.app.get("store_getter")
    store = store_getter() if store_getter else None

    if store is None:
        return web.json_response(
            {"status": "error", "message": "Store not available"},
            status=503,
        )

    head_slot = int(store.blocks[store.head].slot)

    # Determine sync status from SyncService state if available
    sync_service_getter = request.app.get("sync_service_getter")
    sync_service = sync_service_getter() if sync_service_getter else None

    if sync_service is not None:
        synced = sync_service.state.is_synced
    else:
        # Fallback: if no sync service is available, assume synced
        synced = True

    return web.json_response(
        {
            "status": "ok",
            "slot": head_slot,
            "synced": synced,
        },
        status=200 if synced else 503,
    )
