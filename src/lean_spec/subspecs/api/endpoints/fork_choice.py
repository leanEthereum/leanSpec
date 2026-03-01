"""Fork choice endpoint handler."""

from __future__ import annotations

import json

from aiohttp import web


async def handle(request: web.Request) -> web.Response:
    """
    Handle fork choice tree request.

    Returns the fork choice tree snapshot: blocks with weights, head,
    checkpoints, safe target, and validator count.

    Response: JSON object with fields:
        - nodes (array): Blocks in the tree, each with root, slot, parent_root,
          proposer_index, and weight.
        - head (string): Current head block root as 0x-prefixed hex.
        - justified (object): Latest justified checkpoint (slot, root).
        - finalized (object): Latest finalized checkpoint (slot, root).
        - safe_target (string): Safe target block root as 0x-prefixed hex.
        - validator_count (integer): Number of validators in head state.

    Status Codes:
        200 OK: Fork choice tree returned successfully.
        503 Service Unavailable: Store not initialized.
    """
    store_getter = request.app.get("store_getter")
    store = store_getter() if store_getter else None

    if store is None:
        raise web.HTTPServiceUnavailable(reason="Store not initialized")

    finalized_slot = store.latest_finalized.slot
    weights = store.compute_block_weights()

    nodes = []
    for root, block in store.blocks.items():
        if block.slot < finalized_slot:
            continue
        nodes.append(
            {
                "root": "0x" + root.hex(),
                "slot": int(block.slot),
                "parent_root": "0x" + block.parent_root.hex(),
                "proposer_index": int(block.proposer_index),
                "weight": weights.get(root, 0),
            }
        )

    head_state = store.states.get(store.head)
    validator_count = len(head_state.validators) if head_state is not None else 0

    response = {
        "nodes": nodes,
        "head": "0x" + store.head.hex(),
        "justified": {
            "slot": int(store.latest_justified.slot),
            "root": "0x" + store.latest_justified.root.hex(),
        },
        "finalized": {
            "slot": int(store.latest_finalized.slot),
            "root": "0x" + store.latest_finalized.root.hex(),
        },
        "safe_target": "0x" + store.safe_target.hex(),
        "validator_count": validator_count,
    }

    return web.Response(
        body=json.dumps(response),
        content_type="application/json",
    )
