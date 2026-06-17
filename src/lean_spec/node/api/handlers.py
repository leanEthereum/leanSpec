"""HTTP handlers exposing the node's API over aiohttp."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Final

from aiohttp import web

from lean_spec.node.api.context import ApiContext
from lean_spec.node.api.responses import (
    AggregatorStatusBody,
    AggregatorToggleBody,
    CheckpointBody,
    ForkChoiceBody,
    ForkChoiceNode,
    HealthBody,
    json_response,
)
from lean_spec.node.metrics.registry import get_metrics_output

logger = logging.getLogger(__name__)

STATUS_HEALTHY: Final = "healthy"
"""Fixed healthy status returned by the health endpoint."""

SERVICE_NAME: Final = "lean-rpc-api"
"""Fixed service identifier returned by the health endpoint."""

METRICS_CONTENT_TYPE: Final = "text/plain; version=0.0.4"
"""Prometheus text exposition media type, without the charset parameter."""

METRICS_CHARSET: Final = "utf-8"
"""
Body encoding, passed separately from the media type.

aiohttp rejects a charset inside the content_type argument.

It must travel through the dedicated charset parameter instead.
"""


@dataclass(frozen=True, slots=True)
class ApiHandlers:
    """The aiohttp request handlers, bound to the dependencies they serve."""

    context: ApiContext
    """Dependency bundle resolved once at server startup."""

    async def health(self, request: web.Request) -> web.Response:
        """Report that the service is reachable."""
        return json_response(HealthBody(status=STATUS_HEALTHY, service=SERVICE_NAME))

    async def metrics(self, request: web.Request) -> web.Response:
        """Return node metrics in Prometheus text exposition format."""
        return web.Response(
            body=get_metrics_output(),
            content_type=METRICS_CONTENT_TYPE,
            charset=METRICS_CHARSET,
        )

    async def justified_checkpoint(self, request: web.Request) -> web.Response:
        """Return the latest justified checkpoint."""
        store = self.context.require_store()
        return json_response(
            CheckpointBody(slot=store.latest_justified.slot, root=store.latest_justified.root)
        )

    async def fork_choice(self, request: web.Request) -> web.Response:
        """
        Return a snapshot of the fork-choice tree.

        Weights count only the votes currently driving the head.
        They exclude attestations seen but not yet counted.
        """
        store = self.context.require_store()
        weights = self.context.spec.compute_block_weights(store)

        nodes = [
            ForkChoiceNode(
                root=root,
                slot=block.slot,
                parent_root=block.parent_root,
                proposer_index=block.proposer_index,
                weight=weights.get(root, 0),
            )
            for root, block in store.blocks.items()
            if block.slot >= store.latest_finalized.slot
        ]

        # Report a missing head state as null, not zero.
        # Zero would read as "no validators" rather than "state unavailable".
        head_state = store.states.get(store.head)
        validator_count = len(head_state.validators) if head_state is not None else None

        return json_response(
            ForkChoiceBody(
                nodes=nodes,
                head=store.head,
                justified=CheckpointBody(
                    slot=store.latest_justified.slot, root=store.latest_justified.root
                ),
                finalized=CheckpointBody(
                    slot=store.latest_finalized.slot, root=store.latest_finalized.root
                ),
                safe_target=store.safe_target,
                validator_count=validator_count,
            )
        )

    async def finalized_state(self, request: web.Request) -> web.Response:
        """Return the finalized beacon state as SSZ bytes."""
        store = self.context.require_store()

        if store.latest_finalized.root not in store.states:
            raise web.HTTPNotFound(reason="Finalized state not available")

        state = store.states[store.latest_finalized.root]

        # Encoding a full state is CPU-heavy, so run it off the event loop.
        try:
            ssz_bytes = await asyncio.to_thread(state.encode_bytes)
        except Exception as exception:
            logger.error("Failed to encode state: %s", exception)
            raise web.HTTPInternalServerError(reason="Encoding failed") from exception

        return web.Response(body=ssz_bytes, content_type="application/octet-stream")

    async def finalized_block(self, request: web.Request) -> web.Response:
        """
        Return the finalized signed block as SSZ bytes.

        Raises:
            HTTPNotFound: The source has no block for the finalized root.
            HTTPInternalServerError: Encoding the signed block failed.
        """
        store = self.context.require_store()
        signed_block_getter = self.context.require_signed_block_getter()

        signed_block = signed_block_getter(store.latest_finalized.root)
        if signed_block is None:
            raise web.HTTPNotFound(reason="Finalized signed block not available")

        # Encoding a full block is CPU-heavy, so run it off the event loop.
        try:
            ssz_bytes = await asyncio.to_thread(signed_block.encode_bytes)
        except Exception as exception:
            logger.error("Failed to encode signed block: %s", exception)
            raise web.HTTPInternalServerError(reason="Encoding failed") from exception

        return web.Response(body=ssz_bytes, content_type="application/octet-stream")

    async def aggregator_status(self, request: web.Request) -> web.Response:
        """Report whether the node is acting as an aggregator."""
        aggregator_role_control = self.context.require_aggregator_role_control()
        return json_response(
            AggregatorStatusBody(is_aggregator=aggregator_role_control.is_aggregator)
        )

    async def aggregator_toggle(self, request: web.Request) -> web.Response:
        """
        Set the aggregator role at runtime and report the previous value.

        Raises:
            HTTPBadRequest: Body missing, malformed, or 'enabled' not a boolean.
        """
        aggregator_role_control = self.context.require_aggregator_role_control()

        try:
            request_body = await request.json()
        except json.JSONDecodeError as exception:
            raise web.HTTPBadRequest(reason="Invalid JSON body") from exception

        if not isinstance(request_body, dict) or "enabled" not in request_body:
            raise web.HTTPBadRequest(reason="Missing 'enabled' field in body")

        enabled = request_body["enabled"]
        # Reject ints like 0 and 1, which loose JSON parsers blur with booleans but Python does not.
        if not isinstance(enabled, bool):
            raise web.HTTPBadRequest(reason="'enabled' must be a boolean")

        previous_aggregator_state = aggregator_role_control.is_aggregator
        aggregator_role_control.is_aggregator = enabled
        if previous_aggregator_state != enabled:
            logger.info(
                "Aggregator role %s via admin API",
                "activated" if enabled else "deactivated",
            )

        return json_response(
            AggregatorToggleBody(is_aggregator=enabled, previous=previous_aggregator_state)
        )
