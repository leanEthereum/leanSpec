"""Typed response bodies for the HTTP API wire contract."""

from aiohttp import web
from pydantic import BaseModel, ConfigDict

from lean_spec.spec.forks.lstar.containers import Slot
from lean_spec.spec.ssz import Bytes32


class ApiResponseBody(BaseModel):
    """Base for every JSON response body, keyed snake_case, never camelCase-aliased."""

    model_config = ConfigDict(frozen=True)


class HealthBody(ApiResponseBody):
    """Liveness probe response."""

    status: str
    service: str


class CheckpointBody(ApiResponseBody):
    """A checkpoint on the wire: its slot and block root."""

    slot: Slot
    root: Bytes32


class ForkChoiceNode(ApiResponseBody):
    """One block in the fork-choice tree view."""

    root: Bytes32
    slot: Slot
    parent_root: Bytes32
    proposer_index: int
    weight: int


class ForkChoiceBody(ApiResponseBody):
    """A snapshot of the fork-choice tree."""

    nodes: list[ForkChoiceNode]
    head: Bytes32
    justified: CheckpointBody
    finalized: CheckpointBody
    safe_target: Bytes32
    validator_count: int | None


class AggregatorStatusBody(ApiResponseBody):
    """The node's current aggregator role."""

    is_aggregator: bool


class AggregatorToggleBody(ApiResponseBody):
    """The result of a runtime aggregator-role change."""

    is_aggregator: bool
    previous: bool


def json_response(body: ApiResponseBody) -> web.Response:
    """Serialize a response model to a JSON HTTP response."""
    # Build the response by hand rather than via web.json_response.
    # That helper appends "; charset=utf-8", but the wire contract is the bare media type.
    return web.Response(body=body.model_dump_json(), content_type="application/json")
