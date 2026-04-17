"""API endpoint response conformance fixtures."""

from collections.abc import Callable
from typing import Any, ClassVar

from lean_spec.subspecs.containers import BlockBody, Slot, ValidatorIndex
from lean_spec.subspecs.containers.block import Block
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.forkchoice.store import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64

from ..genesis import generate_pre_state
from .base import BaseConsensusFixture

EndpointHandler = Callable[[Store, "ApiEndpointTest"], dict[str, Any]]
"""Uniform signature for all endpoint response builders.

Every handler receives both arguments even if it only needs one.
This keeps the dispatch table simple: one signature, one call site.
"""


def _make_genesis_block(state: State) -> Block:
    """Build a slot-0 block anchored to the given genesis state."""
    body = BlockBody(attestations=AggregatedAttestations(data=[]))
    return Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32(hash_tree_root(state)),
        body=body,
    )


def _build_store(num_validators: int, genesis_time: int) -> Store:
    """Build a deterministic genesis-only store. Same params always produce same roots."""
    state = generate_pre_state(genesis_time=Uint64(genesis_time), num_validators=num_validators)
    block = _make_genesis_block(state)
    # No validator identity — fixture only reads store data, never signs.
    return Store.from_anchor(state, block, validator_id=None)


def _health_response(_store: Store, _fixture: "ApiEndpointTest") -> dict[str, Any]:
    """Static liveness check. Independent of consensus state."""
    return {
        "expected_status_code": 200,
        "expected_content_type": "application/json",
        "expected_body": {"status": "healthy", "service": "lean-rpc-api"},
    }


def _justified_response(store: Store, _fixture: "ApiEndpointTest") -> dict[str, Any]:
    """Latest justified checkpoint: slot + root. Root varies with validator count."""
    return {
        "expected_status_code": 200,
        "expected_content_type": "application/json",
        "expected_body": {
            "slot": int(store.latest_justified.slot),
            "root": "0x" + store.latest_justified.root.hex(),
        },
    }


def _finalized_state_response(store: Store, _fixture: "ApiEndpointTest") -> dict[str, Any]:
    """Full SSZ-encoded finalized state as hex bytes."""
    state = store.states[store.latest_finalized.root]
    return {
        "expected_status_code": 200,
        "expected_content_type": "application/octet-stream",
        "expected_body": "0x" + state.encode_bytes().hex(),
    }


def _fork_choice_response(store: Store, _fixture: "ApiEndpointTest") -> dict[str, Any]:
    """Fork choice tree: blocks with weights, head, checkpoints, validator count."""
    weights = store.compute_block_weights()

    # Only post-finalization blocks are relevant to head selection.
    nodes = [
        {
            "root": "0x" + root.hex(),
            "slot": int(block.slot),
            "parent_root": "0x" + block.parent_root.hex(),
            "proposer_index": int(block.proposer_index),
            "weight": weights.get(root, 0),
        }
        for root, block in store.blocks.items()
        if block.slot >= store.latest_finalized.slot
    ]

    # Validator count from head state (most current view).
    head_state = store.states.get(store.head)
    return {
        "expected_status_code": 200,
        "expected_content_type": "application/json",
        "expected_body": {
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
            "validator_count": len(head_state.validators) if head_state is not None else 0,
        },
    }


def _aggregator_status_response(_store: Store, fixture: "ApiEndpointTest") -> dict[str, Any]:
    """Current aggregator role as seeded by initial_is_aggregator."""
    return {
        "expected_status_code": 200,
        "expected_content_type": "application/json",
        "expected_body": {"is_aggregator": fixture.initial_is_aggregator},
    }


def _aggregator_toggle_response(_store: Store, fixture: "ApiEndpointTest") -> dict[str, Any]:
    """Expected response after toggling the aggregator role.

    The fixture models a single POST against a node whose starting state is
    initial_is_aggregator. The response reflects the new value and the
    previous value as an is_aggregator / previous dict.
    """
    body = fixture.request_body
    if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
        raise ValueError(
            "POST /lean/v0/admin/aggregator fixture requires request_body "
            "with a boolean 'enabled' field"
        )
    new_value = body["enabled"]
    return {
        "expected_status_code": 200,
        "expected_content_type": "application/json",
        "expected_body": {
            "is_aggregator": new_value,
            "previous": fixture.initial_is_aggregator,
        },
    }


_ENDPOINT_HANDLERS: dict[tuple[str, str], EndpointHandler] = {
    ("GET", "/lean/v0/health"): _health_response,
    ("GET", "/lean/v0/checkpoints/justified"): _justified_response,
    ("GET", "/lean/v0/states/finalized"): _finalized_state_response,
    ("GET", "/lean/v0/fork_choice"): _fork_choice_response,
    ("GET", "/lean/v0/admin/aggregator"): _aggregator_status_response,
    ("POST", "/lean/v0/admin/aggregator"): _aggregator_toggle_response,
}
"""Maps (method, path) tuples to response builders."""


class ApiEndpointTest(BaseConsensusFixture):
    """Fixture for API endpoint response conformance.

    JSON output: endpoint, genesisParams, expectedStatusCode,
    expectedContentType, expectedBody.
    """

    format_name: ClassVar[str] = "api_endpoint"
    description: ClassVar[str] = "Tests API endpoint responses against known state"

    endpoint: str
    """API path under test, e.g. /lean/v0/health."""

    method: str = "GET"
    """HTTP method under test. Defaults to GET for read-only endpoints."""

    genesis_params: dict[str, int]
    """Genesis store inputs: numValidators and genesisTime."""

    request_body: Any = None
    """Optional request body for non-GET methods. JSON-serializable.

    Consumed by admin endpoints (e.g. POST /lean/v0/admin/aggregator). Read-only
    GET fixtures leave this as None.
    """

    initial_is_aggregator: bool = False
    """Seeds the node's aggregator role before the request is sent.

    Consumed by the admin aggregator endpoints. Clients must configure their
    node with this value (e.g. via CLI or controller) before replaying the
    fixture. Ignored by other endpoints.
    """

    expected_status_code: int = 0
    """HTTP status code. Filled by make_fixture."""

    expected_content_type: str = ""
    """Response MIME type. Filled by make_fixture."""

    expected_body: Any = None
    """Response payload. JSON dict or hex SSZ string. Filled by make_fixture."""

    def make_fixture(self) -> "ApiEndpointTest":
        """Build genesis store, compute expected response, populate output fields."""
        handler = _ENDPOINT_HANDLERS.get((self.method, self.endpoint))
        if handler is None:
            raise ValueError(f"Unknown endpoint: {self.method} {self.endpoint}")

        store = _build_store(
            num_validators=self.genesis_params.get("numValidators", 4),
            genesis_time=self.genesis_params.get("genesisTime", 0),
        )
        return self.model_copy(update=handler(store, self))
