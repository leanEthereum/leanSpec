"""API endpoint response conformance fixtures."""

from collections.abc import Callable
from typing import Any, ClassVar

from consensus_testing.genesis import (
    build_anchor,
    generate_pre_state,
    reconstruct_block_from_header,
)
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.base import StrictBaseModel
from lean_spec.spec.forks import Slot
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Uint64


class EndpointResponseContract(StrictBaseModel):
    """The status, content type, and body one endpoint handler expects a client to return."""

    status_code: int
    """Expected HTTP status code."""

    content_type: str
    """Expected response MIME type."""

    body: Any = None
    """Expected response payload: a JSON object or a hex SSZ string."""


EndpointHandler = Callable[[Store, "ApiEndpointTest"], EndpointResponseContract]
"""Uniform signature for all endpoint response builders.

Every handler receives both arguments even if it only needs one.
This keeps the dispatch table simple: one signature, one call site.
"""


def _build_store(num_validators: int, genesis_time: int, anchor_slot: int = 0) -> Store:
    """
    Build a deterministic store rooted at genesis or at an advanced anchor.

    At anchor_slot 0 the store is genesis-only. At higher slots the store
    is seeded with a real (state, block) pair produced by advancing an
    empty chain through anchor_slot; the store then carries non-empty
    historical block hashes but leaves justification and finalization at
    genesis (no attestations are injected). This is enough to exercise
    endpoint responses whose shape depends on post-genesis slot numbers,
    historical roots, and multi-node fork-choice trees.
    """
    fork = LstarSpec()
    if anchor_slot == 0:
        state = generate_pre_state(
            fork=fork, genesis_time=Uint64(genesis_time), num_validators=num_validators
        )
        block = reconstruct_block_from_header(state)
        # No validator identity — fixture only reads store data, never signs.
        return fork.create_store(state, block, validator_index=None)

    # Walk the chain from genesis through anchor_slot using empty blocks.
    # The returned pair (state, block) is internally consistent with the
    # historical chain the fixture wants to present to the endpoint.
    state, block = build_anchor(
        fork=fork,
        num_validators=num_validators,
        anchor_slot=Slot(anchor_slot),
        genesis_time=Uint64(genesis_time),
    )
    return fork.create_store(state, block, validator_index=None)


def _health_response(_store: Store, _fixture: "ApiEndpointTest") -> EndpointResponseContract:
    """Static liveness check. Independent of consensus state."""
    return EndpointResponseContract(
        status_code=200,
        content_type="application/json",
        body={"status": "healthy", "service": "lean-rpc-api"},
    )


def _justified_response(store: Store, _fixture: "ApiEndpointTest") -> EndpointResponseContract:
    """Latest justified checkpoint: slot + root. Root varies with validator count."""
    return EndpointResponseContract(
        status_code=200,
        content_type="application/json",
        body={
            "slot": int(store.latest_justified.slot),
            "root": "0x" + store.latest_justified.root.hex(),
        },
    )


def _finalized_state_response(
    store: Store, _fixture: "ApiEndpointTest"
) -> EndpointResponseContract:
    """Full SSZ-encoded finalized state as hex bytes."""
    state = store.states[store.latest_finalized.root]
    return EndpointResponseContract(
        status_code=200,
        content_type="application/octet-stream",
        body="0x" + state.encode_bytes().hex(),
    )


def _fork_choice_response(store: Store, _fixture: "ApiEndpointTest") -> EndpointResponseContract:
    """Fork choice tree: blocks with weights, head, checkpoints, validator count."""
    weights = LstarSpec().compute_block_weights(store)

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
    return EndpointResponseContract(
        status_code=200,
        content_type="application/json",
        body={
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
    )


def _aggregator_status_response(
    _store: Store, fixture: "ApiEndpointTest"
) -> EndpointResponseContract:
    """Current aggregator role as seeded by initial_is_aggregator."""
    return EndpointResponseContract(
        status_code=200,
        content_type="application/json",
        body={"is_aggregator": fixture.initial_is_aggregator},
    )


def _metrics_response(_store: Store, _fixture: "ApiEndpointTest") -> EndpointResponseContract:
    """
    Prometheus-format metrics scrape.

    The body of /metrics is dynamic (counters accumulate, timestamps shift)
    so the fixture pins only the stable contract: status, content-type,
    and the full list of metric names clients must expose.
    """
    from lean_spec.node.metrics.registry import registry as metrics_registry

    # Names enumerated from the leanMetrics spec. Any change to this list
    # is a cross-client-visible metrics surface change and should be
    # reflected in the spec first.
    required_metric_names = [
        "lean_node_info",
        "lean_node_start_time_seconds",
        "lean_head_slot",
        "lean_current_slot",
        "lean_safe_target_slot",
        "lean_fork_choice_block_processing_time_seconds",
        "lean_attestations_valid_total",
        "lean_attestations_invalid_total",
        "lean_attestation_validation_time_seconds",
        "lean_fork_choice_reorgs_total",
        "lean_fork_choice_reorg_depth",
        "lean_attestation_aggregate_coverage_validators",
        "lean_attestation_aggregate_coverage_subnets",
        "lean_attestation_aggregate_coverage_diff_validators",
        "lean_latest_justified_slot",
        "lean_latest_finalized_slot",
        "lean_state_transition_time_seconds",
        "lean_validators_count",
        "lean_connected_peers",
    ]
    # Touch the module import so spec refactors that remove the registry
    # trip the fixture instead of failing silently.
    assert metrics_registry is not None
    return EndpointResponseContract(
        status_code=200,
        content_type="text/plain; version=0.0.4; charset=utf-8",
        body={"required_metric_names": required_metric_names},
    )


def _aggregator_toggle_response(
    _store: Store, fixture: "ApiEndpointTest"
) -> EndpointResponseContract:
    """
    Expected response after toggling the aggregator role.

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
    return EndpointResponseContract(
        status_code=200,
        content_type="application/json",
        body={
            "is_aggregator": new_value,
            "previous": fixture.initial_is_aggregator,
        },
    )


_ENDPOINT_HANDLERS: dict[tuple[str, str], EndpointHandler] = {
    ("GET", "/lean/v0/health"): _health_response,
    ("GET", "/lean/v0/checkpoints/justified"): _justified_response,
    ("GET", "/lean/v0/states/finalized"): _finalized_state_response,
    ("GET", "/lean/v0/fork_choice"): _fork_choice_response,
    ("GET", "/lean/v0/admin/aggregator"): _aggregator_status_response,
    ("POST", "/lean/v0/admin/aggregator"): _aggregator_toggle_response,
    ("GET", "/metrics"): _metrics_response,
}
"""Maps (method, path) tuples to response builders."""


class ApiEndpointFixture(BaseConsensusFixture):
    """
    Emitted vector for API endpoint response conformance.

    JSON output: endpoint, method, genesisParams, requestBody,
    initialIsAggregator, expectedStatusCode, expectedContentType,
    expectedBody.
    """

    endpoint: str
    """API path under test."""

    method: str
    """HTTP method under test."""

    genesis_params: dict[str, int]
    """Genesis store inputs."""

    request_body: Any = None
    """Request body for non-GET methods."""

    initial_is_aggregator: bool
    """Aggregator role seeded before the request is sent."""

    expected_status_code: int
    """HTTP status code."""

    expected_content_type: str
    """Response MIME type."""

    expected_body: Any = None
    """Response payload. JSON dict or hex SSZ string."""


class ApiEndpointTest(BaseTestSpec):
    """Spec for API endpoint response conformance."""

    format_name: ClassVar[str] = "api_endpoint_test"
    description: ClassVar[str] = "Tests API endpoint responses against known state"

    endpoint: str
    """API path under test, e.g. /lean/v0/health."""

    method: str = "GET"
    """HTTP method under test. Defaults to GET for read-only endpoints."""

    genesis_params: dict[str, int]
    """Genesis store inputs.

    - numValidators: validator-set size (defaults to 4 when absent).
    - genesisTime: unix genesis timestamp (defaults to 0 when absent).
    - anchorSlot: optional post-genesis slot to advance the chain to
      before building the store. Defaults to 0 (genesis-only).
    """

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

    def generate(self) -> ApiEndpointFixture:
        """Build genesis store, compute expected response, emit the vector."""
        handler = _ENDPOINT_HANDLERS.get((self.method, self.endpoint))
        if handler is None:
            raise ValueError(f"Unknown endpoint: {self.method} {self.endpoint}")

        store = _build_store(
            num_validators=self.genesis_params.get("numValidators", 4),
            genesis_time=self.genesis_params.get("genesisTime", 0),
            anchor_slot=self.genesis_params.get("anchorSlot", 0),
        )
        response_contract = handler(store, self)
        return ApiEndpointFixture(
            endpoint=self.endpoint,
            method=self.method,
            genesis_params=self.genesis_params,
            request_body=self.request_body,
            initial_is_aggregator=self.initial_is_aggregator,
            expected_status_code=response_contract.status_code,
            expected_content_type=response_contract.content_type,
            expected_body=response_contract.body,
        )
