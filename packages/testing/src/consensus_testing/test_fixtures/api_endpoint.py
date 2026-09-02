"""API endpoint response conformance fixtures."""

from typing import Any, ClassVar

from ssz import Uint64

from consensus_testing.genesis import build_anchor
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_fixtures.hex_codec import to_hex
from lean_spec.base import StrictBaseModel
from lean_spec.node.metrics.registry import registry as metrics_registry
from lean_spec.spec.forks import Slot
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.spec import LstarSpec

REQUIRED_METRIC_NAMES = [
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
"""Metric names every client must expose. Changing this list is a cross-client surface change."""


class EndpointResponseContract(StrictBaseModel):
    """The status, content type, and body one endpoint handler expects a client to return."""

    status_code: int
    """Expected HTTP status code."""

    content_type: str
    """Expected response MIME type."""

    body: Any = None
    """Expected response payload: a JSON object or a hex SSZ string."""


class ApiEndpointFixture(BaseConsensusFixture):
    """Emitted vector for API endpoint response conformance."""

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

    - numValidators: validator-set size, default 4.
    - genesisTime: unix genesis timestamp, default 0.
    - anchorSlot: post-genesis slot to advance to, default 0 for genesis-only.
    """

    request_body: Any = None
    """Optional JSON request body for non-GET methods."""

    initial_is_aggregator: bool = False
    """Aggregator role seeded before the request is sent.
    Clients must configure their node with this value before replaying."""

    def generate(self) -> ApiEndpointFixture:
        """Build genesis store, compute expected response, emit the vector."""
        # Build a deterministic store: genesis-only, or an empty chain advanced to the anchor slot.
        # No attestations are injected, so justification and finalization stay at genesis.
        fork = LstarSpec()
        # Walk the chain from genesis using empty blocks; slot 0 returns the genesis pair unchanged.
        state, block = build_anchor(
            fork=fork,
            num_validators=self.genesis_params.get("numValidators", 4),
            anchor_slot=Slot(self.genesis_params.get("anchorSlot", 0)),
            genesis_time=Uint64(self.genesis_params.get("genesisTime", 0)),
        )
        # No validator identity — fixture only reads store data, never signs.
        store = fork.create_store(state, block, validator_index=None)

        response = self._expected_response(store)
        return ApiEndpointFixture(
            endpoint=self.endpoint,
            method=self.method,
            genesis_params=self.genesis_params,
            request_body=self.request_body,
            initial_is_aggregator=self.initial_is_aggregator,
            expected_status_code=response.status_code,
            expected_content_type=response.content_type,
            expected_body=response.body,
        )

    def _expected_response(self, store: Store) -> EndpointResponseContract:
        """Compute the response a conforming client must return for the route under test."""
        match (self.method, self.endpoint):
            case ("GET", "/lean/v0/health"):
                # Static liveness check, independent of consensus state.
                return EndpointResponseContract(
                    status_code=200,
                    content_type="application/json",
                    body={"status": "healthy", "service": "lean-rpc-api"},
                )

            case ("GET", "/lean/v0/checkpoints/justified"):
                # Latest justified checkpoint; the root varies with validator count.
                return EndpointResponseContract(
                    status_code=200,
                    content_type="application/json",
                    body={
                        "slot": int(store.latest_justified.slot),
                        "root": to_hex(store.latest_justified.root),
                    },
                )

            case ("GET", "/lean/v0/states/finalized"):
                # Full SSZ-encoded finalized state as hex bytes.
                finalized_state = store.states[store.latest_finalized.root]
                return EndpointResponseContract(
                    status_code=200,
                    content_type="application/octet-stream",
                    body=to_hex(finalized_state.encode_bytes()),
                )

            case ("GET", "/lean/v0/fork_choice"):
                # Fork choice tree: blocks with weights, head, checkpoints, validator count.
                weights = LstarSpec().compute_block_weights(store)

                # Only post-finalization blocks are relevant to head selection.
                nodes = [
                    {
                        "root": to_hex(root),
                        "slot": int(block.slot),
                        "parent_root": to_hex(block.parent_root),
                        "proposer_index": int(block.proposer_index),
                        "weight": weights.get(root, 0),
                    }
                    for root, block in store.blocks.items()
                    if block.slot >= store.latest_finalized.slot
                ]

                # The head always has a stored state, so a missing one is a broken invariant.
                head_state = store.states[store.head]
                return EndpointResponseContract(
                    status_code=200,
                    content_type="application/json",
                    body={
                        "nodes": nodes,
                        "head": to_hex(store.head),
                        "justified": {
                            "slot": int(store.latest_justified.slot),
                            "root": to_hex(store.latest_justified.root),
                        },
                        "finalized": {
                            "slot": int(store.latest_finalized.slot),
                            "root": to_hex(store.latest_finalized.root),
                        },
                        "safe_target": to_hex(store.safe_target),
                        "validator_count": len(head_state.validators),
                    },
                )

            case ("GET", "/lean/v0/admin/aggregator"):
                # Current aggregator role as seeded by the spec.
                return EndpointResponseContract(
                    status_code=200,
                    content_type="application/json",
                    body={"is_aggregator": self.initial_is_aggregator},
                )

            case ("POST", "/lean/v0/admin/aggregator"):
                # Toggling reports the new aggregator value and the previous one.
                body = self.request_body
                if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
                    raise ValueError(
                        "POST /lean/v0/admin/aggregator fixture requires request_body "
                        "with a boolean 'enabled' field"
                    )
                return EndpointResponseContract(
                    status_code=200,
                    content_type="application/json",
                    body={
                        "is_aggregator": body["enabled"],
                        "previous": self.initial_is_aggregator,
                    },
                )

            case ("GET", "/metrics"):
                # The body is dynamic, so pin only status, content type, and the metric names.
                # Touch the registry so its removal trips this fixture instead of failing silently.
                assert metrics_registry is not None
                return EndpointResponseContract(
                    status_code=200,
                    content_type="text/plain; version=0.0.4; charset=utf-8",
                    body={"required_metric_names": REQUIRED_METRIC_NAMES},
                )

            case _:
                raise ValueError(f"Unknown endpoint: {self.method} {self.endpoint}")
