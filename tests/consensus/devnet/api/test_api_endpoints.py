"""
Test vectors for API endpoint responses.

Each test generates a JSON fixture that client teams use to validate their
API server returns the exact same response given the same genesis parameters.
"""

import pytest
from consensus_testing import ApiEndpointTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

GENESIS_4V = {"numValidators": 4, "genesisTime": 0}
"""Minimal genesis: 4 validators at epoch 0."""

GENESIS_8V = {"numValidators": 8, "genesisTime": 0}
"""Larger genesis: 8 validators produce a different state root than 4."""


def test_health(api_endpoint: ApiEndpointTestFiller) -> None:
    """Health returns a fixed payload independent of consensus state."""
    api_endpoint(endpoint="/lean/v0/health", genesis_params=GENESIS_4V)


def test_justified_checkpoint_4v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Justified checkpoint at genesis with 4 validators."""
    api_endpoint(endpoint="/lean/v0/checkpoints/justified", genesis_params=GENESIS_4V)


def test_justified_checkpoint_8v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Justified checkpoint at genesis with 8 validators. Root differs from 4v."""
    api_endpoint(endpoint="/lean/v0/checkpoints/justified", genesis_params=GENESIS_8V)


def test_finalized_state_4v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Full SSZ-encoded finalized state for a 4-validator genesis."""
    api_endpoint(endpoint="/lean/v0/states/finalized", genesis_params=GENESIS_4V)


def test_fork_choice_4v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Fork choice tree at genesis: single node, zero attestation weights."""
    api_endpoint(endpoint="/lean/v0/fork_choice", genesis_params=GENESIS_4V)


def test_fork_choice_8v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Fork choice tree at genesis with 8 validators. Same shape, higher count."""
    api_endpoint(endpoint="/lean/v0/fork_choice", genesis_params=GENESIS_8V)


def test_aggregator_status_disabled(api_endpoint: ApiEndpointTestFiller) -> None:
    """GET aggregator status on a node started with aggregator disabled."""
    api_endpoint(
        endpoint="/lean/v0/admin/aggregator",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=False,
    )


def test_aggregator_status_enabled(api_endpoint: ApiEndpointTestFiller) -> None:
    """GET aggregator status on a node started with aggregator enabled."""
    api_endpoint(
        endpoint="/lean/v0/admin/aggregator",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=True,
    )


def test_aggregator_toggle_activate(api_endpoint: ApiEndpointTestFiller) -> None:
    """POST enable=true flips the role from off to on."""
    api_endpoint(
        endpoint="/lean/v0/admin/aggregator",
        method="POST",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=False,
        request_body={"enabled": True},
    )


def test_aggregator_toggle_deactivate(api_endpoint: ApiEndpointTestFiller) -> None:
    """POST enable=false flips the role from on to off."""
    api_endpoint(
        endpoint="/lean/v0/admin/aggregator",
        method="POST",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=True,
        request_body={"enabled": False},
    )


def test_aggregator_toggle_idempotent_enable(api_endpoint: ApiEndpointTestFiller) -> None:
    """POST enable=true on an already-enabled node returns previous=true and is a no-op."""
    api_endpoint(
        endpoint="/lean/v0/admin/aggregator",
        method="POST",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=True,
        request_body={"enabled": True},
    )


def test_aggregator_toggle_idempotent_disable(api_endpoint: ApiEndpointTestFiller) -> None:
    """POST enable=false on an already-disabled node returns previous=false and is a no-op."""
    api_endpoint(
        endpoint="/lean/v0/admin/aggregator",
        method="POST",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=False,
        request_body={"enabled": False},
    )
