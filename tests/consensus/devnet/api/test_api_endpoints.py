"""
Test vectors for API endpoint responses.

Each test generates a JSON fixture that client teams use to validate their
API server returns the exact same response given the same genesis parameters.
"""

import pytest
from consensus_testing import ApiEndpointTestFiller

pytestmark = pytest.mark.valid_until("Devnet")

GENESIS_4V = {"numValidators": 4, "genesisTime": 0}
"""Minimal genesis: 4 validators at epoch 0."""

GENESIS_12V = {"numValidators": 12, "genesisTime": 0}
"""Larger genesis: 12 validators produce a different state root than 4."""


def test_health(api_endpoint: ApiEndpointTestFiller) -> None:
    """Health returns a fixed payload independent of consensus state."""
    api_endpoint(endpoint="/lean/v0/health", genesis_params=GENESIS_4V)


def test_justified_checkpoint_4v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Justified checkpoint at genesis with 4 validators."""
    api_endpoint(endpoint="/lean/v0/checkpoints/justified", genesis_params=GENESIS_4V)


def test_justified_checkpoint_12v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Justified checkpoint at genesis with 12 validators. Root differs from 4v."""
    api_endpoint(endpoint="/lean/v0/checkpoints/justified", genesis_params=GENESIS_12V)


def test_finalized_state_4v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Full SSZ-encoded finalized state for a 4-validator genesis."""
    api_endpoint(endpoint="/lean/v0/states/finalized", genesis_params=GENESIS_4V)


def test_fork_choice_4v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Fork choice tree at genesis: single node, zero attestation weights."""
    api_endpoint(endpoint="/lean/v0/fork_choice", genesis_params=GENESIS_4V)


def test_fork_choice_12v(api_endpoint: ApiEndpointTestFiller) -> None:
    """Fork choice tree at genesis with 12 validators. Same shape, higher count."""
    api_endpoint(endpoint="/lean/v0/fork_choice", genesis_params=GENESIS_12V)
