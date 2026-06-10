"""Test vectors for API endpoint responses at genesis."""

import pytest

from consensus_testing import ApiEndpointTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

GENESIS_4V = {"numValidators": 4, "genesisTime": 0}
"""Minimal genesis: 4 validators at epoch 0."""

GENESIS_8V = {"numValidators": 8, "genesisTime": 0}
"""Larger genesis: 8 validators produce a different state root than 4."""


def test_health(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The health endpoint returns a fixed payload.

    Given
    -----
    - a node started from a 4-validator genesis.

    When
    ----
    - the health endpoint is queried.

    Then
    ----
    - the response is a fixed payload independent of consensus state.
    """
    api_endpoint_test(endpoint="/lean/v0/health", genesis_params=GENESIS_4V)


def test_justified_checkpoint_4v(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The justified-checkpoint endpoint reports genesis with four validators.

    Given
    -----
    - a node started from a 4-validator genesis.

    When
    ----
    - the justified-checkpoint endpoint is queried.

    Then
    ----
    - the response reports the genesis checkpoint.
    """
    api_endpoint_test(endpoint="/lean/v0/checkpoints/justified", genesis_params=GENESIS_4V)


def test_justified_checkpoint_8v(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The justified-checkpoint endpoint reports genesis with eight validators.

    Given
    -----
    - a node started from an 8-validator genesis.

    When
    ----
    - the justified-checkpoint endpoint is queried.

    Then
    ----
    - the response reports the genesis checkpoint.
    - the checkpoint root differs from the four-validator case.
    """
    api_endpoint_test(endpoint="/lean/v0/checkpoints/justified", genesis_params=GENESIS_8V)


def test_finalized_state_4v(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The finalized-state endpoint returns the serialized state with four validators.

    Given
    -----
    - a node started from a 4-validator genesis.

    When
    ----
    - the finalized-state endpoint is queried.

    Then
    ----
    - the response is the full serialized finalized state.
    """
    api_endpoint_test(endpoint="/lean/v0/states/finalized", genesis_params=GENESIS_4V)


def test_fork_choice_4v(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The fork-choice endpoint returns a single-node tree at genesis.

    Given
    -----
    - a node started from a 4-validator genesis.

    When
    ----
    - the fork-choice endpoint is queried.

    Then
    ----
    - the tree holds a single node.
    - the attestation weights are zero.
    """
    api_endpoint_test(endpoint="/lean/v0/fork_choice", genesis_params=GENESIS_4V)


def test_fork_choice_8v(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The fork-choice endpoint returns a single-node tree with eight validators.

    Given
    -----
    - a node started from an 8-validator genesis.

    When
    ----
    - the fork-choice endpoint is queried.

    Then
    ----
    - the tree holds a single node.
    - the shape matches the four-validator case at a higher validator count.
    """
    api_endpoint_test(endpoint="/lean/v0/fork_choice", genesis_params=GENESIS_8V)


def test_aggregator_status_disabled(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The aggregator-status endpoint reports the disabled role.

    Given
    -----
    - a node started with the aggregator role disabled.

    When
    ----
    - the aggregator-status endpoint is queried.

    Then
    ----
    - the response reports the aggregator as disabled.
    """
    api_endpoint_test(
        endpoint="/lean/v0/admin/aggregator",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=False,
    )


def test_aggregator_status_enabled(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The aggregator-status endpoint reports the enabled role.

    Given
    -----
    - a node started with the aggregator role enabled.

    When
    ----
    - the aggregator-status endpoint is queried.

    Then
    ----
    - the response reports the aggregator as enabled.
    """
    api_endpoint_test(
        endpoint="/lean/v0/admin/aggregator",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=True,
    )


def test_aggregator_toggle_activate(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    Posting enable turns the aggregator role on.

    Given
    -----
    - a node started with the aggregator role disabled.

    When
    ----
    - a request posts the role enabled.

    Then
    ----
    - the role flips from off to on.
    """
    api_endpoint_test(
        endpoint="/lean/v0/admin/aggregator",
        method="POST",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=False,
        request_body={"enabled": True},
    )


def test_aggregator_toggle_deactivate(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    Posting disable turns the aggregator role off.

    Given
    -----
    - a node started with the aggregator role enabled.

    When
    ----
    - a request posts the role disabled.

    Then
    ----
    - the role flips from on to off.
    """
    api_endpoint_test(
        endpoint="/lean/v0/admin/aggregator",
        method="POST",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=True,
        request_body={"enabled": False},
    )


def test_aggregator_toggle_idempotent_enable(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    Posting enable on an already-enabled node is a no-op.

    Given
    -----
    - a node started with the aggregator role enabled.

    When
    ----
    - a request posts the role enabled again.

    Then
    ----
    - the response reports the previous role as enabled.
    - the role stays on.
    """
    api_endpoint_test(
        endpoint="/lean/v0/admin/aggregator",
        method="POST",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=True,
        request_body={"enabled": True},
    )


def test_aggregator_toggle_idempotent_disable(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    Posting disable on an already-disabled node is a no-op.

    Given
    -----
    - a node started with the aggregator role disabled.

    When
    ----
    - a request posts the role disabled again.

    Then
    ----
    - the response reports the previous role as disabled.
    - the role stays off.
    """
    api_endpoint_test(
        endpoint="/lean/v0/admin/aggregator",
        method="POST",
        genesis_params=GENESIS_4V,
        initial_is_aggregator=False,
        request_body={"enabled": False},
    )
