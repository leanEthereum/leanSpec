"""API endpoint /metrics scrape contract vector."""

import pytest

from consensus_testing import ApiEndpointTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_metrics_endpoint_scrape_contract(
    api_endpoint_test: ApiEndpointTestFiller,
) -> None:
    """
    The metrics endpoint returns the Prometheus scrape with the required metric names.

    Given
    -----
    - a node started from a 4-validator genesis.
    - the endpoint body is dynamic as counters accumulate and timestamps shift.

    When
    ----
    - the metrics endpoint is queried.

    Then
    ----
    - the status is 200.
    - the content type is the Prometheus text-exposition format.
    - every metric name a compliant node must expose is present.
    """
    api_endpoint_test(
        endpoint="/metrics",
        method="GET",
        genesis_params={"numValidators": 4, "genesisTime": 0},
    )
