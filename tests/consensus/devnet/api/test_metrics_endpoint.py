"""API endpoint: /metrics scrape contract vector."""

import pytest
from consensus_testing import ApiEndpointTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_metrics_endpoint_scrape_contract(
    api_endpoint: ApiEndpointTestFiller,
) -> None:
    """GET /metrics returns the Prometheus-format scrape with the required metric names.

    The endpoint body is dynamic (counters accumulate, timestamps shift),
    so the vector pins only the stable contract: status 200, the
    Prometheus text-exposition content type, and the full list of
    metric names a compliant node must expose. Clients replay the
    fixture and confirm every listed metric appears in their scrape.
    """
    api_endpoint(
        endpoint="/metrics",
        method="GET",
        genesis_params={"numValidators": 4, "genesisTime": 0},
    )
