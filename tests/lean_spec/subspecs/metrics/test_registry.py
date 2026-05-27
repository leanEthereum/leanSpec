"""Tests for the Prometheus metrics registry."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from prometheus_client import CollectorRegistry

from lean_spec.subspecs.metrics.registry import registry


@pytest.fixture(autouse=True)
def _reset_registry() -> Iterator[None]:
    """Ensure metrics are uninitialized before and after each test."""
    registry.reset()
    registry._initialized = False
    yield
    registry.reset()
    registry._initialized = False


def test_pq_sig_aggregated_signature_metrics_registered() -> None:
    """PQ-signature production metrics are registered on init."""
    test_reg = CollectorRegistry()
    registry.init(registry=test_reg)

    assert test_reg.get_sample_value("lean_pq_sig_aggregated_signatures_total") == 0.0
    assert (
        test_reg.get_sample_value("lean_pq_sig_attestations_in_aggregated_signatures_total")
        == 0.0
    )
    assert (
        test_reg.get_sample_value(
            "lean_pq_sig_aggregated_signatures_building_time_seconds_count",
        )
        == 0.0
    )
