"""Tests for the Prometheus metrics registry."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from prometheus_client import CollectorRegistry

from lean_spec.subspecs.metrics.registry import (
    ATTESTATION_AGGREGATE_COVERAGE_DIFF_DIRECTIONS,
    ATTESTATION_AGGREGATE_COVERAGE_SECTIONS,
    registry,
)


@pytest.fixture(autouse=True)
def _reset_registry() -> Iterator[None]:
    """Ensure metrics are uninitialized before and after each test."""
    registry.reset()
    registry._initialized = False
    yield
    registry.reset()
    registry._initialized = False


def test_attestation_aggregate_coverage_metrics_registered() -> None:
    """Coverage gauges are created with default combined-subnet series."""
    test_reg = CollectorRegistry()
    registry.init(registry=test_reg)

    for section in ATTESTATION_AGGREGATE_COVERAGE_SECTIONS:
        assert (
            test_reg.get_sample_value(
                "lean_attestation_aggregate_coverage_validators",
                {"section": section, "subnet": "combined"},
            )
            == 0.0
        )
        assert (
            test_reg.get_sample_value(
                "lean_attestation_aggregate_coverage_subnets",
                {"section": section},
            )
            == 0.0
        )

    for direction in ATTESTATION_AGGREGATE_COVERAGE_DIFF_DIRECTIONS:
        assert (
            test_reg.get_sample_value(
                "lean_attestation_aggregate_coverage_diff_validators",
                {"direction": direction},
            )
            == 0.0
        )
