"""Tests for the Prometheus-backed spec observer."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from prometheus_client import CollectorRegistry, Histogram

from lean_spec.node.metrics import PrometheusObserver, registry as metrics


@pytest.fixture
def fresh_registry() -> CollectorRegistry:
    """Create an isolated Prometheus registry for each test."""
    return CollectorRegistry()


@pytest.fixture(autouse=True)
def _reset_metrics() -> Iterator[None]:
    """Ensure metrics are uninitialized before and after each test."""
    metrics.reset()
    yield
    metrics.reset()


def _get_histogram_sum(histogram: Any) -> float:
    """Read the cumulative observed sum of a Prometheus Histogram."""
    assert isinstance(histogram, Histogram)
    return histogram._sum.get()


# Each row pairs an observer hook with the Prometheus histogram it records into.
SPEC_EVENTS = [
    pytest.param(
        "state_transition_timed",
        "lean_state_transition_time_seconds",
        id="state_transition",
    ),
    pytest.param(
        "on_block_timed",
        "lean_fork_choice_block_processing_time_seconds",
        id="on_block",
    ),
    pytest.param(
        "on_attestation_timed",
        "lean_attestation_validation_time_seconds",
        id="on_attestation",
    ),
]


class TestPrometheusObserverUninitialized:
    """PrometheusObserver is a no-op when metrics have not been initialized."""

    @pytest.mark.parametrize(("method_name", "_metric_attribute"), SPEC_EVENTS)
    def test_no_error_when_metrics_not_initialized(
        self, method_name: str, _metric_attribute: str
    ) -> None:
        """Recording before init neither raises nor initializes the registry."""
        getattr(PrometheusObserver(), method_name)(0.1)

        assert metrics._initialized is False


class TestPrometheusObserverWithRegistry:
    """Each hook forwards into its paired Prometheus histogram."""

    @pytest.mark.parametrize(("method_name", "metric_attribute"), SPEC_EVENTS)
    def test_observes_single_value(
        self, fresh_registry: CollectorRegistry, method_name: str, metric_attribute: str
    ) -> None:
        """A single recorded value lands in the paired histogram's running sum."""
        metrics.init(registry=fresh_registry)

        getattr(PrometheusObserver(), method_name)(0.5)

        assert _get_histogram_sum(getattr(metrics, metric_attribute)) == 0.5

    @pytest.mark.parametrize(("method_name", "metric_attribute"), SPEC_EVENTS)
    def test_accumulates_multiple_values(
        self, fresh_registry: CollectorRegistry, method_name: str, metric_attribute: str
    ) -> None:
        """Repeated recordings accumulate in the paired histogram's running sum."""
        metrics.init(registry=fresh_registry)

        observer = PrometheusObserver()
        getattr(observer, method_name)(0.5)
        getattr(observer, method_name)(0.75)

        assert _get_histogram_sum(getattr(metrics, metric_attribute)) == 1.25
