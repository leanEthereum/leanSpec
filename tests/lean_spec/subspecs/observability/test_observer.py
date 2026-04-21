"""Tests for the spec observer singleton and its Prometheus adapter."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from prometheus_client import CollectorRegistry, Histogram

from lean_spec.subspecs.metrics import PrometheusSpecObserver
from lean_spec.subspecs.metrics import registry as metrics
from lean_spec.subspecs.observability import (
    NullObserver,
    get_observer,
    set_observer,
)


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


@pytest.fixture(autouse=True)
def _reset_observer() -> Iterator[None]:
    """Restore the default NullObserver between tests."""
    yield
    set_observer(NullObserver())


def _init_metrics(registry: CollectorRegistry) -> None:
    """Initialize metrics with the given isolated registry."""
    metrics.init(registry=registry)


def _get_histogram_sum(histogram: Any) -> float:
    """Read the cumulative observed sum of a Prometheus Histogram."""
    assert isinstance(histogram, Histogram)
    return histogram._sum.get()


class TestNullObserverDefault:
    """NullObserver is the registered singleton until set_observer is called."""

    def test_get_observer_returns_null_by_default(self) -> None:
        assert isinstance(get_observer(), NullObserver)

    def test_null_observer_discards_events(self) -> None:
        NullObserver().state_transition_timed(0.5)


class TestSetObserver:
    """set_observer replaces the module singleton."""

    def test_replaces_singleton(self) -> None:
        observer = PrometheusSpecObserver()
        set_observer(observer)
        assert get_observer() is observer


class TestPrometheusObserverUninitialized:
    """PrometheusSpecObserver is a no-op when metrics have not been initialized."""

    def test_no_error_when_metrics_not_initialized(self) -> None:
        PrometheusSpecObserver().state_transition_timed(0.1)


class TestPrometheusObserverWithRegistry:
    """state_transition_timed forwards into the Prometheus histogram."""

    def test_observes_single_value(self, fresh_registry: CollectorRegistry) -> None:
        _init_metrics(fresh_registry)

        PrometheusSpecObserver().state_transition_timed(0.5)

        assert _get_histogram_sum(metrics.lean_state_transition_time_seconds) == 0.5

    def test_accumulates_multiple_values(self, fresh_registry: CollectorRegistry) -> None:
        _init_metrics(fresh_registry)

        observer = PrometheusSpecObserver()
        observer.state_transition_timed(0.5)
        observer.state_transition_timed(0.75)

        assert _get_histogram_sum(metrics.lean_state_transition_time_seconds) == 1.25
