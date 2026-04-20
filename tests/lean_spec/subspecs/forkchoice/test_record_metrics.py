"""Tests for PrometheusForkChoiceObserver."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from prometheus_client import CollectorRegistry, Counter, Gauge

from lean_spec.subspecs.metrics import PrometheusForkChoiceObserver
from lean_spec.subspecs.metrics import registry as metrics


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


def _init_metrics(registry: CollectorRegistry) -> None:
    """Initialize metrics with the given isolated registry."""
    metrics.init(registry=registry)


def _get_gauge_value(gauge: Any) -> float:
    """Read the current value of a Prometheus Gauge."""
    assert isinstance(gauge, Gauge)
    return gauge._value.get()


def _get_counter_value(counter: Any) -> float:
    """Read the current value of a Prometheus Counter."""
    assert isinstance(counter, Counter)
    return counter._value.get()


class TestObserverUninitialized:
    """PrometheusForkChoiceObserver is a no-op when metrics are not initialized."""

    def test_no_error_when_metrics_not_initialized(self) -> None:
        observer = PrometheusForkChoiceObserver()
        observer.state_transition_timed(0.1)
        observer.block_processed(0.2)
        observer.head_advanced(
            head_slot=3,
            safe_target_slot=2,
            latest_justified_slot=1,
            latest_finalized_slot=0,
        )
        observer.head_reorged(4)


class TestHeadAdvanced:
    """head_advanced sets the four fork-choice gauges."""

    def test_sets_all_four_slot_gauges(self, fresh_registry: CollectorRegistry) -> None:
        _init_metrics(fresh_registry)
        PrometheusForkChoiceObserver().head_advanced(
            head_slot=7,
            safe_target_slot=5,
            latest_justified_slot=3,
            latest_finalized_slot=1,
        )
        assert _get_gauge_value(metrics.lean_head_slot) == 7
        assert _get_gauge_value(metrics.lean_safe_target_slot) == 5
        assert _get_gauge_value(metrics.lean_latest_justified_slot) == 3
        assert _get_gauge_value(metrics.lean_latest_finalized_slot) == 1


class TestHeadReorged:
    """head_reorged increments the counter and records depth."""

    def test_increments_reorg_counter(self, fresh_registry: CollectorRegistry) -> None:
        _init_metrics(fresh_registry)
        observer = PrometheusForkChoiceObserver()

        observer.head_reorged(2)
        observer.head_reorged(5)
        observer.head_reorged(1)

        assert _get_counter_value(metrics.lean_fork_choice_reorgs_total) == 3
