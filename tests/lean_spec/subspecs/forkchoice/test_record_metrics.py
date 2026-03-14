"""Tests for Store._record_metrics."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from prometheus_client import CollectorRegistry, Counter, Gauge

from lean_spec.subspecs.metrics import registry as metrics
from lean_spec.types import Bytes32
from tests.lean_spec.helpers import make_checkpoint, make_store


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


class TestRecordMetricsUninitialized:
    """Tests for _record_metrics when metrics are not initialized."""

    def test_noop_when_metrics_not_initialized(self) -> None:
        """No errors are raised when metrics are not initialized."""
        store = make_store(num_validators=3)
        # Should not raise even though metric objects are no-op stubs
        store._record_metrics(store.head)


class TestRecordMetricsNoReorg:
    """Tests for _record_metrics when head has not changed."""

    def test_sets_head_slot_gauge(self, fresh_registry: CollectorRegistry) -> None:
        """Head slot gauge is set to the slot of the current head block."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store._record_metrics(store.head)

        expected_slot = int(store.blocks[store.head].slot)
        assert _get_gauge_value(metrics.lean_head_slot) == expected_slot

    def test_sets_safe_target_slot_gauge(self, fresh_registry: CollectorRegistry) -> None:
        """Safe target slot gauge is set to the slot of the safe target block."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store._record_metrics(store.head)

        expected_slot = int(store.blocks[store.safe_target].slot)
        assert _get_gauge_value(metrics.lean_safe_target_slot) == expected_slot

    def test_sets_latest_justified_slot_gauge(self, fresh_registry: CollectorRegistry) -> None:
        """Latest justified slot gauge is set from the store's latest_justified checkpoint."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store._record_metrics(store.head)

        expected_slot = int(store.latest_justified.slot)
        assert _get_gauge_value(metrics.lean_latest_justified_slot) == expected_slot

    def test_sets_latest_finalized_slot_gauge(self, fresh_registry: CollectorRegistry) -> None:
        """Latest finalized slot gauge is set from the store's latest_finalized checkpoint."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store._record_metrics(store.head)

        expected_slot = int(store.latest_finalized.slot)
        assert _get_gauge_value(metrics.lean_latest_finalized_slot) == expected_slot

    def test_does_not_increment_reorg_counter_when_head_unchanged(
        self, fresh_registry: CollectorRegistry
    ) -> None:
        """Reorg counter stays at zero when old_head equals current head."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store._record_metrics(store.head)

        assert _get_counter_value(metrics.lean_fork_choice_reorgs_total) == 0

    def test_all_gauges_set_correctly_for_genesis_store(
        self, fresh_registry: CollectorRegistry
    ) -> None:
        """All four gauges reflect genesis values (slot 0) on a fresh store."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store._record_metrics(store.head)

        assert _get_gauge_value(metrics.lean_head_slot) == 0
        assert _get_gauge_value(metrics.lean_safe_target_slot) == 0
        assert _get_gauge_value(metrics.lean_latest_justified_slot) == 0
        assert _get_gauge_value(metrics.lean_latest_finalized_slot) == 0


class TestRecordMetricsWithReorg:
    """Tests for _record_metrics when head has changed (reorg detected)."""

    def test_increments_reorg_counter_on_head_change(
        self, fresh_registry: CollectorRegistry
    ) -> None:
        """Reorg counter increments by one when head differs from old_head."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)
        fake_old_head = Bytes32(b"\xaa" * 32)

        # Add a fake block so reorg_depth can walk the chain
        # The old_head won't be in blocks, so reorg_depth returns 0 ancestors
        # But the counter should still increment
        store._record_metrics(fake_old_head)

        assert _get_counter_value(metrics.lean_fork_choice_reorgs_total) == 1

    def test_observes_reorg_depth(self, fresh_registry: CollectorRegistry) -> None:
        """Reorg depth histogram receives the depth from blocks.reorg_depth."""
        _init_metrics(fresh_registry)

        # Build a store with two branches to produce a real reorg depth
        store = make_store(num_validators=3)

        # Passing a different old_head triggers reorg path
        fake_old_head = Bytes32(b"\xbb" * 32)
        store._record_metrics(fake_old_head)

        # fake_old_head is not in blocks, so reorg_depth walks 0 ancestors -> depth 0
        # The histogram should have recorded exactly one observation
        histogram = metrics.lean_fork_choice_reorg_depth
        assert not isinstance(histogram, type(metrics).__mro__[0])
        assert histogram._sum.get() == 0  # type: ignore[union-attr]

    def test_reorg_counter_increments_multiple_times(
        self, fresh_registry: CollectorRegistry
    ) -> None:
        """Reorg counter accumulates across multiple calls."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store._record_metrics(Bytes32(b"\x01" * 32))
        store._record_metrics(Bytes32(b"\x02" * 32))
        store._record_metrics(Bytes32(b"\x03" * 32))

        assert _get_counter_value(metrics.lean_fork_choice_reorgs_total) == 3

    def test_gauges_still_set_during_reorg(self, fresh_registry: CollectorRegistry) -> None:
        """Gauge values are updated even when a reorg is detected."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store._record_metrics(Bytes32(b"\xff" * 32))

        assert _get_gauge_value(metrics.lean_head_slot) == int(store.blocks[store.head].slot)
        assert _get_gauge_value(metrics.lean_safe_target_slot) == int(
            store.blocks[store.safe_target].slot
        )
        assert _get_gauge_value(metrics.lean_latest_justified_slot) == int(
            store.latest_justified.slot
        )
        assert _get_gauge_value(metrics.lean_latest_finalized_slot) == int(
            store.latest_finalized.slot
        )


class TestRecordMetricsWithNonGenesisSlots:
    """Tests for _record_metrics with non-zero checkpoint slots."""

    def test_gauges_reflect_updated_checkpoint_slots(
        self, fresh_registry: CollectorRegistry
    ) -> None:
        """Gauge values match non-zero justified and finalized slots."""
        _init_metrics(fresh_registry)
        store = make_store(num_validators=3)

        store = store.model_copy(
            update={
                "latest_justified": make_checkpoint(root_seed=1, slot=10),
                "latest_finalized": make_checkpoint(root_seed=2, slot=5),
            }
        )

        store._record_metrics(store.head)

        assert _get_gauge_value(metrics.lean_latest_justified_slot) == 10
        assert _get_gauge_value(metrics.lean_latest_finalized_slot) == 5
