"""Tests for the Prometheus metrics registry."""

from __future__ import annotations

from lean_spec.subspecs.metrics import (
    REGISTRY,
    attestations_produced,
    block_processing_time,
    blocks_processed,
    blocks_proposed,
    finalized_slot,
    generate_metrics,
    head_slot,
    justified_slot,
    validators_count,
)


class TestMetricTypes:
    """Tests for metric type behavior."""

    def test_counter_increments_correctly(self) -> None:
        """Counter metrics increment by one on each call."""
        initial = blocks_processed._value.get()
        blocks_processed.inc()
        assert blocks_processed._value.get() == initial + 1.0

    def test_gauge_sets_value_correctly(self) -> None:
        """Gauge metrics can be set to arbitrary values."""
        head_slot.set(42.0)
        assert head_slot._value.get() == 42.0

        head_slot.set(100.0)
        assert head_slot._value.get() == 100.0

    def test_histogram_observes_values(self) -> None:
        """Histogram metrics record observations."""
        # Get initial sample count from the histogram
        initial_samples = list(block_processing_time.collect())[0].samples
        initial_count = next(s.value for s in initial_samples if s.name.endswith("_count"))

        block_processing_time.observe(0.05)

        # Verify count increased
        new_samples = list(block_processing_time.collect())[0].samples
        new_count = next(s.value for s in new_samples if s.name.endswith("_count"))
        assert new_count == initial_count + 1


class TestMetricDefinitions:
    """Tests for pre-defined metric definitions."""

    def test_node_information_gauges_exist(self) -> None:
        """Node information gauges are defined."""
        assert head_slot is not None
        assert justified_slot is not None
        assert finalized_slot is not None
        assert validators_count is not None

    def test_block_processing_metrics_exist(self) -> None:
        """Block processing metrics are defined."""
        assert blocks_processed is not None
        assert block_processing_time is not None

    def test_validator_production_metrics_exist(self) -> None:
        """Validator production metrics are defined."""
        assert blocks_proposed is not None
        assert attestations_produced is not None


class TestPrometheusOutput:
    """Tests for Prometheus text format output."""

    def test_generate_metrics_returns_bytes(self) -> None:
        """Generate metrics returns bytes in Prometheus format."""
        output = generate_metrics()
        assert isinstance(output, bytes)

    def test_output_contains_metric_names(self) -> None:
        """Output contains expected metric names."""
        output = generate_metrics().decode("utf-8")

        assert "lean_head_slot" in output
        assert "lean_blocks_processed_total" in output
        assert "lean_block_processing_seconds" in output

    def test_output_contains_help_text(self) -> None:
        """Output contains HELP lines for metrics."""
        output = generate_metrics().decode("utf-8")

        assert "# HELP lean_head_slot" in output
        assert "# TYPE lean_head_slot gauge" in output

    def test_output_contains_histogram_buckets(self) -> None:
        """Output contains histogram bucket values."""
        output = generate_metrics().decode("utf-8")

        # Histogram exports include _bucket, _count, _sum
        assert "lean_block_processing_seconds_bucket" in output
        assert "lean_block_processing_seconds_count" in output
        assert "lean_block_processing_seconds_sum" in output


class TestRegistryIsolation:
    """Tests for registry isolation from default metrics."""

    def test_registry_is_dedicated(self) -> None:
        """Our registry is separate from default prometheus registry."""
        from prometheus_client import REGISTRY as DEFAULT_REGISTRY

        assert REGISTRY is not DEFAULT_REGISTRY

    def test_metrics_registered_to_custom_registry(self) -> None:
        """All metrics are registered to our custom registry."""
        # Verify a metric is in our registry by generating output
        output = generate_metrics().decode("utf-8")

        # If head_slot is in our registry, it should appear in output
        assert "lean_head_slot" in output


class TestHistogramTiming:
    """Tests for histogram timing context manager."""

    def test_time_context_manager_records_duration(self) -> None:
        """Histogram time() context manager records duration."""
        import time

        # Get initial values from samples
        initial_samples = list(block_processing_time.collect())[0].samples
        initial_count = next(s.value for s in initial_samples if s.name.endswith("_count"))
        initial_sum = next(s.value for s in initial_samples if s.name.endswith("_sum"))

        with block_processing_time.time():
            time.sleep(0.01)

        # Get new values
        new_samples = list(block_processing_time.collect())[0].samples
        new_count = next(s.value for s in new_samples if s.name.endswith("_count"))
        new_sum = next(s.value for s in new_samples if s.name.endswith("_sum"))

        assert new_count == initial_count + 1
        assert new_sum > initial_sum
