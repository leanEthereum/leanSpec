"""
Prometheus-backed implementation of SpecObserver.

Couples vendor-neutral spec events to the Prometheus client library.
Lives in the metrics subpackage because the coupling belongs on the
Prometheus side of the seam.
The spec itself never imports this module.
"""

from __future__ import annotations

from lean_spec.subspecs.metrics.registry import registry as metrics


class PrometheusSpecObserver:
    """Forward SpecObserver callbacks to Prometheus metrics."""

    def state_transition_timed(self, seconds: float) -> None:
        """Record state transition latency into its histogram."""
        metrics.lean_state_transition_time_seconds.observe(seconds)
