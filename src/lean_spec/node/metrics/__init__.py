"""
Prometheus metrics for the lean consensus node.

Metric names and types follow the leanMetrics spec:
https://github.com/leanEthereum/leanMetrics/blob/main/metrics.md
"""

from lean_spec.node.metrics.registry import get_metrics_output, registry
from lean_spec.node.metrics.spec_observer import PrometheusObserver

__all__ = [
    "PrometheusObserver",
    "get_metrics_output",
    "registry",
]
