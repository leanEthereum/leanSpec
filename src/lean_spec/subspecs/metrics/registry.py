"""
Prometheus metric definitions aligned with the leanMetrics spec.

Names, types, and buckets match
https://github.com/leanEthereum/leanMetrics/blob/main/metrics.md

This module uses the null object pattern for zero-cost metrics before
initialization. Every metric attribute starts as a silent no-op stub.
After initialization, stubs are replaced with real Prometheus objects.

This design gives consumers a stable API at import time.
No "is metrics enabled?" checks are needed anywhere in the codebase.
Code that records metrics works identically whether the Prometheus
subsystem is active or not.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from prometheus_client import (
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

if TYPE_CHECKING:
    from prometheus_client import CollectorRegistry

# Histogram bucket boundaries from the leanMetrics spec.
#
# Each tuple defines the upper bounds for a Prometheus histogram.
# Values are chosen to capture the expected latency distributions
# for each operation category.

FORK_CHOICE_BLOCK_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 1, 1.25, 1.5, 2, 4)
"""Seconds. Block processing in fork choice is typically sub-second."""

ATTESTATION_VALIDATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 1)
"""Seconds. Attestation validation is fast, most finish under 100ms."""

STATE_TRANSITION_BUCKETS = (0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 4)
"""Seconds. State transitions are heavier, spanning sub-second to multi-second."""

REORG_DEPTH_BUCKETS = (1, 2, 3, 5, 7, 10, 20, 30, 50, 100)
"""Block count. Reorg depths above 10 are rare and signal network issues."""


class _NoOpMetric:
    """
    Null object that absorbs all metric operations without side effects.

    This stub mirrors the subset of the Prometheus metric interface that
    consumers actually use:

    - Gauge operations: set, inc
    - Histogram operations: observe
    - Label selection: labels (returns another no-op for chaining)

    A single shared instance serves all uninitialized metric attributes.
    This avoids allocating one stub per metric and keeps memory overhead
    near zero.
    """

    def set(self, value: float) -> None:  # noqa: ARG002
        """Accept and discard a gauge value."""

    def inc(self, amount: float = 1) -> None:  # noqa: ARG002
        """Accept and discard a counter increment."""

    def observe(self, amount: float) -> None:  # noqa: ARG002
        """Accept and discard a histogram observation."""

    def labels(self, **kwargs: str) -> _NoOpMetric:  # noqa: ARG002
        """
        Return self to support chained label selection.

        Prometheus metrics with labels require a selection step before
        recording. Returning self allows the full chain to complete
        silently.
        """
        return self


_NOOP = _NoOpMetric()
"""Shared no-op instance used by all uninitialized metric attributes."""


class MetricsRegistry:
    """
    Central holder for all Prometheus metrics in a lean node.

    Attributes start as no-op stubs and become real Prometheus objects
    after initialization. This two-phase lifecycle means:

    - Importing the module is always safe and cheap.
    - Recording metrics works at any point in the node lifetime.
    - No conditional "is metrics ready?" logic pollutes call sites.

    A single module-level instance acts as the singleton.
    Consumers import that instance and use qualified attribute access.
    """

    _initialized: bool = False

    # Node info
    lean_node_info: Gauge | _NoOpMetric = _NOOP
    """Labeled gauge exposing node name and version. Always set to 1."""
    lean_node_start_time_seconds: Gauge | _NoOpMetric = _NOOP
    """Unix timestamp recorded once at node startup."""

    # Fork choice
    lean_head_slot: Gauge | _NoOpMetric = _NOOP
    """Slot of the current chain head selected by fork choice."""
    lean_current_slot: Gauge | _NoOpMetric = _NOOP
    """Wall-clock slot derived from genesis time and the slot interval."""
    lean_safe_target_slot: Gauge | _NoOpMetric = _NOOP
    """Slot of the highest target that has been deemed safe."""
    lean_fork_choice_block_processing_time_seconds: Histogram | _NoOpMetric = _NOOP
    """Latency of integrating a new block into the fork choice store."""
    lean_attestations_valid_total: Counter | _NoOpMetric = _NOOP
    """Running count of attestations that passed all validation checks."""
    lean_attestations_invalid_total: Counter | _NoOpMetric = _NOOP
    """Running count of attestations rejected during validation."""
    lean_attestation_validation_time_seconds: Histogram | _NoOpMetric = _NOOP
    """Latency of a single attestation validation pass."""
    lean_fork_choice_reorgs_total: Counter | _NoOpMetric = _NOOP
    """Running count of chain head reorganizations."""
    lean_fork_choice_reorg_depth: Histogram | _NoOpMetric = _NOOP
    """Number of blocks rolled back during each reorg event."""

    # State transition
    lean_latest_justified_slot: Gauge | _NoOpMetric = _NOOP
    """Slot of the most recently justified checkpoint."""
    lean_latest_finalized_slot: Gauge | _NoOpMetric = _NOOP
    """Slot of the most recently finalized checkpoint."""
    lean_state_transition_time_seconds: Histogram | _NoOpMetric = _NOOP
    """Latency of applying a full state transition for one slot."""

    # Validator
    lean_validators_count: Gauge | _NoOpMetric = _NOOP
    """Number of validator keys managed by this node."""

    # Network
    lean_connected_peers: Gauge | _NoOpMetric = _NOOP
    """Current number of active peer connections."""

    def init(
        self,
        name: str = "leanspec-node",
        version: str = "0.0.1",
        registry: CollectorRegistry | None = None,
    ) -> None:
        """
        Replace all no-op stubs with real Prometheus metric objects.

        Call once at node startup. The method is idempotent.
        Repeated calls after the first are silently ignored.
        This prevents double-registration errors in Prometheus.

        Metric categories created:

        - Node info: identity gauge and start timestamp
        - Fork choice: head/current/safe slots, block processing,
          attestation validation, reorg tracking
        - State transition: justified/finalized slots, transition time
        - Validator: managed validator count
        - Network: connected peer count

        Args:
            name: Human-readable node name exposed in the info gauge.
            version: Node version exposed in the info gauge.
            registry: Prometheus collector registry. Falls back to the
                global default registry when not provided.
        """
        # Guard against repeated initialization.
        if self._initialized:
            return
        reg = registry or REGISTRY

        # Node info (leanMetrics: Node Info Metrics)
        #
        # The info gauge is always 1. Labels carry the identity metadata.
        self.lean_node_info = Gauge(
            "lean_node_info",
            "Node information (always 1).",
            ["name", "version"],
            registry=reg,
        )
        self.lean_node_info.labels(name=name, version=version).set(1)
        self.lean_node_start_time_seconds = Gauge(
            "lean_node_start_time_seconds",
            "Start timestamp.",
            registry=reg,
        )
        self.lean_node_start_time_seconds.set(time.time())

        # Fork choice (leanMetrics: Fork-Choice Metrics)
        self.lean_head_slot = Gauge(
            "lean_head_slot",
            "Latest slot of the lean chain.",
            registry=reg,
        )
        self.lean_current_slot = Gauge(
            "lean_current_slot",
            "Current slot of the lean chain.",
            registry=reg,
        )
        self.lean_safe_target_slot = Gauge(
            "lean_safe_target_slot",
            "Safe target slot.",
            registry=reg,
        )
        self.lean_fork_choice_block_processing_time_seconds = Histogram(
            "lean_fork_choice_block_processing_time_seconds",
            "Time taken to process block in fork choice.",
            buckets=FORK_CHOICE_BLOCK_BUCKETS,
            registry=reg,
        )
        self.lean_attestations_valid_total = Counter(
            "lean_attestations_valid_total",
            "Total number of valid attestations.",
            ["source"],
            registry=reg,
        )
        self.lean_attestations_invalid_total = Counter(
            "lean_attestations_invalid_total",
            "Total number of invalid attestations.",
            ["source"],
            registry=reg,
        )
        self.lean_attestation_validation_time_seconds = Histogram(
            "lean_attestation_validation_time_seconds",
            "Time taken to validate attestation.",
            buckets=ATTESTATION_VALIDATION_BUCKETS,
            registry=reg,
        )
        self.lean_fork_choice_reorgs_total = Counter(
            "lean_fork_choice_reorgs_total",
            "Total number of fork choice reorgs.",
            registry=reg,
        )
        self.lean_fork_choice_reorg_depth = Histogram(
            "lean_fork_choice_reorg_depth",
            "Depth of fork choice reorgs (in blocks).",
            buckets=REORG_DEPTH_BUCKETS,
            registry=reg,
        )

        # State transition (leanMetrics: State Transition Metrics)
        self.lean_latest_justified_slot = Gauge(
            "lean_latest_justified_slot",
            "Latest justified slot.",
            registry=reg,
        )
        self.lean_latest_finalized_slot = Gauge(
            "lean_latest_finalized_slot",
            "Latest finalized slot.",
            registry=reg,
        )
        self.lean_state_transition_time_seconds = Histogram(
            "lean_state_transition_time_seconds",
            "Time to process state transition.",
            buckets=STATE_TRANSITION_BUCKETS,
            registry=reg,
        )

        # Validator (leanMetrics: Validator Metrics)
        self.lean_validators_count = Gauge(
            "lean_validators_count",
            "Number of validators managed by a node.",
            registry=reg,
        )
        self.lean_validators_count.set(0)

        # Network (leanMetrics: Network Metrics)
        self.lean_connected_peers = Gauge(
            "lean_connected_peers",
            "Number of connected peers.",
            registry=reg,
        )
        self.lean_connected_peers.set(0)

        self._initialized = True

    def reset(self) -> None:
        """
        Restore all metrics to their initial no-op state.

        Intended exclusively for test teardown.
        Production code should never call this.

        Clears all instance overrides so attributes fall back to
        the class-level no-op defaults.
        """
        self.__dict__.clear()


registry = MetricsRegistry()
"""
Module-level singleton shared by all consumers.

Import this instance and use qualified attribute access
throughout the codebase.
"""


def get_metrics_output(registry: CollectorRegistry | None = None) -> bytes:
    """
    Serialize all registered metrics into Prometheus text exposition format.

    Typically called by an HTTP handler to serve the ``/metrics`` endpoint.
    The output is ready to return as a response body.

    Args:
        registry: Prometheus collector registry to export. Falls back to
            the global default registry when not provided.

    Returns:
        UTF-8 encoded bytes in Prometheus text exposition format.
    """
    reg = registry or REGISTRY
    return generate_latest(reg)
