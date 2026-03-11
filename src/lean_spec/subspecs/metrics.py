"""
Prometheus metrics for the lean consensus node.

Provides instrumentation for monitoring node health, protocol behavior,
and synchronization status.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from prometheus_client import CollectorRegistry, Counter, Gauge


def _make_registry() -> CollectorRegistry:
    """Create a fresh Prometheus collector registry."""
    return CollectorRegistry()


@dataclass(frozen=True, slots=True)
class Metrics:
    """
    Prometheus metrics registry for leanspec-node.

    Each Metrics instance owns its own CollectorRegistry so that multiple
    instances (e.g. in tests) don't collide on the global registry.
    """

    registry: CollectorRegistry = field(default_factory=_make_registry)
    """Prometheus collector registry for this metrics instance."""

    slot_current: Gauge = field(init=False)
    epoch_current: Gauge = field(init=False)
    peers_connected: Gauge = field(init=False)
    blocks_imported_total: Counter = field(init=False)
    attestations_processed_total: Counter = field(init=False)
    sync_distance: Gauge = field(init=False)
    process_start_time_seconds: Gauge = field(init=False)

    def __post_init__(self) -> None:
        """Initialize all metrics on the instance registry."""
        reg = self.registry

        object.__setattr__(
            self,
            "slot_current",
            Gauge("leanspec_slot_current", "Current slot number", registry=reg),
        )
        object.__setattr__(
            self,
            "epoch_current",
            Gauge("leanspec_epoch_current", "Current epoch", registry=reg),
        )
        object.__setattr__(
            self,
            "peers_connected",
            Gauge("leanspec_peers_connected", "Number of connected peers", registry=reg),
        )
        object.__setattr__(
            self,
            "blocks_imported_total",
            Counter("leanspec_blocks_imported_total", "Cumulative blocks imported", registry=reg),
        )
        object.__setattr__(
            self,
            "attestations_processed_total",
            Counter(
                "leanspec_attestations_processed_total",
                "Cumulative attestations processed",
                registry=reg,
            ),
        )
        object.__setattr__(
            self,
            "sync_distance",
            Gauge("leanspec_sync_distance", "Slots behind head (0 when synced)", registry=reg),
        )
        object.__setattr__(
            self,
            "process_start_time_seconds",
            Gauge(
                "leanspec_process_start_time_seconds",
                "Unix timestamp of node startup",
                registry=reg,
            ),
        )

        self.process_start_time_seconds.set(time.time())

    @classmethod
    def create(cls) -> Metrics:
        """Create and initialize a new metrics registry."""
        return cls()
