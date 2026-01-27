"""
Metric registry using prometheus_client.

Provides pre-defined metrics for a consensus client.
Exposes metrics in Prometheus text format via the /metrics endpoint.
"""

from __future__ import annotations

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# Create a dedicated registry for lean-spec metrics.
#
# Using a dedicated registry avoids pollution from default Python process metrics.
REGISTRY = CollectorRegistry()

# -----------------------------------------------------------------------------
# Node Information
# -----------------------------------------------------------------------------

head_slot = Gauge(
    "lean_head_slot",
    "Current head slot",
    registry=REGISTRY,
)

current_slot = Gauge(
    "lean_current_slot",
    "Current time slot",
    registry=REGISTRY,
)

justified_slot = Gauge(
    "lean_justified_slot",
    "Latest justified slot",
    registry=REGISTRY,
)

finalized_slot = Gauge(
    "lean_finalized_slot",
    "Latest finalized slot",
    registry=REGISTRY,
)

validators_count = Gauge(
    "lean_validators_count",
    "Active validators",
    registry=REGISTRY,
)

# -----------------------------------------------------------------------------
# Block Processing
# -----------------------------------------------------------------------------

blocks_processed = Counter(
    "lean_blocks_processed_total",
    "Total blocks processed",
    registry=REGISTRY,
)

block_processing_time = Histogram(
    "lean_block_processing_seconds",
    "Block processing duration",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    registry=REGISTRY,
)

# -----------------------------------------------------------------------------
# Attestations
# -----------------------------------------------------------------------------

attestations_received = Counter(
    "lean_attestations_received_total",
    "Total attestations received",
    registry=REGISTRY,
)

attestations_valid = Counter(
    "lean_attestations_valid_total",
    "Valid attestations",
    registry=REGISTRY,
)

attestations_invalid = Counter(
    "lean_attestations_invalid_total",
    "Invalid attestations",
    registry=REGISTRY,
)

# -----------------------------------------------------------------------------
# Network
# -----------------------------------------------------------------------------

peers_connected = Gauge(
    "lean_peers_connected",
    "Connected peers",
    registry=REGISTRY,
)

# -----------------------------------------------------------------------------
# Consensus Events
# -----------------------------------------------------------------------------

reorgs = Counter(
    "lean_reorgs_total",
    "Chain reorganizations",
    registry=REGISTRY,
)

# -----------------------------------------------------------------------------
# Validator Production
# -----------------------------------------------------------------------------

blocks_proposed = Counter(
    "lean_blocks_proposed_total",
    "Blocks proposed by this node",
    registry=REGISTRY,
)

attestations_produced = Counter(
    "lean_attestations_produced_total",
    "Attestations produced by this node",
    registry=REGISTRY,
)


def generate_metrics() -> bytes:
    """
    Generate Prometheus metrics output.

    Returns:
        Prometheus text format output as bytes.
    """
    return generate_latest(REGISTRY)
