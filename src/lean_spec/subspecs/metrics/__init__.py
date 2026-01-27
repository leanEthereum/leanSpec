"""
Metrics module for observability.

Provides counters, gauges, and histograms for tracking consensus client behavior.
Exposes metrics in Prometheus text format.
"""

from .registry import (
    REGISTRY,
    attestations_invalid,
    attestations_produced,
    attestations_received,
    attestations_valid,
    block_processing_time,
    blocks_processed,
    blocks_proposed,
    current_slot,
    finalized_slot,
    generate_metrics,
    head_slot,
    justified_slot,
    peers_connected,
    reorgs,
    validators_count,
)

__all__ = [
    "REGISTRY",
    "attestations_invalid",
    "attestations_produced",
    "attestations_received",
    "attestations_valid",
    "block_processing_time",
    "blocks_processed",
    "blocks_proposed",
    "current_slot",
    "finalized_slot",
    "generate_metrics",
    "head_slot",
    "justified_slot",
    "peers_connected",
    "reorgs",
    "validators_count",
]
