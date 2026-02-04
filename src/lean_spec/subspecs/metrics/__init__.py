"""
Metrics module for observability.

Provides counters, gauges, and histograms for tracking consensus client behavior.
Exposes metrics in Prometheus text format.
"""

from .registry import (
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

__all__ = [
    "REGISTRY",
    "attestations_produced",
    "block_processing_time",
    "blocks_processed",
    "blocks_proposed",
    "finalized_slot",
    "generate_metrics",
    "head_slot",
    "justified_slot",
    "validators_count",
]
