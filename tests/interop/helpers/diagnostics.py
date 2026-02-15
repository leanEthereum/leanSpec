"""
Pipeline diagnostics for interop tests.

Captures attestation pipeline state from test nodes for debugging
and assertions. Provides a snapshot of the full pipeline:
block production -> attestation -> aggregation -> safe target -> justification.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PipelineDiagnostics:
    """Snapshot of a node's attestation pipeline state."""

    head_slot: int
    """Current head slot."""

    safe_target_slot: int
    """Current safe target slot."""

    finalized_slot: int
    """Latest finalized slot."""

    justified_slot: int
    """Latest justified slot."""

    gossip_signatures_count: int
    """Number of pending gossip signatures (pre-aggregation)."""

    new_aggregated_count: int
    """Number of entries in latest_new_aggregated_payloads."""

    known_aggregated_count: int
    """Number of entries in latest_known_aggregated_payloads."""

    block_count: int
    """Total blocks in the store."""
