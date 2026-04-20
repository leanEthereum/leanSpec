"""
Prometheus-backed implementation of ForkChoiceObserver.

Lives in the metrics subpackage because it couples the vendor-neutral
spec observer to the Prometheus client library. The spec itself remains
unaware of Prometheus.
"""

from __future__ import annotations

from lean_spec.subspecs.forkchoice.observer import ForkChoiceObserver
from lean_spec.subspecs.metrics.registry import registry as metrics


class PrometheusForkChoiceObserver(ForkChoiceObserver):
    """Translate ForkChoiceObserver callbacks into Prometheus metric updates."""

    def state_transition_timed(self, seconds: float) -> None:
        """Record state transition latency into its histogram."""
        metrics.lean_state_transition_time_seconds.observe(seconds)

    def block_processed(self, seconds: float) -> None:
        """Record end-to-end block processing latency into its histogram."""
        metrics.lean_fork_choice_block_processing_time_seconds.observe(seconds)

    def head_advanced(
        self,
        *,
        head_slot: int,
        safe_target_slot: int,
        latest_justified_slot: int,
        latest_finalized_slot: int,
    ) -> None:
        """Update the four fork-choice slot gauges."""
        metrics.lean_head_slot.set(head_slot)
        metrics.lean_safe_target_slot.set(safe_target_slot)
        metrics.lean_latest_justified_slot.set(latest_justified_slot)
        metrics.lean_latest_finalized_slot.set(latest_finalized_slot)

    def head_reorged(self, reorg_depth: int) -> None:
        """Increment the reorg counter and record depth into its histogram."""
        metrics.lean_fork_choice_reorgs_total.inc()
        metrics.lean_fork_choice_reorg_depth.observe(reorg_depth)
