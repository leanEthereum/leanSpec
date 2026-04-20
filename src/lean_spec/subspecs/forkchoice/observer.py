"""
Observer protocol for fork choice telemetry.

Store.on_block calls into an observer at defined hook points.
Clients pass in an implementation that forwards to Prometheus, logs, traces,
or any other backend. The default is a no-op, so the spec remains usable
without any observability wiring.

The protocol is part of the spec surface: other language implementations
should expose an equivalent interface so that metrics stay comparable
across clients.
"""

from __future__ import annotations

from typing import Protocol


class ForkChoiceObserver(Protocol):
    """
    Hooks invoked by Store.on_block during block processing.

    Every method is a side-effect-only callback. Return values are ignored.
    Implementations must not raise from these hooks: an exception here
    would abort a consensus-critical operation for telemetry reasons.
    """

    def state_transition_timed(self, seconds: float) -> None:
        """Report the wall time of the state transition function."""

    def block_processed(self, seconds: float) -> None:
        """Report the wall time of end-to-end block processing."""

    def head_advanced(
        self,
        *,
        head_slot: int,
        safe_target_slot: int,
        latest_justified_slot: int,
        latest_finalized_slot: int,
    ) -> None:
        """Report the post-transition fork choice slots."""

    def head_reorged(self, reorg_depth: int) -> None:
        """Report that the head moved off the previous chain."""


class NullObserver:
    """
    Default observer that discards every event.

    Shared as a single instance to avoid per-call allocations.
    """

    def state_transition_timed(self, seconds: float) -> None:  # noqa: ARG002
        """Accept and discard."""

    def block_processed(self, seconds: float) -> None:  # noqa: ARG002
        """Accept and discard."""

    def head_advanced(
        self,
        *,
        head_slot: int,  # noqa: ARG002
        safe_target_slot: int,  # noqa: ARG002
        latest_justified_slot: int,  # noqa: ARG002
        latest_finalized_slot: int,  # noqa: ARG002
    ) -> None:
        """Accept and discard."""

    def head_reorged(self, reorg_depth: int) -> None:  # noqa: ARG002
        """Accept and discard."""


NULL_OBSERVER: ForkChoiceObserver = NullObserver()
"""Module-level singleton used as the default observer."""
