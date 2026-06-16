"""
Telemetry observer protocol and its process-wide singleton.

Hook Points

The observer is called from spec code at a small set of well-defined points.
Each hook corresponds to a phenomenon whose measurement is intrinsic to the
function being observed, not to any particular caller.

Contract

An observer must not raise.
A hook fires during a consensus-critical code path.
Any exception propagates and aborts the operation.
Clients must swallow internal errors inside their own observer implementation.
A metrics backend that goes down, for example, must not break the spec.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol


class SpecObserver(Protocol):
    """
    Telemetry hooks invoked at spec-level event points.

    Return values are ignored.
    Every method is side-effect-only.
    """

    def state_transition_timed(self, seconds: float) -> None:
        """Report the wall time of a state transition."""

    def on_block_timed(self, seconds: float) -> None:
        """Report the wall time of processing a block into the fork-choice store."""

    def on_attestation_timed(self, seconds: float) -> None:
        """Report the wall time of validating and integrating a gossip attestation."""


class _NullObserver:
    """
    Default observer that discards every event.

    A single instance serves every unregistered consumer.
    No allocations per call.
    """

    def state_transition_timed(self, seconds: float) -> None:  # noqa: ARG002
        """Accept and discard."""

    def on_block_timed(self, seconds: float) -> None:  # noqa: ARG002
        """Accept and discard."""

    def on_attestation_timed(self, seconds: float) -> None:  # noqa: ARG002
        """Accept and discard."""


_observer: SpecObserver = _NullObserver()
"""
Process-wide observer singleton.

Starts as a discard-everything observer so spec imports stay side-effect-free.
The client swaps in its own observer at startup.
"""


def set_observer(observer: SpecObserver) -> None:
    """
    Register the global observer.

    Call once at client startup, after the metrics backend is ready.
    A later call replaces the previous observer.
    """
    global _observer
    _observer = observer


@contextmanager
def observe_state_transition() -> Iterator[None]:
    """
    Time the wrapped state transition and publish the elapsed duration.

    Spec code wraps the body of a state transition in this block instead
    of calling a stopwatch primitive directly.
    On clean exit the elapsed wall time is published through the observer.

    Semantics

    - The state-transition timing event fires only when the body returns normally.
    - If the body raises, no event is emitted and the exception propagates.

    Other-language ports

    This helper is Python sugar.
    The portable contract is the state-transition timing hook on the observer.
    Clients in other languages produce the same event through whatever
    scoped-timer idiom is natural in their language (RAII, defer, etc.).
    """
    start = time.perf_counter()
    yield
    _observer.state_transition_timed(time.perf_counter() - start)


@contextmanager
def observe_on_block() -> Iterator[None]:
    """
    Time the wrapped fork-choice block integration and publish the duration.

    Timing semantics match the state-transition timer.
    The event fires only on clean exit.
    An exception propagates without emitting an event.
    """
    start = time.perf_counter()
    yield
    _observer.on_block_timed(time.perf_counter() - start)


@contextmanager
def observe_on_attestation() -> Iterator[None]:
    """
    Time the wrapped gossip-attestation validation and publish the duration.

    Timing semantics match the state-transition timer.
    The event fires only on clean exit.
    An exception propagates without emitting an event.
    The caller still classifies the outcome as valid or invalid.
    That classification is a caller-side concern.
    """
    start = time.perf_counter()
    yield
    _observer.on_attestation_timed(time.perf_counter() - start)
