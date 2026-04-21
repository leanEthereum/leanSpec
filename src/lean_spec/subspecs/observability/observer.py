"""
SpecObserver Protocol and its module-level singleton.

Hook Points

The observer is called from spec code at a small set of well-defined points.
Each hook corresponds to a phenomenon whose measurement is intrinsic to the
function being observed, not to any particular caller.

Contract

Observers must not raise.
A hook fires during a consensus-critical code path.
Exceptions propagate and abort the operation.
Clients are expected to swallow internal errors in their observer
implementations (for example, a Prometheus backend outage).
"""

from __future__ import annotations

from typing import Protocol


class SpecObserver(Protocol):
    """
    Telemetry hooks invoked at spec-level event points.

    Return values are ignored.
    Every method is side-effect-only.
    """

    def state_transition_timed(self, seconds: float) -> None:
        """Report the wall time of a state transition."""


class NullObserver:
    """
    Default observer that discards every event.

    A single instance serves every unregistered consumer.
    No allocations per call.
    """

    def state_transition_timed(self, seconds: float) -> None:  # noqa: ARG002
        """Accept and discard."""


_observer: SpecObserver = NullObserver()
"""
Process-wide observer singleton.

Starts as a NullObserver so spec imports are side-effect-free.
Replaced by the client at startup via set_observer.
"""


def set_observer(observer: SpecObserver) -> None:
    """
    Register the global observer.

    Call once at client startup after any backend initialization
    (for example, after metrics.init in the Prometheus case).
    Repeat calls replace the previous observer.
    """
    global _observer
    _observer = observer


def get_observer() -> SpecObserver:
    """
    Return the currently registered observer.

    Spec code calls this to publish events.
    When no observer has been registered the returned value is a NullObserver.
    """
    return _observer
