"""
Vendor-neutral observability for the Lean specification.

Defines a single module-level observer that spec code publishes events to.
The default is a no-op. Clients register a real observer at startup to
forward events into Prometheus, logs, traces, or any other sink.

Keeping the observer vendor-neutral is what lets the spec stay free of
any metrics backend. The metrics subpackage provides a Prometheus-backed
implementation that clients wire in; other clients are free to supply
their own.
"""

from .observer import (
    NullObserver,
    SpecObserver,
    get_observer,
    observe_on_attestation,
    observe_on_block,
    observe_state_transition,
    set_observer,
)

__all__ = [
    "NullObserver",
    "SpecObserver",
    "get_observer",
    "observe_on_attestation",
    "observe_on_block",
    "observe_state_transition",
    "set_observer",
]
