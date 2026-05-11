"""Smoke tests for the @requires(capability) marker dispatch.

These exercise the marker through the live pytest collection and
parametrization plumbing (rather than the dispatch helper in isolation).

Two tests live here:

- One marked `@requires(SigScheme)` — Lstar satisfies SigScheme, so this
  test runs and asserts a trivial state-transition fixture.
- One marked `@requires(_AbsentCapability)` — a Protocol no fork can
  satisfy, so this test must be deselected by the framework. If it ever
  executes, it fails loudly.

The second test is the actual proof: a successful `uv run fill` with
this file present means the framework deselected it correctly.

Marker placement note
---------------------
Real consensus fillers pin themselves to a fork at the module level via
`pytestmark = pytest.mark.valid_until("Lstar")` (67 files do this).
That's the convention for new fillers.

This file uses per-function decorators only because each test needs a
*different* capability — one requires `SigScheme`, the other requires
`_AbsentCapability`. A module-level `pytestmark` would apply the same
marker to both. The decorator form is the right tool when individual
tests within a module advertise different capability requirements.
"""

from typing import ClassVar, Protocol, runtime_checkable

import pytest
from consensus_testing import StateExpectation, StateTransitionTestFiller, generate_pre_state
from framework import requires

from lean_spec.forks import SigScheme
from lean_spec.types import Slot

pytestmark = pytest.mark.valid_until("Lstar")


@runtime_checkable
class _AbsentCapability(Protocol):
    """A capability no real fork advertises (its required attribute is bogus)."""

    never_an_attribute_on_any_real_fork: ClassVar[object]


@requires(SigScheme)
def test_runs_when_fork_advertises_sigscheme(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """Lstar advertises SigScheme; this test must run."""
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[],
        post=StateExpectation(slot=Slot(0)),
    )


@requires(_AbsentCapability)
def test_deselected_when_capability_absent(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """No fork advertises _AbsentCapability; this test must be deselected."""
    raise AssertionError(
        "test_deselected_when_capability_absent was executed — @requires deselection is broken."
    )
