"""Smoke tests for the capability-requirement marker dispatch."""

from typing import ClassVar, Protocol, runtime_checkable

import pytest
from consensus_testing import StateExpectation, StateTransitionTestFiller, generate_pre_state
from framework import requires_capability

from lean_spec.forks import SigScheme
from lean_spec.types import Slot

pytestmark = pytest.mark.valid_until("Lstar")


@runtime_checkable
class _AbsentCapability(Protocol):
    """A capability no real fork advertises."""

    never_an_attribute_on_any_real_fork: ClassVar[object]


@requires_capability(SigScheme)
def test_runs_when_fork_advertises_sigscheme(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """Lstar advertises the signature-scheme capability — this test runs."""
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[],
        post=StateExpectation(slot=Slot(0)),
    )


@requires_capability(_AbsentCapability)
def test_deselected_when_capability_absent(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """No fork advertises the absent capability — this test must be deselected."""
    raise AssertionError("this test was executed — capability-requirement deselection is broken")
