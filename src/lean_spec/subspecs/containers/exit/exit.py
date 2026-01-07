"""
Validator exit operation definitions.

Exits are how validators leave the network.
A ValidatorExit operation signals a validator's intent to leave.
The exit enters a queue and the validator is removed after a delay.
"""

from __future__ import annotations

from lean_spec.types import Container, Uint64

from ..slot import Slot


class ValidatorExit(Container):
    """
    Operation for a validator to request exit from the active set.

    Validators signal their intent to leave the network.
    The exit is added to a queue and the validator is removed after MIN_EXIT_DELAY slots.
    """

    validator_index: Uint64
    """The index of the validator requesting exit."""


class ExitRequest(Container):
    """
    A validator exit request in the queue.

    Tracks when the exit was requested.
    The validator is removed after MIN_EXIT_DELAY slots from exit_slot.
    """

    validator_index: Uint64
    """The index of the validator requesting exit."""

    exit_slot: Slot
    """The slot when the exit was requested."""
