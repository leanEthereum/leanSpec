"""
Validator deposit operation definitions.

Deposits are how new validators join the network.
A ValidatorDeposit operation specifies a validator's XMSS public key.
The deposit enters a pending queue and activates after a delay.
"""

from __future__ import annotations

from lean_spec.types import Bytes52, Container

from ..slot import Slot


class ValidatorDeposit(Container):
    """
    Operation for registering a new validator.

    Validators submit their XMSS public key to join the network.
    The deposit is added to a pending queue and activates after MIN_ACTIVATION_DELAY slots.
    """

    pubkey: Bytes52
    """The XMSS public key for the new validator."""


class PendingDeposit(Container):
    """
    A validator deposit awaiting activation.

    Tracks when the deposit was included in a block.
    The deposit becomes active after MIN_ACTIVATION_DELAY slots from queued_slot.
    """

    pubkey: Bytes52
    """The XMSS public key for the validator."""

    queued_slot: Slot
    """The slot when this deposit was included in a block."""
