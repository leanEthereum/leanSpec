"""Validator-related type definitions and utilities for the specification."""

from .uint import Uint64

ValidatorIndex = Uint64
"""A type alias for a validator's index in the registry."""


def is_proposer(validator_index: ValidatorIndex, slot: Uint64, num_validators: Uint64) -> bool:
    """
    Determine if a validator is the proposer for a given slot.

    Uses round-robin proposer selection based on slot number and total
    validator count, following the lean protocol specification.

    Args:
        validator_index: The validator's unique index.
        slot: The slot number to check proposer assignment for.
        num_validators: Total number of validators in the registry.

    Returns:
        True if the validator is the proposer for the slot, False otherwise.
    """
    return slot % num_validators == validator_index
