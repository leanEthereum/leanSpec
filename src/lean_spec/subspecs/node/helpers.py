"""
Helper functions for node operations.
"""

from lean_spec.subspecs.containers.validator import ValidatorIndex


def is_aggregator(validator_id: ValidatorIndex | None) -> bool:
    """
    Determine if a validator is an aggregator.

    Args:
        validator_id: The index of the validator.

    Returns:
        True if the validator is an aggregator, False otherwise.
    """
    if validator_id is None:
        return False
    return (
        False  # Placeholder implementation, in future should be defined by node operator settings
    )
