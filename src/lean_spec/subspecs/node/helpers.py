"""Helper functions for node operations."""

from lean_spec.subspecs.containers.validator import ValidatorIndex


def is_aggregator(
    validator_id: ValidatorIndex | None,
    node_is_aggregator: bool = False,
) -> bool:
    """
    Determine if a validator is an aggregator.

    A validator acts as an aggregator when:
    1. The validator is active (validator_id is not None)
    2. The node operator has enabled aggregator mode

    Args:
        validator_id: The index of the validator.
        node_is_aggregator: Whether the node is configured as an aggregator.

    Returns:
        True if the validator should perform aggregation, False otherwise.
    """
    if validator_id is None:
        return False
    return node_is_aggregator
