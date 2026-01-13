"""Subnet helpers for networking.

Provides a small utility to compute a validator's attestation subnet id from
its validator index and number of committees.
"""
from __future__ import annotations

def compute_subnet_id(validator_index: int, num_committees: int) -> int:
    """Compute the attestation subnet id for a validator.

    Args:
        validator_index: Non-negative validator index (int).
        num_committees: Positive number of committees (int).

    Returns:
        An integer subnet id in 0..(num_committees-1).

    Raises:
        ValueError: If validator_index is negative or num_committees is not
            a positive integer.
    """
    if not isinstance(validator_index, int) or validator_index < 0:
        raise ValueError("validator_index must be a non-negative integer")
    if not isinstance(num_committees, int) or num_committees <= 0:
        raise ValueError("num_committees must be a positive integer")

    subnet_id = validator_index % num_committees
    return subnet_id
