"""Subnet helpers for networking.

Provides a small utility to compute a validator's attestation subnet id from
its validator index and number of committees.
"""
from __future__ import annotations

from src.lean_spec.types import Uint64


def compute_subnet_id(validator_index: Uint64, num_committees: Uint64) -> Uint64:
    """Compute the attestation subnet id for a validator.

    Args:
        validator_index: Non-negative validator index .
        num_committees: Positive number of committees.

    Returns:
        An integer subnet id in 0..(num_committees-1).
    """
    subnet_id = validator_index % num_committees
    return subnet_id

def compute_subnet_size(subnet_id: Uint64, num_committees: Uint64, total_validators: Uint64) -> Uint64:
    """Compute the size of a given subnet.

    Args:
        subnet_id: The subnet id to compute the size for.
        num_committees: Positive number of committees.
        total_validators: Total number of validators.

    Returns:
        The size of the specified subnet.
    """
    base_size = total_validators // num_committees
    remainder = total_validators % num_committees
    if subnet_id < remainder:
        return base_size + 1
    else:
        return base_size