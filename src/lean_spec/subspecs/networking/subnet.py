"""Subnet helpers for networking.

Provides a small utility to compute a validator's attestation subnet id from
its validator index and number of committees.
"""

from __future__ import annotations

from lean_spec.types import Uint64


def compute_subnet_id(validator_index: Uint64, num_committees: Uint64) -> int:
    """Compute the attestation subnet id for a validator.

    Args:
        validator_index: Non-negative validator index .
        num_committees: Positive number of committees.

    Returns:
        An integer subnet id in 0..(num_committees-1).
    """
    subnet_id = validator_index % num_committees
    return subnet_id
