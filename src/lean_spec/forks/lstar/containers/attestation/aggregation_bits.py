"""Aggregation bits for tracking validator participation."""

from __future__ import annotations

from lean_spec.forks.lstar.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.types.bitfields import BaseBitlist


class AggregationBits(BaseBitlist):
    """
    Bitlist representing validator participation in an attestation or signature.

    A general-purpose bitfield for tracking which validators have participated
    in some collective action (attestation, signature aggregation, etc.).
    """

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def to_validator_indices(self) -> ValidatorIndices:
        """
        Extract all validator indices encoded in these aggregation bits.

        Returns:
            ValidatorIndices containing the indices, sorted in ascending order.

        Raises:
            AssertionError: If no bits are set.
        """
        # Extract indices where bit is set; fail if none found.
        indices = [ValidatorIndex(i) for i, bit in enumerate(self.data) if bool(bit)]
        if not indices:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        return ValidatorIndices(data=indices)
