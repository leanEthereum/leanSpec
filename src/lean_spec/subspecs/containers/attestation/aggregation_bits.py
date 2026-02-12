"""Aggregation bits for tracking validator participation."""

from __future__ import annotations

from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.types import Boolean
from lean_spec.types.bitfields import BaseBitlist


class AggregationBits(BaseBitlist):
    """
    Bitlist representing validator participation in an attestation or signature.

    A general-purpose bitfield for tracking which validators have participated
    in some collective action (attestation, signature aggregation, etc.).
    """

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    @classmethod
    def from_validator_indices(
        cls, indices: "ValidatorIndices | list[ValidatorIndex]"
    ) -> AggregationBits:
        """
        Construct aggregation bits from a set of validator indices.

        Args:
            indices: Validator indices to set in the bitlist. Accepts either
                a ValidatorIndices collection or a plain list of ValidatorIndex.

        Returns:
            AggregationBits with the corresponding indices set to True.

        Raises:
            AssertionError: If no indices are provided.
            AssertionError: If any index is outside the supported LIMIT.
        """
        # Extract list from ValidatorIndices if needed
        index_list = indices.data if isinstance(indices, ValidatorIndices) else indices

        # Require at least one validator for a valid aggregation.
        if not index_list:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        # Convert to a set of native ints.
        #
        # This combines int conversion and deduplication in a single O(N) pass.
        ids = {int(i) for i in index_list}

        # Validate bounds: max index must be within registry limit.
        if (max_id := max(ids)) >= cls.LIMIT:
            raise AssertionError("Validator index out of range for aggregation bits")

        # Build bit list:
        # - True at positions present in indices,
        # - False elsewhere.
        return cls(data=[Boolean(i in ids) for i in range(max_id + 1)])

    def to_validator_indices(self) -> "ValidatorIndices":
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
