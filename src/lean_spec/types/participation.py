"""Validator participation"""

from typing import Final

from lean_spec.types.bitfields import BaseBitlist
from lean_spec.types.boolean import Boolean
from lean_spec.types.collections import SSZList
from lean_spec.types.uint import Uint64
from lean_spec.types.validator import ValidatorIndex

VALIDATOR_REGISTRY_LIMIT: Final = Uint64(2**12)
"""The maximum number of validators that can be in the registry."""


class AggregationBits(BaseBitlist):
    """Bitlist representing validator participation in an attestation or signature."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def to_validator_indices(self) -> "ValidatorIndices":
        """
        Extract all validator indices encoded in these aggregation bits.

        Returns:
            `ValidatorIndices` containing the indices, sorted in ascending order.

        Raises:
            `AssertionError`: If no bits are set.
        """
        # Extract indices where bit is set; fail if none found.
        indices = [ValidatorIndex(i) for i, bit in enumerate(self.data) if bit]
        if not indices:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        return ValidatorIndices(data=indices)


class ValidatorIndices(SSZList[ValidatorIndex]):
    """List of validator indices up to the registry limit."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def to_aggregation_bits(self) -> AggregationBits:
        """
        Convert to aggregation bits marking which validators are present.

        Returns:
            `AggregationBits` with the corresponding indices set to True.

        Raises:
            `AssertionError`: If no indices are provided.
            `AssertionError`: If any index is outside the supported LIMIT.
        """
        index_list = self.data

        # Require at least one validator for a valid aggregation.
        if not index_list:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        # Convert to a set of native ints.
        #
        # This combines int conversion and deduplication in a single O(N) pass.
        ids = {int(i) for i in index_list}

        # Validate bounds: max index must be within registry limit.
        if (max_id := max(ids)) >= AggregationBits.LIMIT:
            raise AssertionError("Validator index out of range for aggregation bits")

        # Build bit list:
        # - True at positions present in indices,
        # - False elsewhere.
        return AggregationBits(data=[Boolean(i in ids) for i in range(max_id + 1)])
