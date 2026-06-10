"""Validator participation bitfields over the registry index space."""

from collections.abc import Iterable

from lean_spec.spec.forks.lstar.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex, ValidatorIndices
from lean_spec.spec.forks.lstar.errors import RejectionReason, SpecRejectionError
from lean_spec.spec.ssz import Boolean
from lean_spec.spec.ssz.bitfields import BaseBitlist


class AggregationBits(BaseBitlist):
    """Bitlist representing validator participation in an attestation or signature."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    @classmethod
    def from_indices(cls, indices: Iterable[ValidatorIndex]) -> "AggregationBits":
        """
        Build aggregation bits from validator indices.

        Returns:
            Aggregation bits with exactly the given indices set to True.

        Raises:
            SpecRejectionError: EMPTY_AGGREGATION_BITS if no indices are provided.
            SpecRejectionError: VALIDATOR_INDEX_OUT_OF_RANGE if an index exceeds the limit.
        """
        # Convert to native ints once for bounds checking and membership tests.
        #
        # This also deduplicates and lets any iterable be passed in.
        ids = {int(i) for i in indices}

        # Require at least one validator for a valid aggregation.
        if not ids:
            raise SpecRejectionError(
                RejectionReason.EMPTY_AGGREGATION_BITS,
                "Aggregated attestation must reference at least one validator",
            )

        # Validate bounds: max index must be within registry limit.
        if (max_id := max(ids)) >= cls.LIMIT:
            raise SpecRejectionError(
                RejectionReason.VALIDATOR_INDEX_OUT_OF_RANGE,
                "Validator index out of range for aggregation bits",
            )

        # Build bit list:
        # - True at positions present in indices,
        # - False elsewhere.
        return cls(data=[Boolean(i in ids) for i in range(max_id + 1)])

    def to_validator_indices(self) -> ValidatorIndices:
        """
        Extract all validator indices encoded in these aggregation bits.

        Returns:
            ValidatorIndices containing the indices, sorted in ascending order.

        Raises:
            SpecRejectionError: EMPTY_AGGREGATION_BITS if no bits are set.
        """
        # Extract indices where bit is set; fail if none found.
        indices = [ValidatorIndex(i) for i, bit in enumerate(self.data) if bit]
        if not indices:
            raise SpecRejectionError(
                RejectionReason.EMPTY_AGGREGATION_BITS,
                "Aggregated attestation must reference at least one validator",
            )

        return ValidatorIndices(data=indices)
