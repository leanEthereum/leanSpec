"""Attestation-related SSZ types for the Lean consensus specification."""

from __future__ import annotations

from lean_spec.types import SSZList, Uint64
from lean_spec.types.bitfields import BaseBitlist

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ...xmss.containers import Signature


class AggregationBits(BaseBitlist):
    """Bitlist representing validator participation in an attestation."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    @classmethod
    def from_validator_indices(cls, indices: list[Uint64]) -> AggregationBits:
        """
        Construct aggregation bits from a set of validator indices.

        Args:
            indices: Validator indices to set in the bitlist.

        Returns:
            AggregationBits with the corresponding indices set to True.

        Raises:
            AssertionError: If no indices are provided.
            AssertionError: If any index is outside the supported LIMIT.
        """
        ids = [int(i) for i in indices]
        if not ids:
            raise AssertionError("Aggregated attestation must reference at least one validator")

        max_id = max(ids)
        if max_id >= cls.LIMIT:
            raise AssertionError("Validator index out of range for aggregation bits")

        bits = [False] * (max_id + 1)
        for i in ids:
            bits[i] = True

        return cls(data=bits)

    def to_validator_indices(self) -> list[Uint64]:
        """
        Extract all validator indices encoded in these aggregation bits.

        Returns:
            List of validator indices, sorted in ascending order.

        Raises:
            AssertionError: If no bits are set.
        """
        if not (indices := [Uint64(i) for i, bit in enumerate(self.data) if bool(bit)]):
            raise AssertionError("Aggregated attestation must reference at least one validator")

        return indices


class NaiveAggregatedSignature(SSZList[Signature]):
    """Naive list of validator signatures used for aggregation placeholders."""

    ELEMENT_TYPE = Signature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
