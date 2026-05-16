"""Tests for AggregationBits and ValidatorIndices conversions."""

import pytest

from lean_spec.types import (
    VALIDATOR_REGISTRY_LIMIT,
    AggregationBits,
    Boolean,
    ValidatorIndex,
    ValidatorIndices,
)


class TestAggregationBitsToValidatorIndices:
    """Convert an aggregation bitlist to the validator indices it encodes."""

    def test_reject_empty_aggregation_bits(self) -> None:
        """No bits set must raise."""
        bits = AggregationBits(data=[Boolean(False), Boolean(False), Boolean(False)])
        with pytest.raises(
            AssertionError,
            match="Aggregated attestation must reference at least one validator",
        ):
            bits.to_validator_indices()

    def test_single_bit_set(self) -> None:
        """One bit set yields a single-index list."""
        bits = AggregationBits(data=[Boolean(False), Boolean(True), Boolean(False)])
        assert bits.to_validator_indices() == ValidatorIndices(data=[ValidatorIndex(1)])

    def test_multiple_bits_set(self) -> None:
        """Multiple bits set yield indices in ascending order."""
        bits = AggregationBits(
            data=[Boolean(True), Boolean(False), Boolean(True), Boolean(True), Boolean(False)]
        )
        assert bits.to_validator_indices() == ValidatorIndices(
            data=[ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)]
        )


class TestValidatorIndicesToAggregationBits:
    """Convert a list of validator indices to an aggregation bitlist."""

    def test_reject_empty_indices(self) -> None:
        """An empty index list must raise."""
        indices = ValidatorIndices(data=[])
        with pytest.raises(
            AssertionError,
            match="Aggregated attestation must reference at least one validator",
        ):
            indices.to_aggregation_bits()

    def test_reject_index_at_limit(self) -> None:
        """An index equal to VALIDATOR_REGISTRY_LIMIT exceeds the bitfield range."""
        indices = ValidatorIndices(data=[ValidatorIndex(VALIDATOR_REGISTRY_LIMIT)])
        with pytest.raises(
            AssertionError, match="Validator index out of range for aggregation bits"
        ):
            indices.to_aggregation_bits()

    def test_reject_index_above_limit(self) -> None:
        """An index above VALIDATOR_REGISTRY_LIMIT exceeds the bitfield range."""
        indices = ValidatorIndices(data=[ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT) + 100)])
        with pytest.raises(
            AssertionError, match="Validator index out of range for aggregation bits"
        ):
            indices.to_aggregation_bits()

    def test_deduplicates_repeated_indices(self) -> None:
        """Repeated indices collapse to a single set bit per position."""
        indices = ValidatorIndices(
            data=[ValidatorIndex(1), ValidatorIndex(3), ValidatorIndex(1), ValidatorIndex(3)]
        )
        assert indices.to_aggregation_bits() == AggregationBits(
            data=[Boolean(False), Boolean(True), Boolean(False), Boolean(True)]
        )

    def test_handles_unsorted_input(self) -> None:
        """Unsorted indices produce a positionally correct bitfield."""
        indices = ValidatorIndices(data=[ValidatorIndex(5), ValidatorIndex(1), ValidatorIndex(3)])
        assert indices.to_aggregation_bits() == AggregationBits(
            data=[
                Boolean(False),
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(False),
                Boolean(True),
            ]
        )

    def test_length_matches_max_index(self) -> None:
        """Returned bitfield has length max_index + 1 — no trailing zeros."""
        indices = ValidatorIndices(data=[ValidatorIndex(3)])
        assert indices.to_aggregation_bits() == AggregationBits(
            data=[Boolean(False), Boolean(False), Boolean(False), Boolean(True)]
        )

    def test_roundtrip_through_aggregation_bits(self) -> None:
        """Indices to bits and back yields the original input."""
        original = ValidatorIndices(data=[ValidatorIndex(1), ValidatorIndex(5), ValidatorIndex(7)])
        assert original.to_aggregation_bits().to_validator_indices() == original
