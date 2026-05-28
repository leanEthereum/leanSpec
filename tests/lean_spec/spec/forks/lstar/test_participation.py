"""Tests for AggregationBits and ValidatorIndices conversions."""

import pytest

from lean_spec.spec.forks import (
    VALIDATOR_REGISTRY_LIMIT,
    AggregationBits,
    ValidatorIndex,
    ValidatorIndices,
)
from lean_spec.spec.ssz import Boolean


class TestAggregationBitsToValidatorIndices:
    """Convert an aggregation bitlist to the validator indices it encodes."""

    def test_reject_zero_length_bits(self) -> None:
        """A zero-length bitlist raises with the exact empty-aggregation message."""
        bits = AggregationBits(data=[])
        with pytest.raises(AssertionError) as exc_info:
            bits.to_validator_indices()
        assert str(exc_info.value) == "Aggregated attestation must reference at least one validator"

    def test_reject_all_false_bits(self) -> None:
        """A bitlist with no bits set raises with the exact empty-aggregation message."""
        bits = AggregationBits(data=[Boolean(False), Boolean(False), Boolean(False)])
        with pytest.raises(AssertionError) as exc_info:
            bits.to_validator_indices()
        assert str(exc_info.value) == "Aggregated attestation must reference at least one validator"

    def test_single_bit_set_at_position_zero(self) -> None:
        """Only bit 0 set yields the single index 0."""
        bits = AggregationBits(data=[Boolean(True)])
        assert bits.to_validator_indices() == ValidatorIndices(data=[ValidatorIndex(0)])

    def test_single_bit_set_in_middle(self) -> None:
        """One non-leading bit set yields a single-index list at that position."""
        bits = AggregationBits(data=[Boolean(False), Boolean(True), Boolean(False)])
        assert bits.to_validator_indices() == ValidatorIndices(data=[ValidatorIndex(1)])

    def test_single_bit_set_at_last_valid_position(self) -> None:
        """Bitlist of length LIMIT with only the final bit set yields index LIMIT - 1."""
        data = [Boolean(False)] * (int(VALIDATOR_REGISTRY_LIMIT) - 1) + [Boolean(True)]
        bits = AggregationBits(data=data)
        assert bits.to_validator_indices() == ValidatorIndices(
            data=[ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT) - 1)]
        )

    def test_all_bits_set_at_full_limit(self) -> None:
        """All LIMIT bits set yields every validator index from 0 to LIMIT - 1 inclusive."""
        bits = AggregationBits(data=[Boolean(True)] * int(VALIDATOR_REGISTRY_LIMIT))
        expected = ValidatorIndices(
            data=[ValidatorIndex(i) for i in range(int(VALIDATOR_REGISTRY_LIMIT))]
        )
        assert bits.to_validator_indices() == expected

    def test_multiple_bits_set_ascending(self) -> None:
        """Multiple bits set yield indices in ascending order."""
        bits = AggregationBits(
            data=[Boolean(True), Boolean(False), Boolean(True), Boolean(True), Boolean(False)]
        )
        assert bits.to_validator_indices() == ValidatorIndices(
            data=[ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)]
        )

    def test_two_bits_set_at_extremes(self) -> None:
        """Bits at positions 0 and LIMIT - 1 produce the two extreme indices in order."""
        data = (
            [Boolean(True)]
            + [Boolean(False)] * (int(VALIDATOR_REGISTRY_LIMIT) - 2)
            + [Boolean(True)]
        )
        bits = AggregationBits(data=data)
        assert bits.to_validator_indices() == ValidatorIndices(
            data=[ValidatorIndex(0), ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT) - 1)]
        )

    def test_alternating_even_positions(self) -> None:
        """Bits true at every even position from 0 to 10 yield exactly those indices."""
        data = [Boolean(i % 2 == 0) for i in range(11)]
        bits = AggregationBits(data=data)
        assert bits.to_validator_indices() == ValidatorIndices(
            data=[ValidatorIndex(i) for i in (0, 2, 4, 6, 8, 10)]
        )

    def test_trailing_false_bits_are_ignored(self) -> None:
        """Trailing false bits after the last set bit do not influence the index list."""
        data = [Boolean(False)] * 10
        data[2] = Boolean(True)
        bits = AggregationBits(data=data)
        assert bits.to_validator_indices() == ValidatorIndices(data=[ValidatorIndex(2)])


class TestValidatorIndicesToAggregationBits:
    """Convert a list of validator indices to an aggregation bitlist."""

    def test_reject_empty_indices(self) -> None:
        """An empty index list raises with the exact empty-aggregation message."""
        indices = ValidatorIndices(data=[])
        with pytest.raises(AssertionError) as exc_info:
            indices.to_aggregation_bits()
        assert str(exc_info.value) == "Aggregated attestation must reference at least one validator"

    def test_single_index_zero(self) -> None:
        """Single index 0 produces a one-bit bitlist with the only bit set."""
        indices = ValidatorIndices(data=[ValidatorIndex(0)])
        assert indices.to_aggregation_bits() == AggregationBits(data=[Boolean(True)])

    def test_single_index_at_last_valid_position(self) -> None:
        """Single index LIMIT - 1 produces a LIMIT-length bitlist with only the final bit true."""
        indices = ValidatorIndices(data=[ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT) - 1)])
        expected_data = [Boolean(False)] * (int(VALIDATOR_REGISTRY_LIMIT) - 1) + [Boolean(True)]
        assert indices.to_aggregation_bits() == AggregationBits(data=expected_data)

    def test_reject_index_at_limit(self) -> None:
        """An index equal to LIMIT exceeds the bitfield range and raises exact message."""
        indices = ValidatorIndices(data=[ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT))])
        with pytest.raises(AssertionError) as exc_info:
            indices.to_aggregation_bits()
        assert str(exc_info.value) == "Validator index out of range for aggregation bits"

    def test_reject_index_just_above_limit(self) -> None:
        """An index of LIMIT + 1 raises the exact out-of-range message."""
        indices = ValidatorIndices(data=[ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT) + 1)])
        with pytest.raises(AssertionError) as exc_info:
            indices.to_aggregation_bits()
        assert str(exc_info.value) == "Validator index out of range for aggregation bits"

    def test_reject_index_far_above_limit(self) -> None:
        """An index well above LIMIT raises the exact out-of-range message."""
        indices = ValidatorIndices(data=[ValidatorIndex(2**20)])
        with pytest.raises(AssertionError) as exc_info:
            indices.to_aggregation_bits()
        assert str(exc_info.value) == "Validator index out of range for aggregation bits"

    def test_one_bad_index_poisons_the_batch(self) -> None:
        """A mix of valid indices and one out-of-range index raises the out-of-range message."""
        indices = ValidatorIndices(
            data=[
                ValidatorIndex(0),
                ValidatorIndex(1),
                ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT)),
            ]
        )
        with pytest.raises(AssertionError) as exc_info:
            indices.to_aggregation_bits()
        assert str(exc_info.value) == "Validator index out of range for aggregation bits"

    def test_deduplicates_repeated_indices(self) -> None:
        """Repeated indices collapse to a single set bit per position."""
        indices = ValidatorIndices(
            data=[ValidatorIndex(1), ValidatorIndex(3), ValidatorIndex(1), ValidatorIndex(3)]
        )
        assert indices.to_aggregation_bits() == AggregationBits(
            data=[Boolean(False), Boolean(True), Boolean(False), Boolean(True)]
        )

    def test_all_duplicate_input(self) -> None:
        """An input of repeated index 5 yields a length-6 bitlist with only the final bit true."""
        indices = ValidatorIndices(data=[ValidatorIndex(5)] * 4)
        assert indices.to_aggregation_bits() == AggregationBits(
            data=[Boolean(False)] * 5 + [Boolean(True)]
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

    def test_unsorted_with_duplicates(self) -> None:
        """Unsorted input with duplicates yields a length-6 bitlist set at 1, 3, and 5."""
        indices = ValidatorIndices(
            data=[
                ValidatorIndex(5),
                ValidatorIndex(1),
                ValidatorIndex(3),
                ValidatorIndex(5),
                ValidatorIndex(1),
            ]
        )
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
        """Returned bitfield has length max_index + 1 with no trailing zeros."""
        indices = ValidatorIndices(data=[ValidatorIndex(3)])
        assert indices.to_aggregation_bits() == AggregationBits(
            data=[Boolean(False), Boolean(False), Boolean(False), Boolean(True)]
        )

    def test_dense_full_registry(self) -> None:
        """Every index from 0 to LIMIT - 1 yields a LIMIT-length all-true bitlist."""
        indices = ValidatorIndices(
            data=[ValidatorIndex(i) for i in range(int(VALIDATOR_REGISTRY_LIMIT))]
        )
        assert indices.to_aggregation_bits() == AggregationBits(
            data=[Boolean(True)] * int(VALIDATOR_REGISTRY_LIMIT)
        )

    def test_sparse_maximum(self) -> None:
        """Indices 0 and LIMIT - 1 yield a LIMIT-length bitlist with only those two bits set."""
        indices = ValidatorIndices(
            data=[ValidatorIndex(0), ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT) - 1)]
        )
        expected_data = (
            [Boolean(True)]
            + [Boolean(False)] * (int(VALIDATOR_REGISTRY_LIMIT) - 2)
            + [Boolean(True)]
        )
        assert indices.to_aggregation_bits() == AggregationBits(data=expected_data)


class TestRoundTrip:
    """Round-trip symmetry between AggregationBits and ValidatorIndices."""

    def test_roundtrip_indices_to_bits_to_indices(self) -> None:
        """Indices to bits and back yields the original input."""
        original = ValidatorIndices(data=[ValidatorIndex(1), ValidatorIndex(5), ValidatorIndex(7)])
        assert original.to_aggregation_bits().to_validator_indices() == original

    def test_roundtrip_bits_to_indices_to_bits_preserves_last_true(self) -> None:
        """Bits to indices and back is exact when the bitlist ends with a true bit."""
        original = AggregationBits(
            data=[
                Boolean(False),
                Boolean(True),
                Boolean(False),
                Boolean(True),
                Boolean(True),
                Boolean(False),
                Boolean(False),
                Boolean(True),
            ]
        )
        assert original.to_validator_indices().to_aggregation_bits() == original

    def test_roundtrip_bits_to_indices_to_bits_trims_trailing_false(self) -> None:
        """Round-trip trims trailing false bits because output is sized by max index plus one."""
        original = AggregationBits(
            data=[Boolean(False), Boolean(True), Boolean(False), Boolean(False)]
        )
        trimmed = AggregationBits(data=[Boolean(False), Boolean(True)])
        assert original.to_validator_indices().to_aggregation_bits() == trimmed

    def test_roundtrip_boundary_index(self) -> None:
        """Round-trip starting from the highest valid index preserves the input exactly."""
        original = ValidatorIndices(data=[ValidatorIndex(int(VALIDATOR_REGISTRY_LIMIT) - 1)])
        assert original.to_aggregation_bits().to_validator_indices() == original
