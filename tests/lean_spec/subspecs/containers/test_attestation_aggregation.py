"""Tests for attestation aggregation and signature ordering."""

import pytest

from lean_spec.forks.lstar.containers.attestation import (
    AggregatedAttestation,
    AggregationBits,
    AttestationData,
)
from lean_spec.forks.lstar.containers.checkpoint import Checkpoint
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.types import Boolean, Bytes32


class TestAggregationBits:
    """Test aggregation bits functionality."""

    def test_reject_empty_aggregation_bits(self) -> None:
        """Validate aggregated attestation must include at least one validator."""
        bits = AggregationBits(data=[Boolean(False), Boolean(False), Boolean(False)])
        with pytest.raises(AssertionError, match="at least one validator"):
            bits.to_validator_indices()

    def test_to_validator_indices_single_bit(self) -> None:
        """Test conversion with a single bit set."""
        bits = AggregationBits(data=[Boolean(False), Boolean(True), Boolean(False)])
        indices = bits.to_validator_indices()
        assert indices == ValidatorIndices(data=[ValidatorIndex(1)])

    def test_to_validator_indices_multiple_bits(self) -> None:
        """Test conversion with multiple bits set."""
        bits = AggregationBits(
            data=[Boolean(True), Boolean(False), Boolean(True), Boolean(True), Boolean(False)]
        )
        indices = bits.to_validator_indices()
        assert indices == ValidatorIndices(
            data=[ValidatorIndex(0), ValidatorIndex(2), ValidatorIndex(3)]
        )

    def test_to_aggregation_bits_roundtrip(self) -> None:
        """Test that to_aggregation_bits and to_validator_indices are inverses."""
        original_indices = ValidatorIndices(
            data=[ValidatorIndex(1), ValidatorIndex(5), ValidatorIndex(7)]
        )
        bits = original_indices.to_aggregation_bits()
        recovered_indices = bits.to_validator_indices()
        assert recovered_indices == original_indices


class TestAggregatedAttestation:
    """Test aggregated attestation structure."""

    def test_aggregated_attestation_structure(self) -> None:
        """Test that aggregated attestation properly stores bits and data."""
        att_data = AttestationData(
            slot=Slot(5),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(4)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
        )

        bits = ValidatorIndices(data=[ValidatorIndex(2), ValidatorIndex(7)]).to_aggregation_bits()
        agg = AggregatedAttestation(aggregation_bits=bits, data=att_data)

        # Verify we can extract validator indices
        indices = agg.aggregation_bits.to_validator_indices()
        assert set(indices) == {ValidatorIndex(2), ValidatorIndex(7)}
        assert agg.data == att_data

    def test_aggregated_attestation_with_many_validators(self) -> None:
        """Test aggregated attestation with many validators."""
        att_data = AttestationData(
            slot=Slot(10),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(9)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(8)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(7)),
        )

        validator_ids = ValidatorIndices(data=[ValidatorIndex(i) for i in [0, 5, 10, 15, 20, 25]])
        bits = validator_ids.to_aggregation_bits()
        agg = AggregatedAttestation(aggregation_bits=bits, data=att_data)

        recovered = agg.aggregation_bits.to_validator_indices()
        assert recovered == validator_ids
