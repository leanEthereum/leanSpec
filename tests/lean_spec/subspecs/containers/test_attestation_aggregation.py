"""Tests for attestation aggregation and signature ordering."""

import pytest

from lean_spec.subspecs.containers.attestation import (
    AggregatedAttestation,
    AggregationBits,
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, Uint64


class TestAttestationAggregation:
    """Test proper attestation aggregation by common data."""

    def test_reject_empty_aggregation_bits(self) -> None:
        """Validate aggregated attestation must include at least one validator."""
        bits = AggregationBits(data=[False, False, False])
        with pytest.raises(AssertionError, match="at least one validator"):
            bits.to_validator_indices()

    def test_aggregate_attestations_by_common_data(self) -> None:
        """Test that attestations with same data are properly aggregated."""
        # Create three attestations with two having common data
        att_data1 = AttestationData(
            slot=Slot(5),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(4)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
        )
        att_data2 = AttestationData(
            slot=Slot(6),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(5)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(4)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
        )

        attestations = [
            Attestation(validator_id=Uint64(1), data=att_data1),
            Attestation(validator_id=Uint64(3), data=att_data1),
            Attestation(validator_id=Uint64(5), data=att_data2),
        ]

        aggregated = AggregatedAttestation.aggregate_by_data(attestations)

        # Should have 2 aggregated attestations (one per unique data)
        assert len(aggregated) == 2

        # Find the aggregated attestation with att_data1
        agg1 = next(agg for agg in aggregated if agg.data == att_data1)
        validator_ids1 = agg1.aggregation_bits.to_validator_indices()

        # Should contain validators 1 and 3
        assert set(validator_ids1) == {Uint64(1), Uint64(3)}

        # Find the aggregated attestation with att_data2
        agg2 = next(agg for agg in aggregated if agg.data == att_data2)
        validator_ids2 = agg2.aggregation_bits.to_validator_indices()

        # Should contain only validator 5
        assert set(validator_ids2) == {Uint64(5)}

    def test_aggregate_attestations_sets_all_bits(self) -> None:
        """Test that aggregation sets all validator bits correctly."""
        att_data = AttestationData(
            slot=Slot(5),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(4)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
        )

        attestations = [
            Attestation(validator_id=Uint64(2), data=att_data),
            Attestation(validator_id=Uint64(7), data=att_data),
            Attestation(validator_id=Uint64(10), data=att_data),
        ]

        aggregated = AggregatedAttestation.aggregate_by_data(attestations)

        assert len(aggregated) == 1
        validator_ids = aggregated[0].aggregation_bits.to_validator_indices()

        # Should have all three validators
        assert len(validator_ids) == 3
        assert set(validator_ids) == {Uint64(2), Uint64(7), Uint64(10)}

    def test_aggregate_empty_attestations(self) -> None:
        """Test aggregation with no attestations."""
        aggregated = AggregatedAttestation.aggregate_by_data([])
        assert len(aggregated) == 0

    def test_aggregate_single_attestation(self) -> None:
        """Test aggregation with a single attestation."""
        att_data = AttestationData(
            slot=Slot(5),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(4)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
        )

        attestations = [Attestation(validator_id=Uint64(5), data=att_data)]

        aggregated = AggregatedAttestation.aggregate_by_data(attestations)

        assert len(aggregated) == 1
        validator_ids = aggregated[0].aggregation_bits.to_validator_indices()
        assert validator_ids == [Uint64(5)]


class TestDuplicateAttestationDataValidation:
    """Test validation that blocks don't contain duplicate AttestationData."""

    def test_duplicate_attestation_data_detection(self) -> None:
        """Ensure conversion to plain attestations preserves duplicates."""
        att_data = AttestationData(
            slot=Slot(1),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )

        from lean_spec.subspecs.containers.attestation import AggregatedAttestation
        from lean_spec.subspecs.containers.attestation.types import AggregationBits

        agg1 = AggregatedAttestation(
            aggregation_bits=AggregationBits(data=[False, True]),
            data=att_data,
        )
        agg2 = AggregatedAttestation(
            aggregation_bits=AggregationBits(data=[False, True, True]),
            data=att_data,
        )

        plain = [plain_att for aggregated in (agg1, agg2) for plain_att in aggregated.to_plain()]

        # Expect 2 plain attestations (because validator 1 is common in agg1 and agg2)
        # validator 1 and validator 2 are the only unique validators in the attestations
        assert len(set(plain)) == 2
        assert all(att.data == att_data for att in plain)
