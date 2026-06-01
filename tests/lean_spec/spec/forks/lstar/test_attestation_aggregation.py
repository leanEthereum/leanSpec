"""Tests for AggregatedAttestation structure."""

from lean_spec.spec.forks import (
    AggregationBits,
    Checkpoint,
    Slot,
    ValidatorIndex,
    ValidatorIndices,
)
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AttestationData,
)
from lean_spec.spec.ssz import Bytes32


class TestAggregatedAttestation:
    """Test aggregated attestation structure."""

    def test_aggregated_attestation_structure(self) -> None:
        """Test that aggregated attestation properly stores bits and data."""
        attestation_data = AttestationData(
            slot=Slot(5),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(4)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(3)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
        )

        bits = AggregationBits.from_indices([ValidatorIndex(2), ValidatorIndex(7)])
        aggregate = AggregatedAttestation(aggregation_bits=bits, data=attestation_data)

        # Verify we can extract validator indices
        indices = aggregate.aggregation_bits.to_validator_indices()
        assert set(indices) == {ValidatorIndex(2), ValidatorIndex(7)}
        assert aggregate.data == attestation_data

    def test_aggregated_attestation_with_many_validators(self) -> None:
        """Test aggregated attestation with many validators."""
        attestation_data = AttestationData(
            slot=Slot(10),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(9)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(8)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(7)),
        )

        validator_indices = ValidatorIndices(
            data=[ValidatorIndex(i) for i in [0, 5, 10, 15, 20, 25]]
        )
        bits = AggregationBits.from_indices(validator_indices)
        aggregate = AggregatedAttestation(aggregation_bits=bits, data=attestation_data)

        recovered = aggregate.aggregation_bits.to_validator_indices()
        assert recovered == validator_indices
