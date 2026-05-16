"""Tests for AggregatedAttestation structure."""

from lean_spec.forks.lstar.containers.attestation import (
    AggregatedAttestation,
    AttestationData,
)
from lean_spec.types import (
    Bytes32,
    Checkpoint,
    Slot,
    ValidatorIndex,
    ValidatorIndices,
)


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
