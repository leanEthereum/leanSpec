"""Tests for block-specific SSZ types and validation methods."""

import pytest

from lean_spec.subspecs.containers.attestation import (
    AggregatedAttestation,
    AggregationBits,
    AttestationData,
)
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Boolean, Bytes32, Uint64


def make_attestation_data(slot: int) -> AttestationData:
    """Create deterministic attestation data for testing."""
    return AttestationData(
        slot=Slot(slot),
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(slot)),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(slot)),
        source=Checkpoint(root=Bytes32.zero(), slot=Slot(slot - 1)),
    )


def make_aggregation_bits(validator_indices: list[int]) -> AggregationBits:
    """Create aggregation bits from validator indices."""
    return AggregationBits.from_validator_indices([Uint64(i) for i in validator_indices])


class TestEachDuplicateAttestationHasUniqueParticipant:
    """Test the each_duplicate_attestation_has_unique_participant validation method."""

    def test_empty_attestations_list(self) -> None:
        """Empty attestations list should return True."""
        attestations = AggregatedAttestations(data=[])
        assert attestations.each_duplicate_attestation_has_unique_participant() is True

    def test_single_attestation(self) -> None:
        """Single attestation should return True (no duplicates)."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1]),
                    data=att_data,
                )
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is True

    def test_multiple_attestations_different_data(self) -> None:
        """Multiple attestations with different data should return True."""
        att_data1 = make_attestation_data(slot=1)
        att_data2 = make_attestation_data(slot=2)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1]),
                    data=att_data1,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1]),
                    data=att_data2,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is True

    def test_duplicates_with_all_unique_participants(self) -> None:
        """Duplicates where each has unique participant should return True."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1]),  # unique: 0
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([1, 2]),  # unique: 2
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is True

    def test_duplicates_with_completely_disjoint_participants(self) -> None:
        """Duplicates with completely disjoint participants should return True."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1]),
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([2, 3]),
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is True

    def test_duplicates_with_complete_overlap_fails(self) -> None:
        """Duplicates with complete overlap should return False."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1, 2]),
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1, 2]),
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is False

    def test_duplicates_where_one_has_no_unique_participant_fails(self) -> None:
        """Duplicates where one attestation has no unique participant should return False."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1, 2]),
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1]),  # no unique participant
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is False

    def test_three_duplicates_with_partial_overlap_and_unique_participants(self) -> None:
        """Three duplicates with partial overlap, each having unique participant."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1, 2]),  # unique: 0
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([1, 2, 3]),  # unique: 3
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([2, 4]),  # unique: 4
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is True

    def test_three_duplicates_where_one_has_no_unique_participant_fails(self) -> None:
        """Three duplicates where one has no unique participant should return False."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1, 2]),
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([1, 2, 3]),
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([1, 2]),  # no unique participant
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is False

    def test_single_validator_in_each_duplicate(self) -> None:
        """Duplicates where each has a single unique validator should return True."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0]),
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([1]),
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([2]),
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is True

    def test_multiple_attestation_data_groups_mixed_validity(self) -> None:
        """Multiple attestation data groups where one is valid, one is invalid."""
        att_data1 = make_attestation_data(slot=1)
        att_data2 = make_attestation_data(slot=2)
        attestations = AggregatedAttestations(
            data=[
                # Group 1: valid (each has unique participant)
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1]),  # unique: 0
                    data=att_data1,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([1, 2]),  # unique: 2
                    data=att_data1,
                ),
                # Group 2: invalid (second has no unique participant)
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([3, 4, 5]),
                    data=att_data2,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([3, 4]),  # no unique participant
                    data=att_data2,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is False

    def test_complex_overlap_pattern_with_unique_participants(self) -> None:
        """Complex overlap pattern where all attestations have unique participants."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1, 2, 3]),  # unique: 0
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([1, 2, 3, 4]),  # unique: 4
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([2, 3, 5]),  # unique: 5
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([3, 6]),  # unique: 6
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is True

    def test_subset_relationship_where_subset_has_no_unique_fails(self) -> None:
        """One attestation is a strict subset of another - subset has no unique participant."""
        att_data = make_attestation_data(slot=1)
        attestations = AggregatedAttestations(
            data=[
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([0, 1, 2, 3, 4]),
                    data=att_data,
                ),
                AggregatedAttestation(
                    aggregation_bits=make_aggregation_bits([1, 2, 3]),  # strict subset
                    data=att_data,
                ),
            ]
        )
        assert attestations.each_duplicate_attestation_has_unique_participant() is False
