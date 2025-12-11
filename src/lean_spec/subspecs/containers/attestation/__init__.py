"""Attestation containers and related types for the Lean spec."""

from .attestation import (
    AggregatedAttestation,
    Attestation,
    AttestationData,
    SignedAggregatedAttestations,
    SignedAttestation,
    aggregate_attestations_by_data,
    aggregated_attestations_to_plain,
    aggregation_bits_to_validator_indices,
    attestation_to_aggregated,
)
from .types import AggregatedSignatures, AggregationBits

__all__ = [
    "AttestationData",
    "Attestation",
    "SignedAttestation",
    "SignedAggregatedAttestations",
    "AggregatedAttestation",
    "AggregatedSignatures",
    "AggregationBits",
    "aggregate_attestations_by_data",
    "aggregation_bits_to_validator_indices",
    "aggregated_attestations_to_plain",
    "attestation_to_aggregated",
]
