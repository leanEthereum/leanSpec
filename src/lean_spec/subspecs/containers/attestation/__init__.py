"""Attestation containers and related types for the Lean spec."""

from .attestation import (
    AggregatedAttestations,
    Attestation,
    AttestationData,
    SignedAggregatedAttestations,
    SignedAttestation,
    aggregated_attestation_to_plain,
    aggregation_bits_to_validator_index,
    attestation_to_aggregated,
)
from .types import AggregatedSignatures, AggregationBits

__all__ = [
    "AttestationData",
    "Attestation",
    "SignedAttestation",
    "SignedAggregatedAttestations",
    "AggregatedAttestations",
    "AggregatedSignatures",
    "AggregationBits",
    "aggregation_bits_to_validator_index",
    "aggregated_attestation_to_plain",
    "attestation_to_aggregated",
]
