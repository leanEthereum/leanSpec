"""Attestation containers and related types for the Lean spec."""

from .attestation import (
    AggregatedAttestation,
    Attestation,
    AttestationData,
    SignedAggregatedAttestation,
    SignedAttestation,
)
from .types import AggregationBits, NaiveAggregatedSignature

__all__ = [
    "AttestationData",
    "Attestation",
    "SignedAttestation",
    "SignedAggregatedAttestation",
    "AggregatedAttestation",
    "NaiveAggregatedSignature",
    "AggregationBits",
]
