"""Attestation-related container definitions."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes4000, Container, Uint64

from ..checkpoint import Checkpoint
from .types import AggregatedSignatures, AggregationBits


class AttestationData(Container):
    """Attestation content describing the validator's observed chain view."""

    slot: Slot
    head: Checkpoint
    target: Checkpoint
    source: Checkpoint


class Attestation(Container):
    """Validator specific attestation wrapping shared attestation data."""

    validator_id: Uint64
    data: AttestationData


class SignedAttestation(Container):
    """Validator attestation bundled with its signature."""

    message: Attestation
    signature: Bytes4000
    """Signature produced by the lean signature VM.

    Unlike BLS, signatures over ValidatorAttestation messages that share the
    same underlying AttestationData can be aggregated efficiently by the lean
    signature VM.
    """


class AggregatedAttestations(Container):
    """Aggregated attestation consisting of participation bits and message."""

    aggregation_bits: AggregationBits
    data: AttestationData
    """Combined vote data similar to the beacon chain format.

    Multiple validator votes are aggregated here without the complexity of
    committee assignments.
    """


class SignedAggregatedAttestations(Container):
    """Aggregated attestation bundled with aggregated signatures."""

    message: AggregatedAttestations
    signature: AggregatedSignatures
    """Aggregated vote plus its combined signature.

    Stores a naive list of validator signatures that mirrors the attestation
    order; this will be replaced by a single zk-verified signature in later
    devnets. Lean signatures permit recursive aggregation even when individual
    ValidatorAttestation and Attestation messages differ, so long as their
    embedded AttestationData matches.
    """
