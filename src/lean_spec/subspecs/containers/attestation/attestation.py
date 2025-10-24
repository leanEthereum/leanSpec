"""Attestation-related container definitions."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes4000, Container, Uint64

from ..checkpoint import Checkpoint
from .types import AggregatedSignatures, AggregationBits


class AttestationData(Container):
    """Attestation content describing the validator's observed chain view."""

    slot: Slot
    """The slot for which the attestation is made."""

    head: Checkpoint
    """The checkpoint representing the head block as observed by the validator."""

    target: Checkpoint
    """The checkpoint representing the target block as observed by the validator."""

    source: Checkpoint
    """The checkpoint representing the source block as observed by the validator."""


class Attestation(Container):
    """Validator specific attestation wrapping shared attestation data."""

    validator_id: Uint64
    """The index of the validator making the attestation."""

    data: AttestationData
    """The attestation data voted on by the validator."""


class SignedAttestation(Container):
    """Validator attestation bundled with its signature."""

    message: Attestation
    """The attestation message signed by the validator."""

    signature: Bytes4000
    """Signature aggregation produced by the leanVM (SNARKs in the future)."""


class AggregatedAttestations(Container):
    """Aggregated attestation consisting of participation bits and message."""

    aggregation_bits: AggregationBits
    """Bitfield indicating which validators participated in the aggregation."""

    data: AttestationData
    """Combined vote data similar to the beacon chain format.

    Multiple validator votes are aggregated here without the complexity of
    committee assignments.
    """


class SignedAggregatedAttestations(Container):
    """Aggregated attestation bundled with aggregated signatures."""

    message: AggregatedAttestations
    """Aggregated vote data."""

    signature: AggregatedSignatures
    """Aggregated vote plus its combined signature.

    Stores a naive list of validator signatures that mirrors the attestation
    order.

    TODO: this will be replaced by a SNARK in future devnets.
    """
