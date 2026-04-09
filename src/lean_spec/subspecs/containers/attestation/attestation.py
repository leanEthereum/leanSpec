"""
Attestation-related container definitions.

Attestations are how validators express their view of the chain.
Each attestation specifies:

- What the validator thinks is the chain head
- What is already justified (source)
- What should be justified next (target)

Attestations can be aggregated by common data to save space and bandwidth.
"""

from __future__ import annotations

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Container

from ...xmss.aggregation import AggregatedSignatureProof
from ...xmss.containers import Signature
from ..checkpoint import Checkpoint
from .aggregation_bits import AggregationBits


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

    validator_id: ValidatorIndex
    """The index of the validator making the attestation."""

    data: AttestationData
    """The attestation data produced by the validator."""


class SignedAttestation(Attestation):
    """Validator attestation bundled with its signature."""

    signature: Signature
    """Signature aggregation produced by the leanVM (SNARKs in the future)."""


class AggregatedAttestation(Container):
    """Aggregated attestation consisting of participation bits and message."""

    aggregation_bits: AggregationBits
    """Bitfield indicating which validators participated in the aggregation."""

    data: AttestationData
    """Combined attestation data similar to the beacon chain format.

    Multiple validator attestations are aggregated here without the complexity of
    committee assignments.
    """


class SignedAggregatedAttestation(Container):
    """
    A signed aggregated attestation for broadcasting.

    Contains the attestation data and the aggregated signature proof.
    """

    data: AttestationData
    """Combined attestation data similar to the beacon chain format."""

    proof: AggregatedSignatureProof
    """Aggregated signature proof covering all participating validators."""
