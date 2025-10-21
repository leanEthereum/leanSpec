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


class ValidatorAttestation(Container):
    """Validator specific attestation wrapping shared attestation data."""

    validator_id: Uint64
    data: AttestationData

    @property
    def slot(self) -> Slot:
        """Return the attested slot."""
        return self.data.slot

    @property
    def head(self) -> Checkpoint:
        """Return the attested head checkpoint."""
        return self.data.head

    @property
    def target(self) -> Checkpoint:
        """Return the attested target checkpoint."""
        return self.data.target

    @property
    def source(self) -> Checkpoint:
        """Return the attested source checkpoint."""
        return self.data.source


class SignedValidatorAttestation(Container):
    """Validator attestation bundled with its signature."""

    message: ValidatorAttestation
    signature: Bytes4000
    """Signature produced by the lean signature VM.

    Unlike BLS, signatures over ValidatorAttestation messages that share the
    same underlying AttestationData can be aggregated efficiently by the lean
    signature VM.
    """

    @property
    def data(self) -> ValidatorAttestation:
        """Expose the message for backwards compatibility with SignedVote."""
        return self.message


class Attestation(Container):
    """Aggregated attestation consisting of participation bits and message."""

    aggregation_bits: AggregationBits
    data: AttestationData
    """Combined vote data similar to the beacon chain format.

    Multiple validator votes are aggregated here without the complexity of
    committee assignments. This structure is defined for future use and is not
    currently exercised by devnets.
    """


class SignedAttestation(Container):
    """Aggregated attestation bundled with aggregated signatures."""

    message: Attestation
    signature: AggregatedSignatures
    """Aggregated vote plus its combined signature.

    Stores a naive list of validator signatures that mirrors the attestation
    order; this will be replaced by a single zk-verified signature in later
    devnets. Lean signatures permit recursive aggregation even when individual
    ValidatorAttestation and Attestation messages differ, so long as their
    embedded AttestationData matches.
    """
