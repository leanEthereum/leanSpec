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


class ProposerAttestationData(Container):
    """Vote metadata included by the block proposer."""

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

    @property
    def data(self) -> ValidatorAttestation:
        """Expose the message for backwards compatibility with SignedVote."""
        return self.message


class Attestation(Container):
    """Aggregated attestation consisting of participation bits and message."""

    aggregation_bits: AggregationBits
    message: AttestationData


class SignedAttestation(Container):
    """Aggregated attestation bundled with aggregated signatures."""

    message: Attestation
    signature: AggregatedSignatures
