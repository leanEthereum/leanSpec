"""Attestation vote envelopes: signed, aggregated, and their list form."""

from lean_spec.spec.crypto.xmss.containers import Signature
from lean_spec.spec.forks.lstar.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.aggregation import SingleMessageAggregate
from lean_spec.spec.forks.lstar.containers.checkpoint import AttestationData
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.forks.lstar.containers.participation import AggregationBits
from lean_spec.spec.ssz import Container, SSZList


class Attestation(Container):
    """Validator specific attestation wrapping shared attestation data."""

    model_config = Container.model_config | {"frozen": True}

    validator_index: ValidatorIndex
    """The index of the validator making the attestation."""

    data: AttestationData
    """The attestation data produced by the validator."""


class SignedAttestation(Attestation):
    """Validator attestation bundled with its signature."""

    signature: Signature
    """Signature aggregation produced by the leanVM (SNARKs in the future)."""


class AggregatedAttestation(Container):
    """Aggregated attestation consisting of participation bits and message."""

    model_config = Container.model_config | {"frozen": True}

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

    model_config = Container.model_config | {"frozen": True}

    data: AttestationData
    """Combined attestation data similar to the beacon chain format."""

    proof: SingleMessageAggregate
    """Aggregated single-message proof covering all participating validators."""


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
