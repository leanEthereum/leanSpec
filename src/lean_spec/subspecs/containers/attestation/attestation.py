"""
Attestation-related container definitions.

Attestations are how validators express their view of the chain.
Each attestation specifies:

- What the validator thinks is the chain head
- What is already justified (source)
- What should be justified next (target)

Attestations can be aggregated to save space, but the current specification
doesn't do this yet.
"""

from __future__ import annotations

from collections import defaultdict

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.types import Container, Uint64

from ...xmss.containers import Signature
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

    def data_root_bytes(self) -> bytes:
        """The root of the attestation data."""
        return bytes(hash_tree_root(self))


class Attestation(Container):
    """Validator specific attestation wrapping shared attestation data."""

    validator_id: Uint64
    """The index of the validator making the attestation."""

    data: AttestationData
    """The attestation data produced by the validator."""


class SignedAttestation(Container):
    """Validator attestation bundled with its signature."""

    validator_id: Uint64
    """The index of the validator making the attestation."""

    message: AttestationData
    """The attestation message signed by the validator."""

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

    def to_plain(self) -> list[Attestation]:
        """
        Expand this aggregated attestation into plain per-validator attestations.

        Returns:
            One `Attestation` per participating validator index, all sharing the same
            `AttestationData`.
        """
        validator_indices = self.aggregation_bits.to_validator_indices()
        return [
            Attestation(validator_id=validator_id, data=self.data)
            for validator_id in validator_indices
        ]

    @classmethod
    def aggregate_by_data(
        cls,
        attestations: list[Attestation],
    ) -> list[AggregatedAttestation]:
        """
        Aggregate plain per-validator attestations by their shared AttestationData.

        Args:
            attestations: Attestations to aggregate.

        Returns:
            One AggregatedAttestation per unique AttestationData, with aggregation
            bits set for all participating validators.
        """
        data_to_validator_ids: dict[AttestationData, list[Uint64]] = defaultdict(list)
        for attestation in attestations:
            data_to_validator_ids[attestation.data].append(attestation.validator_id)

        return [
            cls(
                aggregation_bits=AggregationBits.from_validator_indices(validator_ids),
                data=data,
            )
            for data, validator_ids in data_to_validator_ids.items()
        ]


class SignedAggregatedAttestation(Container):
    """Aggregated attestation bundled with aggregated signatures."""

    message: AggregatedAttestation
    """Aggregated attestation data."""

    signature: AggregatedSignatures
    """Aggregated attestation plus its combined signature.

    Stores a naive list of validator signatures that mirrors the attestation
    order.

    TODO:
    - signatures will be replaced by MegaBytes in next PR to include leanVM proof.
    - this will be replaced by a SNARK in future devnets.
    - this will be aggregated by aggregators in future devnets.
    """
