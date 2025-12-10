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

from collections import defaultdict

from lean_spec.subspecs.containers.slot import Slot
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


class AggregatedAttestations(Container):
    """Aggregated attestation consisting of participation bits and message."""

    aggregation_bits: AggregationBits
    """Bitfield indicating which validators participated in the aggregation."""

    data: AttestationData
    """Combined attestation data similar to the beacon chain format.

    Multiple validator attestations are aggregated here without the complexity of
    committee assignments.
    """


class SignedAggregatedAttestations(Container):
    """Aggregated attestation bundled with aggregated signatures."""

    message: AggregatedAttestations
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


def aggregation_bits_to_validator_indices(bits: AggregationBits) -> list[Uint64]:
    """
    Extract all validator indices encoded in aggregation bits.

    Returns the list of all validators who participated in the aggregation,
    sorted by validator index.

    Args:
        bits: Aggregation bitlist with participating validators.

    Returns:
        List of validator indices, sorted in ascending order.
    """
    validator_indices = [Uint64(index) for index, bit in enumerate(bits) if bool(bit)]
    if not validator_indices:
        raise AssertionError("Aggregated attestation must reference at least one validator")
    return validator_indices


def aggregated_attestations_to_plain(
    aggregated: AggregatedAttestations,
) -> list[Attestation]:
    """
    Convert aggregated attestation to a list of plain Attestation containers.

    Extracts all participating validator indices from the aggregation bits
    and creates individual Attestation objects for each validator.

    Args:
        aggregated: Aggregated attestation with one or more participating validators.

    Returns:
        List of plain attestations, one per participating validator.
    """
    validator_indices = aggregation_bits_to_validator_indices(aggregated.aggregation_bits)
    return [
        Attestation(validator_id=validator_id, data=aggregated.data)
        for validator_id in validator_indices
    ]


def attestation_to_aggregated(attestation: Attestation) -> AggregatedAttestations:
    """Convert a plain Attestation into the aggregated representation."""
    validator_index = int(attestation.validator_id)
    bits = [False] * (validator_index + 1)
    bits[validator_index] = True
    return AggregatedAttestations(
        aggregation_bits=AggregationBits(data=bits),
        data=attestation.data,
    )


def aggregate_attestations_by_data(
    attestations: list[Attestation],
) -> list[AggregatedAttestations]:
    """
    Aggregate attestations with common attestation data.

    Groups attestations by their AttestationData and creates one AggregatedAttestations
    per unique data, with all participating validator bits set.

    Args:
        attestations: List of attestations to aggregate.

    Returns:
        List of aggregated attestations with proper bit aggregation.
    """
    # Group validator IDs by attestation data (avoids intermediate objects)
    data_to_validator_ids: dict[AttestationData, list[int]] = defaultdict(list)

    for attestation in attestations:
        data_to_validator_ids[attestation.data].append(int(attestation.validator_id))

    # Create aggregated attestations with all relevant bits set
    result: list[AggregatedAttestations] = []

    for data, validator_ids in data_to_validator_ids.items():
        # Find the maximum validator index to determine bitlist size
        max_validator_id = max(validator_ids)

        # Create bitlist with all participating validators set to True
        bits = [False] * (max_validator_id + 1)
        for validator_id in validator_ids:
            bits[validator_id] = True

        result.append(
            AggregatedAttestations(
                aggregation_bits=AggregationBits(data=bits),
                data=data,
            )
        )

    return result
