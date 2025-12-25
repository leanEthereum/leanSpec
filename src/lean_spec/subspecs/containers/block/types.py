"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from collections import Counter, defaultdict

from lean_spec.types import SSZList
from lean_spec.types.byte_arrays import LeanAggregatedSignature

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import AggregatedAttestation
from ..attestation.types import AggregationBits


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    ELEMENT_TYPE = AggregatedAttestation
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def each_duplicate_attestation_has_unique_participant(self) -> bool:
        """
        Check if each duplicate aggregated attestation has a unique participant.

        Returns:
            True if each duplicate aggregated attestation has a unique participant.
        """
        groups: dict[bytes, list[AggregationBits]] = defaultdict(list)

        for att in self:
            groups[att.data.data_root_bytes()].append(att.aggregation_bits)

        for bits_list in groups.values():
            if len(bits_list) <= 1:
                continue

            counts: Counter[int] = Counter()

            # Pass 1: count participants across the group
            for bits in bits_list:
                for i, bit in enumerate(bits.data):
                    if bit:
                        counts[i] += 1

            # Pass 2: each attestation must have a participant that appears exactly once
            for bits in bits_list:
                unique = False
                for i, bit in enumerate(bits.data):
                    if bit and counts[i] == 1:
                        unique = True
                        break
                if not unique:
                    return False

        return True


class AttestationSignatures(SSZList[LeanAggregatedSignature]):
    """
    List of per-attestation aggregated signature proof blobs.

    Each entry corresponds to an aggregated attestation from the block body and contains
    the raw bytes of the leanVM XMSSAggregatedSignature proof produced by
    `xmss_aggregate_signatures`.
    """

    ELEMENT_TYPE = LeanAggregatedSignature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
