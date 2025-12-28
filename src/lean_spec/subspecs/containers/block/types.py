"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from collections import Counter, defaultdict

from lean_spec.subspecs.xmss.aggregation import MultisigAggregatedSignature
from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import AggregatedAttestation


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    ELEMENT_TYPE = AggregatedAttestation
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def validate_unique_participant(self) -> bool:
        """
        Validate that each duplicate aggregated attestation has a unique participant.

        Returns:
            True if each duplicate aggregated attestation has a unique participant.
        """
        groups = defaultdict(list)
        for att in self:
            groups[att.data.data_root_bytes()].append(att.aggregation_bits)

        for bits_list in groups.values():
            if len(bits_list) <= 1:
                continue

            # 1. Convert bitfields to sets of active indices
            sets = [{i for i, bit in enumerate(bits.data) if bit} for bits in bits_list]

            # 2. Count index occurrences across the entire group
            counts = Counter(idx for s in sets for idx in s)

            # 3. Verify EVERY attestation has ANY index that appears EXACTLY once
            if not all(any(counts[i] == 1 for i in s) for s in sets):
                return False

        return True


class AttestationSignatures(SSZList[MultisigAggregatedSignature]):
    """
    List of per-attestation aggregated signature proof blobs.

    Each entry corresponds to an aggregated attestation from the block body and contains
    the raw bytes of the leanVM signature aggregation proof.
    """

    ELEMENT_TYPE = MultisigAggregatedSignature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
