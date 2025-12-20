"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import SSZList
from lean_spec.types.byte_arrays import LeanAggregatedSignature

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import AggregatedAttestation, AttestationData


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    ELEMENT_TYPE = AggregatedAttestation
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

    def has_duplicate_data(self) -> bool:
        """Check if any two attestations share the same AttestationData."""
        seen: set[AttestationData] = set()
        for attestation in self:
            if attestation.data in seen:
                return True
            seen.add(attestation.data)
        return False


class AttestationSignatures(SSZList[LeanAggregatedSignature]):
    """
    List of per-attestation aggregated signature proof blobs.

    Each entry corresponds to an aggregated attestation from the block body and contains
    the raw bytes of the leanVM XMSSAggregatedSignature proof produced by
    `xmss_aggregate_signatures`.
    """

    ELEMENT_TYPE = LeanAggregatedSignature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
