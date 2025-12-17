"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import AggregatedAttestation, AttestationData, NaiveAggregatedSignature


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


class AttestationSignatures(SSZList[NaiveAggregatedSignature]):
    """List of per-attestation naive signature lists aligned with block body attestations."""

    ELEMENT_TYPE = NaiveAggregatedSignature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
