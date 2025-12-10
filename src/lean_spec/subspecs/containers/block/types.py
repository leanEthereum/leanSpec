"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import AggregatedAttestations, SignedAggregatedAttestations
from ...xmss.containers import Signature


class AggregatedAttestationsList(SSZList):
    """List of aggregated attestations included in a block."""

    ELEMENT_TYPE = AggregatedAttestations
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

class AttestationSignatures(SSZList):
    """Aggregated signature list included alongside the block proposer's attestation."""

    ELEMENT_TYPE = Signature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)

