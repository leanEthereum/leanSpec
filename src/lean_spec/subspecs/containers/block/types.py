"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ...xmss.containers import Signature
from ..attestation import AggregatedAttestation


class AggregatedAttestationList(SSZList):
    """List of aggregated attestations included in a block."""

    ELEMENT_TYPE = AggregatedAttestation
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class AttestationSignatures(SSZList):
    """Aggregated signature list included alongside the block proposer's attestation."""

    ELEMENT_TYPE = Signature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
