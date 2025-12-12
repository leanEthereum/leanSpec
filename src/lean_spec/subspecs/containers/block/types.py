"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ...xmss.containers import Signature as XmssSignature
from ..attestation import AggregatedAttestation


class AggregatedAttestations(SSZList):
    """List of aggregated attestations included in a block."""

    ELEMENT_TYPE = AggregatedAttestation
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class NaiveAggregatedSignatures(SSZList):
    """Aggregated signature list included alongside the block proposer's attestation."""

    ELEMENT_TYPE = XmssSignature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class AttestationSignatures(SSZList):
    """List of per-attestation naive signature lists aligned with block body attestations."""

    ELEMENT_TYPE = NaiveAggregatedSignatures
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
