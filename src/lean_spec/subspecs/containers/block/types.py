"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.subspecs.xmss.aggregation import MultisigAggregatedSignature
from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import AggregatedAttestation


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    ELEMENT_TYPE = AggregatedAttestation
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class AttestationSignatures(SSZList[MultisigAggregatedSignature]):
    """
    List of per-attestation aggregated signature proof blobs.

    Each entry corresponds to an aggregated attestation from the block body and contains
    the raw bytes of the leanVM signature aggregation proof.
    """

    ELEMENT_TYPE = MultisigAggregatedSignature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
