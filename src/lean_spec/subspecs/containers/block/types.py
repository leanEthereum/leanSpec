"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from __future__ import annotations

from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import AggregatedAttestation


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class AttestationSignatures(SSZList[AggregatedSignatureProof]):
    """
    List of per-attestation aggregated signature proofs.

    Each entry corresponds to an aggregated attestation from the block body.

    It contains:
        - the participants bitfield,
        - proof bytes from leanVM signature aggregation.
    """

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
