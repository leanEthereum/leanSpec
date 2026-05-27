"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.types import SSZList

from ..attestation import AggregatedAttestation


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
