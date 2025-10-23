"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import Bytes4000, SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..vote import Attestation


class Attestations(SSZList):
    """List of validator attestations included in a block."""

    ELEMENT_TYPE = Attestation
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class BlockSignatures(SSZList):
    """Aggregated signature list included alongside the block."""

    ELEMENT_TYPE = Bytes4000
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
