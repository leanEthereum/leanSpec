"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import Attestation
from ..signature import Signature


class Attestations(SSZList):
    """List of validator attestations included in a block."""

    ELEMENT_TYPE = Attestation
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class BlockSignatures(SSZList):
    """Aggregated signature list included alongside the block."""

    ELEMENT_TYPE = Signature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
