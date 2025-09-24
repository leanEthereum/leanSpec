"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..vote import SignedVote


class Attestations(SSZList):
    """List of signed votes (attestations) included in a block."""

    ELEMENT_TYPE = SignedVote
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
