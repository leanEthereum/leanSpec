"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import SSZList

from ..vote import SignedVote


# Domain-specific list type for BlockBody
class Attestations(SSZList):
    """List of signed votes (attestations) included in a block."""

    ELEMENT_TYPE = SignedVote
    LIMIT = 4096  # VALIDATOR_REGISTRY_LIMIT
