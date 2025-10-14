"""Vote-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import Bytes4000, SSZList
from lean_spec.types.bitfields import BaseBitlist

from ...chain.config import VALIDATOR_REGISTRY_LIMIT


class AggregationBits(BaseBitlist):
    """Bitlist representing validator participation in an attestation."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class AggregatedSignatures(SSZList):
    """Naive list of validator signatures used for aggregation placeholders."""

    ELEMENT_TYPE = Bytes4000
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
