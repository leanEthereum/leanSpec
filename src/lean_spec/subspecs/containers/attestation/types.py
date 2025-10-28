"""Attestation-related SSZ types for the Lean consensus specification."""

from lean_spec.types import SSZList
from lean_spec.types.bitfields import BaseBitlist

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..signature import Signature


class AggregationBits(BaseBitlist):
    """Bitlist representing validator participation in an attestation."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class AggregatedSignatures(SSZList):
    """Naive list of validator signatures used for aggregation placeholders."""

    ELEMENT_TYPE = Signature
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
