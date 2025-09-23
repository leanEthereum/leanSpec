"""State-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import Bytes32, SSZList
from lean_spec.types.bitfields import BitlistBase

# Maximum number of historical roots to keep
HISTORICAL_ROOTS_LIMIT = 262144


class HistoricalBlockHashes(SSZList):
    """List of historical block root hashes up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = HISTORICAL_ROOTS_LIMIT


class JustificationRoots(SSZList):
    """List of justified block roots up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = HISTORICAL_ROOTS_LIMIT


class JustifiedSlots(BitlistBase):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = HISTORICAL_ROOTS_LIMIT


class JustificationValidators(BitlistBase):
    """Bitlist for tracking validator justifications (262144^2 limit)."""

    LIMIT = HISTORICAL_ROOTS_LIMIT * HISTORICAL_ROOTS_LIMIT
