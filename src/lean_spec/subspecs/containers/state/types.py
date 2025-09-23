"""State-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.types import Bytes32, SSZList
from lean_spec.types.bitfields import BitlistBase


# Domain-specific collection types for State
class HistoricalBlockHashes(SSZList):
    """List of historical block root hashes up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = 262144  # historical_roots_limit


class JustificationRoots(SSZList):
    """List of justified block roots up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = 262144  # historical_roots_limit


# Domain-specific bitfield types for State
class JustifiedSlots(BitlistBase):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = 262144  # historical_roots_limit


class JustificationValidators(BitlistBase):
    """Bitlist for tracking validator justifications (262144^2 limit)."""

    LIMIT = 262144 * 262144  # For flattened validator justifications
