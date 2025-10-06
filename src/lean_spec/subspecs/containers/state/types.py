"""State-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.subspecs.chain.config import DEVNET_CONFIG
from lean_spec.types import Bytes32, SSZList, Validator
from lean_spec.types.bitfields import BaseBitlist


class HistoricalBlockHashes(SSZList):
    """List of historical block root hashes up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = DEVNET_CONFIG.historical_roots_limit.as_int()


class JustificationRoots(SSZList):
    """List of justified block roots up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = DEVNET_CONFIG.historical_roots_limit.as_int()


class JustifiedSlots(BaseBitlist):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = DEVNET_CONFIG.historical_roots_limit.as_int()


class JustificationValidators(BaseBitlist):
    """Bitlist for tracking validator justifications per historical root."""

    LIMIT = (
        DEVNET_CONFIG.historical_roots_limit.as_int()
        * DEVNET_CONFIG.validator_registry_limit.as_int()
    )

class Validators(SSZList):
    """List of validators up to validator registry limit."""

    ELEMENT_TYPE = Validator
    LIMIT = DEVNET_CONFIG.validator_registry_limit.as_int()
