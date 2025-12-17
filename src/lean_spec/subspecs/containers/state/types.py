"""State-specific SSZ types for the Lean Ethereum consensus specification."""

from lean_spec.subspecs.chain.config import DEVNET_CONFIG
from lean_spec.types import Bytes32, SSZList
from lean_spec.types.bitfields import BaseBitlist

from ..validator import Validator


class HistoricalBlockHashes(SSZList[Bytes32]):
    """List of historical block root hashes up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)


class JustificationRoots(SSZList[Bytes32]):
    """List of justified block roots up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)


class JustifiedSlots(BaseBitlist):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)


class JustificationValidators(BaseBitlist):
    """Bitlist for tracking validator justifications per historical root."""

    LIMIT = int(DEVNET_CONFIG.historical_roots_limit) * int(DEVNET_CONFIG.validator_registry_limit)


class Validators(SSZList[Validator]):
    """Validator registry tracked in the state."""

    ELEMENT_TYPE = Validator
    LIMIT = int(DEVNET_CONFIG.validator_registry_limit)
