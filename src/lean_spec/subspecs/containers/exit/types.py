"""Exit-specific SSZ types for the Lean Ethereum consensus specification."""

from __future__ import annotations

from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from .exit import ValidatorExit


class ValidatorExits(SSZList[ValidatorExit]):
    """List of validator exit requests included in a block."""

    ELEMENT_TYPE = ValidatorExit
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
