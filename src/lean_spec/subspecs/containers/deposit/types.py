"""Deposit-specific SSZ types for the Lean Ethereum consensus specification."""

from __future__ import annotations

from lean_spec.types import SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from .deposit import ValidatorDeposit


class ValidatorDeposits(SSZList[ValidatorDeposit]):
    """List of validator deposits included in a block."""

    ELEMENT_TYPE = ValidatorDeposit
    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
