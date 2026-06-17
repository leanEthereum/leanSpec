"""
Validator key management and duty execution.

Validators are the active participants in Ethereum consensus.
A registry holds the signing keys this node controls.
A service runs each validator's duties off the slot clock.
"""

from lean_spec.node.validator.registry import ValidatorRegistry
from lean_spec.node.validator.service import ValidatorService

__all__ = [
    "ValidatorService",
    "ValidatorRegistry",
]
