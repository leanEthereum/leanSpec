"""
Validator service module for producing blocks and attestations.

Validators are the active participants in Ethereum consensus.
This module provides:

- A registry that manages validator secret keys for signing
- A service that drives duty execution based on the slot clock

Lifecycle:

1. Load validator keys from YAML configuration
2. Start the service to monitor slot intervals
3. At interval 0, produce blocks if scheduled
4. At interval 1, produce attestations for non-proposers
"""

from .registry import ValidatorRegistry
from .service import ValidatorService

__all__ = [
    "ValidatorService",
    "ValidatorRegistry",
]
