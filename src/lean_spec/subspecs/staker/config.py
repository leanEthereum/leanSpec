"""This file defines the parameters used for the Staker and staking."""

from typing_extensions import Final
from lean_spec.types import StrictBaseModel, Uint64

DELEGATIONS_REGISTRY_LIMIT: Uint64 = Uint64(2**12)
"""The maximum number of delegations that can be stored in the state, per staker role."""


class _StakerConfig(StrictBaseModel):
    """
    A model holding the canonical, immutable configuration constants
    for the Staker and staking.
    """

    delegations_registry_limit: Uint64


DEVNET_STAKER_CONFIG: Final = _StakerConfig(
    delegations_registry_limit=DELEGATIONS_REGISTRY_LIMIT,
)
"""The Devnet Staker Configuration."""
