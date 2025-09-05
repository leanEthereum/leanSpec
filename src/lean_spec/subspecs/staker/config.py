"""This file defines the parameters used for the Staker and staking."""

from pydantic import BaseModel, ConfigDict
from typing_extensions import Final

from lean_spec.types import Uint64

DELEGATIONS_REGISTRY_LIMIT: Final = 2**12
"""The maximum number of delegations that can be stored in the state, per staker role."""


class _StakerConfig(BaseModel):
    """
    A model holding the canonical, immutable configuration constants
    for the Staker and staking.
    """

    # Configuration to make the model immutable.
    model_config = ConfigDict(frozen=True, extra="forbid")

    delegations_registry_limit: Uint64


# The Devnet Staker Configuration.
DEVNET_STAKER_CONFIG: Final = _StakerConfig(
    delegations_registry_limit=DELEGATIONS_REGISTRY_LIMIT,
)
