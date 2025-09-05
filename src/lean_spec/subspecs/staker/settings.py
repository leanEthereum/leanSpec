"""This defines the settings for a role a Staker can activate."""

from pydantic import BaseModel

from lean_spec.types import Bytes1, StakerIndex, Uint64


class StakerSettings(BaseModel):
    """Parameters for the StakerSettings."""

    role_identifier: Bytes1
    """The role for which these settings are applied."""

    active: bool
    """Determines if the role should be active or not."""

    delegated: bool
    """Determines if the role should be delegated or not."""

    target_staker: StakerIndex
    """Represents the index of a target staker that should receive the
    delegation."""

    delegatable: bool
    """Determines if the staker should accept delegations for this role."""

    fee_quotient: Uint64
    """Defines the quotient used to calculate the fees that the delegate
    owes to the staker."""
