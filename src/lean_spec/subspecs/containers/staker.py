"""Staker Container"""

from pydantic import Field
from typing_extensions import Annotated

from lean_spec.subspecs.staker import AttesterRole, IncluderRole, ProposerRole, StakerSettings
from lean_spec.types import StrictBaseModel


class Staker(StrictBaseModel):
    """The consensus staker object."""

    role_config: Annotated[
        list[StakerSettings],
        Field(min_length=3, max_length=3),
    ]
    """The list contains the settings for each of the roles the staker can activate."""

    attester_role: AttesterRole
    """Represents the state of the Attester Role."""

    includer_role: IncluderRole
    """Represents the state of the Includer Role."""

    proposer_role: ProposerRole
    """Represents the state of the Proposer Role."""
