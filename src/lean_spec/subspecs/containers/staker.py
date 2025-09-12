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
    """
    Contains the state related to the Attester role.
    
    This role is responsible for providing economic security by voting on the
    validity of blocks. This field tracks all attestation-specific data.
    """

    includer_role: IncluderRole
    """
    Contains the state related to the Includer role.
    
    This role upholds censorship resistance by creating inclusion lists (ILs)
    that constrain block producers. This field tracks all inclusion-specific data.
    """

    proposer_role: ProposerRole
    """
    Contains the state related to the Execution Proposer role.
    
    This role focuses on performance by building and proposing valuable
    execution blocks, including transaction ordering and MEV extraction.
    """
