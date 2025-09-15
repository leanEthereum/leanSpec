"""
Staker Container

Lean Consensus participants are part of a unified pool of stakers, as described in this [3TS design proposal](https://ethresear.ch/t/three-tier-staking-3ts-unbundling-attesters-includers-and-execution-proposers/21648/1).

Each slot, the **Staker** chooses from three different available roles:
- Attester
- Includer
- (Execution) Proposer

Each staker explicitly opts into the role(s) that they wish to take as protocol participants.
One, two, or all three roles can be chosen, based on the stakers preferences and level of sophistication.
Mixing and matching multiple roles is possible, under certain constraints.

Each role can be delegated to a target staker and each role can be set as delegatable for other stakers to execute as operators.
The staker can update the staking configuration at any time.
"""

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
