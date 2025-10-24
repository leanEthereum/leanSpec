"""Step types for fork choice tests."""

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field

from lean_spec.subspecs.containers.block import SignedBlock
from lean_spec.subspecs.containers.vote import SignedVote

from .store_checks import StoreChecks


class BaseForkChoiceStep(BaseModel):
    """
    Base class for fork choice event steps.

    All step types inherit from this base and include:
    - valid flag for expected success/failure
    - optional Store state checks to validate after processing
    """

    valid: bool = True
    """Whether this step is expected to succeed."""

    checks: StoreChecks | None = None
    """
    Store state checks to validate after processing this step.

    If provided, the fixture will validate the Store state matches
    these checks after executing the step.
    Only fields that are explicitly set will be validated.
    """


class TickStep(BaseForkChoiceStep):
    """
    Time advancement step.

    Advances the fork choice store time to a specific unix timestamp.
    This triggers interval-based actions like vote processing.
    """

    step_type: Literal["tick"] = "tick"
    """Discriminator field for serialization."""

    time: int
    """Time to advance to (unix timestamp)."""


class BlockStep(BaseForkChoiceStep):
    """
    Block processing step.

    Processes a signed block through the fork choice store.
    This updates the store's block tree and may trigger head updates.
    """

    step_type: Literal["block"] = "block"
    """Discriminator field for serialization."""

    block: SignedBlock
    """Signed block to process."""


class AttestationStep(BaseForkChoiceStep):
    """
    Attestation processing step.

    Processes an attestation (signed vote) received from gossip.
    This updates validator vote tracking in the store.

    Note: Attestations included in blocks are processed automatically
    when the block is processed. This step is for gossip attestations.
    """

    step_type: Literal["attestation"] = "attestation"
    """Discriminator field for serialization."""

    attestation: SignedVote
    """Attestation (SignedVote) to process from gossip."""


# Discriminated union type for all fork choice steps
ForkChoiceStep = Annotated[
    Union[TickStep, BlockStep, AttestationStep],
    Field(discriminator="step_type"),
]
