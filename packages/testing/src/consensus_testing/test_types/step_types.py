"""Step types for fork choice tests."""

from typing import Annotated, Any, Literal, Union

from pydantic import ConfigDict, Field, PrivateAttr, field_serializer

from lean_spec.subspecs.containers.attestation import (
    SignedAggregatedAttestation,
    SignedAttestation,
)
from lean_spec.subspecs.containers.block.block import Block
from lean_spec.types import CamelModel

from .block_spec import BlockSpec
from .gossip_aggregated_attestation_spec import GossipAggregatedAttestationSpec
from .gossip_attestation_spec import GossipAttestationSpec
from .store_checks import StoreChecks


class BaseForkChoiceStep(CamelModel):
    """
    Base class for fork choice event steps.

    All step types inherit from this base and include:
    - valid flag for expected success/failure
    - optional Store state checks to validate after processing
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    valid: bool = True
    """Whether this step is expected to succeed."""

    expected_error: str | None = None
    """
    Expected error message substring when valid=False.

    When set, the exception message must contain this string.
    When None and valid=False, any exception is accepted.
    Ignored when valid=True.
    """

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
    This triggers interval-based actions like attestation processing.
    """

    step_type: Literal["tick"] = "tick"
    """Discriminator field for serialization."""

    time: int
    """Time to advance to (unix timestamp)."""


class BlockStep(BaseForkChoiceStep):
    """
    Block processing step.

    Processes a block through the fork choice store.
    This updates the store's block tree and may trigger head updates.

    Input: BlockSpec (can be partial or fully specified).
    Output: Block object built and processed through the spec.
    """

    step_type: Literal["block"] = "block"
    """Discriminator field for serialization."""

    block: BlockSpec
    """
    Block specification for this step.

    Tests provide a BlockSpec with required slot and optional field overrides.
    The framework fills a complete Block during make_fixture() and stores it
    in the private _filled_block attribute for serialization.
    """

    # TODO: We should figure out a configuration to raise if a private attr is
    #  attempted to be set during model initialization.
    _filled_block: Block | None = PrivateAttr(default=None)
    """The filled Block, processed through the spec."""

    @field_serializer("block", when_used="json")
    def serialize_block(self, value: BlockSpec) -> dict[str, Any]:
        """
        Serialize the filled Block instead of the BlockSpec.

        This ensures the fixture output contains the complete Block that was
        filled from the spec, not the input BlockSpec.

        Parameters:
        ----------
        value : BlockSpec
            The BlockSpec field value (ignored, we use _filled_block instead).

        Returns:
        -------
        dict[str, Any]
            The serialized Block.

        Raises:
        ------
        ValueError
            If _filled_block is None (make_fixture not called yet).
        """
        if self._filled_block is None:
            raise ValueError(
                "Block not filled yet - make_fixture() must be called before serialization. "
                "This BlockStep should only be serialized after the fixture has been processed."
            )
        result = self._filled_block.to_json()
        if value.label:
            result["blockRootLabel"] = value.label
        return result


class AttestationStep(BaseForkChoiceStep):
    """
    Attestation processing step.

    Processes an attestation received from gossip.
    This updates validator attestation tracking in the store.

    Note: Attestations included in blocks are processed automatically
    when the block is processed. This step is for gossip attestations.
    """

    step_type: Literal["attestation"] = "attestation"
    """Discriminator field for serialization."""

    attestation: GossipAttestationSpec
    """
    Gossip attestation specification for this step.

    Tests provide a GossipAttestationSpec with required fields.
    The framework fills in the attestation data and signature during make_fixture().
    """

    is_aggregator: bool = False
    """
    Whether the node holds the aggregator role for this attestation.

    Only aggregator nodes store gossip signatures in the raw signature pool.
    Defaults to False so existing fillers preserve the behavior where gossip
    attestations are validated but not stored.
    """

    _filled_attestation: SignedAttestation | None = PrivateAttr(default=None)
    """The filled SignedAttestation, processed through the spec."""

    @field_serializer("attestation", when_used="json")
    def serialize_gossip_attestation(self, value: GossipAttestationSpec) -> dict[str, Any]:
        """
        Serialize the filled SignedAttestation instead of the spec.

        This ensures the fixture output contains the complete attestation that was
        filled from the spec, not the input specification.

        Parameters:
        ----------
        value : GossipAttestationSpec
            The spec field value (ignored, we use _filled_attestation instead).

        Returns:
        -------
        dict[str, Any]
            The serialized SignedAttestation.

        Raises:
        ------
        ValueError
            If _filled_attestation is None (make_fixture not called yet).
        """
        if self._filled_attestation is None:
            raise ValueError(
                "Attestation not filled yet - make_fixture() must be called "
                "before serialization. This AttestationStep should only be "
                "serialized after the fixture has been processed."
            )
        return self._filled_attestation.to_json()


class GossipAggregatedAttestationStep(BaseForkChoiceStep):
    """Aggregated attestation processing step."""

    step_type: Literal["gossipAggregatedAttestation"] = "gossipAggregatedAttestation"
    """Discriminator field for serialization."""

    attestation: GossipAggregatedAttestationSpec
    """
    Specification for the aggregated gossip attestation.
    """

    _filled_attestation: SignedAggregatedAttestation | None = PrivateAttr(default=None)

    @field_serializer("attestation", when_used="json")
    def serialize_gossip_aggregated_attestation(
        self, value: GossipAggregatedAttestationSpec
    ) -> dict[str, Any]:
        """Return the filled aggregated attestation for serialization."""
        if self._filled_attestation is None:
            raise ValueError(
                "Aggregated attestation not filled yet - make_fixture() must process the step."
            )
        return self._filled_attestation.to_json()


# Discriminated union type for all fork choice steps
ForkChoiceStep = Annotated[
    Union[TickStep, BlockStep, AttestationStep, GossipAggregatedAttestationStep],
    Field(discriminator="step_type"),
]
