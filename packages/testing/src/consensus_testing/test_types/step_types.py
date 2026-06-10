"""Step types for fork choice tests: author-facing inputs and emitted results."""

from typing import Annotated, Any, Literal

from pydantic import Field, field_serializer, model_validator

from consensus_testing.test_fixtures.base import ExpectedRejection
from consensus_testing.test_types.attestation_specs import (
    AggregatedAttestationSpec,
    GossipAttestationSpec,
)
from consensus_testing.test_types.block_spec import BlockSpec
from consensus_testing.test_types.store_checks import StoreChecks
from consensus_testing.test_types.store_snapshot import StoreSnapshot
from lean_spec.base import CamelModel
from lean_spec.spec.forks import RejectionReason
from lean_spec.spec.forks.lstar.containers import (
    Block,
    SignedAggregatedAttestation,
    SignedAttestation,
)


class BaseForkChoiceStep(CamelModel):
    """
    Base class for fork choice event steps.

    All step types inherit from this base and include:
    - valid flag for expected success/failure
    - optional Store state checks to validate after processing
    """

    model_config = CamelModel.model_config | {"frozen": True}

    valid: bool = True
    """Whether this step is expected to succeed."""

    expected_rejection: ExpectedRejection | None = None
    """
    Expected rejection when valid=False.

    The classified reason must match.
    The exception message must contain the optional substring.
    Never serialized: the emitted contract is the filled step's reason field.
    """

    checks: StoreChecks | None = None
    """
    Store state checks to validate after processing this step.

    If provided, the fixture will validate the Store state matches
    these checks after executing the step.
    Only fields that are explicitly set will be validated.
    """

    @model_validator(mode="after")
    def validate_rejection_is_declared(self) -> "BaseForkChoiceStep":
        """
        Require a declared rejection on every step expected to fail.

        Why: a vector saying only "reject this" lets a client reject
        for the wrong reason and still pass.
        """
        if not self.valid and self.expected_rejection is None:
            raise ValueError("steps with valid=False must declare their expected_rejection")
        return self


class TickStep(BaseForkChoiceStep):
    """
    Time advancement step.

    Advances the fork choice store time to a specific unix timestamp or
    exact interval count. This triggers interval-based actions like
    attestation processing.
    """

    step_type: Literal["tick"] = "tick"
    """Discriminator field for serialization."""

    time: int | None = None
    """Optional unix timestamp to advance to."""

    interval: int | None = None
    """Optional exact interval count to advance to."""

    has_proposal: bool = False
    """Whether interval 0 of the target slot should see a proposal."""

    @model_validator(mode="after")
    def validate_target(self) -> "TickStep":
        """Require exactly one time target representation."""
        if (self.time is None) == (self.interval is None):
            raise ValueError("TickStep requires exactly one of time or interval")
        return self


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
    Generation fills a complete Block and emits it in the filled step.
    """

    tick_to_slot: bool = True
    """
    Whether to advance the store clock to the block's slot before import.

    Default True matches a node whose clock reached the slot already.
    Set False to deliver the block while the store clock lags behind,
    pinning how clients treat a block ahead of their local time.
    """


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
    Generation fills in the attestation data and signature.
    """

    is_aggregator: bool = False
    """
    Whether the node holds the aggregator role for this attestation.

    Only aggregator nodes store gossip signatures in the raw signature pool.
    Defaults to False so existing fillers preserve the behavior where gossip
    attestations are validated but not stored.
    """


class GossipAggregatedAttestationStep(BaseForkChoiceStep):
    """Aggregated attestation processing step."""

    step_type: Literal["gossipAggregatedAttestation"] = "gossipAggregatedAttestation"
    """Discriminator field for serialization."""

    attestation: AggregatedAttestationSpec
    """
    Specification for the aggregated gossip attestation.
    """


# Discriminated union type for all fork choice steps
ForkChoiceStep = Annotated[
    TickStep | BlockStep | AttestationStep | GossipAggregatedAttestationStep,
    Field(discriminator="step_type"),
]


class BaseFilledStep(CamelModel):
    """
    Base class for emitted fork choice steps.

    Carries the authored flags plus the generation outputs every step shares.
    """

    model_config = CamelModel.model_config | {"frozen": True}

    valid: bool
    """Whether this step succeeded."""

    rejection_reason: RejectionReason | None = None
    """
    Language-neutral reason this step's input must be rejected.

    Filled during generation for invalid steps.
    This is the field clients assert against.
    """

    checks: StoreChecks | None = None
    """Store state checks the step was validated against."""

    store_snapshot: StoreSnapshot
    """
    Canonical store observables after this step.

    Populated for every step, including rejected ones.
    A rejected input leaves the store unchanged, and the snapshot
    pins that no-op so a client cannot corrupt state on rejection.
    """


class FilledTickStep(BaseFilledStep):
    """Emitted time advancement step."""

    step_type: Literal["tick"] = "tick"
    """Discriminator field for serialization."""

    time: int | None = None
    """Optional unix timestamp advanced to."""

    interval: int | None = None
    """Optional exact interval count advanced to."""

    has_proposal: bool
    """Whether interval 0 of the target slot saw a proposal."""


class FilledBlockStep(BaseFilledStep):
    """Emitted block processing step carrying the complete built block."""

    step_type: Literal["block"] = "block"
    """Discriminator field for serialization."""

    tick_to_slot: bool
    """Whether the store clock advanced to the block's slot before import."""

    block: Block
    """The filled Block, processed through the spec."""

    block_root_label: str | None = Field(default=None, exclude=True)
    """Authored label for this block, merged into the block payload."""

    @field_serializer("block", when_used="json")
    def serialize_block(self, filled_block: Block) -> dict[str, Any]:
        """
        Serialize the block, merging the authored label into its payload.

        The label rides inside the block object so consumers can resolve
        fork references without a side table.
        """
        serialized_block = filled_block.to_json()
        if self.block_root_label:
            serialized_block["blockRootLabel"] = self.block_root_label
        return serialized_block


class FilledAttestationStep(BaseFilledStep):
    """Emitted gossip attestation step carrying the signed attestation."""

    step_type: Literal["attestation"] = "attestation"
    """Discriminator field for serialization."""

    attestation: SignedAttestation
    """The filled SignedAttestation, processed through the spec."""

    is_aggregator: bool
    """Whether the node held the aggregator role for this attestation."""


class FilledGossipAggregatedAttestationStep(BaseFilledStep):
    """Emitted aggregated attestation step carrying the signed aggregate."""

    step_type: Literal["gossipAggregatedAttestation"] = "gossipAggregatedAttestation"
    """Discriminator field for serialization."""

    attestation: SignedAggregatedAttestation
    """The filled SignedAggregatedAttestation, processed through the spec."""


# Discriminated union type for all emitted fork choice steps
FilledForkChoiceStep = Annotated[
    FilledTickStep
    | FilledBlockStep
    | FilledAttestationStep
    | FilledGossipAggregatedAttestationStep,
    Field(discriminator="step_type"),
]
