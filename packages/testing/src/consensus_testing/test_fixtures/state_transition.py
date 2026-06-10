"""State transition test fixture format."""

from typing import ClassVar

from pydantic import Field, model_validator

from consensus_testing.genesis import generate_pre_state
from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_types import AggregatedAttestationSpec, BlockSpec, StateExpectation
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import SpecRejectionError
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    SingleMessageAggregate,
    State,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32


class StateTransitionFixture(BaseConsensusFixture):
    """
    Emitted vector for block processing through state_transition().

    JSON output: pre, blocks, post, postStateRoot.
    """

    pre: State
    """The initial consensus state before processing."""

    blocks: list[Block]
    """The filled Blocks, processed through the spec."""

    post: StateExpectation | None = None
    """Authored post-state expectations, echoed for readability."""

    post_state_root: Bytes32 | None = None
    """
    Hash tree root of the full post-state.

    Populated whenever processing succeeds.
    Clients must reproduce this root exactly, so two clients cannot
    pass the same vector while holding divergent state.
    Stays None for invalid tests, which produce no post-state.
    """


class StateTransitionTest(BaseTestSpec):
    """
    Spec for block processing through state_transition().

    This is the primary test type that covers:
    - Operations (attestations via blocks)
    - Slot advancement (empty slots)
    - Multi-block sequences
    - Justification and finalization
    - Invalid blocks

    Tests everything through the main state_transition() public API.

    The state transition assumes signatures were verified upstream.
    Invalid-signature scenarios belong to the fork choice and signature
    verification formats, never to this one.
    """

    format_name: ClassVar[str] = "state_transition_test"
    description: ClassVar[str] = (
        "Tests block processing through state_transition() - covers operations, "
        "epochs, and finality"
    )

    pre: State = Field(default_factory=generate_pre_state)
    """
    The initial consensus state before processing.

    Defaults to the standard genesis state.
    Spell it out only when the test needs a non-default pre-state.
    """

    blocks: list[BlockSpec]
    """
    Block specifications to process through the spec.

    Tests provide a list of BlockSpec objects with required slots and optional
    field overrides. Generation fills complete Block objects and emits them.
    """

    post: StateExpectation | None = None
    """
    Expected state after processing all blocks.

    Only fields explicitly set in the StateExpectation will be validated.
    If None, no post-state validation is performed (e.g., for invalid tests).
    """

    @model_validator(mode="after")
    def validate_signatures_are_out_of_scope(self) -> "StateTransitionTest":
        """Reject signature-flavored attestation fields at construction."""
        for block_spec in self.blocks:
            for attestation_spec in block_spec.attestations or []:
                if (
                    not attestation_spec.valid_signature
                    or attestation_spec.signer_indices is not None
                ):
                    raise ValueError(
                        "state transition assumes signatures were verified upstream; "
                        "author invalid-signature scenarios through the fork choice "
                        "or signature verification formats"
                    )
        return self

    def generate(self) -> StateTransitionFixture:
        """
        Generate the fixture by running the spec.

        Returns:
            The emitted vector with filled blocks and post-state root.

        Raises:
            AssertionError: If processing fails unexpectedly or validation fails.
        """
        actual_post_state: State | None = None
        exception_raised: Exception | None = None
        spec = LstarSpec()

        # Filled blocks accumulate as we process, even if a later block fails.
        # This ensures the test fixture includes all blocks that were attempted.
        filled_blocks: list[Block] = []
        block_registry: dict[str, Block] = {}
        try:
            state = self.pre

            for block_index, block_spec in enumerate(self.blocks):
                # Build block and optionally get cached post-state to avoid redundant transitions
                block, cached_state = self._build_block_from_spec(
                    block_spec,
                    state,
                    block_registry,
                    is_final_block=block_index == len(self.blocks) - 1,
                )

                # Store the filled Block for serialization
                filled_blocks.append(block)

                # Register labeled blocks for parent and attestation target resolution
                if block_spec.label is not None:
                    if block_spec.label in block_registry:
                        raise ValueError(
                            f"Duplicate label '{block_spec.label}' - "
                            f"labels must be unique within a test"
                        )
                    block_registry[block_spec.label] = block

                # Use cached state if available, otherwise run state transition
                if cached_state is not None:
                    state = cached_state
                elif block_spec.skip_slot_processing:
                    state = spec.process_block(state, block)
                else:
                    state = spec.state_transition(state, block=block)

            actual_post_state = state
        except SpecRejectionError as exception:
            exception_raised = exception

        # Validate exception expectations
        self.assert_expected_outcome(exception_raised)
        rejection_reason = None
        if exception_raised is not None:
            # Emit the language-neutral reason clients assert against.
            rejection_reason = self.resolve_rejection_reason(exception_raised)

        # Pin the full post-state for clients.
        # Selective expectations below only cover authored fields.
        # The root covers every field, closing the divergence gap.
        post_state_root = None
        if actual_post_state is not None:
            post_state_root = hash_tree_root(actual_post_state)

        # Validate post-state expectations if provided
        if self.post is not None and actual_post_state is not None:
            self.post.validate_against_state(actual_post_state, block_registry=block_registry)

        return StateTransitionFixture(
            pre=self.pre,
            blocks=filled_blocks,
            post=self.post,
            post_state_root=post_state_root,
            rejection_reason=rejection_reason,
        )

    def _build_block_from_spec(
        self,
        block_spec: BlockSpec,
        state: State,
        block_registry: dict[str, Block],
        is_final_block: bool,
    ) -> tuple[Block, State | None]:
        """
        Build a Block from a BlockSpec, optionally caching the post-state.

        Three construction paths:

        1. Explicit state_root -- caller controls the root, no transition
        2. Final block of an invalid test, or skip-slot -- placeholder zero
           root, no transition. Earlier blocks of an invalid test build
           normally so processing reaches the block expected to fail.
        3. Normal -- full build_block with computed state root

        After construction, any forced attestations are appended to the
        body. These bypass the builder's filtering so they reach
        process_attestations directly (e.g., unjustified source tests).

        Args:
            block_spec: Block specification with optional field overrides.
            state: Current state to build against.
            block_registry: Labeled blocks for parent and target resolution.
            is_final_block: Whether this is the last block of the test.

        Returns:
            Block and cached post-state (None if not computed).
        """
        fork = LstarSpec()
        proposer_index = block_spec.resolve_proposer_index(len(state.validators))

        # Advance slots unless the spec intentionally skips slot processing.
        slot_advanced_state: State | None = None
        if not block_spec.skip_slot_processing:
            slot_advanced_state = fork.process_slots(state, block_spec.slot)

        # Resolve the parent root.
        # Default: latest block header from the slot-advanced state.
        source_state = slot_advanced_state or state
        parent_root = block_spec.resolve_parent_root(
            block_registry,
            default_root=hash_tree_root(source_state.latest_block_header),
        )

        body = block_spec.body or BlockBody(attestations=AggregatedAttestations(data=[]))
        post_state: State | None = None

        # Path 1: explicit state root override -- no state transition needed.
        if block_spec.state_root is not None:
            block = Block(
                slot=block_spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=block_spec.state_root,
                body=body,
            )

        # Path 2: failing block of an invalid test, or skip-slot --
        # placeholder root, no transition.
        elif (
            self.expected_rejection is not None and is_final_block
        ) or block_spec.skip_slot_processing:
            block = Block(
                slot=block_spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=Bytes32.zero(),
                body=body,
            )

        # Path 3: normal block construction via the spec's builder.
        else:
            aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = {}
            if block_spec.attestations:
                aggregated_payloads = StateTransitionTest._build_aggregated_payloads_from_spec(
                    block_spec.attestations, state, block_registry
                )

            known_block_roots = frozenset(
                hash_tree_root(block) for block in block_registry.values()
            )

            block, post_state, _, _ = fork.build_block(
                state,
                slot=block_spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                known_block_roots=known_block_roots,
                aggregated_payloads=aggregated_payloads,
            )

        # Append forced attestations if any.
        # These bypass the builder's filtering so they reach the state
        # transition even when the builder would exclude them.
        if block_spec.forced_attestations:
            forced = [
                AggregatedAttestation(
                    aggregation_bits=forced_attestation.resolve_aggregation_bits(),
                    data=forced_attestation.build_attestation_data(
                        block_registry, state.latest_justified
                    ),
                )
                for forced_attestation in block_spec.forced_attestations
            ]
            block = block.model_copy(
                update={
                    "body": block.body.model_copy(
                        update={
                            "attestations": AggregatedAttestations(
                                data=[*block.body.attestations.data, *forced]
                            )
                        }
                    )
                }
            )

            # The body changed, so re-run the transition to get the correct
            # post-state and state root.
            if post_state is not None:
                post_state = fork.process_slots(state, block_spec.slot)
                post_state = fork.process_block(post_state, block)
                block = block.model_copy(update={"state_root": hash_tree_root(post_state)})

        return block, post_state

    @staticmethod
    def _build_aggregated_payloads_from_spec(
        attestation_specs: list[AggregatedAttestationSpec],
        state: State,
        block_registry: dict[str, Block],
    ) -> dict[AttestationData, set[SingleMessageAggregate]]:
        """
        Build aggregated signature payloads from attestation specifications.

        Args:
            attestation_specs: Attestation specifications from the block spec.
            state: Current state for source checkpoint lookup.
            block_registry: Labels to blocks for resolving target roots.

        Returns:
            Aggregated payloads keyed by attestation data.
        """
        # Compute max slot across all attestation specs for XMSS key lifetime.
        # XMSS keys require precomputation up to the highest slot used.
        max_slot = max(spec.slot for spec in attestation_specs)
        key_manager = XmssKeyManager.shared(max_slot=max_slot)
        payloads: dict[AttestationData, set[SingleMessageAggregate]] = {}

        for spec in attestation_specs:
            attestation_data = spec.build_attestation_data(block_registry, state.latest_justified)
            proof = key_manager.sign_and_aggregate(spec.validator_indices, attestation_data)
            payloads.setdefault(attestation_data, set()).add(proof)

        return payloads
