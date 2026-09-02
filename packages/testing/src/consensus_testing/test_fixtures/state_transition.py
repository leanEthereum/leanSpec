"""State transition test fixture format."""

from typing import ClassVar

from pydantic import Field, model_validator
from ssz import hash_tree_root

from consensus_testing.genesis import build_genesis_state
from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_types import AggregatedAttestationSpec, BlockSpec, StateExpectation
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
from lean_spec.spec.ssz_types import Bytes32


class StateTransitionFixture(BaseConsensusFixture):
    """Emitted vector for block processing through the state transition."""

    pre: State
    """Initial consensus state before processing."""

    blocks: list[Block]
    """Filled blocks processed through the spec."""

    post: StateExpectation | None = None
    """Authored post-state expectations, echoed for readability."""

    post_state_root: Bytes32 | None = None
    """Hash tree root of the full post-state, so two clients cannot pass with divergent state."""


class StateTransitionTest(BaseTestSpec):
    """
    Spec for block processing through the state transition.

    The state transition assumes signatures were verified upstream.
    """

    format_name: ClassVar[str] = "state_transition_test"
    description: ClassVar[str] = (
        "Tests block processing through state_transition() - covers operations, "
        "epochs, and finality"
    )

    pre: State = Field(default_factory=build_genesis_state)
    """Initial consensus state before processing, defaulting to genesis."""

    blocks: list[BlockSpec]
    """Block specifications, each a required slot plus optional field overrides."""

    post: StateExpectation | None = None
    """Expected state after processing all blocks, validating only the fields explicitly set."""

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

        Raises:
            AssertionError: If processing fails unexpectedly or validation fails.
        """
        actual_post_state: State | None = None
        exception_raised: Exception | None = None
        spec = LstarSpec()

        # Accumulate filled blocks even if a later block fails, so the vector keeps every attempt.
        filled_blocks: list[Block] = []
        block_registry: dict[str, Block] = {}
        try:
            state = self.pre

            for block_index, block_spec in enumerate(self.blocks):
                # A cached post-state, when returned, avoids a redundant transition below.
                block, cached_state = self._build_block_from_spec(
                    block_spec,
                    state,
                    block_registry,
                    is_final_block=block_index == len(self.blocks) - 1,
                )

                filled_blocks.append(block)

                # Register labeled blocks for parent and attestation target resolution.
                if block_spec.label is not None:
                    if block_spec.label in block_registry:
                        raise ValueError(
                            f"Duplicate label '{block_spec.label}' - "
                            f"labels must be unique within a test"
                        )
                    block_registry[block_spec.label] = block

                if cached_state is not None:
                    state = cached_state
                elif block_spec.skip_slot_processing and not block_spec.check_state_transition:
                    state = spec.process_block(state, block)
                else:
                    state = spec.state_transition(state, block=block)

            actual_post_state = state
        except SpecRejectionError as exception:
            exception_raised = exception

        self.assert_expected_outcome(exception_raised)
        rejection_reason = None
        if exception_raised is not None:
            # Emit the language-neutral reason clients assert against.
            rejection_reason = self.resolve_rejection_reason(exception_raised)

        # Authored expectations cover only some fields, so pin the full-state root too.
        # The root closes the divergence gap across every other field.
        post_state_root = None
        if actual_post_state is not None:
            post_state_root = hash_tree_root(actual_post_state)

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
        *,
        is_final_block: bool,
    ) -> tuple[Block, State | None]:
        """
        Build a block from its spec, optionally caching the post-state.

        Args:
            block_spec: Block specification with optional field overrides.
            state: Current state to build against.
            block_registry: Labeled blocks for parent and target resolution.
            is_final_block: Whether this is the last block of the test.

        Returns:
            Block and cached post-state, None when not computed.
        """
        fork = LstarSpec()
        proposer_index = block_spec.resolve_proposer_index(len(state.validators))

        # Advance slots unless the spec intentionally skips slot processing.
        slot_advanced_state: State | None = None
        if not block_spec.skip_slot_processing:
            slot_advanced_state = fork.process_slots(state, block_spec.slot)

        # Parent root defaults to the latest block header of the slot-advanced state.
        source_state = slot_advanced_state or state
        parent_root = block_spec.resolve_parent_root(
            block_registry,
            default_root=hash_tree_root(source_state.latest_block_header),
        )

        body = block_spec.body or BlockBody(attestations=AggregatedAttestations(data=[]))
        post_state: State | None = None

        # Path 1: explicit state root override, no transition.
        if block_spec.state_root is not None:
            block = Block(
                slot=block_spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=block_spec.state_root,
                body=body,
            )

        # Path 2: failing block of an invalid test, or skip-slot: placeholder root, no transition.
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

        # Forced attestations bypass the builder's filtering to reach the state transition.
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

            # The body changed, so re-run the transition for the correct post-state and root.
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
        # XMSS keys need precomputation up to the highest slot any attestation uses.
        max_slot = max(attestation_spec.slot for attestation_spec in attestation_specs)
        key_manager = XmssKeyManager.shared(max_slot=max_slot)
        payloads: dict[AttestationData, set[SingleMessageAggregate]] = {}

        for attestation_spec in attestation_specs:
            attestation_data = attestation_spec.build_attestation_data(
                block_registry, state.latest_justified
            )
            proof = key_manager.sign_and_aggregate(
                attestation_spec.validator_indices, attestation_data
            )
            payloads.setdefault(attestation_data, set()).add(proof)

        return payloads
