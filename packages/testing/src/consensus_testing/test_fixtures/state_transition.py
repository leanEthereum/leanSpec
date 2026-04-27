"""State transition test fixture format."""

from typing import Any, ClassVar

from pydantic import ConfigDict, PrivateAttr, field_serializer

from lean_spec.forks.lstar.containers.attestation import AggregatedAttestation, AttestationData
from lean_spec.forks.lstar.containers.block.block import Block, BlockBody
from lean_spec.forks.lstar.containers.block.types import AggregatedAttestations
from lean_spec.forks.lstar.containers.state import State
from lean_spec.forks.lstar.containers.validator import ValidatorIndices
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32

from ..keys import XmssKeyManager
from ..test_types import AggregatedAttestationSpec, BlockSpec, StateExpectation
from .base import BaseConsensusFixture


class StateTransitionTest(BaseConsensusFixture):
    """
    Test fixture for block processing through state_transition().

    This is the primary test type that covers:
    - Operations (attestations via blocks)
    - Slot advancement (empty slots)
    - Multi-block sequences
    - Justification and finalization
    - Invalid blocks

    Tests everything through the main state_transition() public API.

    Structure:
        pre: Initial consensus state
        blocks: Sequence of signed blocks to process
        post: Expected state after processing (None if invalid, filled by spec)
        expect_exception: Expected exception for invalid tests
    """

    format_name: ClassVar[str] = "state_transition_test"
    description: ClassVar[str] = (
        "Tests block processing through state_transition() - covers operations, "
        "epochs, and finality"
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)

    pre: State
    """The initial consensus state before processing."""

    blocks: list[BlockSpec]
    """
    Block specifications to process through the spec.

    Tests provide a list of BlockSpec objects with required slots and optional
    field overrides. The framework fills complete Block objects during
    make_fixture() and stores them in the private _filled_blocks attribute.
    """

    # TODO: We should figure out a configuration to raise if a private attr is
    #  attempted to be set during model initialization.
    _filled_blocks: list[Block] = PrivateAttr(default_factory=list)
    """
    The filled Blocks, processed through the specs.

    This is a private attribute not part of the model schema.

    Tests cannot set this.

    The framework populates it during make_fixture().
    """

    post: StateExpectation | None = None
    """
    Expected state after processing all blocks.

    Only fields explicitly set in the StateExpectation will be validated.
    If None, no post-state validation is performed (e.g., for invalid tests).
    """

    expect_exception_message: str | None = None
    """Expected exception message for invalid tests."""

    @field_serializer("blocks", when_used="json")
    def serialize_blocks(self, value: list[BlockSpec]) -> list[dict[str, Any]]:
        """
        Serialize filled blocks instead of the input specs.

        Ensures fixture output contains complete blocks, not partial specs.

        Args:
            value: The BlockSpec list (ignored; filled blocks are used instead).

        Returns:
            The serialized blocks.
        """
        del value
        return [block.to_json() for block in self._filled_blocks]

    def make_fixture(self) -> "StateTransitionTest":
        """
        Generate the fixture by running the spec.

        Returns:
            A validated fixture.

        Raises:
            AssertionError: If processing fails unexpectedly or validation fails.
        """
        actual_post_state: State | None = None
        exception_raised: Exception | None = None

        # Initialize filled_blocks list that will be populated as we process blocks
        filled_blocks: list[Block] = []
        block_registry: dict[str, Block] = {}
        try:
            state = self.pre

            for block_spec in self.blocks:
                # Build block and optionally get cached post-state to avoid redundant transitions
                block, cached_state = self._build_block_from_spec(block_spec, state, block_registry)

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
                elif getattr(block_spec, "skip_slot_processing", False):
                    state = state.process_block(block)
                else:
                    state = state.state_transition(
                        block=block,
                        valid_signatures=True,
                    )

            actual_post_state = state
        except (AssertionError, ValueError) as e:
            exception_raised = e
            # If we expect an exception, this is fine
            if self.expect_exception is None:
                # Unexpected failure
                raise AssertionError(f"Unexpected error processing blocks: {e}") from e
        finally:
            # Always store filled blocks for serialization, even if an exception occurred
            # This ensures the test fixture includes all blocks that were attempted
            self._filled_blocks = filled_blocks

        # Validate exception expectations
        if self.expect_exception is not None:
            if exception_raised is None:
                raise AssertionError(
                    f"Expected exception {self.expect_exception.__name__} but processing succeeded"
                )
            if not isinstance(exception_raised, self.expect_exception):
                raise AssertionError(
                    f"Expected {self.expect_exception.__name__} "
                    f"but got {type(exception_raised).__name__}: {exception_raised}"
                )
            if self.expect_exception_message is not None:
                if str(exception_raised) != self.expect_exception_message:
                    raise AssertionError(
                        f"Expected exception message '{self.expect_exception_message}' "
                        f"but got '{exception_raised}'"
                    )

        # Validate post-state expectations if provided
        if self.post is not None and actual_post_state is not None:
            self.post.validate_against_state(actual_post_state, block_registry=block_registry)

        # Return self (fixture is already complete)
        return self

    def _build_block_from_spec(
        self,
        spec: BlockSpec,
        state: State,
        block_registry: dict[str, Block],
    ) -> tuple[Block, State | None]:
        """
        Build a Block from a BlockSpec, optionally caching the post-state.

        Three construction paths:

        1. Explicit state_root -- caller controls the root, no transition
        2. Invalid or skip-slot -- placeholder zero root, no transition
        3. Normal -- full build_block with computed state root

        After construction, any forced attestations are appended to the
        body. These bypass the builder's filtering so they reach
        process_attestations directly (e.g., unjustified source tests).

        Args:
            spec: Block specification with optional field overrides.
            state: Current state to build against.
            block_registry: Labeled blocks for parent and target resolution.

        Returns:
            Block and cached post-state (None if not computed).
        """
        proposer_index = spec.resolve_proposer_index(len(state.validators))

        # Advance slots unless the spec intentionally skips slot processing.
        slot_advanced_state: State | None = None
        if not spec.skip_slot_processing:
            slot_advanced_state = state.process_slots(spec.slot)

        # Resolve the parent root.
        # Default: latest block header from the slot-advanced state.
        source_state = slot_advanced_state or state
        parent_root = spec.resolve_parent_root(
            block_registry,
            default_root=hash_tree_root(source_state.latest_block_header),
        )

        body = spec.body or BlockBody(attestations=AggregatedAttestations(data=[]))
        post_state: State | None = None

        # Path 1: explicit state root override -- no state transition needed.
        if spec.state_root is not None:
            block = Block(
                slot=spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=spec.state_root,
                body=body,
            )

        # Path 2: invalid test or skip-slot -- placeholder root, no transition.
        elif self.expect_exception is not None or spec.skip_slot_processing:
            block = Block(
                slot=spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=Bytes32.zero(),
                body=body,
            )

        # Path 3: normal block construction via the spec's builder.
        else:
            aggregated_payloads: dict[AttestationData, set[AggregatedSignatureProof]] = {}
            if spec.attestations:
                aggregated_payloads = StateTransitionTest._build_aggregated_payloads_from_spec(
                    spec.attestations, state, block_registry
                )

            known_block_roots = frozenset(hash_tree_root(b) for b in block_registry.values())

            block, post_state, _, _ = state.build_block(
                slot=spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                known_block_roots=known_block_roots,
                aggregated_payloads=aggregated_payloads,
            )

        # Append forced attestations if any.
        # These bypass the builder's filtering so they reach the state
        # transition even when the builder would exclude them.
        if spec.forced_attestations:
            forced = [
                AggregatedAttestation(
                    aggregation_bits=ValidatorIndices(data=fa.validator_ids).to_aggregation_bits(),
                    data=fa.build_attestation_data(block_registry, state),
                )
                for fa in spec.forced_attestations
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
                post_state = state.process_slots(spec.slot).process_block(block)
                block = block.model_copy(update={"state_root": hash_tree_root(post_state)})

        return block, post_state

    @staticmethod
    def _build_aggregated_payloads_from_spec(
        attestation_specs: list[AggregatedAttestationSpec],
        state: State,
        block_registry: dict[str, Block],
    ) -> dict[AttestationData, set[AggregatedSignatureProof]]:
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
        payloads: dict[AttestationData, set[AggregatedSignatureProof]] = {}

        for spec in attestation_specs:
            if not spec.valid_signature:
                raise NotImplementedError(
                    "valid_signature=False not yet supported in StateTransitionTest"
                )
            if spec.signer_ids is not None:
                raise NotImplementedError("signer_ids not yet supported in StateTransitionTest")

            attestation_data = spec.build_attestation_data(block_registry, state)
            proof = key_manager.sign_and_aggregate(spec.validator_ids, attestation_data)
            payloads.setdefault(attestation_data, set()).add(proof)

        return payloads
