"""State transition test fixture format."""

from typing import Any, ClassVar, List

from pydantic import ConfigDict, PrivateAttr, field_serializer

from lean_spec.subspecs.containers.attestation import Attestation
from lean_spec.subspecs.containers.block.block import Block, BlockBody
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64

from ..test_types import BlockSpec, StateExpectation
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

    blocks: List[BlockSpec]
    """
    Block specifications to process through the spec.

    Tests provide a list of BlockSpec objects with required slots and optional
    field overrides. The framework fills complete Block objects during
    make_fixture() and stores them in the private _filled_blocks attribute.
    """

    # TODO: We should figure out a configuration to raise if a private attr is
    #  attempted to be set during model initialization.
    _filled_blocks: List[Block] = PrivateAttr(default_factory=list)
    """
    The filled Blocks, processed through the specs.

    This is a private attribute not part of the model schema. Tests cannot set
    this. The framework populates it during make_fixture().
    """

    post: StateExpectation | None = None
    """
    Expected state after processing all blocks.

    Only fields explicitly set in the StateExpectation will be validated.
    If None, no post-state validation is performed (e.g., for invalid tests).
    """

    expect_exception: type[Exception] | None = None
    """Expected exception type for invalid tests."""

    expect_exception_message: str | None = None
    """Expected exception message for invalid tests."""

    @field_serializer("blocks", when_used="json")
    def serialize_blocks(self, value: List[BlockSpec]) -> List[dict[str, Any]]:
        """
        Serialize the filled `Block`s instead of the `BlockSpec`s.

        This ensures the fixture output contains the complete `Blocks` that were
        filled from the specs, not the input `BlockSpec`s.

        Parameters:
        ----------
        value : List[BlockSpec]
            The BlockSpec list (ignored, we use _filled_blocks instead).

        Returns:
        -------
        List[dict[str, Any]]
            The serialized Blocks.
        """
        del value
        return [block.to_json() for block in self._filled_blocks]

    @field_serializer("expect_exception", when_used="json")
    def serialize_exception(self, value: type[Exception] | None) -> str | None:
        """Serialize exception type to string."""
        if value is None:
            return None
        # Format: "ExceptionClassName" (just the class name for now)
        # TODO: This can be used to map exceptions to expected exceptions from clients
        #  as in execution-spec-tests - e.g., "StateTransitionException.INVALID_SLOT"
        return value.__name__

    def make_fixture(self) -> "StateTransitionTest":
        """
        Generate the fixture by running the spec.

        Builds blocks from BlockSpec if needed, then processes them through state_transition.

        Returns:
        -------
        StateTransitionTest
            A validated fixture.

        Raises:
        ------
        AssertionError
            If processing fails unexpectedly or validation fails.
        """
        actual_post_state: State | None = None
        exception_raised: Exception | None = None

        # Initialize filled_blocks list that will be populated as we process blocks
        filled_blocks: list[Block] = []
        try:
            state = self.pre

            for block_spec in self.blocks:
                # Build block and optionally get cached post-state to avoid redundant transitions
                block, cached_state = self._build_block_from_spec(block_spec, state)

                # Store the filled Block for serialization
                filled_blocks.append(block)

                # Process block through state transition
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
            self.post.validate_against_state(actual_post_state)

        # Return self (fixture is already complete)
        return self

    def _build_block_from_spec(self, spec: BlockSpec, state: State) -> tuple[Block, State | None]:
        """
        Build a Block from a BlockSpec, optionally caching the post-state.

        Uses provided fields from spec, computes any missing fields.
        This mimics what a local block builder would do.

        Returns both the block and the cached post-state (if computed) to avoid
        redundant state transitions.

        TODO: If the spec implements a State.produce_block() method in the
        future, we should use that instead of manually computing fields here.
        Until then, this manual approach is necessary.

        Parameters
        ----------
        spec : BlockSpec
            Block specification with optional field overrides.
        state : State
            Current state to build against.

        Returns:
        -------
        tuple[Block, State | None]
            Block and cached post-state (None if not computed).
        """
        # Use provided proposer index or compute it
        proposer_index = spec.proposer_index or Uint64(int(spec.slot) % len(state.validators))

        # Optionally advance a temporary state to the block's slot
        temp_state: State | None = None
        if not spec.skip_slot_processing:
            temp_state = state.process_slots(spec.slot)

        # Use provided parent_root or compute it
        if spec.parent_root is not None:
            parent_root = spec.parent_root
        else:
            source_state = temp_state if temp_state is not None else state
            parent_root = hash_tree_root(source_state.latest_block_header)

        # Extract attestations from body if provided
        aggregated_attestations = (
            spec.body.attestations if spec.body else AggregatedAttestations(data=[])
        )

        # Handle explicit state root override
        if spec.state_root is not None:
            block = Block(
                slot=spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=spec.state_root,
                body=spec.body or BlockBody(attestations=aggregated_attestations),
            )
            return block, None

        # Create temporary block with zero state root (will be computed)
        temp_block = Block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),
            body=spec.body or BlockBody(attestations=aggregated_attestations),
        )

        # If we are expecting an exception or skipping slot advancement,
        # return the partially-filled block without running the transition.
        if self.expect_exception is not None or spec.skip_slot_processing:
            return temp_block, None

        # Build the block using the state for standard case
        # Convert aggregated attestations to plain attestations to build block
        plain_attestations = [
            Attestation(validator_id=vid, data=agg.data)
            for agg in aggregated_attestations
            for vid in agg.aggregation_bits.to_validator_indices()
        ]

        # Use temp_state if available (already advanced to slot), otherwise use state
        build_state = temp_state if temp_state is not None else state
        block, post_state, _, _ = build_state.build_block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            attestations=plain_attestations,
        )
        return block, post_state
