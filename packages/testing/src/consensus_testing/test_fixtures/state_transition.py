"""State transition test fixture format."""

from typing import Any, ClassVar, List

from pydantic import ConfigDict, PrivateAttr, field_serializer

from lean_spec.subspecs.containers.block.block import Block, BlockBody
from lean_spec.subspecs.containers.block.types import Attestations
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, ValidatorIndex

from ..block_spec import BlockSpec
from ..test_types import StateExpectation
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

    This is a private attribute not part of the model schema. Tests cannot set this.
    The framework populates it during make_fixture().
    """

    post: StateExpectation | None = None
    """
    Expected state after processing all blocks.

    Only fields explicitly set in the StateExpectation will be validated.
    If None, no post-state validation is performed (e.g., for invalid tests).
    """

    expect_exception: type[Exception] | None = None
    """Expected exception type for invalid tests."""

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
        return [block.model_dump(mode="json") for block in self._filled_blocks]

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
                # Fill Block from BlockSpec
                block = self._build_block_from_spec(block_spec, state)

                # Store the filled Block for serialization
                filled_blocks.append(block)

                # Process block through state transition
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

        # Validate post-state expectations if provided
        if self.post is not None and actual_post_state is not None:
            self.post.validate_against_state(actual_post_state)

        # Return self (fixture is already complete)
        return self

    def _build_block_from_spec(self, spec: BlockSpec, state: State) -> Block:
        """
        Build a Block from a BlockSpec for state transition tests.

        Uses provided fields from spec, computes any missing fields.
        This mimics what a local block builder would do.

        TODO: If the spec implements a State.produce_block() method in the future,
        we should use that instead of manually computing fields here. Until then,
        this manual approach is necessary.

        Parameters
        ----------
        spec : BlockSpec
            The block specification with optional field overrides.
        state : State
            The current state to build against.

        Returns:
        -------
        Block
            A complete block ready for state_transition.
        """
        # Use provided proposer_index or compute it
        if spec.proposer_index is not None:
            proposer_index = spec.proposer_index
        else:
            proposer_index = ValidatorIndex(int(spec.slot) % int(state.validators.count))

        # Use provided parent_root or compute it
        if spec.parent_root is not None:
            parent_root = spec.parent_root
        else:
            temp_state = state.process_slots(spec.slot)
            parent_root = hash_tree_root(temp_state.latest_block_header)

        # Use provided body or create empty one
        if spec.body is not None:
            body = spec.body
        else:
            body = BlockBody(attestations=Attestations(data=[]))

        # Use provided state_root or compute it via dry-run
        if spec.state_root is not None:
            state_root = spec.state_root
        else:
            # Need to dry-run to compute state_root
            temp_state = state.process_slots(spec.slot)
            temp_block = Block(
                slot=spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=Bytes32.zero(),
                body=body,
            )
            post_state = temp_state.process_block(temp_block)
            state_root = hash_tree_root(post_state)

        # Create final block with all fields
        return Block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=state_root,
            body=body,
        )
