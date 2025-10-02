"""Consensus chain test fixture format."""

from typing import ClassVar, List

from pydantic import field_serializer

from lean_spec.subspecs.containers.block.block import SignedBlock
from lean_spec.subspecs.containers.state.state import State

from .base import BaseConsensusFixture


class ConsensusChainTest(BaseConsensusFixture):
    """
    Unified test fixture for block processing through state_transition().

    This is the primary test type that covers:
    - Operations (attestations via blocks)
    - Slot advancement (empty slots)
    - Multi-block sequences
    - Justification and finalization
    - Invalid blocks

    Replaces separate operations/epoch_processing/rewards test types
    by testing everything through the main public API.

    Structure:
        pre: Initial consensus state
        blocks: Sequence of signed blocks to process
        post: Expected state after processing (None if invalid, filled by spec)
        scenario_tags: Tags for categorization
        expect_exception: Expected exception for invalid tests
    """

    format_name: ClassVar[str] = "consensus_chain_test"
    description: ClassVar[str] = (
        "Tests block processing through state_transition() - "
        "covers operations, epochs, and finality"
    )

    pre: State
    """The consensus state before processing."""

    blocks: List[SignedBlock]
    """The sequence of signed blocks to process in order."""

    post: State | None = None
    """
    Expected state after processing all blocks (filled by make_fixture).

    If None after filling, the chain is invalid and processing failed.
    """

    expect_exception: type[Exception] | None = None
    """Expected exception type for invalid tests."""

    @field_serializer("expect_exception", when_used="json")
    def serialize_exception(self, value: type[Exception] | None) -> str | None:
        """Serialize exception type to string."""
        if value is None:
            return None
        # Format: "ExceptionClassName" (just the class name for now)
        # TODO: This can be used to map exceptions to expected exceptions from clients
        #  as in execution-spec-tests - e.g., "StateTransitionException.INVALID_SLOT"
        return value.__name__

    def make_fixture(self) -> "ConsensusChainTest":
        """
        Generate the fixture by running the spec.

        Returns:
        -------
        ConsensusChainTest
            A filled fixture with post state populated.

        Raises:
        ------
        AssertionError
            If processing fails unexpectedly (when expect_exception is None).
        """
        post_state: State | None = None
        exception_raised: Exception | None = None

        try:
            state = self.pre
            for block in self.blocks:
                state = state.state_transition(
                    signed_block=block,
                    valid_signatures=True,  # Signatures must be valid
                )
            post_state = state
        except (AssertionError, ValueError) as e:
            exception_raised = e
            # If we expect an exception, this is fine
            if self.expect_exception is None:
                # Unexpected failure
                raise AssertionError(f"Unexpected error processing blocks: {e}") from e

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

        # Return filled fixture
        return self.model_copy(update={"post": post_state})
