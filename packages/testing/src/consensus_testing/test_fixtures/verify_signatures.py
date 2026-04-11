"""Signature test fixture format."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from lean_spec.subspecs.containers.block import (
    SignedBlock,
)
from lean_spec.subspecs.containers.state.state import State

from ..keys import XmssKeyManager
from ..test_types import BlockSpec
from .base import BaseConsensusFixture


class VerifySignaturesTest(BaseConsensusFixture):
    """
    Test fixture for verifying signatures on a signed block.

    Generates a complete signed block from the block specification,
    then verifies that signatures pass or fail as expected.
    """

    format_name: ClassVar[str] = "verify_signatures_test"
    description: ClassVar[str] = "Tests signature verification for signed blocks."

    anchor_state: State | None = None
    """
    The initial consensus state before processing.

    If not provided, the framework will use the genesis fixture.
    """

    block: BlockSpec = Field(exclude=True)
    """
    Block specifications to generate signatures for.

    This defines the block parameters including attestations. The framework will
    build a complete signed block with all necessary signatures.
    """

    signed_block: SignedBlock | None = None
    """
    The generated signed block.
    """

    def make_fixture(self) -> VerifySignaturesTest:
        """
        Generate the fixture by creating and verifying a signed block.

        Returns:
            The validated fixture.

        Raises:
            AssertionError: If signature verification fails unexpectedly.
        """
        # Ensure anchor_state is set
        assert self.anchor_state is not None, "anchor state must be set before making the fixture"

        # Use shared key manager
        key_manager = XmssKeyManager.shared()

        # Build the signed block
        signed_block = self.block.build_signed_block(self.anchor_state, key_manager)

        exception_raised: Exception | None = None

        # Verify signatures
        try:
            signed_block.verify_signatures(self.anchor_state.validators)
        except AssertionError as e:
            exception_raised = e
            # If we expect an exception, this is fine
            if self.expect_exception is None:
                # Unexpected failure
                raise AssertionError(f"Unexpected error verifying block signature(s): {e}") from e
        finally:
            # Always store filled block for serialization, even if an exception occurred
            # This ensures the test fixture contains the signed block that consumer can test with
            self.signed_block = signed_block

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

        return self
