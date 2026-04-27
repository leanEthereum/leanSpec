"""Signature test fixture format."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field

from lean_spec.forks.lstar.containers.attestation import AggregatedAttestation
from lean_spec.forks.lstar.containers.attestation.aggregation_bits import AggregationBits
from lean_spec.forks.lstar.containers.block import (
    SignedBlock,
)
from lean_spec.forks.lstar.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.forks.lstar.containers.state import State
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.types import Boolean

from ..keys import XmssKeyManager
from ..test_types import BlockSpec
from .base import BaseConsensusFixture


class VerifySignaturesTest(BaseConsensusFixture):
    """
    Test fixture for verifying signatures on a signed block.

    Generates a complete signed block from the block specification,
    then verifies that signatures pass or fail as expected.

    An optional `tamper` hook mutates the built signed block before
    verification runs. This is the only supported way to exercise
    signature-verification rejection paths that lie behind structural
    invariants the block builder normally upholds.
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

    tamper: dict[str, Any] | None = Field(default=None, exclude=True)
    """
    Optional post-build mutation applied before verification.

    Supported operations:

    - `{"operation": "drop_last_signature"}`: Remove the last entry
      from the block's attestation_signatures list. Produces a signed
      block whose signature-group count is one less than its
      attestation count.
    - `{"operation": "set_proposer_index", "value": int}`: Rewrite
      the block's proposer_index field. Use this to exercise the
      validator-bounds check that the builder skips because its round-
      robin selection stays within range by construction.
    - `{"operation": "clear_first_attestation_bits"}`: Replace the
      first body attestation with one whose aggregation_bits carry no
      set bit. Exercises the empty-participants check inside
      signature verification.

    Tampered blocks bypass the builder's structural invariants. The
    resulting fixture pins the exact rejection a client must raise when
    receiving such a block from a peer.
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

        # Apply optional post-build tamper before verification runs.
        # This is the only way to exercise rejection paths the builder would
        # otherwise prevent by construction.
        if self.tamper is not None:
            signed_block = self._apply_tamper(signed_block)

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

    def _apply_tamper(self, signed_block: SignedBlock) -> SignedBlock:
        """Apply the configured post-build mutation to a signed block.

        Args:
            signed_block: The validly built signed block.

        Returns:
            A new signed block with the requested mutation applied.

        Raises:
            ValueError: If the operation is unknown or cannot be applied.
        """
        assert self.tamper is not None
        operation = self.tamper.get("operation")

        if operation == "drop_last_signature":
            original = signed_block.signature.attestation_signatures.data
            if not original:
                raise ValueError("drop_last_signature requires at least one attestation signature")
            truncated = AttestationSignatures(data=list(original[:-1]))
            tampered_signatures = signed_block.signature.model_copy(
                update={"attestation_signatures": truncated}
            )
            return signed_block.model_copy(update={"signature": tampered_signatures})

        if operation == "set_proposer_index":
            value = self.tamper.get("value")
            if value is None:
                raise ValueError("set_proposer_index requires a value")
            tampered_block = signed_block.block.model_copy(
                update={"proposer_index": ValidatorIndex(int(value))}
            )
            return signed_block.model_copy(update={"block": tampered_block})

        if operation == "clear_first_attestation_bits":
            body = signed_block.block.body
            original = body.attestations.data
            if not original:
                raise ValueError("clear_first_attestation_bits requires at least one attestation")
            first = original[0]
            empty_bits = AggregationBits(data=[Boolean(False)] * len(first.aggregation_bits.data))
            cleared = AggregatedAttestation(aggregation_bits=empty_bits, data=first.data)
            new_attestations = AggregatedAttestations(data=[cleared, *original[1:]])
            new_body = body.model_copy(update={"attestations": new_attestations})
            new_block = signed_block.block.model_copy(update={"body": new_body})
            return signed_block.model_copy(update={"block": new_block})

        raise ValueError(f"Unknown tamper operation: {operation!r}")
