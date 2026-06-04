"""Signature test fixture format."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field

from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture
from consensus_testing.test_types import BlockSpec
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import AggregationBits, Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    MultiMessageAggregate,
    SignedBlock,
    State,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Boolean, ByteList512KiB, Bytes32


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

    - `{"operation": "set_proposer_index", "value": int}`: Rewrite
      the block's proposer_index field. Use this to exercise the
      validator-bounds check that the builder skips because its round-
      robin selection stays within range by construction.
    - `{"operation": "clear_first_attestation_bits"}`: Replace the
      first body attestation with one whose aggregation_bits carry no
      set bit. Exercises the empty-participants check inside
      signature verification.
    - `{"operation": "corrupt_proof"}`: Replace the merged proof with
      a short non-decodable blob. Exercises the multi-message aggregate decode check.
    - `{"operation": "append_phantom_attestation"}`: Add a body
      attestation with no matching proof component. Exercises the
      component count check between the body and the merged proof.
    - `{"operation": "mutate_state_root"}`: Change a block field after
      signing so the block root differs. Exercises the per-component
      message binding that prevents reusing an honest proof under a
      different message.
    - `{"operation": "swap_first_two_attestations"}`: Swap the first
      two body attestations and re-sign only the proposer. Exercises
      body/proof ordering without relying on a block-root mismatch.

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
            LstarSpec().verify_signatures(signed_block, self.anchor_state.validators)
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

        if operation == "set_proposer_index":
            value = self.tamper.get("value")
            if value is None:
                raise ValueError("set_proposer_index requires a value")
            return signed_block.model_copy(
                update={
                    "block": signed_block.block.model_copy(
                        update={"proposer_index": ValidatorIndex(int(value))}
                    )
                }
            )

        if operation == "clear_first_attestation_bits":
            original = signed_block.block.body.attestations.data
            if not original:
                raise ValueError("clear_first_attestation_bits requires at least one attestation")
            first = original[0]
            empty_bits = AggregationBits(data=[Boolean(False)] * len(first.aggregation_bits.data))
            cleared = AggregatedAttestation(aggregation_bits=empty_bits, data=first.data)
            return signed_block.model_copy(
                update={
                    "block": signed_block.block.model_copy(
                        update={
                            "body": signed_block.block.body.model_copy(
                                update={
                                    "attestations": AggregatedAttestations(
                                        data=[cleared, *original[1:]]
                                    )
                                }
                            )
                        }
                    )
                }
            )

        if operation == "corrupt_proof":
            # Replace the merged proof with a short bogus payload.
            # The verifier rejects the malformed proof bytes.
            return signed_block.model_copy(
                update={
                    "proof": MultiMessageAggregate(
                        proof=ByteList512KiB(data=b"\x00\x01\x02\x03"),
                    )
                }
            )

        if operation == "append_phantom_attestation":
            # Add a body attestation with no matching proof component.
            # The proof binds one component per original attestation plus
            # the proposer, so the body now claims more components than the
            # proof carries.
            phantom_data = AttestationData(
                slot=Slot(0),
                head=Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0)),
                target=Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0)),
                source=Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(0)),
            )
            phantom = AggregatedAttestation(
                aggregation_bits=AggregationBits(data=[Boolean(True)]),
                data=phantom_data,
            )
            return signed_block.model_copy(
                update={
                    "block": signed_block.block.model_copy(
                        update={
                            "body": signed_block.block.body.model_copy(
                                update={
                                    "attestations": AggregatedAttestations(
                                        data=[*signed_block.block.body.attestations.data, phantom]
                                    )
                                }
                            )
                        }
                    )
                }
            )

        if operation == "mutate_state_root":
            # Change a block field after signing so the block root differs.
            # The proposer component's bound message no longer matches the
            # recomputed block root, even though the signature is honest.
            # This is the repackaging vector: an honest proof reused under
            # a different message.
            return signed_block.model_copy(
                update={
                    "block": signed_block.block.model_copy(
                        update={"state_root": Bytes32(b"\xff" * 32)}
                    )
                }
            )

        if operation == "swap_first_two_attestations":
            body = signed_block.block.body
            original = body.attestations.data
            if len(original) < 2:
                raise ValueError("swap_first_two_attestations requires at least two attestations")
            assert self.anchor_state is not None

            key_manager = XmssKeyManager.shared()
            original_attestation_proofs = [
                key_manager.sign_and_aggregate(
                    list(attestation.aggregation_bits.to_validator_indices()),
                    attestation.data,
                )
                for attestation in original
            ]

            swapped_body = body.model_copy(
                update={
                    "attestations": AggregatedAttestations(
                        data=[original[1], original[0], *original[2:]]
                    )
                }
            )
            swapped_block = signed_block.block.model_copy(update={"body": swapped_body})

            # Keep the block root honestly signed; only the attestation
            # proof order remains mismatched with the body order.
            post_state = LstarSpec().process_slots(self.anchor_state, swapped_block.slot)
            post_state = LstarSpec().process_block(post_state, swapped_block)
            swapped_block = swapped_block.model_copy(
                update={"state_root": hash_tree_root(post_state)}
            )

            return self.block._sign_block(
                swapped_block,
                original_attestation_proofs,
                swapped_block.proposer_index,
                key_manager,
                self.anchor_state,
            )

        raise ValueError(f"Unknown tamper operation: {operation!r}")
