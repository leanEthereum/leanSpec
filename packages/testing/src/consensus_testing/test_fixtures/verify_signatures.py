"""Signature test fixture format."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from consensus_testing.genesis import generate_pre_state
from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_types import BlockSpec
from lean_spec.base import StrictBaseModel
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import (
    AggregationBits,
    Checkpoint,
    Slot,
    SpecRejectionError,
    ValidatorIndex,
)
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


class SetProposerIndex(StrictBaseModel):
    """
    Rewrite the block's proposer index.

    Exercises the validator-bounds check that the builder skips
    because its round-robin selection stays within range by
    construction.
    """

    proposer_index: ValidatorIndex
    """Replacement proposer index written into the block."""


class ClearFirstAttestationBits(StrictBaseModel):
    """
    Replace the first body attestation with one whose participation bits carry no set bit.

    Exercises the empty-participants check inside signature verification.
    """


class CorruptProof(StrictBaseModel):
    """
    Replace the merged proof with a short non-decodable blob.

    Exercises the multi-message aggregate decode check.
    """


class AppendPhantomAttestation(StrictBaseModel):
    """
    Add a body attestation with no matching proof component.

    Exercises the component count check between the body and the merged proof.
    """


class MutateStateRoot(StrictBaseModel):
    """
    Change a block field after signing so the block root differs.

    Exercises the per-component message binding that prevents
    reusing an honest proof under a different message.
    """


class SwapFirstTwoAttestations(StrictBaseModel):
    """
    Swap the first two body attestations and re-sign only the proposer.

    Exercises body/proof ordering without relying on a block-root mismatch.
    """


SignedBlockTamper = (
    SetProposerIndex
    | ClearFirstAttestationBits
    | CorruptProof
    | AppendPhantomAttestation
    | MutateStateRoot
    | SwapFirstTwoAttestations
)
"""Union of post-build mutations that each produce a rejection vector."""


class VerifySignaturesFixture(BaseConsensusFixture):
    """
    Emitted vector for signature verification on a signed block.

    JSON output: anchorState, signedBlock.
    """

    anchor_state: State
    """The consensus state whose validators verify the block."""

    signed_block: SignedBlock
    """The generated signed block."""


class VerifySignaturesTest(BaseTestSpec):
    """
    Spec for verifying signatures on a signed block.

    Generates a complete signed block from the block specification,
    then verifies that signatures pass or fail as expected.

    An optional `tamper` hook mutates the built signed block before
    verification runs. This is the only supported way to exercise
    signature-verification rejection paths that lie behind structural
    invariants the block builder normally upholds.
    """

    format_name: ClassVar[str] = "verify_signatures_test"
    description: ClassVar[str] = "Tests signature verification for signed blocks."

    anchor_state: State = Field(default_factory=generate_pre_state)
    """
    The initial consensus state before processing.

    Defaults to the standard genesis state.
    """

    block: BlockSpec
    """
    Block specifications to generate signatures for.

    This defines the block parameters including attestations. Generation
    builds a complete signed block with all necessary signatures.
    """

    tamper: SignedBlockTamper | None = None
    """
    Optional post-build mutation applied before verification.

    Each tamper type documents the rejection path it exercises.

    Tampered blocks bypass the builder's structural invariants. The
    resulting fixture pins the exact rejection a client must raise when
    receiving such a block from a peer.
    """

    def generate(self) -> VerifySignaturesFixture:
        """
        Generate the fixture by creating and verifying a signed block.

        Returns:
            The emitted vector carrying the signed block.

        Raises:
            AssertionError: If signature verification fails unexpectedly.
        """
        # Use shared key manager
        key_manager = XmssKeyManager.shared()

        # Build the signed block
        signed_block = self.block.build_signed_block(self.anchor_state, key_manager)

        # Apply optional post-build tamper before verification runs.
        # This is the only way to exercise rejection paths the builder would
        # otherwise prevent by construction.
        if self.tamper is not None:
            signed_block = self._apply_tamper(signed_block, self.tamper)

        exception_raised: Exception | None = None

        # Verify signatures
        try:
            LstarSpec().verify_signatures(signed_block, self.anchor_state.validators)
        except SpecRejectionError as exception:
            exception_raised = exception

        # Validate exception expectations
        self.assert_expected_outcome(exception_raised)
        rejection_reason = None
        if exception_raised is not None:
            # Emit the language-neutral reason clients assert against.
            rejection_reason = self.resolve_rejection_reason(exception_raised)

        return VerifySignaturesFixture(
            anchor_state=self.anchor_state,
            signed_block=signed_block,
            rejection_reason=rejection_reason,
        )

    def _apply_tamper(self, signed_block: SignedBlock, tamper: SignedBlockTamper) -> SignedBlock:
        """
        Apply the configured post-build mutation to a signed block.

        Args:
            signed_block: The validly built signed block.
            tamper: The mutation to apply.

        Returns:
            A new signed block with the requested mutation applied.

        Raises:
            ValueError: If the mutation cannot be applied to this block.
        """
        match tamper:
            case SetProposerIndex(proposer_index=new_proposer_index):
                return signed_block.model_copy(
                    update={
                        "block": signed_block.block.model_copy(
                            update={"proposer_index": new_proposer_index}
                        )
                    }
                )

            case ClearFirstAttestationBits():
                attestations = signed_block.block.body.attestations.data
                if not attestations:
                    raise ValueError(
                        "clearing the first attestation's bits requires at least one attestation"
                    )
                first_attestation = attestations[0]
                empty_bits = AggregationBits(
                    data=[Boolean(False)] * len(first_attestation.aggregation_bits.data)
                )
                cleared = AggregatedAttestation(
                    aggregation_bits=empty_bits, data=first_attestation.data
                )
                return signed_block.model_copy(
                    update={
                        "block": signed_block.block.model_copy(
                            update={
                                "body": signed_block.block.body.model_copy(
                                    update={
                                        "attestations": AggregatedAttestations(
                                            data=[cleared, *attestations[1:]]
                                        )
                                    }
                                )
                            }
                        )
                    }
                )

            case CorruptProof():
                # Replace the merged proof with a short bogus payload.
                # The verifier rejects the malformed proof bytes.
                return signed_block.model_copy(
                    update={
                        "proof": MultiMessageAggregate(
                            proof=ByteList512KiB(data=b"\x00\x01\x02\x03"),
                        )
                    }
                )

            case AppendPhantomAttestation():
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
                                            data=[
                                                *signed_block.block.body.attestations.data,
                                                phantom,
                                            ]
                                        )
                                    }
                                )
                            }
                        )
                    }
                )

            case MutateStateRoot():
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

            case SwapFirstTwoAttestations():
                body = signed_block.block.body
                attestations = body.attestations.data
                if len(attestations) < 2:
                    raise ValueError(
                        "swapping the first two attestations requires at least two attestations"
                    )

                key_manager = XmssKeyManager.shared()
                original_attestation_proofs = [
                    key_manager.sign_and_aggregate(
                        list(attestation.aggregation_bits.to_validator_indices()),
                        attestation.data,
                    )
                    for attestation in attestations
                ]

                swapped_body = body.model_copy(
                    update={
                        "attestations": AggregatedAttestations(
                            data=[attestations[1], attestations[0], *attestations[2:]]
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
