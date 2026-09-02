"""Signature test fixture format."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field
from ssz import Boolean, hash_tree_root

from consensus_testing.genesis import build_genesis_state
from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_types import BlockSpec
from lean_spec.base import StrictBaseModel
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
from lean_spec.spec.ssz_types import ByteList512KiB, Bytes32


class SetProposerIndex(StrictBaseModel):
    """Rewrite the proposer index to exercise the validator-bounds check the builder skips."""

    proposer_index: ValidatorIndex
    """Replacement proposer index written into the block."""


class ClearFirstAttestationBits(StrictBaseModel):
    """Clear the first attestation's bits to exercise the empty-participants check."""


class CorruptProof(StrictBaseModel):
    """Replace the merged proof with a non-decodable blob to exercise the decode check."""


class AppendPhantomAttestation(StrictBaseModel):
    """Add an attestation with no proof component to exercise the component-count check."""


class MutateStateRoot(StrictBaseModel):
    """Change a block field after signing to break the proposer's per-component message binding."""


class SwapFirstTwoAttestations(StrictBaseModel):
    """Swap the first two attestations and re-sign the proposer to exercise body/proof ordering."""


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
    """Input spec for verifying signatures on a generated signed block."""

    format_name: ClassVar[str] = "verify_signatures_test"
    description: ClassVar[str] = "Tests signature verification for signed blocks."

    anchor_state: State = Field(default_factory=build_genesis_state)
    """The initial consensus state before processing."""

    block: BlockSpec
    """Block parameters from which the complete signed block is generated."""

    tamper: SignedBlockTamper | None = None
    """Optional post-build mutation that reaches rejection paths the builder prevents."""

    def generate(self) -> VerifySignaturesFixture:
        """
        Generate the fixture by creating and verifying a signed block.

        Returns:
            The emitted vector carrying the signed block.

        Raises:
            AssertionError: If verification fails unexpectedly.
        """
        key_manager = XmssKeyManager.shared()
        signed_block = self.block.build_signed_block(self.anchor_state, key_manager)

        # A tamper is the only way to reach rejection paths the builder prevents by construction.
        if self.tamper is not None:
            signed_block = self._apply_tamper(signed_block, self.tamper)

        exception_raised: Exception | None = None
        try:
            LstarSpec().verify_signatures(signed_block, self.anchor_state.validators)
        except SpecRejectionError as exception:
            exception_raised = exception

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
            A new signed block with the mutation applied.

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
                # Replace the merged proof with a short bogus payload the verifier cannot decode.
                return signed_block.model_copy(
                    update={
                        "proof": MultiMessageAggregate(
                            proof=ByteList512KiB(data=b"\x00\x01\x02\x03"),
                        )
                    }
                )

            case AppendPhantomAttestation():
                # The proof binds one component per original attestation plus the proposer.
                # An unbacked attestation makes the body claim more components than the proof.
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
                # Change a block field after signing so the recomputed block root differs.
                # The proposer's honest signature now binds a message no client will recompute.
                # This is the repackaging vector: an honest proof reused under a different message.
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

                # Keep the block root honestly signed.
                # Only the attestation proof order stays mismatched with the body order.
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
