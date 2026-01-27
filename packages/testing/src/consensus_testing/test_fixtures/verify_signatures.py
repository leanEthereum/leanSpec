"""Signature test fixture format."""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field, field_serializer

from lean_spec.subspecs.containers.attestation import (
    AggregatedAttestation,
    AggregationBits,
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.block import (
    BlockSignatures,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.constants import TARGET_CONFIG
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Randomness,
)
from lean_spec.types import Bytes32
from lean_spec.types.byte_arrays import ByteListMiB

from ..keys import XmssKeyManager, get_shared_key_manager
from ..test_types import AggregatedAttestationSpec, BlockSpec
from .base import BaseConsensusFixture


def _create_dummy_signature() -> Signature:
    """
    Create a structurally valid but cryptographically invalid individual signature.

    The signature has proper structure (correct number of siblings, hashes, etc.)
    but all values are zeros, so it will fail cryptographic verification.
    """
    # Create zero-filled hash digests with correct dimensions
    zero_digest = HashDigestVector(data=[Fp(0) for _ in range(TARGET_CONFIG.HASH_LEN_FE)])

    # Path needs LOG_LIFETIME siblings for the Merkle authentication path
    siblings = HashDigestList(data=[zero_digest for _ in range(TARGET_CONFIG.LOG_LIFETIME)])

    # Hashes need DIMENSION vectors for the Winternitz chain hashes
    hashes = HashDigestList(data=[zero_digest for _ in range(TARGET_CONFIG.DIMENSION)])

    return Signature(
        path=HashTreeOpening(siblings=siblings),
        rho=Randomness(data=[Fp(0) for _ in range(TARGET_CONFIG.RAND_LEN_FE)]),
        hashes=hashes,
    )


def _create_dummy_aggregated_proof(validator_ids: list[ValidatorIndex]) -> AggregatedSignatureProof:
    """
    Create a dummy aggregated signature proof with invalid proof data.

    The proof has the correct participants bitfield but invalid proof bytes,
    so it will fail verification.
    """
    return AggregatedSignatureProof(
        participants=AggregationBits.from_validator_indices(validator_ids),
        proof_data=ByteListMiB(data=b"\x00" * 32),  # Invalid proof bytes
    )


class VerifySignaturesTest(BaseConsensusFixture):
    """
    Test fixture for verifying signatures on SignedBlockWithAttestation.

    The fixture takes a BlockSpec and optional AggregatedAttestationSpec inputs and generates
    a complete SignedBlockWithAttestation as the test output.

    Use the generated test vectors to test that client implementation can verify signatures
    of the generated signed block with attestation..

    Structure:
        anchor_state: Initial trusted consensus state
        signed_block_with_attestation: The generated SignedBlockWithAttestation
        expect_exception: Expected exception for invalid tests
    """

    format_name: ClassVar[str] = "verify_signatures_test"
    description: ClassVar[str] = "Tests signature verification for blocks with attestations."

    anchor_state: State | None = None
    """
    The initial consensus state before processing.

    If not provided, the framework will use the genesis fixture.
    """

    block: BlockSpec = Field(exclude=True)
    """
    Block specifications to generate signatures for.

    This defines the block parameters including attestations. The framework will
    build a complete signed block with attestation with all necessary signatures.
    """

    signed_block_with_attestation: SignedBlockWithAttestation | None = None
    """
    The generated signed block with attestation.
    """

    expect_exception: type[Exception] | None = None
    """
    Expected exception type for invalid tests.

    If provided, an exception of this type is expected during signature verification.
    """

    @field_serializer("expect_exception", when_used="json")
    def serialize_exception(self, value: type[Exception] | None) -> str | None:
        """Serialize exception type to string."""
        if value is None:
            return None
        # Format: "ExceptionClassName" (just the class name for now)
        # TODO: This can be used to map exceptions to expected exceptions from clients
        # as in execution-spec-tests - e.g., "StateTransitionException.INVALID_SLOT"
        return value.__name__

    def make_fixture(self) -> VerifySignaturesTest:
        """
        Generate the fixture by creating a signed block with attestations.

        Builds a block from BlockSpec, generates the relevant signatures to produce
        SignedBlockWithAttestation, then verifies that the signatures are valid.

        Returns:
        -------
        SignatureTest
            The validated fixture.

        Raises:
        ------
        AssertionError
            If signature verification fails.
        """
        # Ensure anchor_state is set
        assert self.anchor_state is not None, "anchor state must be set before making the fixture"

        # Use shared key manager
        key_manager = get_shared_key_manager()

        # Build the signed block with attestation
        signed_block = self._build_block_from_spec(self.block, self.anchor_state, key_manager)

        exception_raised: Exception | None = None

        # Verify signatures
        try:
            signed_block.verify_signatures(self.anchor_state)
        except AssertionError as e:
            exception_raised = e
            # If we expect an exception, this is fine
            if self.expect_exception is None:
                # Unexpected failure
                raise AssertionError(f"Unexpected error verifying block signature(s): {e}") from e
        finally:
            # Always store filled block for serialization, even if an exception occurred
            # This ensures the test fixture contains the signed block that consumer can test with
            self.signed_block_with_attestation = signed_block

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

    def _build_block_from_spec(
        self,
        spec: BlockSpec,
        state: State,
        key_manager: XmssKeyManager,
    ) -> SignedBlockWithAttestation:
        """
        Build a complete SignedBlockWithAttestation from a BlockSpec.

        This method combines:
            - spec logic (via the state block building logic),
            - test-specific logic (signing),
        to produce a complete signed block.

        Parameters
        ----------
        spec : BlockSpec
            The lightweight block specification.
        state : State
            The anchor state to build against.
        key_manager : XmssKeyManager
            The key manager for signing.

        Returns:
        -------
        SignedBlockWithAttestation
            A complete signed block with all attestations.
        """
        # Determine proposer index
        proposer_index = spec.proposer_index or ValidatorIndex(
            int(spec.slot) % len(state.validators)
        )

        # Resolve parent root
        parent_state = state.process_slots(spec.slot)
        parent_root = hash_tree_root(parent_state.latest_block_header)

        # Build attestations from spec - only valid ones go through aggregation
        valid_attestations, valid_signatures, invalid_specs = self._build_attestations_from_spec(
            spec, state, key_manager
        )

        # Use State.build_block for valid attestations (pure spec logic)
        final_block, _, _, aggregated_signatures = state.build_block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            attestations=valid_attestations,
            aggregated_payloads={},
        )

        # Create proofs for invalid attestation specs
        for invalid_spec in invalid_specs:
            attestation_data = self._build_attestation_data_from_spec(invalid_spec, state)
            data_root = attestation_data.data_root_bytes()

            # Create aggregated attestation claiming validator_ids as participants
            aggregation_bits = AggregationBits.from_validator_indices(invalid_spec.validator_ids)
            invalid_aggregated = AggregatedAttestation(
                aggregation_bits=aggregation_bits,
                data=attestation_data,
            )

            # Determine proof type based on the invalidity scenario
            if not invalid_spec.valid_signature:
                # Cryptographically invalid proof (all zeros)
                invalid_proof = _create_dummy_aggregated_proof(invalid_spec.validator_ids)
            elif invalid_spec.signer_ids is not None:
                # Valid proof but from wrong validators
                # Sign with signer_ids but claim validator_ids as participants
                signer_public_keys = [
                    key_manager.get_public_key(vid) for vid in invalid_spec.signer_ids
                ]
                signer_signatures = [
                    key_manager.sign_attestation_data(vid, attestation_data)
                    for vid in invalid_spec.signer_ids
                ]
                # Create valid aggregated proof from actual signers
                valid_proof = AggregatedSignatureProof.aggregate(
                    participants=AggregationBits.from_validator_indices(invalid_spec.signer_ids),
                    public_keys=signer_public_keys,
                    signatures=signer_signatures,
                    message=data_root,
                    epoch=attestation_data.slot,
                )
                # Replace participants with claimed validator_ids (mismatch!)
                invalid_proof = AggregatedSignatureProof(
                    participants=aggregation_bits,
                    proof_data=valid_proof.proof_data,
                )
            else:
                # Fallback to dummy proof
                invalid_proof = _create_dummy_aggregated_proof(invalid_spec.validator_ids)

            # Add to block's attestations
            final_block = final_block.model_copy(
                update={
                    "body": final_block.body.model_copy(
                        update={
                            "attestations": AggregatedAttestations(
                                data=[*final_block.body.attestations.data, invalid_aggregated]
                            )
                        }
                    )
                }
            )
            aggregated_signatures.append(invalid_proof)

        attestation_signatures = AttestationSignatures(
            data=aggregated_signatures,
        )

        # Create proposer attestation for this block
        block_root = hash_tree_root(final_block)
        proposer_attestation = Attestation(
            validator_id=proposer_index,
            data=AttestationData(
                slot=spec.slot,
                head=Checkpoint(root=block_root, slot=spec.slot),
                target=Checkpoint(root=block_root, slot=spec.slot),
                source=Checkpoint(root=parent_root, slot=parent_state.latest_block_header.slot),
            ),
        )

        # Sign proposer attestation - use valid or dummy signature based on spec
        if spec.valid_signature:
            proposer_attestation_signature = key_manager.sign_attestation_data(
                proposer_attestation.validator_id,
                proposer_attestation.data,
            )
        else:
            proposer_attestation_signature = _create_dummy_signature()

        return SignedBlockWithAttestation(
            message=BlockWithAttestation(
                block=final_block,
                proposer_attestation=proposer_attestation,
            ),
            signature=BlockSignatures(
                attestation_signatures=attestation_signatures,
                proposer_signature=proposer_attestation_signature,
            ),
        )

    def _build_attestations_from_spec(
        self,
        spec: BlockSpec,
        state: State,
        key_manager: XmssKeyManager,
    ) -> tuple[list[Attestation], list[Any], list[AggregatedAttestationSpec]]:
        """
        Build attestations list from BlockSpec.

        Returns:
        -------
        tuple of:
            - valid_attestations: Attestations with valid signatures for aggregation
            - valid_signatures: Corresponding signatures for valid attestations
            - invalid_specs: Specs with valid_signature=False (handled separately)
        """
        if spec.attestations is None:
            return [], [], []

        valid_attestations = []
        valid_signatures = []
        invalid_specs = []

        for aggregated_spec in spec.attestations:
            # Check for invalid scenarios that need special handling
            has_signer_mismatch = (
                aggregated_spec.signer_ids is not None
                and aggregated_spec.signer_ids != aggregated_spec.validator_ids
            )

            if not aggregated_spec.valid_signature or has_signer_mismatch:
                # Defer invalid specs - they'll get special proofs created directly
                invalid_specs.append(aggregated_spec)
                continue

            # Build attestation data (shared across all validators in this group)
            attestation_data = self._build_attestation_data_from_spec(aggregated_spec, state)

            # Create individual attestations and signatures for each validator
            for validator_id in aggregated_spec.validator_ids:
                valid_attestations.append(
                    Attestation(
                        validator_id=validator_id,
                        data=attestation_data,
                    )
                )
                signature = key_manager.sign_attestation_data(
                    validator_id,
                    attestation_data,
                )
                valid_signatures.append(signature)

        return valid_attestations, valid_signatures, invalid_specs

    def _build_attestation_data_from_spec(
        self,
        spec: AggregatedAttestationSpec,
        state: State,
    ) -> AttestationData:
        """
        Build AttestationData from an AggregatedAttestationSpec.

        Parameters
        ----------
        spec : AggregatedAttestationSpec
            The aggregated attestation specification.
        state : State
            The state to get latest_justified checkpoint from.

        Returns:
        -------
        AttestationData
            The attestation data shared by all validators in this aggregation.
        """
        # For this test, we use a dummy target since we're just testing signature generation
        # In a real test, you would resolve target_root_label from a block registry
        target_root = Bytes32.zero()
        target_checkpoint = Checkpoint(root=target_root, slot=spec.target_slot)

        # Derive head = target
        head_checkpoint = target_checkpoint

        # Derive source from state's latest justified checkpoint
        source_checkpoint = state.latest_justified

        return AttestationData(
            slot=spec.slot,
            head=head_checkpoint,
            target=target_checkpoint,
            source=source_checkpoint,
        )
