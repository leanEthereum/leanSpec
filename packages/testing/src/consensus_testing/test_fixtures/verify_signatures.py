"""Signature test fixture format."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, ClassVar

from pydantic import Field, field_serializer

from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
    SignedAttestation,
)
from lean_spec.subspecs.containers.block.block import (
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import BlockSignatures
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.subspecs.xmss.interface import PROD_SIGNATURE_SCHEME
from lean_spec.types import Bytes32, Uint64

from ..keys import XmssKeyManager
from ..test_types import BlockSpec, SignedAttestationSpec
from .base import BaseConsensusFixture


@lru_cache(maxsize=1)
def _get_shared_prod_key_manager() -> XmssKeyManager:
    """
    Get or create the shared XMSS key manager for reusing keys across tests.

    Uses functools.lru_cache to create a singleton instance that's shared
    across all test fixture generations within a session. This optimizes
    performance by reusing keys when possible.

    Returns:
        Shared XmssKeyManager instance with max_slot=10.
    """
    return XmssKeyManager(max_slot=Slot(10), scheme=PROD_SIGNATURE_SCHEME)


class VerifySignaturesTest(BaseConsensusFixture):
    """
    Test fixture for verifying signatures on SignedBlockWithAttestation.

    The fixture takes a BlockSpec and optional SignedAttestationSpec inputs and generates
    a complete SignedBlockWithAttestation as the test output.

    To execute test vectors produced by this fixture, simply pass the vector's
    `signed_block_with_attestation` and `anchor_state` through the client's
    `SignedBlockWithAttestation.verify_signatures()`. The test case is expected to fail
    if `expect_exception` is set.

    Structure:
        anchor_state: Initial trusted consensus state
        signed_block_with_attestation: The generated SignedBlockWithAttestation
        expect_exception: Expected exception for invalid tests
    """

    format_name: ClassVar[str] = "verify_signature_test"
    description: ClassVar[str] = (
        "Tests signature verification for blocks with attestations through"
        "SignedBlockWithAttestation.verify_signatures()"
    )

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

    Attestations should be specified via block.attestations as SignedAttestationSpec objects.
    Use block.valid_signature to control proposer attestation signature validity.
    Use block.attestations.valid_signature to control attester signature validity.

    Note: This field is excluded from the output test vector. Use signed_block_with_attestation.
    """

    signed_block_with_attestation: SignedBlockWithAttestation | None = None
    """
    The generated signed block with attestation.

    This is populated by make_fixture() and contains the complete signed block
    ready for verification.
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
        assert self.anchor_state is not None, "anchor_state must be set before make_fixture"

        # Use shared key manager
        key_manager = _get_shared_prod_key_manager()

        # Build the signed block with attestation
        signed_block = self._build_block_from_spec(self.block, self.anchor_state, key_manager)

        exception_raised: Exception | None = None

        # Verify signatures
        try:
            signed_block.verify_signatures(self.anchor_state, scheme=PROD_SIGNATURE_SCHEME)
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
        proposer_index = spec.proposer_index or Uint64(int(spec.slot) % int(state.validators.count))

        # Resolve parent root
        parent_state = state.process_slots(spec.slot)
        parent_root = hash_tree_root(parent_state.latest_block_header)

        # Build attestations from spec
        attestations, signatures = self._build_attestations_from_spec(
            spec, state, key_manager
        )

        # Use State.build_block for core block building (pure spec logic)
        final_block, _, _, _ = state.build_block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            attestations=attestations,
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
            proposer_attestation_signature = key_manager.sign_attestation(proposer_attestation)
        else:
            # Generate an invalid dummy signature (all zeros)
            from lean_spec.subspecs.xmss.constants import PROD_CONFIG
            from lean_spec.subspecs.xmss.containers import Signature
            from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness

            proposer_attestation_signature = Signature(
                path=HashTreeOpening(siblings=HashDigestList(data=[])),
                rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
                hashes=HashDigestList(data=[]),
            )

        signatures.append(proposer_attestation_signature)

        return SignedBlockWithAttestation(
            message=BlockWithAttestation(
                block=final_block,
                proposer_attestation=proposer_attestation,
            ),
            signature=BlockSignatures(data=signatures),
        )

    def _build_attestations_from_spec(
        self,
        spec: BlockSpec,
        state: State,
        key_manager: XmssKeyManager,
    ) -> tuple[list[Attestation], list[Any]]:
        """Build attestations list from BlockSpec."""
        if spec.attestations is None:
            return [], []

        attestations = []
        attestation_signatures = []

        for attestation_item in spec.attestations:
            if isinstance(attestation_item, SignedAttestationSpec):
                signed_attestation = self._build_signed_attestation_from_spec(
                    attestation_item, state, key_manager
                )
                attestations.append(signed_attestation.message)
                attestation_signatures.append(signed_attestation.signature)
            else:
                attestations.append(attestation_item.message)
                attestation_signatures.append(attestation_item.signature)

        return attestations, attestation_signatures

    def _build_signed_attestation_from_spec(
        self,
        spec: SignedAttestationSpec,
        state: State,
        key_manager: XmssKeyManager,
    ) -> SignedAttestation:
        """
        Build a SignedAttestation from a SignedAttestationSpec.

        Parameters
        ----------
        spec : SignedAttestationSpec
            The attestation specification to resolve.
        state : State
            The state to get latest_justified checkpoint from.
        key_manager : XmssKeyManager
            The key manager for signing.

        Returns:
        -------
        SignedAttestation
            The resolved signed attestation.
        """
        # For this test, we use a dummy target since we're just testing signature generation
        # In a real test, you would resolve target_root_label from a block registry
        target_root = Bytes32.zero()
        target_checkpoint = Checkpoint(root=target_root, slot=spec.target_slot)

        # Derive head = target
        head_checkpoint = target_checkpoint

        # Derive source from state's latest justified checkpoint
        source_checkpoint = state.latest_justified

        # Create attestation
        attestation = Attestation(
            validator_id=spec.validator_id,
            data=AttestationData(
                slot=spec.slot,
                head=head_checkpoint,
                target=target_checkpoint,
                source=source_checkpoint,
            ),
        )

        # Sign the attestation - use dummy signature if expecting invalid signature
        if spec.valid_signature:
            # Generate valid signature using key manager
            signature = key_manager.sign_attestation(attestation)
        else:
            # Generate an invalid dummy signature (all zeros)
            from lean_spec.subspecs.xmss.constants import PROD_CONFIG
            from lean_spec.subspecs.xmss.containers import Signature
            from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness

            signature = Signature(
                path=HashTreeOpening(siblings=HashDigestList(data=[])),
                rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
                hashes=HashDigestList(data=[]),
            )

        # Create signed attestation
        return SignedAttestation(
            message=attestation,
            signature=signature,
        )
