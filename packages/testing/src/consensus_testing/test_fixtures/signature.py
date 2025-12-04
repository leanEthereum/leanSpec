"""Signature test fixture format."""

from __future__ import annotations

from functools import lru_cache
from typing import ClassVar

from pydantic import Field

from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT
from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.block.block import (
    Block,
    BlockBody,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import Attestations, BlockSignatures
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.types import Bytes32, Uint64

from ..keys import XmssKeyManager
from ..test_types import BlockSpec, SignedAttestationSpec
from .base import BaseConsensusFixture


@lru_cache(maxsize=1)
def _get_shared_key_manager() -> XmssKeyManager:
    """
    Get or create the shared XMSS key manager for reusing keys across tests.

    Uses functools.lru_cache to create a singleton instance that's shared
    across all test fixture generations within a session. This optimizes
    performance by reusing keys when possible.

    Returns:
        Shared XmssKeyManager instance with max_slot=10.
    """
    return XmssKeyManager(max_slot=Slot(10))


class SignatureTest(BaseConsensusFixture):
    """
    Test fixture for signature generation with blocks and attestations.

    The fixture takes a BlockSpec and optional SignedAttestationSpec inputs and generates
    a complete SignedBlockWithAttestation as the test output. This fixture
    is useful for testing cryptographic signature verification.

    To execute test vectors produced by this fixture, simply pass the vector's
    `signed_block_with_attestation` and `anchor_state` through the client's
    `SignedBlockWithAttestation.verify_signatures()`

    Output Structure (in JSON):
        anchor_state: Initial trusted consensus state
        signed_block_with_attestation: The generated SignedBlockWithAttestation

    Input Fields (excluded from output):
        block: Block specification including attestations (used to generate the output)
    """

    format_name: ClassVar[str] = "signature_test"
    description: ClassVar[str] = "Tests signature generation for blocks with attestations"

    anchor_state: State | None = None
    """
    The initial trusted consensus state.

    If not provided, the framework will use the genesis fixture from pytest.
    """

    block: BlockSpec = Field(exclude=True)
    """
    Block specification to generate signatures for.

    This defines the block parameters including attestations. The framework will
    build a complete signed block with all necessary signatures.

    Attestations should be specified via block.attestations as SignedAttestationSpec objects.

    Note: This field is excluded from the output test vector JSON.
    """

    signed_block_with_attestation: SignedBlockWithAttestation | None = None
    """
    The generated signed block with attestation.

    This is populated by make_fixture() and contains the complete
    cryptographically signed block ready for verification.
    """

    def make_fixture(self) -> SignatureTest:
        """
        Generate the fixture by creating a signed block with attestations.

        This:
        1. Sets up XMSS keys for validators
        2. Builds a complete block from the BlockSpec
        3. Creates and signs attestations
        4. Generates the proposer attestation
        5. Collects all signatures
        6. Verifies all signatures against the anchor state

        Returns:
        -------
        SignatureTest
            The validated fixture with populated output field and verified signatures.

        Raises:
        ------
        AssertionError
            If any required field is missing or generation fails.
        Exception
            If signature verification fails.
        """
        # Ensure anchor_state is set
        assert self.anchor_state is not None, "anchor_state must be set before make_fixture"

        # Determine max_slot from block spec
        max_slot = self.block.slot

        # Use shared key manager if it has sufficient capacity, otherwise create a new one
        shared_key_manager = _get_shared_key_manager()
        key_manager = (
            shared_key_manager
            if max_slot <= shared_key_manager.max_slot
            else XmssKeyManager(max_slot=max_slot)
        )

        # Update validator pubkeys to match key_manager's generated keys
        updated_validators = [
            validator.model_copy(update={"pubkey": key_manager[Uint64(i)].public.encode_bytes()})
            for i, validator in enumerate(self.anchor_state.validators)
        ]

        self.anchor_state = self.anchor_state.model_copy(
            update={"validators": Validators(data=updated_validators)}
        )

        # Build the signed block with attestation
        signed_block = self._build_signed_block_from_spec(
            self.block, self.anchor_state, key_manager
        )

        # Verify signatures before outputting
        signed_block.verify_signatures(self.anchor_state)

        # Store the output
        self.signed_block_with_attestation = signed_block

        return self

    def _build_signed_block_from_spec(
        self,
        spec: BlockSpec,
        state: State,
        key_manager: XmssKeyManager,
    ) -> SignedBlockWithAttestation:
        """
        Build a complete SignedBlockWithAttestation from a BlockSpec.

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
        # Determine proposer
        if spec.proposer_index is None:
            validator_count = state.validators.count
            proposer_index = Uint64(int(spec.slot) % int(validator_count))
        else:
            proposer_index = spec.proposer_index

        # Process state to the block's slot
        temp_state = state.process_slots(spec.slot)
        parent_root = hash_tree_root(temp_state.latest_block_header)

        # Prepare attestations from spec if provided
        attestations = []
        attestation_signatures = []
        if spec.attestations is not None:
            for attestation_spec in spec.attestations:
                signed_attestation = self._build_signed_attestation_from_spec(
                    attestation_spec, state, key_manager
                )
                # Extract the Attestation message and signature
                attestations.append(signed_attestation.message)
                attestation_signatures.append(signed_attestation.signature)

        # Build block body with collected attestations
        body = BlockBody(attestations=Attestations(data=attestations))

        # Create temporary block for dry-run
        temp_block = Block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),
            body=body,
        )

        # Process to get correct state root
        post_state = temp_state.process_block(temp_block)
        correct_state_root = hash_tree_root(post_state)

        # Create final block
        final_block = Block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=correct_state_root,
            body=body,
        )

        # Create proposer attestation for this block
        block_root = hash_tree_root(final_block)
        proposer_attestation = Attestation(
            validator_id=proposer_index,
            data=AttestationData(
                slot=spec.slot,
                head=Checkpoint(root=block_root, slot=spec.slot),
                target=Checkpoint(root=block_root, slot=spec.slot),
                source=Checkpoint(root=parent_root, slot=temp_state.latest_block_header.slot),
            ),
        )

        # Collect all signatures: attestations first, then proposer attestation
        signature_list = attestation_signatures.copy()
        proposer_attestation_signature = key_manager.sign_attestation(proposer_attestation)
        signature_list.append(proposer_attestation_signature)

        return SignedBlockWithAttestation(
            message=BlockWithAttestation(
                block=final_block,
                proposer_attestation=proposer_attestation,
            ),
            signature=BlockSignatures(data=signature_list),
        )

    def _build_signed_attestation_from_spec(
        self,
        spec: SignedAttestationSpec,
        state: State,
        key_manager: XmssKeyManager,
    ) -> "SignedAttestation":
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
        from lean_spec.subspecs.containers.attestation import SignedAttestation

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

        # Sign the attestation using the key manager
        signature = key_manager.sign_attestation(attestation)

        # Create signed attestation
        return SignedAttestation(
            message=attestation,
            signature=signature,
        )
