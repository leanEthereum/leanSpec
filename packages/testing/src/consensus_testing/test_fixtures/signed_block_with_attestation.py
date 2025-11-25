"""Signed block with attestation test fixture format."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, ClassVar, Dict, cast

from pydantic import model_serializer, model_validator

from lean_spec.subspecs.containers.block.block import (
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import BlockSignatures
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.xmss.interface import TEST_SIGNATURE_SCHEME
from lean_spec.types import ValidatorIndex

from ..keys import XmssKeyManager
from .base import BaseConsensusFixture


@lru_cache(maxsize=1)
def _get_shared_key_manager() -> XmssKeyManager:
    """
    Get or create the shared XMSS key manager for reusing keys across tests.

    Uses functools.lru_cache to create a singleton instance that's shared
    across all test fixture generations within a session. This optimizes
    performance by reusing keys when possible.

    Returns:
        Shared XmssKeyManager instance with max_slot=2.
    """
    return XmssKeyManager(max_slot=Slot(2))


class SignedBlockWithAttestationTest(BaseConsensusFixture):
    """
    Test fixture for verifying signed block with attestation signature correctness.

    This fixture tests the cryptographic correctness of a single SignedBlockWithAttestation:
    - Block + proposer attestation + aggregated signatures

    The fixture verifies that:
    1. Signatures are correctly generated using XMSS keys
    2. Signatures can be verified using the validators' public keys
    3. Invalid signatures are properly rejected
    4. Signature aggregation is correct

    Structure:
        anchor_state: Initial state with validator public keys
        container: Single signed block with attestation to test
        valid: Whether all signatures should verify (default: True)
    """

    format_name: ClassVar[str] = "signed_block_with_attestation_test"
    description: ClassVar[str] = "Tests signed block with attestation signature correctness"

    anchor_state: State | None = None
    """
    The initial consensus state with validator public keys.

    If not provided, the framework will use the genesis fixture from pytest.
    This allows tests to omit genesis for simpler test code while still
    allowing customization when needed.
    """

    signed_block_with_attestation: SignedBlockWithAttestation
    """
    Single signed block with attestation to verify.

    The block will be verified for signature correctness against the
    validator public keys in anchor_state.
    """

    valid: bool = True
    """
    Whether all signatures are expected to be valid.

    If True, all signatures must verify successfully.
    If False, at least one signature must fail verification.
    """

    max_slot: Slot | None = None
    """
    Maximum slot for which XMSS keys should be valid.

    If not provided, will be auto-calculated from the container. This determines
    how many slots worth of XMSS signatures can be generated.
    """

    @model_serializer(mode="wrap", when_used="json")
    def _serialize_model(self, serializer: Any) -> Dict[str, Any]:
        """
        Custom serializer for JSON output.

        Outputs:
        - blockWithAttestation: The unsigned block with proposer attestation
        - attesterPubkeys: Array of public keys for attestations in block body (in order)
        - proposerPubkey: The proposer's public key
        - maxSlot: Maximum slot value
        - signedBlockWithAttestation: The complete signed block with signatures
        """
        # Get default serialization
        data = cast(Dict[str, Any], serializer(self))
        signed_block = self.signed_block_with_attestation

        if self.anchor_state is not None:
            # Collect attester pubkeys for all attestations in the block body
            attester_pubkeys = []
            for attestation in signed_block.message.block.body.attestations:
                validator_index = ValidatorIndex(int(attestation.validator_id))
                validator = self.anchor_state.validators[int(validator_index)]
                attester_pubkeys.append(
                    validator.pubkey.hex()
                    if isinstance(validator.pubkey, bytes)
                    else validator.pubkey
                )

            # Get proposer pubkey
            proposer_index = ValidatorIndex(int(signed_block.message.block.proposer_index))
            proposer = self.anchor_state.validators[int(proposer_index)]
            proposer_pubkey = (
                proposer.pubkey.hex() if isinstance(proposer.pubkey, bytes) else proposer.pubkey
            )

            data["blockWithAttestation"] = signed_block.message.to_json()
            data["attesterPubkeys"] = attester_pubkeys
            data["proposerPubkey"] = proposer_pubkey
            data["signedBlockWithAttestation"] = signed_block.to_json()
            data.pop("container", None)
            data.pop("anchorState", None)

        return data

    @model_validator(mode="after")
    def set_max_slot_default(self) -> SignedBlockWithAttestationTest:
        """
        Auto-calculate max_slot from signed_block_with_attestation if not provided.

        Uses the slot value from the block to ensure XMSS keys are
        generated with sufficient capacity.
        """
        if self.max_slot is None:
            self.max_slot = Slot(int(self.signed_block_with_attestation.message.block.slot))

        return self

    def make_fixture(self) -> SignedBlockWithAttestationTest:
        """
        Generate the fixture by building and verifying the signed block.

        This validates the test by:
        1. Setting up XMSS key manager with validator keys
        2. Updating anchor_state with generated public keys
        3. Generating signatures using XMSS keys
        4. Verifying signatures against validator public keys
        5. Checking that valid/invalid expectation is met

        Returns:
        -------
        SignedBlockWithAttestationTest
            The validated fixture with properly signed block.

        Raises:
        ------
        AssertionError
            If signature verification doesn't match expected validity.
        """
        # Ensure anchor_state is set
        assert self.anchor_state is not None, "anchor_state must be set before make_fixture"
        assert self.max_slot is not None, "max_slot must be set before make_fixture"

        # Use shared key manager if it has sufficient capacity, otherwise create a new one
        shared_key_manager = _get_shared_key_manager()
        key_manager = (
            shared_key_manager
            if self.max_slot <= shared_key_manager.max_slot
            else XmssKeyManager(max_slot=self.max_slot, scheme=TEST_SIGNATURE_SCHEME)
        )

        # Update validator pubkeys to match key_manager's generated keys
        updated_validators = [
            validator.model_copy(
                update={
                    "pubkey": key_manager[ValidatorIndex(i)].public.to_bytes(
                        key_manager.scheme.config
                    )
                }
            )
            for i, validator in enumerate(self.anchor_state.validators)
        ]

        self.anchor_state = self.anchor_state.model_copy(
            update={"validators": Validators(data=updated_validators)}
        )

        # Build signed block with correct signatures
        self.signed_block_with_attestation = self._build_signed_block(
            self.signed_block_with_attestation.message, key_manager
        )

        # Verify all signatures in the block
        is_valid = self.signed_block_with_attestation.verify_signatures(self.anchor_state)

        if self.valid and not is_valid:
            raise AssertionError(
                "SignedBlockWithAttestation: expected valid signatures but verification failed"
            )
        elif not self.valid and is_valid:
            raise AssertionError(
                "SignedBlockWithAttestation: expected invalid signatures but verification succeeded"
            )

        return self

    def _build_signed_block(
        self, block_with_attestation: BlockWithAttestation, key_manager: XmssKeyManager
    ) -> SignedBlockWithAttestation:
        """
        Build a SignedBlockWithAttestation with correct XMSS signatures.

        This generates signatures for:
        1. All attestations in the block body
        2. The proposer's attestation

        Parameters
        ----------
        block_with_attestation : BlockWithAttestation
            The block and proposer attestation to sign.
        key_manager : XmssKeyManager
            Key manager for generating XMSS signatures.

        Returns:
        -------
        SignedBlockWithAttestation
            The block with valid XMSS signatures.
        """
        block = block_with_attestation.block
        proposer_attestation = block_with_attestation.proposer_attestation

        # Sign all attestations in the block body
        signature_list = []
        for attestation in block.body.attestations:
            signature_list.append(key_manager.sign_attestation(attestation))

        # Sign the proposer attestation
        proposer_signature = key_manager.sign_attestation(proposer_attestation)
        signature_list.append(proposer_signature)

        return SignedBlockWithAttestation(
            message=block_with_attestation, signature=BlockSignatures(data=signature_list)
        )
