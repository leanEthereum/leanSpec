"""
Block containers for Lean Ethereum consensus.

Blocks propose changes to the chain.
Each references its parent, forming a chain.
The proposer is determined by slot assignment.
"""

from typing import TYPE_CHECKING

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.xmss.aggregation import AggregationError
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import Bytes32
from lean_spec.types.container import Container

from ...xmss.containers import Signature as XmssSignature
from ..attestation import Attestation
from .types import (
    AggregatedAttestations,
    AttestationSignatures,
)

if TYPE_CHECKING:
    from ..state import State


class BlockBody(Container):
    """Payload of a block containing attestations."""

    attestations: AggregatedAttestations
    """Attestations in the block. Signatures are in BlockSignatures."""


class BlockHeader(Container):
    """
    Metadata summarizing a block.

    Contains parent reference, state root, and body hash.
    Smaller than full blocks.
    """

    slot: Slot
    """The slot in which the block was proposed."""

    proposer_index: ValidatorIndex
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after applying transactions in this block."""

    body_root: Bytes32
    """The root of the block body."""


class Block(Container):
    """A complete block including header and body."""

    slot: Slot
    """The slot in which the block was proposed."""

    proposer_index: ValidatorIndex
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after applying transactions in this block."""

    body: BlockBody
    """The block's payload."""


class BlockWithAttestation(Container):
    """Bundle containing a block and the proposer's attestation."""

    block: Block
    """The proposed block message."""

    proposer_attestation: Attestation
    """The proposer's attestation corresponding to this block."""


class BlockSignatures(Container):
    """Aggregated signature payload for a block."""

    attestation_signatures: AttestationSignatures
    """Aggregated signatures for attestations in the block body."""

    proposer_signature: XmssSignature
    """Signature for the proposer's attestation."""


class SignedBlockWithAttestation(Container):
    """Envelope carrying a block, an attestation from proposer, and aggregated signatures."""

    message: BlockWithAttestation
    """The block plus an attestation from proposer being signed."""

    signature: BlockSignatures
    """Aggregated signature payload for the block."""

    def verify_signatures(
        self, parent_state: "State", scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME
    ) -> bool:
        """
        Verify all XMSS signatures in this signed block.

        Checks that:

        - Each attestation is signed by participating validators
        - The proposer attestation is signed by the block proposer

        Args:
            parent_state: State at parent block. Provides validator public keys.
            scheme: XMSS signature scheme for verification.

        Returns:
            True if all signatures are valid.

        Raises:
            AssertionError: On verification failure.
        """
        # Extract block components for verification.
        block = self.message.block
        signatures = self.signature
        aggregated_attestations = block.body.attestations
        attestation_signatures = signatures.attestation_signatures

        # Each attestation in the body must have a corresponding signature entry.
        # This ensures no attestation is missing cryptographic proof.
        assert len(aggregated_attestations) == len(attestation_signatures), (
            "Attestation signature groups must align with block body attestations"
        )

        # Validator registry from parent state contains public keys for verification.
        validators = parent_state.validators

        # Attestations and signatures are parallel arrays.
        # - Each attestation says "validators X, Y, Z voted for this data".
        # - Each signature proves those validators actually signed.
        for aggregated_attestation, aggregated_signature in zip(
            aggregated_attestations, attestation_signatures, strict=True
        ):
            # Extract which validators participated in this attestation.
            # The aggregation bits encode validator indices as a bitfield.
            validator_ids = aggregated_attestation.aggregation_bits.to_validator_indices()

            # The signed message is the attestation data root.
            # All validators in this group signed this exact data.
            attestation_data_root = aggregated_attestation.data.data_root_bytes()

            # Bounds check: all validators must exist in the registry.
            for validator_id in validator_ids:
                assert validator_id.is_valid(len(validators)), "Validator index out of range"

            # Collect public keys for all participating validators.
            # Order matters: must match the order in the aggregated signature.
            public_keys = [validators[vid].get_pubkey() for vid in validator_ids]

            # Verify the aggregated signature against all public keys.
            # Uses slot as epoch for XMSS one-time signature indexing.
            try:
                aggregated_signature.verify(
                    public_keys=public_keys,
                    message=attestation_data_root,
                    epoch=aggregated_attestation.data.slot,
                )
            except AggregationError as exc:
                raise AssertionError(
                    f"Attestation aggregated signature verification failed: {exc}"
                ) from exc

        # Verify proposer attestation signature.
        # The proposer includes their own attestation separate from the body.
        proposer_attestation = self.message.proposer_attestation
        proposer_signature = signatures.proposer_signature

        # Critical safety check: the attestation must be from the actual proposer.
        # Without this, an attacker could substitute another validator's attestation.
        assert proposer_attestation.validator_id == block.proposer_index, (
            "Proposer attestation must be from the block proposer"
        )

        # Bounds check: proposer must exist in the validator registry.
        assert proposer_attestation.validator_id.is_valid(len(validators)), (
            "Proposer index out of range"
        )
        proposer = validators[proposer_attestation.validator_id]

        # Verify the proposer's individual XMSS signature.
        # This is not aggregated since there's only one signer.
        assert proposer_signature.verify(
            proposer.get_pubkey(),
            proposer_attestation.data.slot,
            proposer_attestation.data.data_root_bytes(),
            scheme,
        ), "Proposer signature verification failed"

        return True
