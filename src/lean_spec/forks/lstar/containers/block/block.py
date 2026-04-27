"""
Block containers for Lean Ethereum consensus.

Blocks propose changes to the chain.
Each references its parent, forming a chain.
The proposer is determined by slot assignment.
"""

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex, Validators
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregationError
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.container import Container

from .types import (
    AggregatedAttestations,
    AttestationSignatures,
)


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


BlockLookup = dict[Bytes32, "Block"]
"""Mapping from block root to Block objects."""


class BlockSignatures(Container):
    """Aggregated signature payload for a block."""

    attestation_signatures: AttestationSignatures
    """Aggregated signatures for attestations in the block body."""

    proposer_signature: Signature
    """Signature over the block root using the proposer's proposal key."""


class SignedBlock(Container):
    """Envelope carrying a block and its aggregated signatures."""

    block: Block
    """The block being signed."""

    signature: BlockSignatures
    """Aggregated signature payload for the block."""

    def verify_signatures(
        self,
        validators: Validators,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
    ) -> bool:
        """
        Verify all XMSS signatures in this signed block.

        Checks that:

        - Each body attestation is signed by participating validators
        - The proposer signed the block root with the proposal key

        Args:
            validators: Validator registry providing public keys for verification.
            scheme: XMSS signature scheme for verification.

        Returns:
            True if all signatures are valid.

        Raises:
            AssertionError: On verification failure.
        """
        block = self.block
        signatures = self.signature
        aggregated_attestations = self.block.body.attestations
        attestation_signatures = signatures.attestation_signatures

        # Each attestation in the body must have a corresponding signature entry.
        assert len(aggregated_attestations) == len(attestation_signatures), (
            "Attestation signature groups must align with block body attestations"
        )

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
            attestation_data_root = hash_tree_root(aggregated_attestation.data)

            for validator_id in validator_ids:
                num_validators = Uint64(len(validators))
                assert validator_id.is_valid(num_validators), "Validator index out of range"

            # Collect attestation public keys for all participating validators.
            # Order matters: must match the order in the aggregated signature.
            public_keys = [validators[vid].get_attestation_pubkey() for vid in validator_ids]

            try:
                aggregated_signature.verify(
                    public_keys=public_keys,
                    message=attestation_data_root,
                    slot=aggregated_attestation.data.slot,
                )
            except AggregationError as exc:
                raise AssertionError(
                    f"Attestation aggregated signature verification failed: {exc}"
                ) from exc

        # Verify the proposer's signature over the block root.
        #
        # The proposer signs hash_tree_root(block) with their proposal key.
        # This proves the proposer endorsed this specific block.
        proposer_index = block.proposer_index
        assert proposer_index.is_valid(Uint64(len(validators))), "Proposer index out of range"

        proposer = validators[proposer_index]
        block_root = hash_tree_root(block)

        try:
            valid = scheme.verify(
                proposer.get_proposal_pubkey(),
                block.slot,
                block_root,
                signatures.proposer_signature,
            )
        except (ValueError, IndexError):
            valid = False
        assert valid, "Proposer block signature verification failed"

        return True
