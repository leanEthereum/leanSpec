"""
Block Containers for the Lean Ethereum consensus specification.

A block proposes changes to the chain. It references its parent block, creating
a chain. The block includes a state root that represents the result of
applying this block.

Each block has a proposer who created it. The slot determines which validator
can propose.
"""

from typing import TYPE_CHECKING, cast

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.container import Container

from ...xmss.containers import Signature as XmssSignature
from ..attestation import Attestation
from ..validator import Validator
from .types import AggregatedAttestationsList, AttestationSignatures

if TYPE_CHECKING:
    from ..state import State


class BlockBody(Container):
    """
    The body of a block, containing payload data.

    Currently, the main operation is voting. Validators submit attestations which are
    packaged into blocks.
    """

    attestations: AggregatedAttestationsList
    """Plain validator attestations carried in the block body.

    Individual signatures live in the aggregated block signature list, so
    these entries contain only attestation data without per-attestation signatures.
    """


class BlockHeader(Container):
    """
    The header of a block, containing metadata.

    Block headers summarize blocks without storing full content. The header
    includes references to the parent and the resulting state. It also contains
    a hash of the block body.

    Headers are smaller than full blocks. They're useful for tracking the chain
    without storing everything.
    """

    slot: Slot
    """The slot in which the block was proposed."""

    proposer_index: Uint64
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

    proposer_index: Uint64
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
    """Signature payload for the block."""

    attestation_signatures: AttestationSignatures
    """Signatures for the attestations in the block body.
    
    Contains a naive list of signatures for the attestations in the block body.

    TODO:
    - this will be replaced by a BytesArray in next PR to include leanVM aggregated sproof.
    """

    proposer_signature: XmssSignature
    """Signature for the proposer's attestation."""


class SignedBlockWithAttestation(Container):
    """Envelope carrying a block, an attestation from proposer, and aggregated signatures."""

    message: BlockWithAttestation
    """The block plus an attestation from proposer being signed."""

    signature: BlockSignatures
    """Aggregated signature payload for the block.

    Signatures remain in attestation order followed by the proposer signature
    over entire message. For devnet 1, however the proposer signature is just
    over message.proposer_attestation since leanVM is not yet performant enough
    to aggregate signatures with sufficient throughput.

    Eventually this field will be replaced by a SNARK (which represents the
    aggregation of all signatures).
    """

    def verify_signatures(self, parent_state: "State") -> bool:
        """
        Verify all XMSS signatures in this signed block.

        This function ensures that every attestation included in the block
        (both on-chain attestations from the block body and the proposer's
        own attestation) is properly signed by the claimed validator using
        their registered XMSS public key.

        Args:
            parent_state: The state at the parent block, used to retrieve
                validator public keys and verify signatures.

        Returns:
            True if all signatures are cryptographically valid.

        Raises:
            AssertionError: If signature verification fails, including:
                - Signature count mismatch
                - Validator index out of range
                - XMSS signature verification failure
        """
        # Unpack the signed block components
        block = self.message.block
        signatures = self.signature

        # Combine all attestations that need verification
        #
        # This creates a single list containing both:
        # 1. Block body attestations (from other validators)
        # 2. Proposer attestation (from the block producer)
        all_attestations = block.body.attestations + [self.message.proposer_attestation]

        # Verify signature count matches attestation count
        #
        # Each attestation must have exactly one corresponding signature.
        #
        # The ordering must be preserved:
        # 1. Block body attestations,
        # 2. The proposer attestation.
        assert len(signatures) == len(all_attestations), (
            "Number of signatures does not match number of attestations"
        )

        validators = parent_state.validators

        # Verify each attestation signature
        for attestation, signature in zip(all_attestations, signatures, strict=True):
            # Ensure validator exists in the active set
            assert attestation.validator_id < Uint64(len(validators)), (
                "Validator index out of range"
            )
            validator = cast(Validator, validators[attestation.validator_id])

            # Verify the XMSS signature
            #
            # This cryptographically proves that:
            # - The validator possesses the secret key for their public key
            # - The attestation has not been tampered with
            # - The signature was created at the correct epoch (slot)
            assert signature.verify(
                validator.get_pubkey(),
                attestation.data.slot,
                bytes(hash_tree_root(attestation)),
            ), "Attestation signature verification failed"

        return True
