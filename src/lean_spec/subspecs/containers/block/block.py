"""
Block Containers for the Lean Ethereum consensus specification.

A block proposes changes to the chain. It references its parent block, creating
a chain. The block includes a state root that represents the result of
applying this block.

Each block has a proposer who created it. The slot determines which validator
can propose.
"""

from typing import TYPE_CHECKING

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.xmss.aggregation import (
    MultisigError,
)
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import Bytes32, Uint64
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
    """
    The body of a block, containing payload data.

    Currently, the main operation is voting. Validators submit attestations which are
    packaged into blocks.
    """

    attestations: AggregatedAttestations
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
    """Attestation signatures for the aggregated attestations in the block body.

    Each entry corresponds to an aggregated attestation from the block body and
    contains the leanVM aggregated signature proof bytes for the participating validators.

    TODO:
    - Eventually this field will be replaced by a single SNARK aggregating *all* signatures.
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

    def verify_signatures(
        self, parent_state: "State", scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME
    ) -> bool:
        """
        Verify all XMSS signatures in this signed block.

        This function ensures that every attestation included in the block
        (both on-chain attestations from the block body and the proposer's
        own attestation) is properly signed by the claimed validator using
        their registered XMSS public key.

        Args:
            parent_state: The state at the parent block, used to retrieve
                validator public keys and verify signatures.
            scheme: The XMSS signature scheme to use for verification.

        Returns:
            True if all signatures are cryptographically valid.

        Raises:
            AssertionError: If signature verification fails, including:
                - Signature count mismatch
                - Validator index out of range
                - lean-multisig aggregated signature verification failure
                - XMSS signature verification failure
        """
        block = self.message.block
        signatures = self.signature
        aggregated_attestations = block.body.attestations
        attestation_signatures = signatures.attestation_signatures

        assert len(aggregated_attestations) == len(attestation_signatures), (
            "Attestation signature groups must align with block body attestations"
        )

        validators = parent_state.validators

        for aggregated_attestation, aggregated_signature in zip(
            aggregated_attestations, attestation_signatures, strict=True
        ):
            validator_ids = aggregated_attestation.aggregation_bits.to_validator_indices()

            attestation_data_root = aggregated_attestation.data.data_root_bytes()

            # Verify the leanVM aggregated proof for this attestation data root
            for validator_id in validator_ids:
                # Ensure validator exists in the active set
                assert validator_id < Uint64(len(validators)), "Validator index out of range"

            public_keys = [validators[vid].get_pubkey() for vid in validator_ids]
            try:
                aggregated_signature.verify_aggregated_payload(
                    public_keys=public_keys,
                    message=attestation_data_root,
                    epoch=aggregated_attestation.data.slot,
                )
            except MultisigError as exc:
                raise AssertionError(
                    f"Attestation aggregated signature verification failed: {exc}"
                ) from exc

        # Verify proposer attestation signature
        proposer_attestation = self.message.proposer_attestation
        proposer_signature = signatures.proposer_signature
        assert proposer_attestation.validator_id < Uint64(len(validators)), (
            "Proposer index out of range"
        )
        proposer = validators[proposer_attestation.validator_id]

        assert proposer_signature.verify(
            proposer.get_pubkey(),
            proposer_attestation.data.slot,
            proposer_attestation.data.data_root_bytes(),
            scheme,
        ), "Proposer signature verification failed"

        return True
