"""Block Containers for the Lean Ethereum consensus specification."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.container import Container

from ..vote import ValidatorAttestation
from .types import Attestations, BlockSignatures


class BlockBody(Container):
    """The body of a block, containing payload data."""

    attestations: Attestations
    """Plain validator attestations carried in the block body.

    Individual signatures live in the aggregated block signature list, so
    these entries contain only vote data without per-attestation signatures.
    """


class BlockHeader(Container):
    """The header of a block, containing metadata."""

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


class BlockAndProposerVote(Container):
    """Bundle containing a block and the proposer's attestation."""

    block: Block
    """The proposed block message."""

    proposer_attestation: ValidatorAttestation
    """The proposer's vote corresponding to this block."""


class SignedBlockAndVote(Container):
    """Envelope carrying a block, proposer vote, and aggregated signatures."""

    message: BlockAndProposerVote
    """The block plus proposer vote being signed."""

    signature: BlockSignatures
    """Aggregated signature payload for the block.

    Signatures remain in attestation order followed by the proposer signature
    over entire message. For devnet 1, however the proposer signature is just
    over message.proposer_attestation since lean VM is not yet there to establish
    validity/mergability of the signature for its packaging into the future blocks.

    Eventually this field will be replaced by a single zk-aggregated signature.
    """
