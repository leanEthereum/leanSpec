"""
Block Containers for the Lean Ethereum consensus specification.

A block proposes changes to the chain. It references its parent block, creating
a chain. The block includes a state root that represents the result of
applying this block.

Each block has a proposer who created it. The slot determines which validator
can propose.
"""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.container import Container

from ..attestation import Attestation
from .types import Attestations, BlockSignatures


class BlockBody(Container):
    """
    The body of a block, containing payload data.

    Currently, the main operation is voting. Validators submit votes which are
    packaged into blocks.
    """

    attestations: Attestations
    """Plain validator attestations carried in the block body.

    Individual signatures live in the aggregated block signature list, so
    these entries contain only vote data without per-attestation signatures.
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
    """The proposer's vote corresponding to this block."""


class SignedBlockWithAttestation(Container):
    """Envelope carrying a block, proposer vote, and aggregated signatures."""

    message: BlockWithAttestation
    """The block plus proposer vote being signed."""

    signature: BlockSignatures
    """Aggregated signature payload for the block.

    Signatures remain in attestation order followed by the proposer signature
    over entire message. For devnet 1, however the proposer signature is just
    over message.proposer_attestation since leanVM is not yet performant enough
    to aggregate signatures with sufficient throughput.

    Eventually this field will be replaced by a SNARK (which represents the
    aggregation of all signatures).
    """
