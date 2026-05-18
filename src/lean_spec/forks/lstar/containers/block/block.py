"""
Block containers for Lean Ethereum consensus.

Blocks propose changes to the chain.
Each references its parent, forming a chain.
The proposer is determined by slot assignment.
"""

from lean_spec.types import ByteList512KiB, Bytes32, Slot, ValidatorIndex
from lean_spec.types.container import Container

from .types import AggregatedAttestations


class BlockBody(Container):
    """Payload of a block containing attestations."""

    attestations: AggregatedAttestations
    """Attestations in the block. Signatures are folded into the block-level proof."""


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


class SignedBlock(Container):
    """Envelope carrying a block with a single aggregated proof for all signatures.

    The proof is the SSZ-encoded form of a Type-2 multi-message proof that
    binds every attestation in the body plus the proposer's signature over
    the block root.
    """

    block: Block
    """The block being signed."""

    proof: ByteList512KiB
    """Single full-block proof covering attestations and the proposer signature."""
