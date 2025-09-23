"""Block Containers."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, SSZList, Uint64
from lean_spec.types.container import Container

from .vote import SignedVote


# Concrete SSZList class for BlockBody
class SignedVoteList4096(SSZList):
    """List of SignedVote with limit 4096 (VALIDATOR_REGISTRY_LIMIT)."""

    ELEMENT_TYPE = SignedVote
    LIMIT = 4096


class BlockBody(Container):
    """The body of a block, containing payload data."""

    attestations: SignedVoteList4096
    """
    A list of votes included in the block.

    Note: This will eventually be replaced by aggregated attestations.
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
    """The root of the state after processing the block."""

    body_root: Bytes32
    """The root of the block's body."""


class Block(Container):
    """Represents a single block in the chain."""

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


class SignedBlock(Container):
    """A container for a block and the proposer's signature."""

    message: Block
    """The block data that was signed."""

    signature: Bytes32
    """
    The proposer's signature of the block message.

    Note: Bytes32 is a placeholder; the actual signature is much larger.
    """
