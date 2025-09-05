"""Block Containers."""

from pydantic import Field
from typing_extensions import Annotated

from lean_spec.types import Bytes32, StrictBaseModel, Uint64

from ..chain import config
from .vote import Vote


class BlockBody(StrictBaseModel):
    """The body of a block, containing payload data."""

    votes: Annotated[
        list[Vote],
        Field(max_length=config.VALIDATOR_REGISTRY_LIMIT),
    ]
    """
    A list of votes included in the block.

    Note: This will eventually be replaced by aggregated attestations.
    """


class BlockHeader(StrictBaseModel):
    """The header of a block, containing metadata."""

    slot: Uint64
    """The slot in which the block was proposed."""

    proposer_index: Uint64
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after processing the block."""

    body_root: Bytes32
    """The root of the block's body."""


class Block(StrictBaseModel):
    """Represents a single block in the chain."""

    slot: Uint64
    """The slot in which the block was proposed."""

    proposer_index: Uint64
    """The index of the validator that proposed the block."""

    parent_root: Bytes32
    """The root of the parent block."""

    state_root: Bytes32
    """The root of the state after applying transactions in this block."""

    body: BlockBody
    """The block's payload."""


class SignedBlock(StrictBaseModel):
    """A container for a block and the proposer's signature."""

    message: Block
    """The block data that was signed."""

    signature: Bytes32
    """
    The proposer's signature of the block message.

    Note: Bytes32 is a placeholder; the actual signature is much larger.
    """
