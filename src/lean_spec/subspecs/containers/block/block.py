"""Block Containers for the Lean Ethereum consensus specification."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.container import Container

from ..checkpoint import Checkpoint
from ..vote.vote import ProposerAttestationData
from .types import Attestations, BlockSignatures

_DEFAULT_PROPOSER_ATTESTATION = ProposerAttestationData(
    target=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
    source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
)


class BlockBody(Container):
    """The body of a block, containing payload data."""

    attestations: Attestations
    """
    A list of votes included in the block.

    Note: This will eventually be replaced by aggregated attestations.
    """

    proposer_attestation: ProposerAttestationData = (
        _DEFAULT_PROPOSER_ATTESTATION
    )
    """The proposer sourced attestation kept separate from the list."""


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


class SignedBlock(Container):
    """A container for a block and its aggregated signatures."""

    message: Block
    """The block being signed."""

    signature: BlockSignatures
    """Naive list of signatures aggregated for the block."""
