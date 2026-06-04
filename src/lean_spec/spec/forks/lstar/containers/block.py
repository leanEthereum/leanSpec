"""Block container family carrying attestations and the merged block proof."""

from lean_spec.spec.forks.lstar.containers.aggregation import MultiMessageAggregate
from lean_spec.spec.forks.lstar.containers.attestation import AggregatedAttestations
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import Bytes32, Container


class BlockBody(Container):
    """Payload of a block containing attestations."""

    model_config = Container.model_config | {"frozen": True}

    attestations: AggregatedAttestations
    """Attestations in the block. Signatures are folded into the block-level proof."""


class BlockHeader(Container):
    """
    Metadata summarizing a block.

    Contains parent reference, state root, and body hash.
    Smaller than full blocks.
    """

    model_config = Container.model_config | {"frozen": True}

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

    model_config = Container.model_config | {"frozen": True}

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

    The proof is a multi-message aggregate multi-message proof.
    It binds every attestation in the body plus the proposer's signature
    over the block root.
    """

    model_config = Container.model_config | {"frozen": True}

    block: Block
    """The block being signed."""

    proof: MultiMessageAggregate
    """Single full-block proof covering attestations and the proposer signature."""
