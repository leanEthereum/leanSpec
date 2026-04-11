"""
Block containers for Lean Ethereum consensus.

Blocks propose changes to the chain.
Each references its parent, forming a chain.
The proposer is determined by slot assignment.
"""

from collections.abc import Iterator
from typing import Any

from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex, Validators
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregationError
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import ZERO_HASH, Bytes32, Uint64
from lean_spec.types.container import Container

from ...xmss.containers import Signature
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


class BlockLookup(dict[Bytes32, Block]):
    """
    Index of all known blocks, keyed by block root.

    The fork choice store uses this mapping to navigate the block tree.
    Every block the node has received and validated appears here.

    Blockchains can fork when two valid blocks reference the same parent.
    This creates a tree structure rather than a single chain.
    Walking this tree is essential for:

    - Determining ancestor relationships between blocks
    - Measuring reorganization depth when the head changes
    - Resolving which chain is canonical

    Supports Pydantic validation so it can be used in store models.
    """

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Define Pydantic validation: accept plain dicts and coerce."""
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(dict),
        )

    @classmethod
    def _validate(cls, v: Any) -> "BlockLookup":
        if isinstance(v, cls):
            return v
        if isinstance(v, dict):
            return cls(v)
        raise ValueError(f"expected dict or BlockLookup, got {type(v)}")

    def __or__(self, other: dict[Bytes32, Block]) -> "BlockLookup":
        """Merge with another dict, preserving the BlockLookup type."""
        return BlockLookup(super().__or__(other))

    def ancestors(self, root: Bytes32) -> Iterator[Bytes32]:
        """
        Walk the chain backward from a block toward genesis.

        Each block points to its parent via parent_root.
        This method follows those links, yielding each block root
        along the way. The walk stops when it reaches:

        - A block whose parent is the zero hash (genesis boundary)
        - A block whose parent is not in the lookup (pruned history)

        Fork choice relies on ancestor walks to compare chains.
        Two blocks share a common ancestor if their ancestor sets
        overlap. The point where they diverge defines a fork.

        Args:
            root: Starting block root. Walk proceeds toward genesis.

        Yields:
            Block roots from the starting block back to the oldest
            reachable ancestor (inclusive on both ends).
        """
        while root in self:
            yield root

            # Follow the parent link one step back.
            #
            # A zero-hash parent means this block sits at the genesis
            # boundary. No further ancestors exist.
            parent = self[root].parent_root
            if parent == ZERO_HASH:
                break
            root = parent

    def reorg_depth(self, old_head: Bytes32, new_head: Bytes32) -> int:
        """
        Count how many blocks the old head must revert to reach the new chain.

        A reorganization (reorg) happens when fork choice switches to a
        different chain. The depth measures how many blocks on the old
        chain are abandoned. Deeper reorgs are more disruptive because
        more transactions and attestations are reverted.

        The algorithm finds the common ancestor by collecting the new
        chain's ancestors, then counting old-chain blocks that are not
        in that set.

        Args:
            old_head: The previous canonical head block root.
            new_head: The new canonical head block root.

        Returns:
            Number of old-chain blocks between old_head and the common
            ancestor (exclusive of the common ancestor itself).
            Returns 0 when both heads are the same.
        """
        # Collect the full ancestry of the new head.
        #
        # This set lets us identify the common ancestor efficiently.
        ancestors_of_new = set(self.ancestors(new_head))

        # Count old-chain blocks not shared with the new chain.
        #
        # Each such block represents one slot of reverted history.
        return sum(1 for root in self.ancestors(old_head) if root not in ancestors_of_new)


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
