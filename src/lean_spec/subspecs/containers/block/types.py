"""Block-specific SSZ types for the Lean Ethereum consensus specification."""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import ZERO_HASH, Bytes32, SSZList

from ...chain.config import VALIDATOR_REGISTRY_LIMIT
from ..attestation import AggregatedAttestation

if TYPE_CHECKING:
    from .block import Block


class BlockLookup(dict[Bytes32, "Block"]):
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
    def _validate(cls, v: Any) -> BlockLookup:
        if isinstance(v, cls):
            return v
        if isinstance(v, dict):
            return cls(v)
        raise ValueError(f"expected dict or BlockLookup, got {type(v)}")

    def __or__(self, other: dict[Bytes32, Block]) -> BlockLookup:
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


class AggregatedAttestations(SSZList[AggregatedAttestation]):
    """List of aggregated attestations included in a block."""

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)


class AttestationSignatures(SSZList[AggregatedSignatureProof]):
    """
    List of per-attestation aggregated signature proofs.

    Each entry corresponds to an aggregated attestation from the block body.

    It contains:
        - the participants bitfield,
        - proof bytes from leanVM signature aggregation.
    """

    LIMIT = int(VALIDATOR_REGISTRY_LIMIT)
