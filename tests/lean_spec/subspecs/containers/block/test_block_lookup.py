"""Tests for BlockLookup mapping type."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers.block.block import Block, BlockBody
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    BlockLookup,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import ZERO_HASH, Bytes32


def _root(seed: int) -> Bytes32:
    """Create a deterministic 32-byte root from a seed."""
    return Bytes32(bytes([seed % 256]) * 32)


def _block(parent_root: Bytes32, slot: int = 1) -> Block:
    """Create a minimal block with the given parent root."""
    return Block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(0),
        parent_root=parent_root,
        state_root=ZERO_HASH,
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


def _chain(length: int) -> tuple[BlockLookup, list[Bytes32]]:
    """Build a linear chain of blocks and return the lookup plus ordered roots.

    The first block's parent is ZERO_HASH (genesis).
    Returns roots ordered from genesis-child to tip.
    """
    roots: list[Bytes32] = []
    lookup = BlockLookup()
    parent = ZERO_HASH
    for i in range(1, length + 1):
        root = _root(i)
        lookup[root] = _block(parent, slot=i)
        roots.append(root)
        parent = root
    return lookup, roots


class TestAncestors:
    """Tests for BlockLookup.ancestors."""

    def test_linear_chain_walks_back_to_genesis(self) -> None:
        """Ancestors of the tip of a 3-block chain returns all roots tip-first."""
        lookup, roots = _chain(3)

        assert list(lookup.ancestors(roots[-1])) == list(reversed(roots))

    def test_single_block_pointing_to_genesis(self) -> None:
        """A single block whose parent is ZERO_HASH yields just that block's root."""
        root = _root(1)
        lookup = BlockLookup({root: _block(ZERO_HASH)})

        assert list(lookup.ancestors(root)) == [root]

    def test_root_not_in_lookup_returns_empty(self) -> None:
        """An unknown root produces no ancestors."""
        lookup = BlockLookup()

        assert list(lookup.ancestors(_root(99))) == []

    def test_genesis_block_yields_only_itself(self) -> None:
        """A block whose parent_root is ZERO_HASH stops immediately after yielding."""
        root = _root(10)
        lookup = BlockLookup({root: _block(ZERO_HASH, slot=0)})

        assert list(lookup.ancestors(root)) == [root]

    def test_two_block_chain(self) -> None:
        """A two-block chain returns both roots in reverse order."""
        lookup, roots = _chain(2)

        assert list(lookup.ancestors(roots[-1])) == [roots[1], roots[0]]

    def test_ancestors_from_middle_of_chain(self) -> None:
        """Starting from a mid-chain root only walks back from that point."""
        lookup, roots = _chain(4)

        assert list(lookup.ancestors(roots[1])) == [roots[1], roots[0]]


class TestReorgDepth:
    """Tests for BlockLookup.reorg_depth."""

    def test_same_head_is_zero(self) -> None:
        """No reorg when old and new head are the same block."""
        lookup, roots = _chain(3)
        head = roots[-1]

        assert lookup.reorg_depth(head, head) == 0

    def test_simple_fork(self) -> None:
        """Two branches diverging from a common ancestor.

        Chain:  genesis -> A -> B (old head)
                               \\-> C -> D (new head)

        Old chain has 1 block (B) past the fork point A.
        """
        root_a = _root(1)
        root_b = _root(2)
        root_c = _root(3)
        root_d = _root(4)

        lookup = BlockLookup(
            {
                root_a: _block(ZERO_HASH, slot=1),
                root_b: _block(root_a, slot=2),
                root_c: _block(root_a, slot=2),
                root_d: _block(root_c, slot=3),
            }
        )

        assert lookup.reorg_depth(old_head=root_b, new_head=root_d) == 1

    def test_deeper_fork(self) -> None:
        """Old chain has multiple blocks past the fork point.

        Chain:  genesis -> A -> B -> C (old head)
                               \\-> D (new head)

        Old chain has 2 blocks (B, C) past the fork point A.
        """
        root_a = _root(1)
        root_b = _root(2)
        root_c = _root(3)
        root_d = _root(4)

        lookup = BlockLookup(
            {
                root_a: _block(ZERO_HASH, slot=1),
                root_b: _block(root_a, slot=2),
                root_c: _block(root_b, slot=3),
                root_d: _block(root_a, slot=2),
            }
        )

        assert lookup.reorg_depth(old_head=root_c, new_head=root_d) == 2

    def test_old_head_not_in_lookup(self) -> None:
        """Old head absent from lookup produces depth 0."""
        lookup, roots = _chain(2)

        assert lookup.reorg_depth(old_head=_root(99), new_head=roots[-1]) == 0

    def test_new_head_not_in_lookup(self) -> None:
        """New head absent means no common ancestors, so all old ancestors are counted."""
        lookup, roots = _chain(3)

        assert lookup.reorg_depth(old_head=roots[-1], new_head=_root(99)) == 3

    def test_both_share_genesis_as_common_ancestor(self) -> None:
        """Two independent chains from genesis diverge at the very first block.

        Chain:  genesis -> A -> B (old head)
                genesis -> C -> D (new head)

        Old chain has 2 blocks (A, B) with no overlap with new chain.
        """
        root_a = _root(1)
        root_b = _root(2)
        root_c = _root(3)
        root_d = _root(4)

        lookup = BlockLookup(
            {
                root_a: _block(ZERO_HASH, slot=1),
                root_b: _block(root_a, slot=2),
                root_c: _block(ZERO_HASH, slot=1),
                root_d: _block(root_c, slot=2),
            }
        )

        assert lookup.reorg_depth(old_head=root_b, new_head=root_d) == 2


class TestValidation:
    """Tests for BlockLookup Pydantic validation."""

    def test_blocklookup_instance_passes_through(self) -> None:
        """An existing BlockLookup is returned as-is."""
        original = BlockLookup()
        result = BlockLookup._validate(original)

        assert result is original

    def test_plain_dict_coerced_to_blocklookup(self) -> None:
        """A plain dict is wrapped into a BlockLookup."""
        root = _root(1)
        block = _block(ZERO_HASH)
        result = BlockLookup._validate({root: block})

        assert isinstance(result, BlockLookup)
        assert result == BlockLookup({root: block})

    def test_invalid_type_raises_valueerror(self) -> None:
        """Non-dict, non-BlockLookup input raises ValueError."""
        with pytest.raises(ValueError, match=r"expected dict or BlockLookup"):
            BlockLookup._validate("not a dict")

    def test_invalid_type_list_raises_valueerror(self) -> None:
        """A list also raises ValueError."""
        with pytest.raises(ValueError, match=r"expected dict or BlockLookup"):
            BlockLookup._validate([1, 2, 3])


class TestDictBehavior:
    """Tests for standard dict operations on BlockLookup."""

    def test_len_and_contains(self) -> None:
        """BlockLookup supports len() and 'in' checks."""
        lookup, roots = _chain(3)

        assert len(lookup) == 3
        assert roots[0] in lookup
        assert _root(99) not in lookup

    def test_iteration_yields_keys(self) -> None:
        """Iterating over a BlockLookup yields its keys."""
        lookup, roots = _chain(2)

        assert set(lookup) == set(roots)

    def test_getitem_returns_block(self) -> None:
        """Subscript access returns the stored Block."""
        root = _root(1)
        block = _block(ZERO_HASH)
        lookup = BlockLookup({root: block})

        assert lookup[root] == block

    def test_empty_lookup(self) -> None:
        """An empty BlockLookup has length 0 and no keys."""
        lookup = BlockLookup()

        assert len(lookup) == 0
        assert list(lookup) == []
