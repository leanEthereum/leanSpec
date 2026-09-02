"""Shared utilities for consensus test types."""

from __future__ import annotations

from ssz import hash_tree_root

from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.forks.lstar.containers import Block
from lean_spec.spec.ssz_types import Bytes32


def resolve_block_root(
    label: str,
    block_registry: dict[str, Block],
) -> Bytes32:
    """Resolve a block label to its hash tree root, raising if the label is unknown."""
    if (block := block_registry.get(label)) is None:
        raise ValueError(f"label '{label}' not found - available: {list(block_registry.keys())}")
    return hash_tree_root(block)


def resolve_checkpoint(
    label: str,
    slot_override: Slot | None,
    block_registry: dict[str, Block],
) -> Checkpoint:
    """Resolve a block label into a checkpoint, preferring the slot override over the block slot."""
    root = resolve_block_root(label, block_registry)
    if slot_override is not None:
        return Checkpoint(root=root, slot=slot_override)
    return Checkpoint(root=root, slot=block_registry[label].slot)
