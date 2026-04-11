"""Shared utilities for consensus test types."""

from __future__ import annotations

from lean_spec.subspecs.containers.block.block import Block
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root


def resolve_checkpoint(
    label: str,
    slot_override: Slot | None,
    block_registry: dict[str, Block],
) -> Checkpoint:
    """
    Resolve a block label and optional slot override into a Checkpoint.

    Args:
        label: Block label in the registry.
        slot_override: When set, overrides the block's actual slot.
        block_registry: Labeled blocks for lookup.

    Returns:
        Checkpoint with the block's root and resolved slot.

    Raises:
        ValueError: If label not found in registry.
    """
    if (block := block_registry.get(label)) is None:
        raise ValueError(f"label '{label}' not found - available: {list(block_registry.keys())}")
    return Checkpoint(
        root=hash_tree_root(block),
        slot=block.slot if slot_override is None else slot_override,
    )
