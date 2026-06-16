"""Shared utilities for consensus test types."""

from __future__ import annotations

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.forks.lstar.containers import Block
from lean_spec.spec.ssz import Bytes32


def resolve_block_root(
    label: str,
    block_registry: dict[str, Block],
) -> Bytes32:
    """
    Resolve a block label to its hash tree root.

    Args:
        label: Block label in the registry.
        block_registry: Labeled blocks for lookup.

    Returns:
        The block's hash tree root.

    Raises:
        ValueError: If label not found in registry.
    """
    if (block := block_registry.get(label)) is None:
        raise ValueError(f"label '{label}' not found - available: {list(block_registry.keys())}")
    return hash_tree_root(block)


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
    root = resolve_block_root(label, block_registry)
    # An explicit override wins; otherwise fall back to the labeled block's own slot.
    if slot_override is not None:
        return Checkpoint(root=root, slot=slot_override)
    return Checkpoint(root=root, slot=block_registry[label].slot)
