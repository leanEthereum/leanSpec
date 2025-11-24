"""
Core forkchoice algorithms.

Pure functions implementing the LMD GHOST forkchoice rule and related utilities.
"""

from typing import Dict

from lean_spec.subspecs.containers import (
    Block,
    SignedAttestation,
)
from lean_spec.types import Bytes32, ValidatorIndex

from .constants import ZERO_HASH


def get_fork_choice_head(
    blocks: Dict[Bytes32, Block],
    root: Bytes32,
    latest_attestations: Dict[ValidatorIndex, SignedAttestation],
    min_score: int = 0,
) -> Bytes32:
    """
    Use LMD GHOST to find the head block from a given root.

    Args:
        blocks: All known blocks indexed by hash.
        root: Starting point root (usually latest justified).
        latest_attestations: Current attestations by validator index.
        min_score: Minimum attestation count for block inclusion.

    Returns:
        Hash of the chosen head block.
    """
    # Start at genesis if root is zero hash
    if root == ZERO_HASH:
        root = min(blocks.keys(), key=lambda block_hash: blocks[block_hash].slot)

    # Count attestations for each block (attestations for descendants count for ancestors)
    attestation_weights: Dict[Bytes32, int] = {}

    for attestation in latest_attestations.values():
        head = attestation.message.data.head
        if head.root in blocks:
            # Walk up from attestation target, incrementing ancestor weights
            block_hash = head.root
            while blocks[block_hash].slot > blocks[root].slot:
                attestation_weights[block_hash] = attestation_weights.get(block_hash, 0) + 1
                block_hash = blocks[block_hash].parent_root

    # Build children mapping for ALL blocks (not just those above min_score)
    # This ensures fork choice works even when there are no attestations
    children_map: Dict[Bytes32, list[Bytes32]] = {}
    for block_hash, block in blocks.items():
        if block.parent_root:
            # Only include blocks that have enough attestations OR when min_score is 0
            if min_score == 0 or attestation_weights.get(block_hash, 0) >= min_score:
                children_map.setdefault(block.parent_root, []).append(block_hash)

    # Walk down tree, choosing child with most attestations (tiebreak by lexicographic hash)
    current = root
    while True:
        children = children_map.get(current, [])
        if not children:
            return current

        # Choose best child: most attestations, then lexicographically highest hash
        current = max(children, key=lambda x: (attestation_weights.get(x, 0), x))
