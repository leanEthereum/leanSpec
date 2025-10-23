"""
Core forkchoice algorithms.

Pure functions implementing the LMD GHOST forkchoice rule and related utilities.
"""

from typing import Dict, Optional

from lean_spec.subspecs.containers import (
    Block,
    Checkpoint,
    SignedAttestation,
    State,
)
from lean_spec.types import Bytes32, ValidatorIndex

from .constants import ZERO_HASH


def get_fork_choice_head(
    blocks: Dict[Bytes32, Block],
    root: Bytes32,
    latest_votes: Dict[ValidatorIndex, SignedAttestation],
    min_score: int = 0,
) -> Bytes32:
    """
    Use LMD GHOST to find the head block from a given root.

    Args:
        blocks: All known blocks indexed by hash.
        root: Starting point root (usually latest justified).
        latest_votes: Current votes by validator index.
        min_score: Minimum vote count for block inclusion.

    Returns:
        Hash of the chosen head block.
    """
    # Start at genesis if root is zero hash
    if root == ZERO_HASH:
        root = min(blocks.keys(), key=lambda block_hash: blocks[block_hash].slot)

    # If no votes, return the starting root immediately
    if not latest_votes:
        return root

    # Count votes for each block (votes for descendants count for ancestors)
    vote_weights: Dict[Bytes32, int] = {}

    for attestation in latest_votes.values():
        head = attestation.message.data.head
        if head.root in blocks:
            # Walk up from vote target, incrementing ancestor weights
            block_hash = head.root
            while blocks[block_hash].slot > blocks[root].slot:
                vote_weights[block_hash] = vote_weights.get(block_hash, 0) + 1
                block_hash = blocks[block_hash].parent_root

    # Build children mapping for blocks above min score
    children_map: Dict[Bytes32, list[Bytes32]] = {}
    for block_hash, block in blocks.items():
        if block.parent_root and vote_weights.get(block_hash, 0) >= min_score:
            children_map.setdefault(block.parent_root, []).append(block_hash)

    # Walk down tree, choosing child with most votes (tiebreak by slot, then hash)
    current = root
    while True:
        children = children_map.get(current, [])
        if not children:
            return current

        # Choose best child: most votes, then highest slot, then highest hash
        current = max(children, key=lambda x: (vote_weights.get(x, 0), blocks[x].slot, x))


def get_latest_justified(states: Dict[Bytes32, "State"]) -> Optional[Checkpoint]:
    """
    Find the justified checkpoint with the highest slot.

    Args:
        states: All known states indexed by hash.

    Returns:
        Latest justified checkpoint, or None if no states.
    """
    if not states:
        return None

    # Find state with maximum justified slot
    latest_state = max(states.values(), key=lambda s: s.latest_justified.slot)

    # Return latest justified checkpoint from that state
    return latest_state.latest_justified
