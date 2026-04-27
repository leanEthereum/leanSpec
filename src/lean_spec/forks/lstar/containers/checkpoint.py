"""
Checkpoint Container.

A checkpoint marks a specific moment in the chain. It combines a block
identifier with a slot number. Checkpoints are used for justification and
finalization.
"""

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.types import Bytes32
from lean_spec.types.container import Container


class Checkpoint(Container):
    """Represents a checkpoint in the chain's history."""

    root: Bytes32
    """The root hash of the checkpoint's block."""

    slot: Slot
    """The slot number of the checkpoint's block."""

    def __lt__(self, other: "Checkpoint") -> bool:
        """Order checkpoints by slot."""
        # Foreign types: defer to Python's reflected fallback.
        if not isinstance(other, Checkpoint):
            return NotImplemented
        # Slot drives the order; equal slots leave the pair incomparable.
        return self.slot < other.slot
