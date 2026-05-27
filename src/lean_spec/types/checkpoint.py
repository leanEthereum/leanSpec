"""
Checkpoint container.

A checkpoint marks a specific moment in the chain.

It combines a block identifier with a slot number.

Checkpoints are used for justification and finalization.
"""

from lean_spec.types.byte_arrays import Bytes32
from lean_spec.types.container import Container
from lean_spec.types.slot import Slot


class Checkpoint(Container):
    """Represents a checkpoint in the chain's history."""

    root: Bytes32
    """The root hash of the checkpoint's block."""

    slot: Slot
    """The slot number of the checkpoint's block."""

    def advance_to(self, candidate: "Checkpoint") -> "Checkpoint":
        """
        Return the later of two checkpoints, keeping self on a slot tie.

        Forward-only progression for justified and finalized checkpoints.

        The candidate replaces the receiver only when its slot is strictly higher.
        """
        return candidate if candidate.slot > self.slot else self
