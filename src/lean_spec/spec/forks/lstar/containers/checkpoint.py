"""
Casper-FFG checkpoints and the attestation vote they anchor.

A checkpoint is the (block root, slot) pair that gets justified and finalized.
An attestation's content is three checkpoints: source, target, and head.
"""

from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import Bytes32, Container


class Checkpoint(Container):
    """
    A checkpoint in the chain's history.

    A checkpoint marks a specific moment in the chain.

    It combines a block identifier with a slot number.

    Checkpoints are used for justification and finalization.
    """

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


class AttestationData(Container):
    """Attestation content describing the validator's observed chain view."""

    slot: Slot
    """The slot for which the attestation is made."""

    head: Checkpoint
    """The checkpoint representing the head block as observed by the validator."""

    target: Checkpoint
    """The checkpoint representing the target block as observed by the validator."""

    source: Checkpoint
    """The checkpoint representing the source block as observed by the validator."""
