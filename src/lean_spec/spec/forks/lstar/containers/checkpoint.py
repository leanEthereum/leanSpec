"""
Casper-FFG checkpoints and the attestation vote they anchor.

A checkpoint is the (block root, slot) pair that gets justified and finalized.
An attestation's content is three checkpoints: source, target, and head.
"""

from collections.abc import Sequence

from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import ZERO_HASH, Bytes32, Container


class Checkpoint(Container):
    """A (block root, slot) pair that can be justified and finalized."""

    root: Bytes32
    """The root hash of the checkpoint's block."""

    slot: Slot
    """The slot number of the checkpoint's block."""

    def advance_to(self, candidate: "Checkpoint") -> "Checkpoint":
        """
        The later of two checkpoints, keeping this one on a slot tie.

        The candidate replaces this checkpoint only when its slot is strictly higher.
        This enforces forward-only progression for justified and finalized checkpoints.
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

    def lies_on_chain(self, historical_block_hashes: Sequence[Bytes32]) -> bool:
        """
        Check that every checkpoint points to a block on the given chain.

        Args:
            historical_block_hashes: Chain view indexed by slot.
                Empty slots carry the zero hash.

        Returns:
            True when all checkpoint roots match the chain at their slot.
            False when any root is the zero hash.
            False when any checkpoint slot is past the end of the chain view.
        """
        # Reject zero-hash checkpoints up front.
        #
        # Empty slots carry the zero hash on the chain.
        # A vote whose recorded root equals the zero hash is meaningless.
        if (
            self.source.root == ZERO_HASH
            or self.target.root == ZERO_HASH
            or self.head.root == ZERO_HASH
        ):
            return False

        # Reject checkpoints whose slot is beyond the chain view.
        #
        # Without this guard, indexed access raises IndexError.
        source_slot = int(self.source.slot)
        target_slot = int(self.target.slot)
        head_slot = int(self.head.slot)
        chain_length = len(historical_block_hashes)
        if source_slot >= chain_length or target_slot >= chain_length or head_slot >= chain_length:
            return False

        # All checkpoint roots must match the chain at their slot.
        return (
            self.source.root == historical_block_hashes[source_slot]
            and self.target.root == historical_block_hashes[target_slot]
            and self.head.root == historical_block_hashes[head_slot]
        )
