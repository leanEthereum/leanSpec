"""Checkpoint Container."""

from typing import Self

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32
from lean_spec.types.container import Container


class Checkpoint(Container):
    """Represents a checkpoint in the chain's history."""

    root: Bytes32
    """The root hash of the checkpoint's block."""

    slot: Slot
    """The slot number of the checkpoint's block."""

    @classmethod
    def default(cls) -> Self:
        """Return a default checkpoint."""
        return cls(root=Bytes32.zero(), slot=Slot(0))
