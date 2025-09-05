"""Checkpoint Container."""

from lean_spec.types import Bytes32, StrictBaseModel, Uint64


class Checkpoint(StrictBaseModel):
    """Represents a checkpoint in the chain's history."""

    root: Bytes32
    """The root hash of the checkpoint's block."""

    slot: Uint64
    """The slot number of the checkpoint's block."""
