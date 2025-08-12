"""
A `Checkpoint` is a single checkpoint for a block in the Lean Consensus chain.
Each `Checkpoint` contains its associated block root and slot.
"""

from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64
from pydantic import BaseModel, ConfigDict


class Checkpoint(BaseModel):
    """A single checkpoint in the Lean Consensus chain."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    root: Bytes32
    slot: U64
