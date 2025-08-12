"""
A `Vote` is a single vote for a block in the Lean Consensus chain. Each `Vote`
contains information about the validator that voted, the slot of the block they
voted for, and the block hash they voted for.
"""

from ethereum_types.numeric import U64
from pydantic import BaseModel, ConfigDict

from .checkpoint import Checkpoint


class Vote(BaseModel):
    """A single vote for a block in the Lean Consensus chain."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    validator_id: U64
    slot: U64
    head: Checkpoint
    target: Checkpoint
    source: Checkpoint
