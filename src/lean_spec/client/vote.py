"""
A `Vote` is a single vote for a block in the Lean Consensus chain. Each `Vote`
contains information about the validator that voted, the slot of the block they
voted for, and the block hash they voted for.
"""

from dataclasses import dataclass

from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64
from pydantic import BaseModel, ConfigDict


@dataclass
class Vote(BaseModel):
    """A single vote for a block in the Lean Consensus chain."""
    
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Diverged from 3SF-mini.py:
    #   - Using `U64` instead of native `int` for all fields
    #   - Using `Bytes32` instead of native `str` for all fields

    validator_id: U64
    slot: U64
    head: Bytes32
    head_slot: U64
    target: Bytes32
    target_slot: U64
    source: Bytes32
    source_slot: U64
