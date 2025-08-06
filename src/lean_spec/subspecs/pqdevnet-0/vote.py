"""
A `Vote` is a single vote for a block in the Lean Consensus chain. Each `Vote`
contains information about the validator that voted, the slot of the block they
voted for, and the block hash they voted for.
"""

from dataclasses import dataclass
from remerkleable.basic import uint64
from remerkleable.byte_arrays import Bytes32
from pydantic import BaseModel, ConfigDict

@dataclass
class Vote(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Diverged from 3SF-mini.py:
    #   - Using `uint64` instead of native `int` for all fields
    #   - Using `Bytes32` instead of native `str` for all fields

    validator_id: uint64
    slot: uint64
    head: Bytes32
    head_slot: uint64
    target: Bytes32
    target_slot: uint64
    source: Bytes32
    source_slot: uint64
