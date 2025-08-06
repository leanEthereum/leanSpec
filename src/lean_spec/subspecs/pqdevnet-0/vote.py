"""
A `Block` is a single link in the Lean Consensus chain. Each `Block` contains
a `Header` and zero or more transactions. Each `Header` contains associated
metadata like the block number, parent block hash, and how much gas was
consumed by its transactions.

Together, these blocks form a cryptographically secure journal recording the
history of all state transitions that have happened since the genesis of the
chain.
"""

from dataclasses import dataclass
from remerkleable.basic import uint64
from remerkleable.byte_arrays import Bytes32
from remerkleable.complex import List
from pydantic import BaseModel, ConfigDict

@dataclass
class Vote(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    validator_id: uint64
    slot: uint64
    head: Bytes32
    head_slot: uint64
    target: Bytes32
    target_slot: uint64
    source: Bytes32
    source_slot: uint64
