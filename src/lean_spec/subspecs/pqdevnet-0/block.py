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

from preset import VALIDATOR_REGISTRY_LIMIT
from vote import Vote

@dataclass
class Block(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    slot: uint64
    parent: Bytes32
    votes: List[Vote, VALIDATOR_REGISTRY_LIMIT]
    state_root: Bytes32
